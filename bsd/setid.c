/*
 * Copyright © 2026 Håvard Sørbø
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "broker.h"
#include "bsd/credentials.h"
#include "bsd/setid.h"
static int guest_descriptors(int skip, int *fds);
static int terminal_of(const int *fds, int count);
static int relayed_terminal(const int *fds, int *sent, int count, int *tty,
		int *master, int *slave);
static bool send_request(int fd, const char *path, char *argv[], const int *fds,
		const int *sent, int count, int terminal, bool job);
static bool receive(int fd, uint32_t type, void *payload, uint32_t length);
static void stand_in(int fd, pid_t pid, int tty, int master)
		__attribute__((noreturn));
static bool relay(int from, int to);
static void stop(int signal, pid_t pid);
static void set_raw(int tty, const struct termios *saved, bool raw);

extern char **environ;

void
setid_exec_as_owner(char *argv[])
{
	const char *path = argv[1];
	struct stat st;
	struct statvfs vfs;
	if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)
			|| !(st.st_mode & (S_ISUID | S_ISGID))
			|| statvfs(path, &vfs) != 0
			|| (vfs.f_flag & ST_NOSUID)) {
		return;
	}
	bool user = (st.st_mode & S_ISUID) && st.st_uid != geteuid();
	bool group = (st.st_mode & S_ISGID) && st.st_gid != getegid();
	if (!user && !group) {
		if (((st.st_mode & S_ISUID) && st.st_uid != getuid())
				|| ((st.st_mode & S_ISGID)
						&& st.st_gid != getgid())) {
			credentials_set_sugid();
		}
		return;
	}
	if (geteuid() == 0) {
		if (group) {
			(void)!setresgid(-1, st.st_gid, st.st_gid);
		}
		if (user) {
			(void)!setresuid(-1, st.st_uid, st.st_uid);
		}
		credentials_set_sugid();
		return;
	}

	const char *socket_path = getenv(LIMBO_BROKER_SOCKET_ENV);
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	if (socket_path != NULL) {
		strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
	}
	if (socket_path == NULL || fd == -1
			|| connect(fd, (struct sockaddr *)&addr, sizeof(addr))
					!= 0) {
		fprintf(stderr,
				"limbo: %s is set-user-ID, and no broker runs "
				"it as its owner\n",
				path);
		if (fd != -1) {
			close(fd);
		}
		return;
	}

	int fds[BROKER_DATAGRAM_FDS];
	int count = guest_descriptors(fd, fds);
	int sent[BROKER_DATAGRAM_FDS];
	int terminal = count < 0 ? -1 : terminal_of(fds, count);
	int tty = -1, master = -1, slave = -1;
	if (count > 0) {
		memcpy(sent, fds, count * sizeof(int));
		if (terminal == -1) {
			terminal = relayed_terminal(fds, sent, count, &tty,
					&master, &slave);
		}
	}
	struct broker_setid_started started;
	if (count < 0
			|| !send_request(fd, path, argv, fds, sent, count,
					terminal, master != -1)
			|| !receive(fd, BROKER_SETID_STARTED, &started,
					sizeof(started))) {
		fprintf(stderr, "limbo: %s: the broker didn't run it\n", path);
		_exit(126);
	}
	if (started.error != 0) {
		fprintf(stderr, "limbo: %s: %s\n", path,
				strerror(started.error));
		_exit(started.error == ENOENT ? 127 : 126);
	}

	int null = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (slave != -1) {
		close(slave);
	}
	for (int i = 0; i != count; i++) {
		if (fds[i] <= STDERR_FILENO && null != -1) {
			dup2(null, fds[i]);
		} else {
			close(fds[i]);
		}
	}
	prctl(PR_SET_NAME, basename(argv[1]));
	stand_in(fd, started.pid, tty, master);
}

static int
guest_descriptors(int skip, int *fds)
{
	DIR *dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		return -1;
	}
	int count = 0;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		int fd = atoi(entry->d_name);
		if (entry->d_name[0] == '.' || fd == dirfd(dir) || fd == skip) {
			continue;
		}
		int flags = fcntl(fd, F_GETFD);
		if (flags == -1 || (flags & FD_CLOEXEC)) {
			continue;
		}
		if (count == BROKER_DATAGRAM_FDS) {
			closedir(dir);
			return -1;
		}
		fds[count++] = fd;
	}
	closedir(dir);
	return count;
}

static int
terminal_of(const int *fds, int count)
{
	pid_t session = getsid(0);
	if (session != getpid()) {
		return -1;
	}
	for (int i = 0; i != count; i++) {
		if (isatty(fds[i]) && tcgetsid(fds[i]) == session) {
			return fds[i];
		}
	}
	return -1;
}

static int
relayed_terminal(const int *fds, int *sent, int count, int *tty, int *master,
		int *slave)
{
	pid_t session = getsid(0);
	*tty = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (*tty == -1) {
		goto none;
	}
	int first = -1;
	for (int i = 0; i != count && first == -1; i++) {
		if (isatty(fds[i]) && tcgetsid(fds[i]) == session) {
			first = i;
		}
	}
	struct termios termios;
	struct winsize size;
	if (first == -1 || tcgetattr(*tty, &termios) != 0) {
		goto none;
	}
	*master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (*master == -1 || grantpt(*master) != 0 || unlockpt(*master) != 0) {
		goto none;
	}
	*slave = open(ptsname(*master), O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (*slave == -1) {
		goto none;
	}
	tcsetattr(*slave, TCSANOW, &termios);
	if (ioctl(*tty, TIOCGWINSZ, &size) == 0) {
		ioctl(*slave, TIOCSWINSZ, &size);
	}
	for (int i = first; i != count; i++) {
		if (isatty(fds[i]) && tcgetsid(fds[i]) == session) {
			sent[i] = *slave;
		}
	}
	return fds[first];

none:
	if (*slave != -1) {
		close(*slave);
	}
	if (*master != -1) {
		close(*master);
	}
	if (*tty != -1) {
		close(*tty);
	}
	*tty = *master = *slave = -1;
	return -1;
}

static bool
send_request(int fd, const char *path, char *argv[], const int *fds,
		const int *sent, int count, int terminal, bool job)
{
	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		strcpy(cwd, "/");
	}
	struct broker_setid_exec request = {
			.fd_count = (uint32_t)count,
			.terminal = terminal,
			.job = job,
	};
	for (int i = 0; i != count; i++) {
		request.fd_numbers[i] = fds[i];
	}
	size_t length = sizeof(struct broker_frame) + sizeof(request)
			+ strlen(path) + 1 + strlen(cwd) + 1;
	for (char **arg = argv + 2; *arg != NULL; arg++) {
		length += strlen(*arg) + 1;
		request.argc++;
	}
	for (char **var = environ; *var != NULL; var++) {
		length += strlen(*var) + 1;
		request.envc++;
	}
	char *frame = malloc(length);
	struct broker_frame header = {
			.type = BROKER_SETID_EXEC,
			.length = (uint32_t)(length - sizeof(header)),
	};
	memcpy(frame, &header, sizeof(header));
	memcpy(frame + sizeof(header), &request, sizeof(request));
	char *cursor = frame + sizeof(header) + sizeof(request);
	cursor = stpcpy(cursor, path) + 1;
	cursor = stpcpy(cursor, cwd) + 1;
	for (char **arg = argv + 2; *arg != NULL; arg++) {
		cursor = stpcpy(cursor, *arg) + 1;
	}
	for (char **var = environ; *var != NULL; var++) {
		cursor = stpcpy(cursor, *var) + 1;
	}

	struct iovec iov = {.iov_base = frame, .iov_len = length};
	union {
		char buffer[CMSG_SPACE(sizeof(int) * BROKER_DATAGRAM_FDS)];
		struct cmsghdr align;
	} control;
	struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
	if (count != 0) {
		msg.msg_control = control.buffer;
		msg.msg_controllen = CMSG_SPACE(sizeof(int) * count);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int) * count);
		memcpy(CMSG_DATA(cmsg), sent, sizeof(int) * count);
	}
	bool done = sendmsg(fd, &msg, MSG_NOSIGNAL) == (ssize_t)length;
	free(frame);
	return done;
}

static bool
receive(int fd, uint32_t type, void *payload, uint32_t length)
{
	for (;;) {
		char frame[sizeof(struct broker_frame) + 64];
		ssize_t n = recv(fd, frame, sizeof(frame), 0);
		struct broker_frame header;
		if (n < (ssize_t)sizeof(header)) {
			return false;
		}
		memcpy(&header, frame, sizeof(header));
		if (header.type != type) {
			continue;
		}
		if (header.length != length
				|| n != (ssize_t)(sizeof(header) + length)) {
			return false;
		}
		memcpy(payload, frame + sizeof(header), length);
		return true;
	}
}

static void
stand_in(int fd, pid_t pid, int tty, int master)
{
	sigset_t all;
	sigfillset(&all);
	sigprocmask(SIG_BLOCK, &all, NULL);
	int signals = signalfd(-1, &all, SFD_CLOEXEC);
	struct termios saved;
	bool relaying = master != -1 && tcgetattr(tty, &saved) == 0;
	bool raw = false, typing = relaying;
	struct pollfd polled[4] = {
			{.fd = fd, .events = POLLIN},
			{.fd = signals, .events = POLLIN},
			{.fd = relaying ? master : -1, .events = POLLIN},
			{.fd = -1, .events = POLLIN},
	};
	for (;;) {
		bool foreground = typing && tcgetpgrp(tty) == getpgrp();
		if (foreground != raw) {
			set_raw(tty, &saved, foreground);
			raw = foreground;
		}
		polled[3].fd = foreground ? tty : -1;
		if (poll(polled, 4, -1) == -1) {
			continue;
		}
		if (polled[1].revents & POLLIN) {
			struct signalfd_siginfo info;
			if (read(signals, &info, sizeof(info)) != sizeof(info)
					|| info.ssi_signo == SIGCHLD) {
			} else if (relaying && info.ssi_signo == SIGWINCH) {
				struct winsize size;
				if (ioctl(tty, TIOCGWINSZ, &size) == 0) {
					ioctl(master, TIOCSWINSZ, &size);
				}
			} else {
				kill(pid, (int)info.ssi_signo);
			}
		}
		if ((polled[2].revents & (POLLIN | POLLHUP | POLLERR))
				&& !relay(master, tty)) {
			polled[2].fd = -1;
		}
		if ((polled[3].revents & (POLLIN | POLLHUP | POLLERR))
				&& !relay(tty, master)) {
			typing = false;
		}
		if (!(polled[0].revents & (POLLIN | POLLHUP | POLLERR))) {
			continue;
		}
		char frame[sizeof(struct broker_frame) + 64];
		ssize_t n = recv(fd, frame, sizeof(frame), MSG_DONTWAIT);
		struct broker_frame header;
		struct broker_setid_exited exited;
		struct broker_setid_stopped stopped;
		if (n == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		}
		if (n < (ssize_t)sizeof(header)) {
			_exit(1);
		}
		memcpy(&header, frame, sizeof(header));
		ssize_t stopped_size = sizeof(header) + sizeof(stopped);
		if (header.type == BROKER_SETID_STOPPED && n == stopped_size) {
			memcpy(&stopped, frame + sizeof(header),
					sizeof(stopped));
			if (raw) {
				set_raw(tty, &saved, false);
				raw = false;
			}
			stop(stopped.signal, pid);
			continue;
		}
		if (header.type != BROKER_SETID_EXITED) {
			continue;
		}
		if (n != (ssize_t)(sizeof(header) + sizeof(exited))) {
			_exit(1);
		}
		memcpy(&exited, frame + sizeof(header), sizeof(exited));
		if (relaying) {
			fcntl(master, F_SETFL, O_NONBLOCK);
			while (relay(master, tty)) {
			}
			if (raw) {
				set_raw(tty, &saved, false);
			}
		}
		if (WIFSIGNALED(exited.status)) {
			int signal = WTERMSIG(exited.status);
			struct sigaction dfl = {.sa_handler = SIG_DFL};
			sigaction(signal, &dfl, NULL);
			sigset_t one;
			sigemptyset(&one);
			sigaddset(&one, signal);
			sigprocmask(SIG_UNBLOCK, &one, NULL);
			raise(signal);
			_exit(128 + signal);
		}
		_exit(WEXITSTATUS(exited.status));
	}
}

static bool
relay(int from, int to)
{
	char buffer[4096];
	ssize_t n = read(from, buffer, sizeof(buffer));
	for (ssize_t done = 0, m; done < n; done += m) {
		m = write(to, buffer + done, n - done);
		if (m <= 0) {
			break;
		}
	}
	return n > 0;
}

static void
stop(int signal, pid_t pid)
{
	struct sigaction dfl = {.sa_handler = SIG_DFL}, old;
	sigaction(signal, &dfl, &old);
	sigset_t one;
	sigemptyset(&one);
	sigaddset(&one, signal);
	sigprocmask(SIG_UNBLOCK, &one, NULL);
	kill(0, signal);
	sigprocmask(SIG_BLOCK, &one, NULL);
	sigaction(signal, &old, NULL);
	sigset_t pending;
	if (sigpending(&pending) == 0 && !sigismember(&pending, SIGCONT)) {
		kill(pid, SIGCONT);
	}
}

static void
set_raw(int tty, const struct termios *saved, bool raw)
{
	struct termios termios = *saved;
	if (raw) {
		cfmakeraw(&termios);
		termios.c_oflag = saved->c_oflag;
	}
	tcsetattr(tty, TCSADRAIN, &termios);
}
