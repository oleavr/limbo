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
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "broker.h"
#include "broker_setid.h"

#define GROUPS_MAX 256

struct program {
	struct program *next;
	pid_t pid;
	int fd;
};

struct identity {
	uid_t real_uid, effective_uid;
	gid_t real_gid, effective_gid;
	gid_t groups[GROUPS_MAX];
	int group_count;
	int session;
	unsigned int terminal;
};
static bool identity_of(int fd, struct identity *identity);
static int check_program(const char *path, const struct identity *identity,
		struct stat *st);
static mode_t execute_bit(
		const struct identity *identity, const struct stat *st);
static bool in_groups(const struct identity *identity, gid_t gid);
static void run_program(int fd, int limbo_fd,
		const struct broker_setid_exec *request, const int *fds,
		size_t fd_count, const struct identity *identity, uid_t uid,
		gid_t gid, char *const argv[], char *const envp[],
		const char *cwd);
static void run_job(int fd, int terminal, const struct identity *identity);
static void monitor(int fd, pid_t pid) __attribute__((noreturn));
static void reply(int fd, uint32_t type, const void *payload, uint32_t length);

static struct program *programs;

void
setid_exec(int fd, const void *payload, uint32_t length, const int *fds,
		size_t fd_count)
{
	struct broker_setid_started started = {.error = EINVAL, .pid = -1};
	const struct broker_setid_exec *request = payload;
	if (length < sizeof(*request) || request->fd_count != fd_count
			|| fd_count > BROKER_DATAGRAM_FDS || request->argc == 0
			|| request->argc > 4096 || request->envc > 4096) {
		reply(fd, BROKER_SETID_STARTED, &started, sizeof(started));
		return;
	}

	size_t count = 2 + request->argc + request->envc;
	char **strings = calloc(count + 4, sizeof(char *));
	const char *cursor = (const char *)(request + 1);
	const char *end = (const char *)payload + length;
	for (size_t i = 0; i != count; i++) {
		const char *nul = memchr(cursor, '\0', end - cursor);
		if (nul == NULL) {
			free(strings);
			reply(fd, BROKER_SETID_STARTED, &started,
					sizeof(started));
			return;
		}
		strings[i] = (char *)cursor;
		cursor = nul + 1;
	}
	const char *path = strings[0];
	const char *cwd = strings[1];
	char **argv = calloc(request->argc + 3, sizeof(char *));
	argv[0] = "limbo";
	argv[1] = (char *)path;
	memcpy(argv + 2, strings + 2, request->argc * sizeof(char *));
	char **envp = strings + 2 + request->argc;
	envp[request->envc] = NULL;

	struct identity identity;
	struct stat st;
	started.error = identity_of(fd, &identity)
			? check_program(path, &identity, &st)
			: EPERM;
	char caller[64];
	size_t kept = 0;
	for (size_t i = 0; i < request->envc; i++) {
		if (strncmp(envp[i], LIMBO_SETID_CALLER_ENV "=",
				    strlen(LIMBO_SETID_CALLER_ENV "="))
				!= 0) {
			envp[kept++] = envp[i];
		}
	}
	if (started.error == 0) {
		snprintf(caller, sizeof(caller), "%s=%d:%u",
				LIMBO_SETID_CALLER_ENV, identity.session,
				identity.terminal);
		envp[kept++] = caller;
	}
	envp[kept] = NULL;
	if (started.error == 0) {
		char self[PATH_MAX], limbo[PATH_MAX];
		ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
		self[n > 0 ? n : 0] = '\0';
		snprintf(limbo, sizeof(limbo), "%s/limbo", dirname(self));
		int limbo_fd = open(limbo, O_PATH | O_CLOEXEC);
		uid_t uid = (st.st_mode & S_ISUID) ? st.st_uid
						   : identity.effective_uid;
		gid_t gid = (st.st_mode & S_ISGID) ? st.st_gid
						   : identity.effective_gid;
		pid_t pid = limbo_fd == -1 ? -1 : fork();
		if (pid == 0) {
			run_program(fd, limbo_fd, request, fds, fd_count,
					&identity, uid, gid, argv, envp, cwd);
		}
		started.error = pid > 0 ? 0 : errno;
		started.pid = pid;
		if (limbo_fd != -1) {
			close(limbo_fd);
		}
		if (pid > 0) {
			struct program *program = malloc(sizeof(*program));
			*program = (struct program){
					.next = programs, .pid = pid, .fd = fd};
			programs = program;
			fprintf(stderr,
					"limbo-broker: %s for uid %d as uid %d "
					"gid %d, pid %d\n",
					path, (int)identity.real_uid, (int)uid,
					(int)gid, (int)pid);
		}
	}
	reply(fd, BROKER_SETID_STARTED, &started, sizeof(started));
	free(argv);
	free(strings);
}

bool
setid_exited(pid_t pid, int status)
{
	for (struct program **link = &programs; *link != NULL;
			link = &(*link)->next) {
		struct program *program = *link;
		if (program->pid != pid) {
			continue;
		}
		if (program->fd != -1) {
			struct broker_setid_exited exited = {.status = status};
			reply(program->fd, BROKER_SETID_EXITED, &exited,
					sizeof(exited));
		}
		*link = program->next;
		free(program);
		return true;
	}
	return false;
}

void
setid_connection_gone(int fd)
{
	for (struct program *program = programs; program != NULL;
			program = program->next) {
		if (program->fd == fd) {
			kill(program->pid, SIGKILL);
			program->fd = -1;
		}
	}
}

static bool
identity_of(int fd, struct identity *identity)
{
	struct ucred peer;
	socklen_t size = sizeof(peer);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0) {
		return false;
	}
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/status", (int)peer.pid);
	FILE *status = fopen(path, "re");
	if (status == NULL) {
		return false;
	}
	bool users = false, groups = false;
	identity->group_count = 0;
	char line[4096];
	while (fgets(line, sizeof(line), status) != NULL) {
		unsigned long real, effective;
		if (sscanf(line, "Uid: %lu %lu", &real, &effective) == 2) {
			identity->real_uid = (uid_t)real;
			identity->effective_uid = (uid_t)effective;
			users = true;
		} else if (sscanf(line, "Gid: %lu %lu", &real, &effective)
				== 2) {
			identity->real_gid = (gid_t)real;
			identity->effective_gid = (gid_t)effective;
			groups = true;
		} else if (strncmp(line, "Groups:", 7) == 0) {
			char *word = line + 7;
			char *next;
			for (unsigned long gid = strtoul(word, &next, 10);
					next != word
					&& identity->group_count < GROUPS_MAX;
					gid = strtoul(word, &next, 10)) {
				identity->groups[identity->group_count++]
						= (gid_t)gid;
				word = next;
			}
		}
	}
	fclose(status);
	snprintf(path, sizeof(path), "/proc/%d/stat", (int)peer.pid);
	FILE *stat = fopen(path, "re");
	char *fields = NULL;
	if (stat != NULL && fgets(line, sizeof(line), stat) != NULL) {
		fields = strrchr(line, ')');
	}
	if (stat != NULL) {
		fclose(stat);
	}
	if (fields == NULL
			|| sscanf(fields + 2, "%*c %*d %*d %d %u",
					   &identity->session,
					   &identity->terminal)
					!= 2) {
		return false;
	}
	return users && groups && identity->effective_uid == peer.uid
			&& identity->effective_gid == peer.gid;
}

static int
check_program(const char *path, const struct identity *identity,
		struct stat *st)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return errno;
	}
	struct statvfs vfs;
	uint8_t magic[4];
	int error = 0;
	if (fstat(fd, st) != 0 || fstatvfs(fd, &vfs) != 0) {
		error = errno;
	} else if (!S_ISREG(st->st_mode) || !(st->st_mode & (S_ISUID | S_ISGID))
			|| (vfs.f_flag & ST_NOSUID)) {
		error = EPERM;
	} else if (!(st->st_mode & execute_bit(identity, st))) {
		error = EACCES;
	} else if (read(fd, magic, sizeof(magic)) != sizeof(magic)
			|| (memcmp(magic, "\xcf\xfa\xed\xfe", 4) != 0
					&& memcmp(magic, "\xca\xfe\xba\xbe", 4)
							!= 0)) {
		error = ENOEXEC;
	}
	close(fd);
	return error;
}

static mode_t
execute_bit(const struct identity *identity, const struct stat *st)
{
	if (identity->effective_uid == st->st_uid) {
		return S_IXUSR;
	}
	return in_groups(identity, st->st_gid) ? S_IXGRP : S_IXOTH;
}

static bool
in_groups(const struct identity *identity, gid_t gid)
{
	if (identity->effective_gid == gid) {
		return true;
	}
	for (int i = 0; i != identity->group_count; i++) {
		if (identity->groups[i] == gid) {
			return true;
		}
	}
	return false;
}

static void
run_program(int fd, int limbo_fd, const struct broker_setid_exec *request,
		const int *fds, size_t fd_count,
		const struct identity *identity, uid_t uid, gid_t gid,
		char *const argv[], char *const envp[], const char *cwd)
{
	sigset_t none;
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	setsid();

	struct rlimit files;
	getrlimit(RLIMIT_NOFILE, &files);
	struct rlimit raised = {files.rlim_max, files.rlim_max};
	setrlimit(RLIMIT_NOFILE, &raised);
	int above = limbo_fd > fd ? limbo_fd : fd;
	for (size_t i = 0; i != fd_count; i++) {
		if (request->fd_numbers[i] > above) {
			above = request->fd_numbers[i];
		}
		if (fds[i] > above) {
			above = fds[i];
		}
	}
	limbo_fd = fcntl(limbo_fd, F_DUPFD_CLOEXEC, above + 1);
	fd = fcntl(fd, F_DUPFD_CLOEXEC, above + 1);
	int high[BROKER_FDS_MAX];
	for (size_t i = 0; i != fd_count; i++) {
		high[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, above + 1);
	}
	for (size_t i = 0; i != fd_count; i++) {
		if (high[i] == -1
				|| dup2(high[i], request->fd_numbers[i])
						== -1) {
			_exit(126);
		}
	}
	DIR *dir = opendir("/proc/self/fd");
	struct dirent *entry;
	while (dir != NULL && (entry = readdir(dir)) != NULL) {
		int open_fd = atoi(entry->d_name);
		bool kept = entry->d_name[0] == '.' || open_fd == dirfd(dir)
				|| open_fd == limbo_fd || open_fd == fd;
		for (size_t i = 0; !kept && i != fd_count; i++) {
			kept = open_fd == request->fd_numbers[i];
		}
		if (!kept) {
			close(open_fd);
		}
	}
	if (dir != NULL) {
		closedir(dir);
	}
	if (request->terminal >= 0) {
		ioctl(request->terminal, TIOCSCTTY, 1);
		if (request->job) {
			run_job(fd, request->terminal, identity);
		}
	}
	close(fd);

	if ((setgroups(identity->group_count, identity->groups) != 0
			    && errno != EPERM)
			|| setresgid(identity->real_gid, gid, gid) != 0
			|| setresuid(identity->real_uid, uid, uid) != 0) {
		_exit(126);
	}
	if (chdir(cwd) != 0) {
		(void)!chdir("/");
	}
	setrlimit(RLIMIT_NOFILE, &files);
	syscall(SYS_execveat, limbo_fd, "", argv, envp, AT_EMPTY_PATH);
	_exit(127);
}

static void
run_job(int fd, int terminal, const struct identity *identity)
{
	sigset_t all, none;
	sigfillset(&all);
	sigemptyset(&none);
	sigprocmask(SIG_BLOCK, &all, NULL);
	pid_t pid = fork();
	if (pid == 0) {
		sigprocmask(SIG_SETMASK, &none, NULL);
		setpgid(0, 0);
		signal(SIGTTOU, SIG_IGN);
		tcsetpgrp(terminal, getpid());
		signal(SIGTTOU, SIG_DFL);
		return;
	}
	if (pid == -1) {
		_exit(126);
	}
	DIR *dir = opendir("/proc/self/fd");
	struct dirent *entry;
	while (dir != NULL && (entry = readdir(dir)) != NULL) {
		int open_fd = atoi(entry->d_name);
		if (entry->d_name[0] != '.' && open_fd != dirfd(dir)
				&& open_fd != fd) {
			close(open_fd);
		}
	}
	if (dir != NULL) {
		closedir(dir);
	}
	if ((setgroups(identity->group_count, identity->groups) != 0
			    && errno != EPERM)
			|| setresgid(identity->real_gid,
					   identity->effective_gid,
					   identity->effective_gid)
					!= 0
			|| setresuid(identity->real_uid,
					   identity->effective_uid,
					   identity->effective_uid)
					!= 0) {
		kill(pid, SIGKILL);
	}
	monitor(fd, pid);
}

static void
monitor(int fd, pid_t pid)
{
	sigset_t all;
	sigfillset(&all);
	for (;;) {
		siginfo_t info;
		int signal = sigwaitinfo(&all, &info);
		if (signal == -1) {
			continue;
		}
		if (signal != SIGCHLD) {
			if (signal == SIGCONT) {
				killpg(pid, SIGCONT);
			} else {
				kill(pid, signal);
			}
			continue;
		}
		int status;
		while (waitpid(pid, &status, WNOHANG | WUNTRACED) == pid) {
			if (WIFSTOPPED(status)) {
				struct broker_setid_stopped stopped
						= {.signal = WSTOPSIG(status)};
				reply(fd, BROKER_SETID_STOPPED, &stopped,
						sizeof(stopped));
				continue;
			}
			if (WIFEXITED(status)) {
				_exit(WEXITSTATUS(status));
			}
			struct rlimit no_core = {0};
			setrlimit(RLIMIT_CORE, &no_core);
			struct sigaction dfl = {.sa_handler = SIG_DFL};
			sigaction(WTERMSIG(status), &dfl, NULL);
			sigset_t one;
			sigemptyset(&one);
			sigaddset(&one, WTERMSIG(status));
			sigprocmask(SIG_UNBLOCK, &one, NULL);
			raise(WTERMSIG(status));
			_exit(128 + WTERMSIG(status));
		}
	}
}

static void
reply(int fd, uint32_t type, const void *payload, uint32_t length)
{
	char frame[sizeof(struct broker_frame) + 64];
	struct broker_frame header = {.type = type, .length = length};
	memcpy(frame, &header, sizeof(header));
	memcpy(frame + sizeof(header), payload, length);
	(void)!send(fd, frame, sizeof(header) + length,
			MSG_NOSIGNAL | MSG_DONTWAIT);
}
