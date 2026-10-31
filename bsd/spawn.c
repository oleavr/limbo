/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2026 Ole André Vadla Ravnås
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
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "handler.h"
#include "signo.h"
#include "sysroot.h"
#include "xnu-errno.h"

#define _MAXPATHLEN 1024

#define _POSIX_SPAWN_RESETIDS        0x0001
#define _POSIX_SPAWN_SETPGROUP       0x0002
#define _POSIX_SPAWN_SETSIGDEF       0x0004
#define _POSIX_SPAWN_SETSIGMASK      0x0008
#define _POSIX_SPAWN_SETEXEC         0x0040
#define _POSIX_SPAWN_START_SUSPENDED 0x0080
#define _POSIX_SPAWN_SETSID          0x0400
#define _POSIX_SPAWN_CLOEXEC_DEFAULT 0x4000

typedef enum {
	PSFA_OPEN = 0,
	PSFA_CLOSE = 1,
	PSFA_DUP2 = 2,
	PSFA_INHERIT = 3,
	PSFA_CHDIR = 5,
	PSFA_FCHDIR = 6,
} psfa_t;

struct darwin_spawnattr {
	int16_t psa_flags;
	int16_t flags_padding;
	uint32_t psa_sigdefault;
	uint32_t psa_sigmask;
	int32_t psa_pgroup;
};

struct darwin_file_action {
	int32_t type;
	int32_t filedes;
	union {
		struct __attribute__((packed)) {
			int32_t oflag;
			uint16_t mode;
			char path[_MAXPATHLEN];
		} open;
		int32_t newfiledes;
		char path[_MAXPATHLEN];
	};
};

struct darwin_file_actions {
	int32_t alloc;
	int32_t count;
	struct darwin_file_action actions[];
};

struct darwin_spawn_args {
	size_t attr_size;
	const struct darwin_spawnattr *attrp;
	size_t file_actions_size;
	const struct darwin_file_actions *file_actions;
};

static void convert_attr(
		const struct darwin_spawnattr *src, posix_spawnattr_t *dst);
static void convert_file_actions(const struct darwin_file_actions *src,
		bool cloexec_default, posix_spawn_file_actions_t *dst);
static int apply_file_actions(const struct darwin_file_actions *actions,
		bool cloexec_default);
static void close_unlisted(const struct darwin_file_actions *src,
		posix_spawn_file_actions_t *dst);
static bool fd_listed(const struct darwin_file_actions *actions, int fd);
static int spawn_exec(const char *path, const struct darwin_spawnattr *attrp,
		const struct darwin_file_actions *file_actions, char **argv,
		char **envp);

int
sys_posix_spawn(void *pid, const char *path, void *adesc, char **argv,
		char **envp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "posix_spawn(%p, \"%s\", %p, %p, %p)\n", pid, path,
			adesc, (void *)argv, (void *)envp);
	for (char **arg = argv; *arg != NULL; arg++) {
		fprintf(stderr, "  argv: \"%s\"\n", *arg);
	}
#endif
	const struct darwin_spawn_args *args = adesc;
	const struct darwin_spawnattr *attrp
			= (args != NULL) ? args->attrp : NULL;
	const struct darwin_file_actions *file_actions
			= (args != NULL) ? args->file_actions : NULL;
	if (attrp != NULL && (attrp->psa_flags & _POSIX_SPAWN_SETEXEC)) {
		return spawn_exec(path, attrp, file_actions, argv, envp);
	}

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	if (attrp != NULL) {
		convert_attr(attrp, &attr);
	}

	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	convert_file_actions(file_actions,
			attrp != NULL
					&& (attrp->psa_flags
							& _POSIX_SPAWN_CLOEXEC_DEFAULT),
			&actions);

	char buffer[PATH_MAX];
	char **script_argv;
	const char *host = exec_path(path, argv, buffer, &script_argv);
	char **env = exec_environment(envp);
	pid_t child;
	int result = posix_spawn(&child, host, &actions, &attr,
			(script_argv != NULL) ? script_argv : argv, env);
	if (env != envp) {
		free(env);
	}
	free(script_argv);
	posix_spawn_file_actions_destroy(&actions);
	posix_spawnattr_destroy(&attr);
	if (result != 0) {
		return err_map(result);
	}
	if (pid != NULL) {
		*(pid_t *)pid = child;
	}
	return 0;
}

static int
spawn_exec(const char *path, const struct darwin_spawnattr *attrp,
		const struct darwin_file_actions *file_actions, char **argv,
		char **envp)
{
	if (attrp->psa_flags & _POSIX_SPAWN_START_SUSPENDED) {
		unimplemented();
	}
	int result = apply_file_actions(file_actions,
			attrp->psa_flags & _POSIX_SPAWN_CLOEXEC_DEFAULT);
	if (result != 0) {
		return result;
	}
	if ((attrp->psa_flags & _POSIX_SPAWN_SETSID) && setsid() == -1) {
		return err_map(errno);
	}
	if ((attrp->psa_flags & _POSIX_SPAWN_SETPGROUP)
			&& setpgid(0, attrp->psa_pgroup) == -1) {
		return err_map(errno);
	}
	if ((attrp->psa_flags & _POSIX_SPAWN_RESETIDS)
			&& (setegid(getgid()) == -1 || seteuid(getuid()) == -1)) {
		return err_map(errno);
	}
	if (attrp->psa_flags & _POSIX_SPAWN_SETSIGMASK) {
		sigset_t set;
		sigset_to_linux(attrp->psa_sigmask, &set);
		sigdelset(&set, SIGSYS);
		sigdelset(&set, SIGILL);
		sigdelset(&set, SIGSEGV);
		sigdelset(&set, SIGBUS);
		sigprocmask(SIG_SETMASK, &set, NULL);
	}

	char buffer[PATH_MAX];
	char **script_argv;
	const char *host = exec_path(path, argv, buffer, &script_argv);
	char **env = exec_environment(envp);
	execve(host, (script_argv != NULL) ? script_argv : argv, env);
	int err = errno;
	if (env != envp) {
		free(env);
	}
	free(script_argv);
	return err_map(err);
}

#define IMG_SHSIZE 512

static const char *script_path(const char *path, const char *host,
		char **argv, char *buffer, char ***script_argv);
static const char *limbo_path(const char *host, char ***argv);
static bool has_variable(char **envp, const char *variable);

const char *
exec_path(const char *path, char **argv, char *buffer, char ***script_argv)
{
	const char *host = sysroot_host_path(path, 0, buffer);
	host = script_path(path, host, argv, buffer, script_argv);
	char **limbo_argv = (*script_argv != NULL) ? *script_argv : argv;
	const char *limbo = limbo_path(host, &limbo_argv);
	if (limbo != host) {
		free(*script_argv);
		*script_argv = limbo_argv;
	}
	return limbo;
}

char **
exec_environment(char **envp)
{
	extern char **environ;
	size_t count = 0, missing = 0;
	while (envp != NULL && envp[count] != NULL) {
		count++;
	}
	for (char **own = environ; *own != NULL; own++) {
		missing += strncmp(*own, "LIMBO_", 6) == 0
				&& !has_variable(envp, *own);
	}
	if (missing == 0) {
		return envp;
	}
	char **result = malloc((count + missing + 1) * sizeof(char *));
	if (result == NULL) {
		return envp;
	}
	if (count != 0) {
		memcpy(result, envp, count * sizeof(char *));
	}
	for (char **own = environ; *own != NULL; own++) {
		if (strncmp(*own, "LIMBO_", 6) == 0
				&& !has_variable(envp, *own)) {
			result[count++] = *own;
		}
	}
	result[count] = NULL;
	return result;
}

static bool
has_variable(char **envp, const char *variable)
{
	size_t length = strcspn(variable, "=");
	for (char **var = envp; var != NULL && *var != NULL; var++) {
		if (strncmp(*var, variable, length) == 0
				&& (*var)[length] == '=') {
			return true;
		}
	}
	return false;
}

static const char *
limbo_path(const char *host, char ***argv)
{
	int fd = open(host, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return host;
	}
	uint8_t magic[4];
	ssize_t length = read(fd, magic, sizeof(magic));
	close(fd);
	static const uint8_t macho[4] = {0xcf, 0xfa, 0xed, 0xfe};
	static const uint8_t fat[4] = {0xca, 0xfe, 0xba, 0xbe};
	if (length != sizeof(magic)
			|| (memcmp(magic, macho, 4) != 0
					&& memcmp(magic, fat, 4) != 0)) {
		return host;
	}

	size_t argc = 0;
	size_t size = strlen(host) + 1 + sizeof("limbo");
	while ((*argv)[argc] != NULL) {
		size += strlen((*argv)[argc++]) + 1;
	}
	size_t pointers = (argc + 3) * sizeof(char *);
	char **result = malloc(pointers + size);
	if (result == NULL) {
		return host;
	}
	char *strings = (char *)result + pointers;
	result[0] = strcpy(strings, "limbo");
	strings += sizeof("limbo");
	result[1] = strcpy(strings, host);
	strings += strlen(host) + 1;
	for (size_t i = 0; i < argc; i++) {
		result[i + 2] = strcpy(strings, (*argv)[i]);
		strings += strlen((*argv)[i]) + 1;
	}
	result[argc + 2] = NULL;
	*argv = result;
	return "/proc/self/exe";
}

static const char *
script_path(const char *path, const char *host, char **argv, char *buffer,
		char ***script_argv)
{
	*script_argv = NULL;
	int fd = open(host, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return host;
	}
	char line[IMG_SHSIZE + 1];
	ssize_t length = read(fd, line, IMG_SHSIZE);
	close(fd);
	if (length < 2 || line[0] != '#' || line[1] != '!') {
		return host;
	}
	line[length] = '\0';
	char *end = strchr(line, '\n');
	if (end == NULL) {
		return host;
	}
	*end = '\0';

	char *interpreter = line + 2 + strspn(line + 2, " \t");
	char *arg = interpreter + strcspn(interpreter, " \t");
	if (*arg != '\0') {
		*arg++ = '\0';
		arg += strspn(arg, " \t");
		for (char *last = arg + strlen(arg);
				last > arg && (last[-1] == ' ' || last[-1] == '\t');
				last--) {
			last[-1] = '\0';
		}
	}
	if (*interpreter == '\0') {
		return host;
	}

	size_t argc = 0;
	while (argv[argc] != NULL) {
		argc++;
	}
	size_t interpreter_size = strlen(interpreter) + 1;
	size_t pointers = (argc + 4) * sizeof(char *);
	char **result = malloc(pointers + interpreter_size + strlen(arg) + 1);
	if (result == NULL) {
		return host;
	}
	char *strings = (char *)result + pointers;
	memcpy(strings, interpreter, interpreter_size);
	strcpy(strings + interpreter_size, arg);

	size_t n = 0;
	result[n++] = strings;
	if (*arg != '\0') {
		result[n++] = strings + interpreter_size;
	}
	result[n++] = (char *)path;
	for (size_t i = 1; i < argc; i++) {
		result[n++] = argv[i];
	}
	result[n] = NULL;
	*script_argv = result;
	return sysroot_host_path(strings, 0, buffer);
}

static void
convert_attr(const struct darwin_spawnattr *src, posix_spawnattr_t *dst)
{
	if (src->psa_flags & _POSIX_SPAWN_START_SUSPENDED) {
		unimplemented();
	}

	short flags = 0;
	if (src->psa_flags & _POSIX_SPAWN_RESETIDS) {
		flags |= POSIX_SPAWN_RESETIDS;
	}
	if (src->psa_flags & _POSIX_SPAWN_SETPGROUP) {
		flags |= POSIX_SPAWN_SETPGROUP;
		posix_spawnattr_setpgroup(dst, src->psa_pgroup);
	}
	if (src->psa_flags & _POSIX_SPAWN_SETSIGDEF) {
		sigset_t set;
		sigset_to_linux(src->psa_sigdefault, &set);
		flags |= POSIX_SPAWN_SETSIGDEF;
		posix_spawnattr_setsigdefault(dst, &set);
	}
	if (src->psa_flags & _POSIX_SPAWN_SETSIGMASK) {
		sigset_t set;
		sigset_to_linux(src->psa_sigmask, &set);
		sigdelset(&set, SIGSYS);
		flags |= POSIX_SPAWN_SETSIGMASK;
		posix_spawnattr_setsigmask(dst, &set);
	}
	if (src->psa_flags & _POSIX_SPAWN_SETSID) {
		flags |= POSIX_SPAWN_SETSID;
	}
	posix_spawnattr_setflags(dst, flags);
}

static void
convert_file_actions(const struct darwin_file_actions *src,
		bool cloexec_default, posix_spawn_file_actions_t *dst)
{
	int count = (src != NULL) ? src->count : 0;
	for (int i = 0; i < count; i++) {
		const struct darwin_file_action *action = &src->actions[i];
		char buffer[PATH_MAX];
		switch (action->type) {
		case PSFA_OPEN:
			posix_spawn_file_actions_addopen(dst, action->filedes,
					sysroot_host_path(action->open.path, 0,
							buffer),
					open_flags(action->open.oflag),
					action->open.mode);
			break;
		case PSFA_CLOSE:
			posix_spawn_file_actions_addclose(dst, action->filedes);
			break;
		case PSFA_DUP2:
			posix_spawn_file_actions_adddup2(dst, action->filedes,
					action->newfiledes);
			break;
		case PSFA_INHERIT:
			posix_spawn_file_actions_adddup2(
					dst, action->filedes, action->filedes);
			break;
		case PSFA_CHDIR:
			posix_spawn_file_actions_addchdir_np(dst,
					sysroot_host_path(action->path, 0,
							buffer));
			break;
		case PSFA_FCHDIR:
			posix_spawn_file_actions_addfchdir_np(
					dst, action->filedes);
			break;
		default:
			unimplemented();
		}
	}

	if (cloexec_default) {
		close_unlisted(src, dst);
	}
}

static int
apply_file_actions(
		const struct darwin_file_actions *actions, bool cloexec_default)
{
	int count = (actions != NULL) ? actions->count : 0;
	for (int i = 0; i < count; i++) {
		const struct darwin_file_action *action = &actions->actions[i];
		char buffer[PATH_MAX];
		int fd;
		switch (action->type) {
		case PSFA_OPEN:
			fd = open(sysroot_host_path(
						  action->open.path, 0, buffer),
					open_flags(action->open.oflag),
					action->open.mode);
			if (fd == -1) {
				return err_map(errno);
			}
			if (fd != action->filedes) {
				if (dup2(fd, action->filedes) == -1) {
					int error = errno;
					close(fd);
					return err_map(error);
				}
				close(fd);
			}
			break;
		case PSFA_CLOSE:
			if (close(action->filedes) == -1) {
				return err_map(errno);
			}
			break;
		case PSFA_DUP2:
			if (action->filedes == action->newfiledes) {
				fd = fcntl(action->filedes, F_GETFD);
				if (fd == -1
						|| fcntl(action->filedes,
								   F_SETFD,
								   fd & ~FD_CLOEXEC)
								== -1) {
					return err_map(errno);
				}
			} else if (dup2(action->filedes, action->newfiledes)
					== -1) {
				return err_map(errno);
			}
			break;
		case PSFA_INHERIT:
			fd = fcntl(action->filedes, F_GETFD);
			if (fd == -1
					|| fcntl(action->filedes, F_SETFD,
							   fd & ~FD_CLOEXEC)
							== -1) {
				return err_map(errno);
			}
			break;
		case PSFA_CHDIR:
			if (chdir(sysroot_host_path(action->path, 0, buffer))
					== -1) {
				return err_map(errno);
			}
			break;
		case PSFA_FCHDIR:
			if (fchdir(action->filedes) == -1) {
				return err_map(errno);
			}
			break;
		default:
			unimplemented();
		}
	}
	if (cloexec_default) {
		DIR *fds = opendir("/proc/thread-self/fd");
		struct dirent *entry;
		while (fds != NULL && (entry = readdir(fds)) != NULL) {
			int fd = atoi(entry->d_name);
			if (entry->d_name[0] != '.' && fd != dirfd(fds)
					&& !fd_listed(actions, fd)) {
				fcntl(fd, F_SETFD, FD_CLOEXEC);
			}
		}
		if (fds != NULL) {
			closedir(fds);
		}
	}
	return 0;
}

static void
close_unlisted(const struct darwin_file_actions *src,
		posix_spawn_file_actions_t *dst)
{
	DIR *fds = opendir("/proc/thread-self/fd");
	struct dirent *entry;
	while ((entry = readdir(fds)) != NULL) {
		int fd = atoi(entry->d_name);
		if (entry->d_name[0] != '.' && fd != dirfd(fds)
				&& !fd_listed(src, fd)) {
			posix_spawn_file_actions_addclose(dst, fd);
		}
	}
	closedir(fds);
}

static bool
fd_listed(const struct darwin_file_actions *actions, int fd)
{
	int count = (actions != NULL) ? actions->count : 0;
	for (int i = 0; i < count; i++) {
		const struct darwin_file_action *action = &actions->actions[i];
		switch (action->type) {
		case PSFA_OPEN:
		case PSFA_INHERIT:
			if (action->filedes == fd) {
				return true;
			}
			break;
		case PSFA_DUP2:
			if (action->newfiledes == fd) {
				return true;
			}
			break;
		}
	}
	return false;
}
