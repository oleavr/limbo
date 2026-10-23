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
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
static void close_unlisted(const struct darwin_file_actions *src,
		posix_spawn_file_actions_t *dst);
static bool fd_listed(const struct darwin_file_actions *actions, int fd);

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
	int result = posix_spawn(pid, sysroot_host_path(path, 0, buffer),
			&actions, &attr, argv, envp);
	posix_spawn_file_actions_destroy(&actions);
	posix_spawnattr_destroy(&attr);
	return (result == 0) ? 0 : err_map(result);
}

static void
convert_attr(const struct darwin_spawnattr *src, posix_spawnattr_t *dst)
{
	if (src->psa_flags
			& (_POSIX_SPAWN_SETEXEC
					| _POSIX_SPAWN_START_SUSPENDED)) {
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
