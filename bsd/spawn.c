/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2026 Ole André Vadla Ravnås
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
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "bsd/persona.h"
#include "bsd/responsibility.h"
#include "fs/acl.h"
#include "handler.h"
#include "process.h"
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

#define AS_FOLDER (O_PATH | O_DIRECTORY | O_CLOEXEC)

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

struct darwin_mac_extension {
	char policyname[128];
	uint64_t data;
	uint64_t datalen;
};

struct darwin_mac_extensions {
	int32_t alloc;
	int32_t count;
	struct darwin_mac_extension extensions[];
};

#ifdef __x86_64__
#define MAC_EXTENSION_SIZE_MAX 4096
#else
#define MAC_EXTENSION_SIZE_MAX 16384
#endif
#define QUARANTINE_SPAWN_DISCLAIM 0x1

struct darwin_quarantine_spawn {
	uint32_t version;
	uint32_t size;
	uint32_t flags;
	uint32_t reserved[3];
};

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 0x1

struct darwin_persona_info {
	uint32_t pspi_id;
	uint32_t pspi_flags;
	uint32_t pspi_uid;
	uint32_t pspi_gid;
	uint32_t pspi_ngroups;
	uint32_t pspi_groups[16];
	uint32_t pspi_gmuid;
};

struct darwin_spawn_args {
	size_t attr_size;
	const struct darwin_spawnattr *attrp;
	size_t file_actions_size;
	const struct darwin_file_actions *file_actions;
	size_t port_actions_size;
	const void *port_actions;
	size_t mac_extensions_size;
	const struct darwin_mac_extensions *mac_extensions;
	size_t coal_info_size;
	const void *coal_info;
	size_t persona_info_size;
	const struct darwin_persona_info *persona_info;
};

static void convert_attr(
		const struct darwin_spawnattr *src, posix_spawnattr_t *dst);
static int convert_file_actions(const struct darwin_file_actions *src,
		bool cloexec_default, posix_spawn_file_actions_t *dst);
static int moved(int folder, int next);
static bool file_actions_fit(const struct darwin_file_actions *actions);
static int apply_file_actions(const struct darwin_file_actions *actions,
		bool cloexec_default);
static void close_unlisted(const struct darwin_file_actions *src,
		posix_spawn_file_actions_t *dst);
static bool fd_listed(const struct darwin_file_actions *actions, int fd);
static int read_quarantine(const struct darwin_spawn_args *args,
		enum responsibility_told *told);
static int spawn_exec(const char *path, const struct darwin_spawnattr *attrp,
		const struct darwin_file_actions *file_actions,
		const struct darwin_persona_info *persona,
		enum responsibility_told told, char **argv, char **envp);
static const struct darwin_persona_info *spawn_persona(
		const struct darwin_spawn_args *args);
static char **suspended_env(char **env);

int
sys_posix_spawn(void *pid, const char *path, void *adesc, char **argv,
		char **envp)
{
	const struct darwin_spawn_args *args = adesc;
	const struct darwin_spawnattr *attrp
			= (args != NULL) ? args->attrp : NULL;
	const struct darwin_file_actions *file_actions
			= (args != NULL) ? args->file_actions : NULL;
	const struct darwin_persona_info *persona = spawn_persona(args);
	if (persona != NULL) {
		int checked = persona_spawn_check(persona->pspi_id);
		if (checked != 0) {
			return checked;
		}
	}
	enum responsibility_told told = RESPONSIBILITY_INHERITED;
	int invalid = args != NULL ? read_quarantine(args, &told) : 0;
	if (invalid != 0) {
		return invalid;
	}
	if (attrp != NULL && (attrp->psa_flags & _POSIX_SPAWN_SETEXEC)) {
		return spawn_exec(path, attrp, file_actions, persona, told,
				argv, envp);
	}

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	if (attrp != NULL) {
		convert_attr(attrp, &attr);
	}

	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	int denied = convert_file_actions(file_actions,
			attrp != NULL
					&& (attrp->psa_flags
							& _POSIX_SPAWN_CLOEXEC_DEFAULT),
			&actions);
	if (denied != 0) {
		posix_spawn_file_actions_destroy(&actions);
		posix_spawnattr_destroy(&attr);
		return denied;
	}

	char buffer[PATH_MAX];
	char **script_argv;
	const char *executable;
	const char *host = exec_path(
			path, argv, buffer, &script_argv, &executable);
	char **env = exec_environment(envp, executable, told);
	char **suspended
			= (attrp != NULL
					  && (attrp->psa_flags
							  & _POSIX_SPAWN_START_SUSPENDED))
			? suspended_env(env)
			: NULL;
	pid_t child;
	int result = posix_spawn(&child, host, &actions, &attr,
			(script_argv != NULL) ? script_argv : argv,
			suspended != NULL ? suspended : env);
	free(suspended);
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
	if (persona != NULL) {
		persona_adopt(child, persona->pspi_id);
	} else {
		persona_inherit(child, getpid());
	}
	return 0;
}

static const struct darwin_persona_info *
spawn_persona(const struct darwin_spawn_args *args)
{
	if (args == NULL || args->persona_info == NULL
			|| args->persona_info_size
					< sizeof(struct darwin_persona_info)
			|| !(args->persona_info->pspi_flags
					& POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE)) {
		return NULL;
	}
	return args->persona_info;
}

static char **
suspended_env(char **env)
{
	size_t count = 0;
	while (env != NULL && env[count] != NULL) {
		count++;
	}
	char **result = malloc((count + 2) * sizeof(*result));
	size_t kept = 0;
	for (size_t i = 0; i < count; i++) {
		if (strncmp(env[i], "LIMBO_START_SUSPENDED=", 22) != 0) {
			result[kept++] = env[i];
		}
	}
	result[kept++] = (char *)"LIMBO_START_SUSPENDED=task";
	result[kept] = NULL;
	return result;
}

static int
read_quarantine(const struct darwin_spawn_args *args,
		enum responsibility_told *told)
{
	const struct darwin_mac_extensions *extensions = args->mac_extensions;
	size_t size = args->mac_extensions_size;
	size_t each = sizeof(extensions->extensions[0]);
	if (size == 0) {
		return 0;
	}
	if (size < sizeof(*extensions) + each || size > MAC_EXTENSION_SIZE_MAX
			|| extensions->count < 0
			|| (size_t)extensions->count
					> (size - sizeof(*extensions)) / each) {
		return _EINVAL;
	}
	const struct darwin_mac_extension *quarantine = NULL;
	for (int32_t i = 0; i != extensions->count; i++) {
		const struct darwin_mac_extension *extension
				= &extensions->extensions[i];
		if (extension->datalen == 0
				|| extension->datalen
						> MAC_EXTENSION_SIZE_MAX) {
			return _EINVAL;
		}
		if (strncmp(extension->policyname, "Quarantine",
				    sizeof(extension->policyname))
						== 0
				&& quarantine == NULL) {
			quarantine = extension;
		}
	}
	if (quarantine == NULL) {
		return 0;
	}
	struct darwin_quarantine_spawn data;
	size_t length = quarantine->datalen < sizeof(data) ? quarantine->datalen
							   : sizeof(data);
	struct iovec local = {&data, length};
	struct iovec remote = {(void *)(uintptr_t)quarantine->data, length};
	if (process_vm_readv(getpid(), &local, 1, &remote, 1, 0)
			!= (ssize_t)length) {
		return _ENOMEM;
	}
	if (length == sizeof(data) && data.size <= quarantine->datalen
			&& (data.flags & QUARANTINE_SPAWN_DISCLAIM)) {
		*told = RESPONSIBILITY_DISCLAIMED;
	}
	return 0;
}

static int
spawn_exec(const char *path, const struct darwin_spawnattr *attrp,
		const struct darwin_file_actions *file_actions,
		const struct darwin_persona_info *persona,
		enum responsibility_told told, char **argv, char **envp)
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
	if (persona != NULL) {
		persona_adopt(getpid(), persona->pspi_id);
	}

	char buffer[PATH_MAX];
	char **script_argv;
	const char *executable;
	const char *host = exec_path(
			path, argv, buffer, &script_argv, &executable);
	char **env = exec_environment(envp, executable, told);
	rlimit_nofile_exec();
	execve(host, (script_argv != NULL) ? script_argv : argv, env);
	int err = errno;
	rlimit_nofile_exec_failed();
	if (env != envp) {
		free(env);
	}
	free(script_argv);
	return err_map(err);
}

#define IMG_SHSIZE 512
#define EXEC_PATH_VARIABLE "LIMBO_EXEC_PATH"
#define SANDBOX_VARIABLE   "LIMBO_SANDBOX"

static const char *script_path(const char *path, const char *host,
		char **argv, char *buffer, char ***script_argv);
static const char *limbo_path(const char *host, char ***argv);
static bool passes_on(
		const char *own, char **envp, enum responsibility_told told);
static bool is_own(const char *variable);
static bool has_variable(char **envp, const char *variable);

const char *
exec_path(const char *path, char **argv, char *buffer, char ***script_argv,
		const char **executable)
{
	const char *host = sysroot_host_path(path, 0, buffer);
	host = script_path(path, host, argv, buffer, script_argv);
	bool script = *script_argv != NULL;
	char **limbo_argv = script ? *script_argv : argv;
	const char *limbo = limbo_path(host, &limbo_argv);
	*executable = NULL;
	if (limbo != host) {
		free(*script_argv);
		*script_argv = limbo_argv;
		*executable = script ? limbo_argv[2] : path;
	}
	return limbo;
}

char **
exec_environment(char **envp, const char *executable,
		enum responsibility_told told)
{
	extern char **environ;
	size_t count = 0, missing = 0, dropped = 0;
	while (envp != NULL && envp[count] != NULL) {
		dropped += is_own(envp[count]);
		count++;
	}
	for (char **own = environ; *own != NULL; own++) {
		missing += passes_on(*own, envp, told);
	}
	if (missing == 0 && dropped == 0 && executable == NULL) {
		return envp;
	}
	size_t executable_size = executable != NULL
			? sizeof(EXEC_PATH_VARIABLE "=") + strlen(executable)
			: 0;
	char **result = malloc((count + missing + 2) * sizeof(char *)
			+ executable_size);
	if (result == NULL) {
		return envp;
	}
	size_t kept = 0;
	for (char **own = environ; *own != NULL; own++) {
		if (responsibility_names(*own) && passes_on(*own, envp, told)) {
			result[kept++] = *own;
		}
	}
	for (size_t i = 0; i != count; i++) {
		if (!is_own(envp[i])) {
			result[kept++] = envp[i];
		}
	}
	for (char **own = environ; *own != NULL; own++) {
		if (!responsibility_names(*own)
				&& passes_on(*own, envp, told)) {
			result[kept++] = *own;
		}
	}
	if (executable != NULL) {
		char *variable = (char *)(result + count + missing + 2);
		snprintf(variable, executable_size, EXEC_PATH_VARIABLE "=%s",
				executable);
		result[kept++] = variable;
	}
	result[kept] = NULL;
	return result;
}

static bool
passes_on(const char *own, char **envp, enum responsibility_told told)
{
	if (strncmp(own, "LIMBO_", 6) != 0) {
		return false;
	}
	if (responsibility_names(own)) {
		return told == RESPONSIBILITY_INHERITED;
	}
	return is_own(own) || !has_variable(envp, own);
}

static bool
is_own(const char *variable)
{
	return strncmp(variable, SANDBOX_VARIABLE "=", sizeof(SANDBOX_VARIABLE))
			== 0
			|| strncmp(variable, EXEC_PATH_VARIABLE "=",
					   sizeof(EXEC_PATH_VARIABLE))
			== 0
			|| responsibility_names(variable);
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

static int
convert_file_actions(const struct darwin_file_actions *src,
		bool cloexec_default, posix_spawn_file_actions_t *dst)
{
	if (!file_actions_fit(src)) {
		return _EBADF;
	}
	int count = (src != NULL) ? src->count : 0;
	int folder = AT_FDCWD;
	bool denied = false;
	for (int i = 0; i < count && !denied; i++) {
		const struct darwin_file_action *action = &src->actions[i];
		char buffer[PATH_MAX];
		const char *host;
		switch (action->type) {
		case PSFA_OPEN:
			denied = sandbox_denies_open(folder, action->open.path,
					action->open.oflag);
			posix_spawn_file_actions_addopen(dst, action->filedes,
					open_path(folder, action->open.path,
							action->open.oflag,
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
			host = sysroot_host_path(action->path, 0, buffer);
			posix_spawn_file_actions_addchdir_np(dst, host);
			folder = moved(folder, openat(folder, host, AS_FOLDER));
			break;
		case PSFA_FCHDIR:
			posix_spawn_file_actions_addfchdir_np(
					dst, action->filedes);
			folder = moved(folder,
					fcntl(action->filedes, F_DUPFD_CLOEXEC,
							0));
			break;
		default:
			unimplemented();
		}
	}
	moved(folder, AT_FDCWD);

	if (cloexec_default) {
		close_unlisted(src, dst);
	}
	return denied ? _EPERM : 0;
}

static int
moved(int folder, int next)
{
	if (folder != AT_FDCWD) {
		close(folder);
	}
	return next;
}

static int
apply_file_actions(
		const struct darwin_file_actions *actions, bool cloexec_default)
{
	if (!file_actions_fit(actions)) {
		return _EBADF;
	}
	int count = (actions != NULL) ? actions->count : 0;
	for (int i = 0; i < count; i++) {
		const struct darwin_file_action *action = &actions->actions[i];
		char buffer[PATH_MAX];
		int fd;
		switch (action->type) {
		case PSFA_OPEN:
			if (sandbox_denies_open(AT_FDCWD, action->open.path,
					    action->open.oflag)) {
				return _EPERM;
			}
			fd = acl_openat(AT_FDCWD,
					open_path(AT_FDCWD, action->open.path,
							action->open.oflag,
							buffer),
					open_flags(action->open.oflag),
					action->open.mode, NULL, NULL);
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
file_actions_fit(const struct darwin_file_actions *actions)
{
	int count = (actions != NULL) ? actions->count : 0;
	for (int i = 0; i < count; i++) {
		const struct darwin_file_action *action = &actions->actions[i];
		if (action->type == PSFA_CHDIR) {
			continue;
		}
		if (action->filedes < 0 || action->filedes >= bsd_fd_limit()
				|| (action->type == PSFA_DUP2
						&& (action->newfiledes < 0
								|| action->newfiledes
										>= bsd_fd_limit()))) {
			return false;
		}
	}
	return true;
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
