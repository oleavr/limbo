/*
 * Copyright © 2021 Keegan Saunders
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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bsd/process.h"
#include "bsd/responsibility.h"
#include "bsd/sandbox_profile.h"
#include "codesign.h"
#include "fs/device.h"
#include "fs/fileid.h"
#include "handler.h"
#include "mac.h"
#include "osfmk/task.h"
#include "sha.h"
#include "sysroot.h"
#include "trace.h"
#include "xnu-errno.h"

#define MAC_MAX_POLICY_NAME 32

#define AMFI_DYLD_OUTPUT_ALLOW_AT_PATH                  (1 << 0)
#define AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS                (1 << 1)
#define AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE      (1 << 2)
#define AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS           (1 << 3)
#define AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS               (1 << 4)
#define AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION (1 << 5)
#define AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING      (1 << 6)

static int
amfi_handle_check_dyld_policy_self_syscall(long arg)
{
	long data[2];

	memcpy(data, (void *)arg, sizeof(data));

	long res = AMFI_DYLD_OUTPUT_ALLOW_AT_PATH
			| AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS
			| AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE
			| AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS
			| AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS
			| AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION
			| AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING;

	memcpy((void *)data[1], &res, sizeof(res));

	return 0;
}

struct amfi_cdhash_in_trustcache_args {
	uint64_t cdhash;
	uint32_t cdhash_length;
	uint64_t result;
};

static int
amfi_handle_cdhash_in_trustcache_syscall(
		struct amfi_cdhash_in_trustcache_args *args)
{
	args->result = 0;
	return 0;
}

static int
amfi_handle_query_bootarg_state_syscall(uint64_t *state)
{
	*state = 0;
	return 0;
}

struct amfi_launch_constraint_args {
	uint32_t audit_token[8];
	uint64_t constraint;
	uint64_t constraint_length;
	uint32_t *error;
	uint64_t error_size;
};

static int
amfi_handle_launch_constraint_syscall(struct amfi_launch_constraint_args *args)
{
	if (args->error != NULL && args->error_size >= sizeof(uint32_t)) {
		*args->error = 0;
	}
	return 0;
}

static int
amfi_handle_syscall(int call, void *arg)
{
	switch (call) {
	case 90:
		return amfi_handle_check_dyld_policy_self_syscall((long)arg);
	case 95:
		return amfi_handle_cdhash_in_trustcache_syscall(arg);
	case 96:
		return amfi_handle_query_bootarg_state_syscall(arg);
	case 102:
		return amfi_handle_launch_constraint_syscall(arg);
	default:
		unimplemented();
	}
}

#define QUARANTINE_RESPONSIBLE_FOR_PID 180

struct quarantine_responsible_for_pid_args {
	uint64_t pid;
	uint64_t *responsible;
	uint64_t *responsible_uniqueid;
};

static int
quarantine_responsible_for_pid(
		const struct quarantine_responsible_for_pid_args *args)
{
	struct process process;
	if (args == NULL) {
		return _EFAULT;
	}
	if (args->pid > INT32_MAX
			|| process_lookup((int32_t)args->pid, &process) != 0
			|| process_exited(&process)) {
		return _ESRCH;
	}
	if (geteuid() != 0 && geteuid() != process.uid[1]) {
		return _EPERM;
	}
	if (args->responsible == NULL) {
		return _EFAULT;
	}
	uint64_t responsible = (uint64_t)responsibility_of(&process);
	*args->responsible = responsible;
	if (args->responsible_uniqueid == NULL) {
		return _EFAULT;
	}
	*args->responsible_uniqueid = responsible;
	return 0;
}

struct quarantine_responsible_args {
	uint64_t pid;
	uint64_t pidversion;
	audit_token_t *responsible;
	uint64_t *path_length;
	char *path;
	uint64_t *offset;
	uint64_t *team_id_length;
	char *team_id;
	uint64_t *signing_id_length;
	char *signing_id;
	uint8_t *uuid;
	uint64_t *flags;
	uint64_t *entitlements_length;
	void *entitlements;
	uint64_t *hosted_path_length;
	char *hosted_path;
	uint8_t *cdhash;
	uint32_t *platform;
	uint32_t *sdk;
	uint64_t *csflags;
	uint32_t *fsid;
	uint64_t *file_id;
	uint64_t *hosted_team_id_length;
	char *hosted_team_id;
	uint8_t *file_flags;
};

#define QUARANTINE_RESPONSIBLE   182
#define CS_OPS_STATUS            0
#define CS_OPS_CDHASH            5
#define CS_OPS_PIDOFFSET         6
#define CS_OPS_ENTITLEMENTS_BLOB 7
#define CS_OPS_IDENTITY          11
#define CS_OPS_TEAMID            14
#define CS_PLATFORM_BINARY       0x04000000
#define CS_BLOB_HEADER           8

static int32_t responsible_pid(int32_t pid);
static void responsible_string(
		const char *string, char *buffer, uint64_t *length);
static const char *responsible_signature_string(
		int32_t pid, uint32_t ops, char *buffer, size_t size);
static int responsible_entitlements(
		int32_t pid, void *entitlements, uint64_t *length);

static int
quarantine_responsible(const struct quarantine_responsible_args *args)
{
	if (args == NULL) {
		return _EFAULT;
	}
	int32_t responsible = responsible_pid((int32_t)args->pid);
	if (args->responsible != NULL) {
		memset(args->responsible, 0, sizeof(*args->responsible));
		task_audit_token_of_pid(responsible, args->responsible);
		args->responsible->val[7] = responsible == (int32_t)args->pid
				? (uint32_t)args->pidversion
				: 10;
		if (args->path_length != NULL) {
			*args->path_length = 0;
		}
		return 0;
	}

	char host[PATH_MAX];
	const char *path = process_executable_path(responsible, host)
			? sysroot_guest_path(host)
			: NULL;
	responsible_string(path, args->path, args->path_length);

	char string[CS_BLOB_HEADER + 1024];
	responsible_string(
			responsible_signature_string(responsible, CS_OPS_TEAMID,
					string, sizeof(string)),
			args->team_id, args->team_id_length);
	responsible_string(responsible_signature_string(responsible,
					   CS_OPS_IDENTITY, string,
					   sizeof(string)),
			args->signing_id, args->signing_id_length);
	responsible_string(NULL, args->hosted_path, args->hosted_path_length);
	responsible_string(NULL, args->hosted_team_id,
			args->hosted_team_id_length);

	uint32_t status = 0;
	codesign_ops(responsible, CS_OPS_STATUS, &status, sizeof(status));
	if (args->flags != NULL) {
		*args->flags = (status & CS_PLATFORM_BINARY) ? 1 : 0;
	}
	if (args->csflags != NULL) {
		*args->csflags = status;
	}
	int binary = path != NULL ? open(host, O_RDONLY | O_CLOEXEC) : -1;
	struct stat file;
	if (binary >= 0 && fstat(binary, &file) == 0) {
		uint64_t id = sysroot_file_id(file.st_dev, file.st_ino);
		fileid_remember(id, path);
		if (args->fsid != NULL) {
			*args->fsid = (uint32_t)darwin_fsid(
					sysroot_device(file.st_dev),
					sysroot_root_device(),
					sysroot_fd_on_data_volume(binary));
		}
		if (args->file_id != NULL) {
			*args->file_id = id;
		}
		if (args->file_flags != NULL) {
			*args->file_flags = 1;
		}
	}
	if (binary >= 0) {
		close(binary);
	}
	if (args->offset != NULL) {
		uint64_t offset = 0;
		codesign_ops(responsible, CS_OPS_PIDOFFSET, &offset,
				sizeof(offset));
		*args->offset = offset;
	}
	if (args->cdhash != NULL) {
		uint8_t hash[20] = {0};
		codesign_ops(responsible, CS_OPS_CDHASH, hash, sizeof(hash));
		memset(args->cdhash, 0, 32);
		memcpy(args->cdhash, hash, sizeof(hash));
	}
	if (args->platform != NULL) {
		*args->platform = codesign_platform(responsible);
	}
	if (args->entitlements_length == NULL) {
		return 0;
	}
	return responsible_entitlements(responsible, args->entitlements,
			args->entitlements_length);
}

static int32_t
responsible_pid(int32_t pid)
{
	struct process process;
	return process_lookup(pid, &process) == 0 ? responsibility_of(&process)
						  : pid;
}

static void
responsible_string(const char *string, char *buffer, uint64_t *length)
{
	if (length == NULL) {
		return;
	}
	size_t size = string != NULL ? strlen(string) + 1 : 0;
	if (buffer == NULL || size == 0 || size > *length) {
		*length = 0;
		return;
	}
	memcpy(buffer, string, size);
	*length = size;
}

static const char *
responsible_signature_string(
		int32_t pid, uint32_t ops, char *buffer, size_t size)
{
	if (codesign_ops(pid, ops, buffer, size) != 0) {
		return NULL;
	}
	buffer[size - 1] = '\0';
	return buffer + CS_BLOB_HEADER;
}

static int
responsible_entitlements(int32_t pid, void *entitlements, uint64_t *length)
{
	uint8_t header[CS_BLOB_HEADER];
	if (codesign_ops(pid, CS_OPS_ENTITLEMENTS_BLOB, header, sizeof(header))
			!= _ERANGE) {
		*length = 0;
		return 0;
	}
	uint32_t blob_length = (uint32_t)header[4] << 24
			| (uint32_t)header[5] << 16 | (uint32_t)header[6] << 8
			| header[7];
	if (blob_length <= CS_BLOB_HEADER) {
		*length = 0;
		return 0;
	}
	uint64_t needed = blob_length - CS_BLOB_HEADER;
	if (entitlements == NULL || *length < needed) {
		*length = needed;
		return _ERANGE;
	}
	uint8_t *blob = malloc(blob_length);
	if (blob == NULL
			|| codesign_ops(pid, CS_OPS_ENTITLEMENTS_BLOB, blob,
					   blob_length)
					!= 0) {
		free(blob);
		*length = 0;
		return 0;
	}
	memcpy(entitlements, blob + CS_BLOB_HEADER, needed);
	*length = needed;
	free(blob);
	return 0;
}

#define QUARANTINE_MOUNT_POINT 88
#define MOUNT_POINT_INFO_MIN   2

struct quarantine_mount_point_args {
	const char *path;
	uint64_t *size;
	void *buffer;
};

static bool same_file(const struct stat *s, const char *path);

static int
quarantine_mount_point(const struct quarantine_mount_point_args *args)
{
	if (args == NULL || args->path == NULL || args->size == NULL) {
		return _EFAULT;
	}
	char buffer[PATH_MAX];
	struct stat s;
	if (stat(sysroot_host_path(args->path, 0, buffer), &s) != 0) {
		return err_map(errno);
	}
	if (*args->size < MOUNT_POINT_INFO_MIN) {
		return _ERANGE;
	}
	if (!same_file(&s, "/") && !same_file(&s, sysroot_data_mount_point())
			&& !same_file(&s, "/dev")) {
		return _EINVAL;
	}
	return _ENOATTR;
}

static bool
same_file(const struct stat *s, const char *path)
{
	char buffer[PATH_MAX];
	struct stat other;
	return stat(sysroot_host_path(path, 0, buffer), &other) == 0
			&& other.st_dev == s->st_dev
			&& other.st_ino == s->st_ino;
}

#define QUARANTINE_SET_TOKEN_RESPONSIBLE  184
#define QUARANTINE_SET_CALLER_RESPONSIBLE 185

struct quarantine_token_args {
	uint64_t pid;
	uint64_t pidversion;
};

static int set_responsible(int32_t responsible);

static int
quarantine_set_token_responsible(const struct quarantine_token_args *args)
{
	if (!codesign_entitled(getpid(),
			    "com.apple.private.responsibility.set-to-other")) {
		return _EPERM;
	}
	if (args == NULL) {
		return _EFAULT;
	}
	return set_responsible((int32_t)args->pid);
}

static int
quarantine_set_caller_responsible(void)
{
	if (!codesign_entitled(getpid(),
			    "com.apple.private.responsibility.set-to-self")) {
		return _EPERM;
	}
	return set_responsible(getpid());
}

static int
set_responsible(int32_t responsible)
{
	struct process named;
	if (process_lookup(responsible, &named) != 0) {
		return _ESRCH;
	}
	char value[64];
	snprintf(value, sizeof(value), "%d:%llu", (int)named.pid,
			(unsigned long long)named.start_ticks);
	setenv(RESPONSIBILITY_VARIABLE, value, 1);
	return 0;
}

static int
quarantine_handle_syscall(int call, void *arg)
{
	switch (call) {
	case 80:
	case 81:
	case 82:
	case 84:
		return _ENOATTR;
	case 87:
		return 0;
	case QUARANTINE_RESPONSIBLE_FOR_PID:
		return quarantine_responsible_for_pid(arg);
	case QUARANTINE_RESPONSIBLE:
		return quarantine_responsible(arg);
	case QUARANTINE_MOUNT_POINT:
		return quarantine_mount_point(arg);
	case QUARANTINE_SET_TOKEN_RESPONSIBLE:
		return quarantine_set_token_responsible(arg);
	case QUARANTINE_SET_CALLER_RESPONSIBLE:
		return quarantine_set_caller_responsible();
	default:
		unimplemented();
	}
}

#define SANDBOX_SET_PROFILE          0
#define SANDBOX_APPLY                1
#define SANDBOX_CHECK                2
#define SANDBOX_CONTAINER_PATH       4
#define SANDBOX_EXTENSION_ISSUE      5
#define SANDBOX_EXTENSION_CONSUME    6
#define SANDBOX_EXTENSION_FILE       0
#define SANDBOX_EXTENSION_TOKEN_SIZE 0x3ff0
#define SANDBOX_FILTER_PATH          1
#define SANDBOX_PROFILES             "/private/var/run/limbo-sandbox"
#define SANDBOX_PROFILES_MODE        01777
#define SANDBOX_PROFILE_MODE         0644
#define SANDBOX_PROFILE_SIZE_MAX     (1 << 24)
#define SANDBOX_DIGEST_HEX_LENGTH    (2 * SHA256_DIGEST_LENGTH)
#define CONTAINER_EXTENSION_CLASS    ";com.apple.sandbox.container;"

struct sandbox_extension_consume_args {
	const char *token;
	uint64_t length;
	int64_t *handle;
};

struct sandbox_container_path_args {
	int64_t pid;
	uint64_t reserved;
	char *buffer;
	uint64_t size;
	uint64_t reserved2;
};

static char container[PATH_MAX];

struct sandbox_check_args {
	uint64_t *result;
	int64_t pid;
	const char *operation;
	uint64_t filter_type;
	uint64_t filter;
	uint64_t flags;
};

struct sandbox_set_profile_args {
	const void *data;
	uint64_t size;
	const char *container;
	uint64_t container_length;
};

static bool sandboxed;
static bool entered;
static struct sandbox_profile profile;

static void
kept_profile_path(const char *digest, char *host)
{
	char path[PATH_MAX], buffer[PATH_MAX];
	snprintf(path, sizeof(path), SANDBOX_PROFILES "/%s.sb", digest);
	snprintf(host, PATH_MAX, "%s", sysroot_host_path(path, 0, buffer));
}

static void
digest_of(const void *data, size_t size, char *hex)
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	sha256(data, size, digest);
	for (int i = 0; i != SHA256_DIGEST_LENGTH; i++) {
		sprintf(hex + 2 * i, "%02x", digest[i]);
	}
}

static void *
kept_profile(const char *digest, size_t *size)
{
	char path[PATH_MAX], hex[SANDBOX_DIGEST_HEX_LENGTH + 1] = "";
	kept_profile_path(digest, path);
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd == -1) {
		return NULL;
	}
	struct stat st;
	void *data = NULL;
	if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)
			&& st.st_size <= SANDBOX_PROFILE_SIZE_MAX) {
		*size = (size_t)st.st_size;
		data = malloc(*size);
		if (read(fd, data, *size) == st.st_size) {
			digest_of(data, *size, hex);
		}
		if (strcmp(hex, digest) != 0) {
			free(data);
			data = NULL;
		}
	}
	close(fd);
	return data;
}

static bool
keep_profile(const void *data, size_t size)
{
	char hex[SANDBOX_DIGEST_HEX_LENGTH + 1];
	digest_of(data, size, hex);
	char folder[PATH_MAX], path[PATH_MAX];
	char temporary[PATH_MAX + sizeof(".XXXXXX")];
	const char *host = sysroot_host_path(SANDBOX_PROFILES, 0, folder);
	if (mkdir(host, SANDBOX_PROFILES_MODE) == 0) {
		chmod(host, SANDBOX_PROFILES_MODE);
	}
	size_t kept_size;
	void *kept = kept_profile(hex, &kept_size);
	free(kept);
	if (kept == NULL) {
		kept_profile_path(hex, path);
		snprintf(temporary, sizeof(temporary), "%s.XXXXXX", path);
		int fd = mkstemp(temporary);
		if (fd == -1) {
			return false;
		}
		bool written = write(fd, data, size) == (ssize_t)size
				&& fchmod(fd, SANDBOX_PROFILE_MODE) == 0;
		close(fd);
		if (!written || rename(temporary, path) != 0) {
			unlink(temporary);
			return false;
		}
	}
	return setenv("LIMBO_SANDBOX", hex, 1) == 0;
}

int
mac_sandbox_init(void)
{
	const char *digest = getenv("LIMBO_SANDBOX");
	if (digest == NULL) {
		return 0;
	}
	size_t size;
	void *data = strlen(digest) == SANDBOX_DIGEST_HEX_LENGTH
			? kept_profile(digest, &size)
			: NULL;
	if (data == NULL) {
		fprintf(stderr, "limbo: no sandbox profile %s\n", digest);
		return 1;
	}
	sandboxed = true;
	sandbox_profile_parse(&profile, data, size);
	free(data);
	return 0;
}

void
mac_sandbox_enter(void)
{
	entered = true;
}

void
mac_sandbox_set_container(const char *path)
{
	snprintf(container, sizeof(container), "%s", path);
}

static int
sandbox_set_profile(const struct sandbox_set_profile_args *args)
{
	if (sandboxed) {
		bool same = args->size == profile.size
				&& memcmp(args->data, profile.data, args->size)
						== 0;
		return same ? 0 : _EPERM;
	}
	if (args->data != NULL
			&& sandbox_profile_parse(
					&profile, args->data, args->size)
			&& profile.enforced != 0
			&& !keep_profile(args->data, args->size)) {
		sandbox_profile_free(&profile);
		return _EPERM;
	}
	sandboxed = true;
	return 0;
}

static bool
canonical_path(int dirfd, const char *path, int follow, bool making, char *out)
{
	char joined[PATH_MAX];
	if (path[0] == '/') {
		snprintf(joined, sizeof(joined), "%s", path);
	} else {
		char base[PATH_MAX];
		if (dirfd == AT_FDCWD) {
			if (getcwd(base, sizeof(base)) == NULL) {
				return false;
			}
		} else {
			char link[48];
			snprintf(link, sizeof(link), "/proc/thread-self/fd/%d",
					dirfd);
			ssize_t length = readlink(link, base, sizeof(base) - 1);
			if (length == -1) {
				return false;
			}
			base[length] = '\0';
		}
		const char *guest = sysroot_guest_path(base);
		int length = snprintf(joined, sizeof(joined), "%s/%s",
				strcmp(guest, "/") == 0 ? "" : guest, path);
		if (length >= (int)sizeof(joined)) {
			errno = ERANGE;
			return false;
		}
	}
	if (strncmp(joined, "/dev", 4) == 0
			&& (joined[4] == '/' || joined[4] == '\0')) {
		snprintf(out, PATH_MAX, "%s", joined);
	} else {
		char buffer[PATH_MAX];
		const char *host = making
				? sysroot_creation_path(AT_FDCWD, joined,
						  follow, buffer)
				: sysroot_host_path(joined, follow, buffer);
		snprintf(out, PATH_MAX, "%s", sysroot_guest_path(host));
	}
	size_t length = strlen(out);
	while (length > 1 && out[length - 1] == '/') {
		out[--length] = '\0';
	}
	return true;
}

static bool
profile_denies(int operation, int dirfd, const char *path, int follow)
{
	char canonical[PATH_MAX];
	bool making = operation == SANDBOX_FILE_WRITE_CREATE;
	errno = 0;
	if (!canonical_path(dirfd, path, follow, making, canonical)) {
		return errno == ERANGE;
	}
	return sandbox_profile_decide(&profile, operation, canonical)
			== SANDBOX_DENY;
}

bool
mac_sandbox_denies(int operation, int dirfd, const char *path, int follow)
{
	return profile.enforced != 0 && path != NULL
			&& profile_denies(operation, dirfd, path, follow);
}

bool
mac_sandbox_denies_fd(int operation, int fd)
{
	if (profile.enforced == 0) {
		return false;
	}
	char link[48], host[PATH_MAX];
	snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
	ssize_t length = readlink(link, host, sizeof(host) - 1);
	if (length <= 0 || host[0] != '/') {
		return false;
	}
	host[length] = '\0';
	char pty[32];
	unsigned number;
	const char *guest = sysroot_guest_path(host);
	if (sscanf(host, "/dev/pts/%u", &number) == 1) {
		snprintf(pty, sizeof(pty), "/dev/ttys%03u", number);
		guest = pty;
	}
	return sandbox_profile_decide(&profile, operation, guest)
			== SANDBOX_DENY;
}

bool
mac_sandbox_denies_open(int dirfd, const char *path, bool write, bool create,
		int follow)
{
	if (profile.enforced == 0 || path == NULL || (!write && !create)) {
		return false;
	}
	char buffer[PATH_MAX];
	bool makes = create
			&& faccessat(dirfd,
					   sysroot_host_path(path, follow,
							   buffer),
					   F_OK, follow)
					== -1;
	if (makes) {
		return profile_denies(
				SANDBOX_FILE_WRITE_CREATE, dirfd, path, follow);
	}
	return write
			&& profile_denies(SANDBOX_FILE_WRITE_DATA, dirfd, path,
					follow);
}

static int
sandbox_check(struct sandbox_check_args *args)
{
	bool self = args->pid == 0 || args->pid == getpid();
	*args->result = self && (sandboxed || entered)
			&& args->operation == NULL;
	if (args->operation == NULL
			|| args->filter_type != SANDBOX_FILTER_PATH) {
		return 0;
	}
	char buffer[PATH_MAX];
	const char *path = (const char *)args->filter;
	if (access(sysroot_host_path(path, 0, buffer), F_OK) == -1) {
		*args->result = 1;
	} else if (self) {
		*args->result = profile_denies(
				sandbox_operation_index(args->operation),
				AT_FDCWD, path, 0);
	}
	return 0;
}

struct sandbox_extension_issue_args {
	const char *class;
	uint64_t type;
	const char *data;
	uint64_t flags;
	char *token;
	int64_t pid;
	uint64_t reserved;
};

static int
sandbox_extension_issue(struct sandbox_extension_issue_args *args)
{
	char rest[PATH_MAX + 256];
	int length = snprintf(rest, sizeof(rest),
			";%02x;%08x;00000000;00000000;%016zx;%s",
			(unsigned)args->type, (unsigned)args->flags,
			strlen(args->class), args->class);
	if (args->type == SANDBOX_EXTENSION_FILE) {
		char buffer[PATH_MAX];
		struct stat s;
		bool exists = true;
		if (stat(sysroot_host_path(args->data, 0, buffer), &s) == -1) {
			const char *slash = strrchr(args->data, '/');
			if (errno != ENOENT || slash == NULL) {
				return err_map(errno);
			}
			int folder_length = slash == args->data
					? 1
					: (int)(slash - args->data);
			char folder[PATH_MAX];
			snprintf(folder, sizeof(folder), "%.*s", folder_length,
					args->data);
			if (stat(sysroot_host_path(folder, 0, buffer), &s)
					== -1) {
				return err_map(errno);
			}
			exists = false;
		}
		length += snprintf(rest + length, sizeof(rest) - length,
				";%s;%08x;%016llx;01;%s", exists ? "01" : "00",
				(unsigned)darwin_device(
						sysroot_device(s.st_dev)),
				(unsigned long long)s.st_ino, args->data);
	} else if (args->data != NULL) {
		length += snprintf(rest + length, sizeof(rest) - length, ";%s",
				args->data);
	}

	uint8_t digest[SHA256_DIGEST_LENGTH];
	sha256(rest, strlen(rest), digest);
	char *cursor = args->token;
	for (size_t i = 0; i < sizeof(digest); i++) {
		cursor += sprintf(cursor, "%02x", digest[i]);
	}
	snprintf(cursor, SANDBOX_EXTENSION_TOKEN_SIZE - 2 * sizeof(digest),
			"%s", rest);
	return 0;
}

static int
sandbox_extension_consume(struct sandbox_extension_consume_args *args)
{
	const char *token = args->token;
	if (token != NULL && strstr(token, CONTAINER_EXTENSION_CLASS) != NULL) {
		const char *path = strrchr(token, ';');
		if (path != NULL && path[1] == '/') {
			mac_sandbox_set_container(path + 1);
		}
	}
	if (args->handle != NULL) {
		*args->handle = 1;
	}
	return 0;
}

static int
sandbox_container_path(struct sandbox_container_path_args *args)
{
	bool self = args->pid == 0 || args->pid == getpid();
	size_t length = strlen(container);
	if (!self || length == 0) {
		return _ENOTSUP;
	}
	if (args->buffer == NULL || args->size <= length) {
		return _ERANGE;
	}
	memcpy(args->buffer, container, length + 1);
	return 0;
}

static int
sandbox_handle_syscall(int call, void *arg)
{
	switch (call) {
	case SANDBOX_SET_PROFILE:
		return sandbox_set_profile(arg);
	case SANDBOX_APPLY:
		mac_sandbox_enter();
		return 0;
	case SANDBOX_CHECK:
		return sandbox_check(arg);
	case SANDBOX_CONTAINER_PATH:
		return sandbox_container_path(arg);
	case SANDBOX_EXTENSION_ISSUE:
		return sandbox_extension_issue(arg);
	case SANDBOX_EXTENSION_CONSUME:
		return sandbox_extension_consume(arg);
	default:
		return 0;
	}
}

int
sys___mac_syscall(char *policy, int call, user_addr_t arg)
{
	trace_string(policy);
	if (strncmp(policy, "AMFI", MAC_MAX_POLICY_NAME) == 0) {
		return amfi_handle_syscall(call, arg);
	} else if (strncmp(policy, "Quarantine", MAC_MAX_POLICY_NAME) == 0) {
		return quarantine_handle_syscall(call, arg);
	} else if (strncmp(policy, "Sandbox", MAC_MAX_POLICY_NAME) == 0) {
		return sandbox_handle_syscall(call, arg);
	} else if (strncmp(policy, "EndpointSecurity", MAC_MAX_POLICY_NAME)
			== 0) {
		return call < 2 ? _ENOTSUP : 0;
	} else {
		unimplemented();
	}
}
