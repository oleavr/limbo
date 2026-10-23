/*
 * Copyright © 2021 Keegan Saunders
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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "fs/device.h"
#include "handler.h"
#include "sha.h"
#include "sysroot.h"
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
	case 102:
		return amfi_handle_launch_constraint_syscall(arg);
	default:
		unimplemented();
	}
}

static int
quarantine_handle_syscall(int call)
{
	switch (call) {
	case 80:
	case 81:
	case 82:
	case 84:
	case 180:
		return _ENOATTR;
	case 87:
		return 0;
	default:
		unimplemented();
	}
}

#define SANDBOX_CONTAINER_PATH 4
#define SANDBOX_EXTENSION_ISSUE 5
#define SANDBOX_EXTENSION_FILE  0
#define SANDBOX_EXTENSION_TOKEN_SIZE 0x3ff0

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
		if (stat(sysroot_host_path(args->data, 0, buffer), &s) == -1) {
			return err_map(errno);
		}
		length += snprintf(rest + length, sizeof(rest) - length,
				";01;%08x;%016llx;01;%s",
				(unsigned)darwin_device(s.st_dev),
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
sandbox_handle_syscall(int call, void *arg)
{
	switch (call) {
	case SANDBOX_CONTAINER_PATH:
		return _ENOTSUP;
	case SANDBOX_EXTENSION_ISSUE:
		return sandbox_extension_issue(arg);
	default:
		return 0;
	}
}

int
sys___mac_syscall(char *policy, int call, user_addr_t arg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_syscall(\"%s\", %p, %p)\n", policy, (void *)call,
			(void *)arg);
#endif
	if (strncmp(policy, "AMFI", MAC_MAX_POLICY_NAME) == 0) {
		return amfi_handle_syscall(call, arg);
	} else if (strncmp(policy, "Quarantine", MAC_MAX_POLICY_NAME) == 0) {
		return quarantine_handle_syscall(call);
	} else if (strncmp(policy, "Sandbox", MAC_MAX_POLICY_NAME) == 0) {
		return sandbox_handle_syscall(call, arg);
	} else {
		unimplemented();
	}
}
