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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define ACL_XATTR "user.limbo.acl"

#define KAUTH_FILESEC_MAGIC   0x012cc16d
#define KAUTH_FILESEC_NOACL   UINT32_MAX
#define KAUTH_ACL_MAX_ENTRIES 128

#define KAUTH_ACL_NO_INHERIT (1 << 17)

#define KAUTH_ACE_KINDMASK 0xf
#define KAUTH_ACE_PERMIT   1
#define KAUTH_ACE_DENY     2

#define KAUTH_VNODE_READ_DATA           (1U << 1)
#define KAUTH_VNODE_WRITE_DATA          (1U << 2)
#define KAUTH_VNODE_EXECUTE             (1U << 3)
#define KAUTH_VNODE_DELETE              (1U << 4)
#define KAUTH_VNODE_APPEND_DATA         (1U << 5)
#define KAUTH_VNODE_DELETE_CHILD        (1U << 6)
#define KAUTH_VNODE_READ_ATTRIBUTES     (1U << 7)
#define KAUTH_VNODE_WRITE_ATTRIBUTES    (1U << 8)
#define KAUTH_VNODE_READ_EXTATTRIBUTES  (1U << 9)
#define KAUTH_VNODE_WRITE_EXTATTRIBUTES (1U << 10)
#define KAUTH_VNODE_READ_SECURITY       (1U << 11)
#define KAUTH_VNODE_WRITE_SECURITY      (1U << 12)
#define KAUTH_VNODE_TAKE_OWNERSHIP      (1U << 13)
#define KAUTH_ACE_GENERIC_ALL           (1U << 21)
#define KAUTH_ACE_GENERIC_EXECUTE       (1U << 22)
#define KAUTH_ACE_GENERIC_WRITE         (1U << 23)
#define KAUTH_ACE_GENERIC_READ          (1U << 24)

#define KAUTH_ACE_INHERITED         (1 << 4)
#define KAUTH_ACE_FILE_INHERIT      (1 << 5)
#define KAUTH_ACE_DIRECTORY_INHERIT (1 << 6)
#define KAUTH_ACE_LIMIT_INHERIT     (1 << 7)
#define KAUTH_ACE_ONLY_INHERIT      (1 << 8)
#define KAUTH_ACE_INHERIT_CONTROL_FLAGS                                        \
	(KAUTH_ACE_FILE_INHERIT | KAUTH_ACE_DIRECTORY_INHERIT                  \
			| KAUTH_ACE_LIMIT_INHERIT | KAUTH_ACE_ONLY_INHERIT)

struct kauth_ace {
	uint8_t applicable[16];
	uint32_t flags;
	uint32_t rights;
};

struct acl_list {
	uint32_t count;
	uint32_t flags;
	struct kauth_ace ace[KAUTH_ACL_MAX_ENTRIES];
};

void acl_record_read(const char *path, struct acl_list *list);
int acl_store(const char *path, const struct stat *s,
		const struct acl_list *list);
int acl_posix_write(const char *path, const struct acl_list *list,
		const struct stat *s, int group);
int acl_posix_group(const char *path, bool follow);
bool acl_inheritable(const struct acl_list *list);
bool acl_inherit(const struct acl_list *parent, const struct acl_list *initial,
		bool directory, struct acl_list *list);

enum acl_result {
	ACL_UNDECIDED,
	ACL_ALLOW,
	ACL_DENY,
};

enum acl_result acl_evaluate(const struct acl_list *list, uid_t uid, gid_t gid,
		const gid_t *groups, size_t group_count, uint32_t rights);
