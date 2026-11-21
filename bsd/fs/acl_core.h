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
#include <stdint.h>
#include <sys/stat.h>

#define ACL_XATTR "user.limbo.acl"

#define KAUTH_FILESEC_MAGIC   0x012cc16d
#define KAUTH_FILESEC_NOACL   UINT32_MAX
#define KAUTH_ACL_MAX_ENTRIES 128

#define KAUTH_ACL_NO_INHERIT (1 << 17)

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
int acl_store(const char *path, const struct acl_list *list);
bool acl_inheritable(const struct acl_list *list);
bool acl_inherit(const struct acl_list *parent, const struct acl_list *initial,
		bool directory, struct acl_list *list);
