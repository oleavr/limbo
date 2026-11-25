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
#include <sys/types.h>

#include "acl_core.h"

#define ACL_FILESEC_DELETE      ((const void *)1)
#define ACL_FILESEC_HEADER_SIZE 44
#define ACL_FILESEC_SIZE_MAX                                                   \
	(ACL_FILESEC_HEADER_SIZE                                               \
			+ KAUTH_ACL_MAX_ENTRIES * sizeof(struct kauth_ace))

int acl_from_filesec(const void *xsecurity, struct acl_list *list);
int acl_set_at(int dirfd, const char *host_path, int at_flags,
		const struct acl_list *list);
int acl_openat(int dirfd, const char *host_path, int flags, mode_t mode,
		const struct acl_list *initial, bool *created);
int acl_mkdirat(int dirfd, const char *host_path, mode_t mode,
		const struct acl_list *initial);
size_t acl_filesec_at(int dirfd, const char *host_path, int at_flags,
		void *buffer, size_t size);
int acl_check_at(int dirfd, const char *host_path, int at_flags,
		uint32_t rights);
int acl_check_delete_at(int dirfd, const char *host_path);
