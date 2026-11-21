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

#include "acl_core.h"
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define LIST_HEADER_SIZE offsetof(struct acl_list, ace)

static bool valid(const struct acl_list *list, ssize_t size);
static size_t list_size(const struct acl_list *list);

void
acl_record_read(const char *path, struct acl_list *list)
{
	ssize_t size = getxattr(path, ACL_XATTR, list, sizeof(*list));
	if (!valid(list, size)) {
		list->count = KAUTH_FILESEC_NOACL;
		list->flags = 0;
	}
}

static bool
valid(const struct acl_list *list, ssize_t size)
{
	return size >= (ssize_t)LIST_HEADER_SIZE
			&& list->count <= KAUTH_ACL_MAX_ENTRIES
			&& (size_t)size == list_size(list);
}

static size_t
list_size(const struct acl_list *list)
{
	return LIST_HEADER_SIZE + list->count * sizeof(struct kauth_ace);
}

int
acl_store(const char *path, const struct acl_list *list)
{
	if (list->count == KAUTH_FILESEC_NOACL) {
		int r = removexattr(path, ACL_XATTR);
		return (r == -1 && errno == ENODATA) ? 0 : r;
	}
	return setxattr(path, ACL_XATTR, list, list_size(list), 0);
}

bool
acl_inheritable(const struct acl_list *list)
{
	uint32_t inheritable
			= KAUTH_ACE_FILE_INHERIT | KAUTH_ACE_DIRECTORY_INHERIT;
	for (uint32_t i = 0;
			list->count != KAUTH_FILESEC_NOACL && i < list->count;
			i++) {
		if (list->ace[i].flags & inheritable) {
			return true;
		}
	}
	return false;
}

bool
acl_inherit(const struct acl_list *parent, const struct acl_list *initial,
		bool directory, struct acl_list *list)
{
	list->count = 0;
	list->flags = initial != NULL ? initial->flags : 0;
	for (uint32_t i = 0; initial != NULL && i < initial->count; i++) {
		if (!(initial->ace[i].flags & KAUTH_ACE_INHERITED)) {
			list->ace[list->count++] = initial->ace[i];
		}
	}
	bool inherits = parent->count != KAUTH_FILESEC_NOACL
			&& !(list->flags & KAUTH_ACL_NO_INHERIT);
	uint32_t inherited = directory ? KAUTH_ACE_DIRECTORY_INHERIT
				       : KAUTH_ACE_FILE_INHERIT;
	for (uint32_t i = 0; inherits && i < parent->count
			&& list->count < KAUTH_ACL_MAX_ENTRIES;
			i++) {
		struct kauth_ace ace = parent->ace[i];
		if (!(ace.flags & inherited)) {
			continue;
		}
		bool passes_on = directory
				&& !(ace.flags & KAUTH_ACE_LIMIT_INHERIT);
		ace.flags |= KAUTH_ACE_INHERITED;
		ace.flags &= ~KAUTH_ACE_ONLY_INHERIT;
		if (!passes_on) {
			ace.flags &= ~KAUTH_ACE_INHERIT_CONTROL_FLAGS;
		}
		list->ace[list->count++] = ace;
	}
	return initial != NULL || list->count > 0;
}
