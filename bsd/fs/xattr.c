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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

#include "bsd/xnu-errno.h"
#include "bsd_flags.h"
#include "sysroot.h"

typedef void *user_addr_t;
typedef ssize_t user_ssize_t;

#define _XATTR_NOFOLLOW 0x0001

#define LINUX_NAMESPACE "user."

static const char *host_path(const char *path, int options, char *buffer);
static const char *host_name(const char *name, char *buffer);
static user_ssize_t xattr_result(ssize_t result);
static user_ssize_t list_result(ssize_t result, const char *names,
		char *namebuf, size_t bufsize);

user_ssize_t
sys_getxattr(user_addr_t path, user_addr_t attrname, user_addr_t value,
		size_t size, uint32_t position, int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getxattr(\"%s\", \"%s\", %p, %p, %p, %p)\n",
			(char *)path, (char *)attrname, (void *)value,
			(void *)size, (void *)position, (void *)options);
#endif
	char path_buffer[PATH_MAX], name[XATTR_NAME_MAX + 1];
	const char *p = host_path(path, options, path_buffer);
	const char *n = host_name(attrname, name);
	return xattr_result((options & _XATTR_NOFOLLOW)
					? lgetxattr(p, n, value, size)
					: getxattr(p, n, value, size));
}

user_ssize_t
sys_fgetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size,
		uint32_t position, int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fgetxattr(%p, \"%s\", %p, %p, %p, %p)\n", (void *)fd,
			(char *)attrname, (void *)value, (void *)size,
			(void *)position, (void *)options);
#endif
	char name[XATTR_NAME_MAX + 1];
	return xattr_result(
			fgetxattr(fd, host_name(attrname, name), value, size));
}

int
sys_setxattr(user_addr_t path, user_addr_t attrname, user_addr_t value,
		size_t size, uint32_t position, int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setxattr(\"%s\", \"%s\", %p, %p, %p, %p)\n",
			(char *)path, (char *)attrname, (void *)value,
			(void *)size, (void *)position, (void *)options);
#endif
	char path_buffer[PATH_MAX], name[XATTR_NAME_MAX + 1];
	const char *p = host_path(path, options, path_buffer);
	const char *n = host_name(attrname, name);
	return xattr_result((options & _XATTR_NOFOLLOW)
					? lsetxattr(p, n, value, size, 0)
					: setxattr(p, n, value, size, 0));
}

int
sys_fsetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size,
		uint32_t position, int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fsetxattr(%p, \"%s\", %p, %p, %p, %p)\n", (void *)fd,
			(char *)attrname, (void *)value, (void *)size,
			(void *)position, (void *)options);
#endif
	char name[XATTR_NAME_MAX + 1];
	return xattr_result(fsetxattr(
			fd, host_name(attrname, name), value, size, 0));
}

int
sys_removexattr(user_addr_t path, user_addr_t attrname, int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "removexattr(\"%s\", \"%s\", %p)\n", (char *)path,
			(char *)attrname, (void *)options);
#endif
	char path_buffer[PATH_MAX], name[XATTR_NAME_MAX + 1];
	const char *p = host_path(path, options, path_buffer);
	const char *n = host_name(attrname, name);
	return xattr_result((options & _XATTR_NOFOLLOW) ? lremovexattr(p, n)
							: removexattr(p, n));
}

int
sys_fremovexattr(int fd, user_addr_t attrname, int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fremovexattr(%p, \"%s\", %p)\n", (void *)fd,
			(char *)attrname, (void *)options);
#endif
	char name[XATTR_NAME_MAX + 1];
	return xattr_result(fremovexattr(fd, host_name(attrname, name)));
}

user_ssize_t
sys_listxattr(user_addr_t path, user_addr_t namebuf, size_t bufsize,
		int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "listxattr(\"%s\", %p, %p, %p)\n", (char *)path,
			(void *)namebuf, (void *)bufsize, (void *)options);
#endif
	char path_buffer[PATH_MAX];
	const char *p = host_path(path, options, path_buffer);
	char *names = malloc(XATTR_LIST_MAX);
	user_ssize_t result = list_result((options & _XATTR_NOFOLLOW)
					? llistxattr(p, names, XATTR_LIST_MAX)
					: listxattr(p, names, XATTR_LIST_MAX),
			names, namebuf, bufsize);
	free(names);
	return result;
}

user_ssize_t
sys_flistxattr(int fd, user_addr_t namebuf, size_t bufsize, int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "flistxattr(%p, %p, %p, %p)\n", (void *)fd,
			(void *)namebuf, (void *)bufsize, (void *)options);
#endif
	char *names = malloc(XATTR_LIST_MAX);
	user_ssize_t result = list_result(flistxattr(fd, names, XATTR_LIST_MAX),
			names, namebuf, bufsize);
	free(names);
	return result;
}

static const char *
host_path(const char *path, int options, char *buffer)
{
	return sysroot_host_path(path,
			(options & _XATTR_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0,
			buffer);
}

static const char *
host_name(const char *name, char *buffer)
{
	snprintf(buffer, XATTR_NAME_MAX + 1, LINUX_NAMESPACE "%s", name);
	return buffer;
}

static user_ssize_t
xattr_result(ssize_t result)
{
	if (result != -1) {
		return result;
	}
	return (errno == ENODATA) ? _ENOATTR : err_map(errno);
}

static user_ssize_t
list_result(ssize_t result, const char *names, char *namebuf, size_t bufsize)
{
	if (result == -1) {
		return err_map(errno);
	}

	size_t prefix_length = strlen(LINUX_NAMESPACE);
	size_t used = 0;
	for (const char *name = names; name < names + result;
			name += strlen(name) + 1) {
		if (strncmp(name, LINUX_NAMESPACE, prefix_length) != 0
				|| strcmp(name, BSD_FLAGS_XATTR) == 0) {
			continue;
		}

		const char *darwin_name = name + prefix_length;
		size_t length = strlen(darwin_name) + 1;
		if (namebuf != NULL) {
			if (used + length > bufsize) {
				return _ERANGE;
			}
			memcpy(namebuf + used, darwin_name, length);
		}
		used += length;
	}

	return used;
}
