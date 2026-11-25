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

#include "protection.h"
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "bsd/codesign.h"

static void fd_path(int fd, char *buffer, size_t size);
static uint32_t default_class(const struct stat *s);
static int class_taken(const struct stat *s, int dpclass);

uint32_t
protection_get(int fd)
{
	struct stat s;
	if (fstat(fd, &s) == -1 || S_ISLNK(s.st_mode)) {
		return PROTECTION_CLASS_DIR_NONE;
	}
	char path[48];
	fd_path(fd, path, sizeof(path));
	uint32_t dpclass;
	if (getxattr(path, PROTECTION_XATTR, &dpclass, sizeof(dpclass))
			!= sizeof(dpclass)) {
		return default_class(&s);
	}
	return dpclass;
}

static void
fd_path(int fd, char *buffer, size_t size)
{
	snprintf(buffer, size, "/proc/thread-self/fd/%d", fd);
}

static uint32_t
default_class(const struct stat *s)
{
	return S_ISDIR(s->st_mode) ? PROTECTION_CLASS_DIR_NONE
				   : PROTECTION_CLASS_C;
}

int
protection_set(int fd, int dpclass)
{
	struct stat s;
	if (fstat(fd, &s) == -1) {
		return -1;
	}
	if (S_ISLNK(s.st_mode)) {
		return 0;
	}
	int taken = class_taken(&s, dpclass);
	if (taken == -1) {
		return -1;
	}
	char path[48];
	fd_path(fd, path, sizeof(path));
	uint32_t value = (uint32_t)taken;
	int r = (value == default_class(&s))
			? removexattr(path, PROTECTION_XATTR)
			: setxattr(path, PROTECTION_XATTR, &value,
					  sizeof(value), 0);
	if (r == -1 && (errno == ENODATA || errno == ENOTSUP)) {
		return 0;
	}
	if (r == -1 && (errno == EACCES || errno == EPERM)) {
		errno = EBADF;
	}
	return r;
}

static int
class_taken(const struct stat *s, int dpclass)
{
	bool folder = S_ISDIR(s->st_mode);
	bool known = (dpclass >= PROTECTION_CLASS_A
				     && dpclass <= PROTECTION_CLASS_D)
			|| dpclass == PROTECTION_CLASS_CX
			|| (!folder && dpclass == PROTECTION_CLASS_F)
			|| (folder && dpclass == PROTECTION_CLASS_DIR_NONE);
	if (!known) {
		errno = EINVAL;
		return -1;
	}
	if (codesign_embedded()) {
		return dpclass;
	}
	if (!folder
			&& (dpclass == PROTECTION_CLASS_F
					|| dpclass == PROTECTION_CLASS_CX)) {
		errno = EPERM;
		return -1;
	}
	if (dpclass == PROTECTION_CLASS_D || dpclass == PROTECTION_CLASS_CX) {
		return PROTECTION_CLASS_C;
	}
	return dpclass;
}

uint32_t
protection_folder_gives(const char *folder_path)
{
	uint32_t dpclass;
	if (getxattr(folder_path, PROTECTION_XATTR, &dpclass, sizeof(dpclass))
			!= sizeof(dpclass)) {
		return PROTECTION_CLASS_DIR_NONE;
	}
	return dpclass;
}
