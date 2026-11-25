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

#include "purgeable.h"
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/xattr.h>

static void
fd_path(int fd, char *buffer, size_t size)
{
	snprintf(buffer, size, "/proc/thread-self/fd/%d", fd);
}

int
purgeable_mark(int fd, uint64_t flags)
{
	struct stat s;
	if (fstat(fd, &s) == -1) {
		return -1;
	}
	if (S_ISLNK(s.st_mode)) {
		errno = EINVAL;
		return -1;
	}
	char path[48];
	fd_path(fd, path, sizeof(path));
	if (flags & PURGEABLE_MARK) {
		int r = setxattr(path, PURGEABLE_XATTR, &flags, sizeof(flags),
				0);
		return r == -1 && errno == ENOTSUP ? 0 : r;
	}
	if (removexattr(path, PURGEABLE_XATTR) == -1 && errno != ENODATA
			&& errno != ENOTSUP) {
		return -1;
	}
	return 0;
}

bool
purgeable_is(int fd)
{
	char path[48];
	fd_path(fd, path, sizeof(path));
	uint64_t flags;
	return getxattr(path, PURGEABLE_XATTR, &flags, sizeof(flags))
			== sizeof(flags)
			&& (flags & PURGEABLE_MARK);
}
