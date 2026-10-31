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

#include "bsd_flags.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void
fd_path(int fd, char *buffer, size_t size)
{
	snprintf(buffer, size, "/proc/thread-self/fd/%d", fd);
}

int
bsd_flags_set(int fd, uint32_t flags)
{
	char path[48];
	fd_path(fd, path, sizeof(path));
	if (flags == 0) {
		if (removexattr(path, BSD_FLAGS_XATTR) == -1
				&& errno != ENODATA) {
			return -1;
		}
		return 0;
	}
	return setxattr(path, BSD_FLAGS_XATTR, &flags, sizeof(flags), 0);
}

uint32_t
bsd_flags_get(int fd)
{
	char path[48];
	fd_path(fd, path, sizeof(path));
	uint32_t flags = 0;
	if (getxattr(path, BSD_FLAGS_XATTR, &flags, sizeof(flags))
			!= sizeof(flags)) {
		return 0;
	}
	return flags;
}

uint32_t
bsd_flags_get_at(int dirfd, const char *host_path, int at_flags)
{
	int fd = openat(dirfd, host_path,
			O_PATH | O_CLOEXEC
					| ((at_flags & AT_SYMLINK_NOFOLLOW)
									? O_NOFOLLOW
									: 0),
			0);
	if (fd == -1 && (at_flags & AT_EMPTY_PATH) && host_path[0] == '\0') {
		return bsd_flags_get(dirfd);
	}
	if (fd == -1) {
		return 0;
	}
	struct stat s;
	uint32_t flags = (fstat(fd, &s) == 0 && !S_ISLNK(s.st_mode))
			? bsd_flags_get(fd)
			: 0;
	close(fd);
	return flags;
}
