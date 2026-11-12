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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "bsd/xnu-errno.h"

typedef size_t user_size_t;
typedef ssize_t user_ssize_t;

#define _MAXPATHLEN 1024

struct __darwin_struct_dirent {
	uint64_t d_ino;
	uint64_t d_seekoff;
	uint16_t d_reclen;
	uint16_t d_namlen;
	uint8_t d_type;
	char d_name[_MAXPATHLEN];
};

user_ssize_t
sys_getdirentries64(int dirfd, void *buf, user_size_t bufsize, off_t *position)
{
	off_t start = lseek(dirfd, 0, SEEK_CUR);
	if (start == -1) {
		return err_map(errno);
	}

	size_t used = 0;
	off_t resume = start;
	bool full = false;
	char entries[4096];
	while (true) {
		long size = syscall(SYS_getdents64, dirfd, entries,
				sizeof(entries));
		if (size == -1) {
			return err_map(errno);
		}
		if (size == 0) {
			break;
		}

		for (long offset = 0; offset < size;) {
			struct dirent64 *d
					= (struct dirent64 *)(entries + offset);
			size_t namlen = strlen(d->d_name);
			size_t reclen = (offsetof(struct __darwin_struct_dirent,
							 d_name)
							+ namlen + 1 + 7)
					& ~7;
			if (used + reclen > bufsize) {
				lseek(dirfd, resume, SEEK_SET);
				full = true;
				goto done;
			}

			struct __darwin_struct_dirent *ent = (struct
					__darwin_struct_dirent *)((char *)buf
					+ used);
			ent->d_ino = d->d_ino;
			ent->d_seekoff = d->d_off;
			ent->d_reclen = reclen;
			ent->d_namlen = namlen;
			ent->d_type = d->d_type;
			memcpy(ent->d_name, d->d_name, namlen + 1);

			used += reclen;
			resume = d->d_off;
			offset += d->d_reclen;
		}
	}

done:
	if (used == 0 && full) {
		return _EINVAL;
	}
	*position = start;
	return used;
}

int
sys_getdirentries(int fd, char *buf, uint32_t count, long *basep)
{
	unimplemented();
}

int
sys_getdirentriesattr(int fd, void *alist, void *buffer, size_t buffersize,
		void *count, void *basep, void *newstate, uint64_t options)
{
	unimplemented();
}
