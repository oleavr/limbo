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

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bsd/boot_state.h"
#include "sysroot.h"

static void
boot_id(char boot[40])
{
	memset(boot, 0, 40);
	FILE *file = fopen("/proc/sys/kernel/random/boot_id", "re");
	if (file != NULL) {
		if (fgets(boot, 40, file) == NULL) {
			boot[0] = '\0';
		}
		fclose(file);
	}
}

void *
boot_state_begin(struct boot_state *state)
{
	pthread_mutex_lock(&state->lock);
	if (state->fd == -1) {
		char buffer[PATH_MAX];
		const char *path = sysroot_host_path(state->path, 0, buffer);
		state->fd = path == NULL
				? -1
				: open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0666);
		struct stat st;

		if (state->fd != -1 && fstat(state->fd, &st) == 0
				&& (st.st_mode & 0777) != 0666) {
			fchmod(state->fd, 0666);
		}
	}
	if (state->fd == -1) {
		pthread_mutex_unlock(&state->lock);
		return NULL;
	}
	flock(state->fd, LOCK_EX);
	struct boot_state_header *header = state->data;
	char boot[40];
	boot_id(boot);
	if (pread(state->fd, state->data, state->size, 0)
					!= (ssize_t)state->size
			|| header->magic != state->magic
			|| memcmp(header->boot, boot, sizeof(boot)) != 0) {
		memset(state->data, 0, state->size);
		header->magic = state->magic;
		memcpy(header->boot, boot, sizeof(boot));
	}
	return state->data;
}

void
boot_state_end(struct boot_state *state, bool changed)
{
	if (changed) {
		pwrite(state->fd, state->data, state->size, 0);
	}
	flock(state->fd, LOCK_UN);
	pthread_mutex_unlock(&state->lock);
}

void
boot_state_close(struct boot_state *state)
{
	pthread_mutex_lock(&state->lock);
	if (state->fd != -1) {
		close(state->fd);
		state->fd = -1;
	}
	pthread_mutex_unlock(&state->lock);
}
