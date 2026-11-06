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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
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

#define STATES_MAX 32
static struct boot_state *_Atomic states[STATES_MAX];
static pthread_once_t fork_hook = PTHREAD_ONCE_INIT;

static void remember(struct boot_state *state);
static void register_fork_hook(void);
static void forget_all(void);
static void forget(struct boot_state *state);
static int open_file(const char *path);

void *
boot_state_begin(struct boot_state *state)
{
	pthread_once(&fork_hook, register_fork_hook);
	remember(state);
	pthread_mutex_lock(&state->lock);
	if (state->fd == -1) {
		char buffer[PATH_MAX];
		const char *path = sysroot_host_path(state->path, 0, buffer);
		state->fd = path == NULL ? -1 : open_file(path);
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

static void
remember(struct boot_state *state)
{
	for (size_t i = 0; i < STATES_MAX; i++) {
		struct boot_state *expected = NULL;
		if (atomic_compare_exchange_strong(&states[i], &expected, state)
				|| expected == state) {
			return;
		}
	}
}

static void
register_fork_hook(void)
{
	pthread_atfork(NULL, NULL, forget_all);
}

static void
forget_all(void)
{
	for (size_t i = 0; i < STATES_MAX; i++) {
		struct boot_state *state = atomic_load(&states[i]);
		if (state != NULL) {
			forget(state);
		}
	}
}

static void
forget(struct boot_state *state)
{
	pthread_mutex_init(&state->lock, NULL);
	if (state->fd != -1) {
		close(state->fd);
		state->fd = -1;
	}
}

static int
open_file(const char *path)
{
	int fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd != -1 || errno != ENOENT) {
		return fd;
	}
	fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
	if (fd == -1 && errno == EEXIST) {
		fd = open(path, O_RDWR | O_CLOEXEC);
	}
	return fd;
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
