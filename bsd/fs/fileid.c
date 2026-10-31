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

#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../xnu-errno.h"
#include "fileid.h"
#include "sysroot.h"

#define SLOT_COUNT 65536

struct slot {
	uint64_t id;
	char *path;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct slot slots[SLOT_COUNT];

#define SHARED_PATH     "/private/var/db/limbo/fileids"
#define SHARED_PATH_MAX 248

struct shared_slot {
	uint64_t id;
	char path[SHARED_PATH_MAX];
};

static struct shared_slot *shared_slots;
static pthread_once_t shared_once = PTHREAD_ONCE_INIT;

static struct slot *slot_for(uint64_t id);
static struct shared_slot *shared_slot_for(uint64_t id);
static bool still_names(const char *path, uint64_t id);

static void
map_shared(void)
{
	char buffer[PATH_MAX];
	int fd = open(sysroot_host_path(SHARED_PATH, 0, buffer),
			O_RDWR | O_CREAT | O_CLOEXEC, 0666);
	if (fd == -1) {
		return;
	}
	struct stat s;
	if (fstat(fd, &s) == 0 && (s.st_mode & 0777) != 0666) {
		fchmod(fd, 0666);
	}
	size_t size = SLOT_COUNT * sizeof(struct shared_slot);
	if (fstat(fd, &s) == 0 && (size_t)s.st_size < size
			&& ftruncate(fd, (off_t)size) != 0) {
		close(fd);
		return;
	}
	void *mapping = mmap(
			NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (mapping != MAP_FAILED) {
		shared_slots = mapping;
	}
}

void
fileid_remember(uint64_t id, const char *path)
{
	if (path[0] != '/') {
		return;
	}
	pthread_mutex_lock(&lock);
	struct slot *slot = slot_for(id);
	if (slot->id != id || slot->path == NULL
			|| strcmp(slot->path, path) != 0) {
		free(slot->path);
		slot->id = id;
		slot->path = strdup(path);
	}
	pthread_mutex_unlock(&lock);

	pthread_once(&shared_once, map_shared);
	size_t length = strlen(path);
	struct shared_slot *shared = shared_slot_for(id);
	if (shared == NULL || length >= SHARED_PATH_MAX) {
		return;
	}
	if (__atomic_load_n(&shared->id, __ATOMIC_ACQUIRE) == id
			&& strncmp(shared->path, path, SHARED_PATH_MAX) == 0) {
		return;
	}
	__atomic_store_n(&shared->id, 0, __ATOMIC_RELEASE);
	memcpy(shared->path, path, length + 1);
	__atomic_store_n(&shared->id, id, __ATOMIC_RELEASE);
}

int
fileid_path(uint64_t id, char *buffer, size_t size)
{
	char path[PATH_MAX];
	if (id == 2) {
		strcpy(path, "/");
	} else {
		pthread_mutex_lock(&lock);
		struct slot *slot = slot_for(id);
		bool found = slot->id == id && slot->path != NULL;
		if (found) {
			snprintf(path, sizeof(path), "%s", slot->path);
		}
		pthread_mutex_unlock(&lock);
		if (!found || !still_names(path, id)) {
			pthread_once(&shared_once, map_shared);
			struct shared_slot *shared = shared_slot_for(id);
			found = false;
			if (shared != NULL
					&& __atomic_load_n(&shared->id,
							   __ATOMIC_ACQUIRE)
							== id) {
				memcpy(path, shared->path, SHARED_PATH_MAX);
				path[SHARED_PATH_MAX - 1] = '\0';
				found = __atomic_load_n(&shared->id,
							__ATOMIC_ACQUIRE)
						== id;
			}
			if (!found || !still_names(path, id)) {
				return _ENOENT;
			}
		}
	}

	size_t length = strlen(path) + 1;
	if (length > size) {
		return _ENOSPC;
	}
	memcpy(buffer, path, length);
	return (int)length;
}

static struct slot *
slot_for(uint64_t id)
{
	return &slots[(id * 0x9e3779b97f4a7c15ull) >> 48];
}

static struct shared_slot *
shared_slot_for(uint64_t id)
{
	if (shared_slots == NULL) {
		return NULL;
	}
	return &shared_slots[(id * 0x9e3779b97f4a7c15ull) >> 48];
}

static bool
still_names(const char *path, uint64_t id)
{
	char buffer[PATH_MAX];
	struct stat s;
	return lstat(sysroot_host_path(path, 0, buffer), &s) == 0
			&& sysroot_file_id(s.st_dev, s.st_ino) == id;
}
