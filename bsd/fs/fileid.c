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

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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

static struct slot *slot_for(uint64_t id);
static bool still_names(const char *path, uint64_t id);

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
			return _ENOENT;
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

static bool
still_names(const char *path, uint64_t id)
{
	char buffer[PATH_MAX];
	struct stat s;
	return lstat(sysroot_host_path(path, 0, buffer), &s) == 0
			&& sysroot_file_id(s.st_dev, s.st_ino) == id;
}
