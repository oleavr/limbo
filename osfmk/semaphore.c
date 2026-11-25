/*
 * Copyright © 2026 Ole André Vadla Ravnås
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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "bsd/process.h"
#include "bsd/signals.h"
#include "ipc.h"
#include "semaphore.h"

struct slot {
	_Atomic int32_t count;
	_Atomic int32_t waiters;
	_Atomic uint32_t destroyed;
	uint32_t reserved;
};

#define CHUNK_SLOTS 1024
#define CHUNK_SIZE  (CHUNK_SLOTS * sizeof(struct slot))

struct chunk {
	struct chunk *next;
	int fd;
	struct slot *slots;
	dev_t dev;
	ino_t ino;
	bool own;
	uint32_t refs;
	uint32_t used;
	bool exported[CHUNK_SLOTS];
	uint32_t free_count;
	uint32_t free_slots[CHUNK_SLOTS];
};

static uint32_t generation;

struct semaphore {
	struct chunk *chunk;
	struct slot *slot;
	uint32_t index;
	bool owner;
	uint32_t generation;
};
static bool slot_alloc(struct chunk **chunk_out, uint32_t *index);
static struct chunk *chunk_map(int fd, bool own);
static struct semaphore *semaphore_get(semaphore_t name);
static void wake(struct slot *slot, int count);
static bool semaphore_describe(
		void *kobject, int *fd, uint64_t *size, uint64_t *offset);
static void *semaphore_adopt(int fd, uint64_t size, uint64_t offset);
static void semaphore_port_gone(void *kobject);

static pthread_mutex_t chunks_lock = PTHREAD_MUTEX_INITIALIZER;

static struct chunk *chunks;

static kern_return_t wait_until(
		struct slot *slot, const struct timespec *deadline);

kern_return_t
semaphore_alloc(int value, semaphore_t *name)
{
	if (value < 0) {
		return KERN_INVALID_ARGUMENT;
	}
	struct semaphore *semaphore = calloc(1, sizeof(*semaphore));
	pthread_mutex_lock(&chunks_lock);
	bool allocated = slot_alloc(&semaphore->chunk, &semaphore->index);
	semaphore->generation = generation;
	pthread_mutex_unlock(&chunks_lock);
	if (!allocated) {
		free(semaphore);
		return KERN_RESOURCE_SHORTAGE;
	}
	semaphore->slot = &semaphore->chunk->slots[semaphore->index];
	semaphore->owner = true;
	atomic_store(&semaphore->slot->destroyed, 0);
	atomic_store(&semaphore->slot->waiters, 0);
	atomic_store(&semaphore->slot->count, value);
	*name = ipc_kobject_alloc(IPC_KOBJECT_SEMAPHORE, semaphore);
	return KERN_SUCCESS;
}

static bool
slot_alloc(struct chunk **chunk_out, uint32_t *index)
{
	struct chunk *chunk;
	for (chunk = chunks; chunk != NULL; chunk = chunk->next) {
		if (chunk->own
				&& (chunk->used < CHUNK_SLOTS
						|| chunk->free_count != 0)) {
			break;
		}
	}
	if (chunk == NULL) {
		int fd = memfd_create("mach semaphores", MFD_CLOEXEC);
		if (fd == -1 || ftruncate(fd, CHUNK_SIZE) == -1) {
			if (fd != -1) {
				close(fd);
			}
			return false;
		}
		chunk = chunk_map(fd, true);
		if (chunk == NULL) {
			return false;
		}
	}
	*index = (chunk->free_count != 0)
			? chunk->free_slots[--chunk->free_count]
			: chunk->used++;
	*chunk_out = chunk;
	return true;
}

static struct chunk *
chunk_map(int fd, bool own)
{
	void *slots = mmap(NULL, CHUNK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
			fd, 0);
	struct stat st;
	if (slots == MAP_FAILED || fstat(fd, &st) == -1) {
		if (slots != MAP_FAILED) {
			munmap(slots, CHUNK_SIZE);
		}
		close(fd);
		return NULL;
	}
	fd = limbo_fd_high(fd);
	struct chunk *chunk = calloc(1, sizeof(*chunk));
	chunk->fd = fd;
	chunk->slots = slots;
	chunk->dev = st.st_dev;
	chunk->ino = st.st_ino;
	chunk->own = own;
	chunk->next = chunks;
	chunks = chunk;
	return chunk;
}

kern_return_t
semaphore_dealloc(semaphore_t name)
{
	struct semaphore *semaphore = semaphore_get(name);
	if (semaphore == NULL || !semaphore->owner) {
		return KERN_INVALID_ARGUMENT;
	}

	ipc_kobject_destroy(name);
	struct slot *slot = semaphore->slot;
	atomic_store(&slot->destroyed, 1);
	wake(slot, INT_MAX);
	pthread_mutex_lock(&chunks_lock);
	struct chunk *chunk = semaphore->chunk;
	if (chunk->own && !chunk->exported[semaphore->index]
			&& atomic_load(&slot->waiters) == 0) {
		chunk->free_slots[chunk->free_count++] = semaphore->index;
	}
	pthread_mutex_unlock(&chunks_lock);
	free(semaphore);
	return KERN_SUCCESS;
}

static struct semaphore *
semaphore_get(semaphore_t name)
{
	struct semaphore *semaphore
			= ipc_kobject_lookup(name, IPC_KOBJECT_SEMAPHORE);
	if (semaphore == NULL || semaphore->generation == generation) {
		return semaphore;
	}
	pthread_mutex_lock(&chunks_lock);
	if (semaphore->generation != generation) {
		struct chunk *chunk;
		uint32_t index;
		if (!slot_alloc(&chunk, &index)) {
			pthread_mutex_unlock(&chunks_lock);
			return NULL;
		}
		struct slot *slot = &chunk->slots[index];
		atomic_store(&slot->destroyed, 0);
		atomic_store(&slot->waiters, 0);
		atomic_store(&slot->count,
				atomic_load(&semaphore->slot->count));
		semaphore->chunk = chunk;
		semaphore->index = index;
		semaphore->slot = slot;
		semaphore->owner = true;
		semaphore->generation = generation;
	}
	pthread_mutex_unlock(&chunks_lock);
	return semaphore;
}

kern_return_t
semaphore_signal(semaphore_t name)
{
	struct semaphore *semaphore = semaphore_get(name);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	struct slot *slot = semaphore->slot;
	if (atomic_load(&slot->destroyed)) {
		return KERN_TERMINATED;
	}
	atomic_fetch_add(&slot->count, 1);
	if (atomic_load(&slot->waiters) > 0) {
		wake(slot, 1);
	}
	return KERN_SUCCESS;
}

kern_return_t
semaphore_signal_all(semaphore_t name)
{
	struct semaphore *semaphore = semaphore_get(name);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	struct slot *slot = semaphore->slot;
	if (atomic_load(&slot->destroyed)) {
		return KERN_TERMINATED;
	}
	int32_t waiters = atomic_load(&slot->waiters);
	if (waiters > 0) {
		atomic_fetch_add(&slot->count, waiters);
		wake(slot, INT_MAX);
	}
	return KERN_SUCCESS;
}

kern_return_t
semaphore_wait(semaphore_t name)
{
	struct semaphore *semaphore = semaphore_get(name);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	return wait_until(semaphore->slot, NULL);
}

static bool
take(struct slot *slot)
{
	int32_t count = atomic_load(&slot->count);
	while (count > 0) {
		if (atomic_compare_exchange_weak(
				    &slot->count, &count, count - 1)) {
			return true;
		}
	}
	return false;
}

static kern_return_t
wait_until(struct slot *slot, const struct timespec *deadline)
{
	for (;;) {
		if (atomic_load(&slot->destroyed)) {
			return KERN_TERMINATED;
		}
		if (take(slot)) {
			return KERN_SUCCESS;
		}
		atomic_fetch_add(&slot->waiters, 1);
		int32_t count = atomic_load(&slot->count);
		long result = 0;
		if (count <= 0 && !atomic_load(&slot->destroyed)) {
			result = syscall(SYS_futex, &slot->count,
					FUTEX_WAIT_BITSET, count, deadline,
					NULL, FUTEX_BITSET_MATCH_ANY);
		}
		int error = (result == -1) ? errno : 0;
		atomic_fetch_sub(&slot->waiters, 1);
		if (error == EINTR && signals_thread_pending() && !take(slot)) {
			return KERN_ABORTED;
		}
		if (error == ETIMEDOUT) {
			return take(slot) ? KERN_SUCCESS
					  : KERN_OPERATION_TIMED_OUT;
		}
	}
}

static void
wake(struct slot *slot, int count)
{
	syscall(SYS_futex, &slot->count, FUTEX_WAKE, count, NULL, NULL, 0);
}

kern_return_t
semaphore_timedwait(semaphore_t name, mach_timespec_t timeout)
{
	struct semaphore *semaphore = semaphore_get(name);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	struct timespec deadline;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	long nanoseconds = deadline.tv_nsec + (long)timeout.tv_nsec;
	deadline.tv_sec += timeout.tv_sec + nanoseconds / 1000000000L;
	deadline.tv_nsec = nanoseconds % 1000000000L;
	return wait_until(semaphore->slot, &deadline);
}

kern_return_t
semaphore_wait_signal(semaphore_t wait_name, semaphore_t signal_name)
{
	kern_return_t kr = semaphore_signal(signal_name);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	return semaphore_wait(wait_name);
}

kern_return_t
semaphore_timedwait_signal(semaphore_t wait_name, semaphore_t signal_name,
		mach_timespec_t timeout)
{
	kern_return_t kr = semaphore_signal(signal_name);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	return semaphore_timedwait(wait_name, timeout);
}

static bool
semaphore_describe(void *kobject, int *fd, uint64_t *size, uint64_t *offset)
{
	struct semaphore *semaphore = kobject;
	pthread_mutex_lock(&chunks_lock);
	semaphore->chunk->exported[semaphore->index] = true;
	*fd = semaphore->chunk->fd;
	pthread_mutex_unlock(&chunks_lock);
	*size = CHUNK_SIZE;
	*offset = (uint64_t)semaphore->index * sizeof(struct slot);
	return true;
}

static void *
semaphore_adopt(int fd, uint64_t size, uint64_t offset)
{
	struct stat st;
	if (size != CHUNK_SIZE || offset % sizeof(struct slot) != 0
			|| offset >= CHUNK_SIZE || fstat(fd, &st) == -1) {
		close(fd);
		return NULL;
	}
	pthread_mutex_lock(&chunks_lock);
	struct chunk *chunk;
	for (chunk = chunks; chunk != NULL; chunk = chunk->next) {
		if (chunk->dev == st.st_dev && chunk->ino == st.st_ino) {
			break;
		}
	}
	if (chunk != NULL) {
		close(fd);
	} else {
		chunk = chunk_map(fd, false);
	}
	if (chunk == NULL) {
		pthread_mutex_unlock(&chunks_lock);
		return NULL;
	}
	uint32_t index = (uint32_t)(offset / sizeof(struct slot));
	if (chunk->own) {
		chunk->exported[index] = true;
	} else {
		chunk->refs++;
	}
	pthread_mutex_unlock(&chunks_lock);

	struct semaphore *semaphore = calloc(1, sizeof(*semaphore));
	semaphore->chunk = chunk;
	semaphore->index = index;
	semaphore->slot = &chunk->slots[index];
	semaphore->generation = generation;
	return semaphore;
}

static void
semaphore_port_gone(void *kobject)
{
	struct semaphore *semaphore = kobject;
	if (semaphore == NULL || semaphore->owner) {
		return;
	}
	pthread_mutex_lock(&chunks_lock);
	struct chunk *chunk = semaphore->chunk;
	if (!chunk->own && --chunk->refs == 0) {
		struct chunk **link = &chunks;
		while (*link != chunk) {
			link = &(*link)->next;
		}
		*link = chunk->next;
		munmap(chunk->slots, CHUNK_SIZE);
		close(chunk->fd);
		free(chunk);
	}
	pthread_mutex_unlock(&chunks_lock);
	free(semaphore);
}

void
semaphore_fork_child(void)
{
	pthread_mutex_init(&chunks_lock, NULL);
	generation++;
	for (struct chunk *chunk = chunks; chunk != NULL; chunk = chunk->next) {
		if (chunk->own) {
			chunk->own = false;
			chunk->refs = UINT32_MAX / 2;
		}
	}
}

static bool
semaphore_describe_record(void *kobject, struct ipc_export *out)
{
	struct ipc_memory_record record = {0};
	int fd;
	if (!semaphore_describe(
			    kobject, &fd, &record.size, &record.data_offset)) {
		return false;
	}
	record.fd_index = (uint32_t)ipc_export_fd(out, fd, false);
	ipc_export_record(out, &record, sizeof(record));
	return true;
}

static void *
semaphore_adopt_record(const void *record, const int *fds, size_t fd_count)
{
	const struct ipc_memory_record *memory = record;
	int fd = ipc_import_fd(fds, fd_count, memory->fd_index);
	void *kobject = fd != -1
			? semaphore_adopt(fd, memory->size, memory->data_offset)
			: NULL;
	if (kobject == NULL) {
		fprintf(stderr, "ipc: semaphore without its memfd\n");
	}
	return kobject;
}

static const struct ipc_kobject_ops semaphore_ops = {
		.type = IPC_KOBJECT_SEMAPHORE,
		.remote_id = IPC_REMOTE_SEMAPHORE,
		.record_size = sizeof(struct ipc_memory_record),
		.fd_count = 1,
		.describe = semaphore_describe_record,
		.adopt = semaphore_adopt_record,
		.destroy = semaphore_port_gone,
};

IPC_KOBJECT_OPS(semaphore_ops);
