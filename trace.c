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
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "trace.h"

#define RING_SIZE     (1UL << 20)
#define RING_SIZE_MIN (2UL * TRACE_BLOCK_SIZE)
#define RING_SIZE_MAX (1UL << 30)

static char directory[PATH_MAX];
static size_t ring_size = RING_SIZE;
static size_t mapping_size;
static struct trace_header *header;
static pthread_key_t ring_key;

static __thread struct trace_ring *ring;
static __thread uint8_t *ring_data;
static __thread uint32_t ring_tid;

static void create_file(const char *program, const char *arguments,
		size_t arguments_size);
static void append(
		enum trace_type type, struct trace_record *record, size_t size);
static bool claim_ring(void);
static void release_ring(void *claimed);
static uint64_t now(void);

void
trace_start(const char *program, char *const arguments[])
{
	const char *path = getenv("LIMBO_TRACE");
	if (path == NULL) {
		return;
	}
	if (realpath(path, directory) == NULL) {
		fprintf(stderr, "limbo: invalid trace directory %s\n", path);
		return;
	}
	const char *size = getenv("LIMBO_TRACE_SIZE");
	if (size != NULL) {
		size_t wanted = strtoull(size, NULL, 0);
		ring_size = RING_SIZE_MIN;
		while (ring_size < wanted && ring_size < RING_SIZE_MAX) {
			ring_size *= 2;
		}
	}
	mapping_size = TRACE_DATA_OFFSET + TRACE_RING_COUNT * ring_size;
	pthread_key_create(&ring_key, release_ring);

	char joined[sizeof(header->arguments)];
	size_t joined_size = 0;
	for (size_t i = 0; arguments[i] != NULL; i++) {
		size_t length = strlen(arguments[i]) + 1;
		if (length > sizeof(joined) - joined_size) {
			break;
		}
		memcpy(joined + joined_size, arguments[i], length);
		joined_size += length;
	}
	create_file(program, joined, joined_size);
}

void
trace_fork_child(void)
{
	struct trace_header *parent = header;
	if (parent == NULL) {
		return;
	}
	header = NULL;
	ring = NULL;
	pthread_setspecific(ring_key, NULL);
	create_file(parent->program, parent->arguments, parent->arguments_size);
	munmap(parent, mapping_size);
}

static void
create_file(const char *program, const char *arguments, size_t arguments_size)
{
	char path[PATH_MAX + 32];
	int fd;
	unsigned image = 0;
	do {
		snprintf(path, sizeof(path), "%s/%d.%u", directory, getpid(),
				image++);
		fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	} while (fd == -1 && errno == EEXIST);

	if (fd == -1 || ftruncate(fd, mapping_size) == -1) {
		fprintf(stderr, "limbo: cannot trace to %s: %s\n", path,
				strerror(errno));
		return;
	}
	struct trace_header *created = mmap(NULL, mapping_size,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);

	created->version = TRACE_VERSION;
#ifdef __x86_64__
	created->arch = TRACE_ARCH_X86_64;
#else
	created->arch = TRACE_ARCH_ARM64;
#endif
	created->pid = getpid();
	created->parent = getppid();
	created->start = now();
	created->ring_size = ring_size;
	created->arguments_size = arguments_size;
	snprintf(created->program, sizeof(created->program), "%s", program);
	memcpy(created->arguments, arguments, arguments_size);
	memcpy(created->magic, TRACE_MAGIC, sizeof(created->magic));

	header = created;
}

void
trace_syscall_enter(uint32_t syscall_class, uint32_t number,
		const uint64_t arguments[6])
{
	if (header == NULL) {
		return;
	}
	struct trace_syscall_enter enter = {
			.syscall_class = syscall_class,
			.number = number,
	};
	memcpy(enter.arguments, arguments, sizeof(enter.arguments));
	append(TRACE_SYSCALL_ENTER, &enter.record, sizeof(enter));
}

void
trace_syscall_return(uint32_t syscall_class, uint32_t number, int64_t result,
		enum trace_outcome outcome)
{
	if (header == NULL) {
		return;
	}
	struct trace_syscall_return returned = {
			.syscall_class = syscall_class,
			.number = number,
			.result = result,
			.outcome = outcome,
	};
	append(TRACE_SYSCALL_RETURN, &returned.record, sizeof(returned));
}

void
trace_string(const char *string)
{
	trace_path(string, string);
}

void
trace_path(const char *guest, const char *host)
{
	if (header == NULL) {
		return;
	}
	union {
		struct trace_string string;
		char bytes[sizeof(struct trace_string) + 2 * TRACE_STRING_SIZE];
	} storage;
	struct trace_string *string = &storage.string;
	string->address = (uintptr_t)guest;
	string->size = strnlen(guest, TRACE_STRING_SIZE - 1);
	string->host_size = host == guest
			? 0
			: strnlen(host, TRACE_STRING_SIZE - 1);
	char *host_copy = string->bytes + string->size + 1;
	size_t size = sizeof(*string) + string->size + string->host_size + 2;
	size_t aligned_size = (size + 7) & ~(size_t)7;
	memcpy(string->bytes, guest, string->size);
	string->bytes[string->size] = '\0';
	memcpy(host_copy, host, string->host_size);
	memset(host_copy + string->host_size, 0, aligned_size - size + 1);
	append(TRACE_STRING, &string->record, aligned_size);
}

static void
append(enum trace_type type, struct trace_record *record, size_t size)
{
	if (ring == NULL && !claim_ring()) {
		return;
	}
	uint64_t position = atomic_load_explicit(
			&ring->written, memory_order_relaxed);
	uint64_t room = TRACE_BLOCK_SIZE - position % TRACE_BLOCK_SIZE;
	if (size > room) {
		struct trace_record *padding = (void *)(ring_data
				+ (position & (ring_size - 1)));
		padding->size = room;
		padding->type = TRACE_PADDING;
		position += room;
	}
	record->size = size;
	record->type = type;
	record->tid = ring_tid;
	record->time = now();
	memcpy(ring_data + (position & (ring_size - 1)), record, size);
	atomic_store_explicit(
			&ring->written, position + size, memory_order_release);
}

static bool
claim_ring(void)
{
	uint32_t tid = gettid();
	uint8_t *base = (uint8_t *)header;
	struct trace_ring *table = (void *)(base + TRACE_TABLE_OFFSET);
	for (size_t i = 0; i < TRACE_RING_COUNT; i++) {
		uint32_t unowned = 0;
		if (!atomic_compare_exchange_strong(
				    &table[i].owner, &unowned, tid)) {
			continue;
		}
		ring = &table[i];
		ring_data = base + TRACE_DATA_OFFSET + i * ring_size;
		ring_tid = tid;
		pthread_setspecific(ring_key, ring);
		return true;
	}
	atomic_fetch_add(&header->dropped, 1);
	return false;
}

static void
release_ring(void *claimed)
{
	struct trace_ring *released = claimed;
	atomic_store(&released->owner, 0);
}

static uint64_t
now(void)
{
	struct timespec time;
	clock_gettime(CLOCK_MONOTONIC, &time);
	return (uint64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}
