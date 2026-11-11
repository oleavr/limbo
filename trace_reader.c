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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "trace_reader.h"

static uint64_t oldest_kept(const struct trace_ring *ring, uint64_t capacity);

int
trace_file_open(struct trace_file *file, const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return -1;
	}
	struct stat status;
	fstat(fd, &status);
	const struct trace_header *header = mmap(
			NULL, status.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (header == MAP_FAILED) {
		return -1;
	}
	if (memcmp(header->magic, TRACE_MAGIC, sizeof(header->magic)) != 0
			|| header->version != TRACE_VERSION) {
		munmap((void *)header, status.st_size);
		return -1;
	}
	file->header = header;
	file->size = status.st_size;
	return 0;
}

void
trace_file_close(struct trace_file *file)
{
	munmap((void *)file->header, file->size);
}

struct trace_run
trace_ring_copy(const struct trace_file *file, uint32_t index)
{
	const uint8_t *base = (const uint8_t *)file->header;
	const struct trace_ring *ring = (const void *)(base + TRACE_TABLE_OFFSET
			+ index * sizeof(*ring));
	uint64_t capacity = file->header->ring_size;
	uint64_t data_offset = TRACE_DATA_OFFSET + index * capacity;
	struct trace_run run = {0};
	if (data_offset + capacity > file->size) {
		return run;
	}

	run.start = oldest_kept(ring, capacity);
	run.end = atomic_load_explicit(&ring->written, memory_order_acquire);
	run.bytes = malloc(run.end - run.start);
	for (uint64_t position = run.start; position < run.end;) {
		uint64_t offset = position % capacity;
		uint64_t length = run.end - position;
		if (length > capacity - offset) {
			length = capacity - offset;
		}
		memcpy(run.bytes + (position - run.start),
				base + data_offset + offset, length);
		position += length;
	}

	uint64_t kept = oldest_kept(ring, capacity);
	if (kept > run.end) {
		kept = run.end;
	}
	memmove(run.bytes, run.bytes + (kept - run.start), run.end - kept);
	run.start = kept;
	return run;
}

static uint64_t
oldest_kept(const struct trace_ring *ring, uint64_t capacity)
{
	uint64_t written = atomic_load_explicit(
			&ring->written, memory_order_acquire);
	uint64_t block_being_written = written / TRACE_BLOCK_SIZE;
	uint64_t next_block_end = (block_being_written + 2) * TRACE_BLOCK_SIZE;
	return next_block_end > capacity ? next_block_end - capacity : 0;
}

const struct trace_record *
trace_run_next(const struct trace_run *run, uint64_t *position)
{
	while (*position < run->end) {
		const struct trace_record *record = (const void *)(run->bytes
				+ (*position - run->start));
		*position += record->size;
		if (record->type != TRACE_PADDING) {
			return record;
		}
	}
	return NULL;
}
