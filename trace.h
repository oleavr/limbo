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

#pragma once

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define TRACE_MAGIC        "limbotrc"
#define TRACE_VERSION      1
#define TRACE_RING_COUNT   256
#define TRACE_TABLE_OFFSET 4096
#define TRACE_DATA_OFFSET  65536
#define TRACE_BLOCK_SIZE   4096
#define TRACE_STRING_SIZE  1024
#define TRACE_CACHE_LINE   128

#define TRACE_ARCH_X86_64 1
#define TRACE_ARCH_ARM64  2

struct trace_header {
	char magic[8];
	uint32_t version;
	uint32_t arch;
	int32_t pid;
	int32_t parent;
	uint64_t start;
	uint32_t ring_size;
	uint32_t arguments_size;
	_Atomic uint64_t dropped;
	char program[TRACE_STRING_SIZE];
	char arguments[2 * TRACE_STRING_SIZE];
};

struct trace_ring {
	_Alignas(TRACE_CACHE_LINE) _Atomic uint32_t owner;
	_Atomic uint64_t written;
};

enum trace_type {
	TRACE_PADDING,
	TRACE_SYSCALL_ENTER,
	TRACE_SYSCALL_RETURN,
	TRACE_STRING,
};

struct trace_record {
	uint16_t size;
	uint16_t type;
	uint32_t tid;
	uint64_t time;
};

#define TRACE_CLASS_MACH 1
#define TRACE_CLASS_BSD  2
#define TRACE_CLASS_MDEP 3

struct trace_syscall_enter {
	struct trace_record record;
	uint32_t syscall_class;
	uint32_t number;
	uint64_t arguments[6];
};

enum trace_outcome {
	TRACE_RESULT,
	TRACE_RAW_RESULT,
	TRACE_KEPT_CONTEXT,
	TRACE_RESTARTED,
};

struct trace_syscall_return {
	struct trace_record record;
	uint32_t syscall_class;
	uint32_t number;
	int64_t result;
	uint64_t outcome;
};

struct trace_string {
	struct trace_record record;
	uint64_t address;
	uint32_t size;
	uint32_t host_size;
	char bytes[];
};

void trace_start(const char *program, char *const arguments[]);
void trace_fork_child(void);
void trace_syscall_enter(uint32_t syscall_class, uint32_t number,
		const uint64_t arguments[6]);
void trace_syscall_return(uint32_t syscall_class, uint32_t number,
		int64_t result, enum trace_outcome outcome);
void trace_string(const char *string);
void trace_path(const char *guest, const char *host);
