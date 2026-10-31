/*
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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct process {
	int32_t pid;
	int32_t ppid;
	int32_t pgid;
	int32_t tpgid;
	int32_t session;
	uint32_t tty;
	int32_t nice;
	uint64_t start_ticks;
	uint64_t user_ticks;
	uint64_t system_ticks;
	int32_t threads;
	uint64_t virtual_size;
	uint64_t resident_pages;
	char comm[16];
	uint32_t uid[3];
	uint32_t gid[3];
};

int process_lookup(int32_t pid, struct process *process);
int32_t process_terminal(const struct process *process);
void process_start_time(
		const struct process *process, uint64_t *sec, uint64_t *usec);

uint64_t process_ticks_to_nanoseconds(uint64_t ticks);

bool process_executable_path(int32_t pid, char *path);

/* The process's arguments, NUL-separated, as /proc has them */
ssize_t process_cmdline(int32_t pid, char *buffer, size_t size);

bool process_environment_value(
		int32_t pid, const char *name, char *value, size_t size);
