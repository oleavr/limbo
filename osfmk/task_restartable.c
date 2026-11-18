/*
 * Copyright © 2021 Keegan Saunders
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

#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "task_restartable.h"
#include "thread.h"

#define RANGES_MAX 64
#define OFFSET_MAX 4096

static task_restartable_range_t registered[RANGES_MAX];
static _Atomic uint32_t registered_count;
static pthread_mutex_t synchronize_lock = PTHREAD_MUTEX_INITIALIZER;

static int compare_ranges(const void *a, const void *b);

kern_return_t
task_restartable_ranges_register(task_t target_task,
		task_restartable_range_array_t ranges,
		mach_msg_type_number_t rangesCnt)
{
	if (rangesCnt == 0) {
		return KERN_INVALID_ARGUMENT;
	}
	task_restartable_range_t sorted[RANGES_MAX];
	memcpy(sorted, ranges, rangesCnt * sizeof(sorted[0]));
	qsort(sorted, rangesCnt, sizeof(sorted[0]), compare_ranges);
	for (mach_msg_type_number_t i = 0; i < rangesCnt; i++) {
		uint64_t start = sorted[i].location;
		uint64_t end = start + sorted[i].length;
		if (sorted[i].length > OFFSET_MAX
				|| sorted[i].recovery_offs > OFFSET_MAX
				|| sorted[i].flags != 0 || end < start
				|| start + sorted[i].recovery_offs < start
				|| (i + 1 < rangesCnt
						&& end > sorted[i + 1].location)) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	pthread_mutex_lock(&synchronize_lock);
	kern_return_t kr = KERN_NOT_SUPPORTED;
	if (registered_count == 0) {
		memcpy(registered, sorted, rangesCnt * sizeof(sorted[0]));
		registered_count = rangesCnt;
		kr = KERN_SUCCESS;
	}
	pthread_mutex_unlock(&synchronize_lock);
	return kr;
}

static int
compare_ranges(const void *a, const void *b)
{
	const task_restartable_range_t *first = a, *second = b;
	if (first->location != second->location) {
		return first->location < second->location ? -1 : 1;
	}
	if (first->length != second->length) {
		return first->length < second->length ? -1 : 1;
	}
	return 0;
}

kern_return_t
task_restartable_ranges_synchronize(task_t target_task)
{
	if (registered_count == 0) {
		return KERN_SUCCESS;
	}
	if (pthread_mutex_trylock(&synchronize_lock) != 0) {
		return KERN_ALREADY_WAITING;
	}
	thread_restart_others();
	pthread_mutex_unlock(&synchronize_lock);
	return KERN_SUCCESS;
}

uint64_t
task_restartable_recovery(uint64_t pc)
{
	uint32_t count = registered_count;
	for (uint32_t i = 0; i < count; i++) {
		const task_restartable_range_t *range = &registered[i];
		if (pc > range->location
				&& pc < range->location + range->length) {
			return range->location + range->recovery_offs;
		}
	}
	return pc;
}
