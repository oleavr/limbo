/*
 * Copyright © 2021 Keegan Saunders
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

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#ifdef __x86_64__
#include <x86intrin.h>
#endif

#include "commpage.h"

#ifdef __x86_64__
static void init_nanotime(void);
static uint64_t sample_clocks(uint64_t *tsc);

int
commpage_mmap(void)
{
	void *commpage = mmap((void *)_COMM_PAGE_START_ADDRESS,
			_COMM_PAGE_AREA_LENGTH, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
	if (commpage == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	/* TODO: Initialize the entire commpage */
	*(uint16_t *)_COMM_PAGE_VERSION = _COMM_PAGE_THIS_VERSION;
	*(uint8_t *)_COMM_PAGE_ACTIVE_CPUS = 12;
	*(uint8_t *)_COMM_PAGE_LOGICAL_CPUS = 24;
	*(uint8_t *)_COMM_PAGE_PHYSICAL_CPUS = 12;
	*(uint8_t *)_COMM_PAGE_USER_PAGE_SHIFT_64 = 12;
	*(uint64_t *)_COMM_PAGE_MEMORY_SIZE = 17179869184;
	init_nanotime();

	return 0;
}

uint64_t
commpage_absolute_time(void)
{
	uint64_t elapsed = __rdtsc() - *(uint64_t *)_COMM_PAGE_NT_TSC_BASE;
	return ((unsigned __int128)elapsed * *(uint32_t *)_COMM_PAGE_NT_SCALE
			       >> 32)
			+ *(uint64_t *)_COMM_PAGE_NT_NS_BASE;
}

void
commpage_timebase(uint32_t *numer, uint32_t *denom)
{
	*numer = 1;
	*denom = 1;
}

static void
init_nanotime(void)
{
	uint64_t start_tsc, end_tsc;
	uint64_t start_ns = sample_clocks(&start_tsc);
	nanosleep(&(struct timespec){.tv_nsec = 1000000}, NULL);
	uint64_t end_ns = sample_clocks(&end_tsc);

	*(uint64_t *)_COMM_PAGE_NT_TSC_BASE = start_tsc;
	*(uint32_t *)_COMM_PAGE_NT_SCALE
			= ((unsigned __int128)(end_ns - start_ns) << 32)
			/ (end_tsc - start_tsc);
	*(uint32_t *)_COMM_PAGE_NT_SHIFT = 0;
	*(uint64_t *)_COMM_PAGE_NT_NS_BASE = start_ns;
	*(uint32_t *)_COMM_PAGE_NT_GENERATION = 1;
}

static uint64_t
sample_clocks(uint64_t *tsc)
{
	struct timespec now;
	uint64_t before = __rdtsc();
	clock_gettime(CLOCK_MONOTONIC, &now);
	uint64_t after = __rdtsc();

	*tsc = before + (after - before) / 2;
	return now.tv_sec * 1000000000ULL + now.tv_nsec;
}
#else /* __arm64__ */

static const uint8_t commpage_snapshot[] = {
	0x63, 0x6f, 0x6d, 0x6d, 0x70, 0x61, 0x67, 0x65, 0x20, 0x36, 0x34, 0x2d,
	0x62, 0x69, 0x74, 0x00, 0xc8, 0x7f, 0x0a, 0xb7, 0x97, 0xef, 0xff, 0xbf,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xc8, 0x7f, 0x0a, 0xb7,
	0x0e, 0x0e, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x87, 0x5a, 0x1d,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x10, 0xe0, 0xb7, 0xdb, 0x5e, 0x5e, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xcb, 0xbe, 0xfc, 0xe0, 0xa4, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x30, 0x30, 0x00, 0x10, 0x20,
	0x00, 0x00, 0x10, 0x30, 0x20, 0x00, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30,
	0x20, 0x00, 0x10, 0x20, 0x00, 0x00, 0x10, 0x30, 0x20, 0x00, 0x10, 0x20,
	0xe1, 0xba, 0xfb, 0xe0, 0xa4, 0x01, 0x00, 0x00, 0x58, 0x3a, 0xda, 0x6a,
	0x00, 0x00, 0x00, 0x00, 0xe3, 0x98, 0x7e, 0x9c, 0xbb, 0xef, 0xa9, 0x29,
	0x4e, 0xe5, 0xe7, 0xf4, 0xb2, 0x00, 0x00, 0x00,
};

#define COMM_PAGE_CNTVCT_TIMEBASE 1
#define COMM_PAGE_TIMEBASE_TYPE   0x90
#define COMM_PAGE_TIMEBASE_OFFSET 0xa8

static const uintptr_t _COMM_PAGE_RO_ADDRESS = 0xfffff4000ULL;
static const uint8_t host_cpu_count = 14;
#define COMM_PAGE_RO_LOGICAL_CPUS  0x24
#define COMM_PAGE_RO_PHYSICAL_CPUS 0x25
#define COMM_PAGE_RO_ACTIVE_CPUS   0x37

static int map_fixed_page(uintptr_t address, size_t length, uint8_t **page);

int
commpage_mmap(void)
{
	uint8_t *config;
	if (map_fixed_page(_COMM_PAGE_RO_ADDRESS, _COMM_PAGE_AREA_LENGTH,
			    &config)) {
		return 1;
	}
	config[COMM_PAGE_RO_LOGICAL_CPUS] = host_cpu_count;
	config[COMM_PAGE_RO_PHYSICAL_CPUS] = host_cpu_count;
	config[COMM_PAGE_RO_ACTIVE_CPUS] = host_cpu_count;

	uint8_t *commpage;
	if (map_fixed_page(_COMM_PAGE_START_ADDRESS, _COMM_PAGE_AREA_LENGTH,
			    &commpage)) {
		return 1;
	}
	memcpy(commpage, commpage_snapshot, sizeof(commpage_snapshot));
	commpage[COMM_PAGE_TIMEBASE_TYPE] = COMM_PAGE_CNTVCT_TIMEBASE;
	*(uint64_t *)(commpage + COMM_PAGE_TIMEBASE_OFFSET) = 0;

	return 0;
}

static int
map_fixed_page(uintptr_t address, size_t length, uint8_t **page)
{
	*page = mmap((void *)address, length, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
	if (*page == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	return 0;
}

uint64_t
commpage_absolute_time(void)
{
	uint64_t ticks;
	asm volatile("isb\n"
		     "mrs %0, cntvct_el0"
			: "=r"(ticks));
	return ticks;
}

void
commpage_timebase(uint32_t *numer, uint32_t *denom)
{
	uint64_t frequency;
	asm("mrs %0, cntfrq_el0" : "=r"(frequency));
	uint64_t a = 1000000000, b = frequency;
	while (b != 0) {
		uint64_t r = a % b;
		a = b;
		b = r;
	}
	*numer = 1000000000 / a;
	*denom = frequency / a;
}
#endif

uint64_t
commpage_absolute_to_nanoseconds(uint64_t absolute)
{
	uint32_t numer, denom;
	commpage_timebase(&numer, &denom);
	return (unsigned __int128)absolute * numer / denom;
}
