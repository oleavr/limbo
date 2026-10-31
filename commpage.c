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
#include <sys/auxv.h>
#include <sys/mman.h>
#include <time.h>
#ifdef __x86_64__
#include <cpuid.h>
#include <x86intrin.h>
#endif

#include "bsd/boot_state.h"
#include "commpage.h"

#define TIMEBASE_PATH  "/private/var/run/limbo-clock"
#define TIMEBASE_MAGIC 0x74626174

struct timebase {
	struct boot_state_header header;
	uint64_t boot_ns;
	uint64_t tsc_base;
	uint64_t ns_base;
	uint32_t scale;
	uint64_t boot_ticks;
};

static struct timebase timebase;
static struct boot_state timebase_state
		= BOOT_STATE_INIT(TIMEBASE_PATH, TIMEBASE_MAGIC, &timebase);
static uint64_t boot_ns;

static uint64_t monotonic_ns(void);

static void
take_timebase(struct timebase *base, void (*start)(struct timebase *))
{
	struct timebase *shared = boot_state_begin(&timebase_state);
	if (shared == NULL) {
		start(base);
	} else {
		bool changed = shared->boot_ns == 0;
		if (changed) {
			start(shared);
		}
		*base = *shared;
		boot_state_end(&timebase_state, changed);
		boot_state_close(&timebase_state);
	}
	boot_ns = base->boot_ns;
}

uint64_t
commpage_boot_nanoseconds(void)
{
	return boot_ns;
}

#ifdef __x86_64__

static uint64_t xcr0(void);
static void init_nanotime(void);
static uint64_t sample_clocks(uint64_t *tsc);
static uint64_t cpu_capabilities(unsigned cpus);

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
	uint64_t capabilities = cpu_capabilities(12);
	*(uint64_t *)_COMM_PAGE_CPU_CAPABILITIES64 = capabilities;
	*(uint32_t *)_COMM_PAGE_CPU_CAPABILITIES = (uint32_t)capabilities;
	*(uint8_t *)_COMM_PAGE_NCPUS = 12;
	*(uint16_t *)_COMM_PAGE_CACHE_LINESIZE = 64;
	*(uint8_t *)_COMM_PAGE_KERNEL_PAGE_SHIFT = 12;
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
calibrate(struct timebase *base)
{
	uint64_t start_tsc, end_tsc;
	uint64_t start_ns = sample_clocks(&start_tsc);
	nanosleep(&(struct timespec){.tv_nsec = 20000000}, NULL);
	uint64_t end_ns = sample_clocks(&end_tsc);

	base->boot_ns = start_ns;
	base->tsc_base = start_tsc;
	base->ns_base = 0;
	base->scale = ((unsigned __int128)(end_ns - start_ns) << 32)
			/ (end_tsc - start_tsc);
}

static void
init_nanotime(void)
{
	struct timebase base;
	take_timebase(&base, calibrate);

	*(uint64_t *)_COMM_PAGE_NT_TSC_BASE = base.tsc_base;
	*(uint32_t *)_COMM_PAGE_NT_SCALE = base.scale;
	*(uint32_t *)_COMM_PAGE_NT_SHIFT = 0;
	*(uint64_t *)_COMM_PAGE_NT_NS_BASE = base.ns_base;
	*(uint32_t *)_COMM_PAGE_NT_GENERATION = 1;
}

#define kHasMMX                 0x00000001ULL
#define kHasSSE                 0x00000002ULL
#define kHasSSE2                0x00000004ULL
#define kHasSSE3                0x00000008ULL
#define kCache64                0x00000020ULL
#define kFastThreadLocalStorage 0x00000080ULL
#define kHasSupplementalSSE3    0x00000100ULL
#define k64Bit                  0x00000200ULL
#define kHasSSE4_1              0x00000400ULL
#define kHasSSE4_2              0x00000800ULL
#define kHasAES                 0x00001000ULL
#define kNumCPUsShift           16
#define kHasAVX1_0              0x01000000ULL
#define kHasRDRAND              0x02000000ULL
#define kHasF16C                0x04000000ULL
#define kHasENFSTRG             0x08000000ULL
#define kHasFMA                 0x10000000ULL
#define kHasAVX2_0              0x20000000ULL
#define kHasBMI1                0x40000000ULL
#define kHasBMI2                0x80000000ULL
#define kHasRTM                 0x0000000100000000ULL
#define kHasHLE                 0x0000000200000000ULL
#define kHasADX                 0x0000000400000000ULL
#define kHasRDSEED              0x0000000800000000ULL
#define kHasAVX512F             0x0000004000000000ULL
#define kHasAVX512CD            0x0000008000000000ULL
#define kHasAVX512DQ            0x0000010000000000ULL
#define kHasAVX512BW            0x0000020000000000ULL
#define kHasAVX512IFMA          0x0000040000000000ULL
#define kHasAVX512VBMI          0x0000080000000000ULL
#define kHasAVX512VL            0x0000100000000000ULL

static uint64_t
cpu_capabilities(unsigned cpus)
{
	unsigned a, b, c, d;
	uint64_t caps = kCache64 | kFastThreadLocalStorage | k64Bit
			| (uint64_t)(cpus & 0xff) << kNumCPUsShift;

	if (!__get_cpuid(1, &a, &b, &c, &d)) {
		return caps;
	}
	struct {
		unsigned reg;
		unsigned bit;
		uint64_t cap;
	} leaf1[] = {
			{d, bit_MMX, kHasMMX},
			{d, bit_SSE, kHasSSE},
			{d, bit_SSE2, kHasSSE2},
			{c, bit_SSE3, kHasSSE3},
			{c, bit_SSSE3, kHasSupplementalSSE3},
			{c, bit_SSE4_1, kHasSSE4_1},
			{c, bit_SSE4_2, kHasSSE4_2},
			{c, bit_AES, kHasAES},
			{c, bit_RDRND, kHasRDRAND},
			{c, bit_F16C, kHasF16C},
			{c, bit_FMA, kHasFMA},
	};
	for (size_t i = 0; i < sizeof(leaf1) / sizeof(leaf1[0]); i++) {
		if (leaf1[i].reg & leaf1[i].bit) {
			caps |= leaf1[i].cap;
		}
	}
	bool avx = (c & bit_OSXSAVE) && (c & bit_AVX) && (xcr0() & 6) == 6;
	if (avx) {
		caps |= kHasAVX1_0;
	} else {
		caps &= ~(kHasF16C | kHasFMA);
	}
	if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) {
		struct {
			unsigned bit;
			uint64_t cap;
			bool needs_avx;
		} leaf7[] = {
				{bit_BMI, kHasBMI1, false},
				{bit_BMI2, kHasBMI2, false},
				{1u << 9, kHasENFSTRG, false},
				{bit_RTM, kHasRTM, false},
				{bit_HLE, kHasHLE, false},
				{bit_ADX, kHasADX, false},
				{bit_RDSEED, kHasRDSEED, false},
				{bit_AVX2, kHasAVX2_0, true},
		};
		for (size_t i = 0; i < sizeof(leaf7) / sizeof(leaf7[0]); i++) {
			if ((b & leaf7[i].bit)
					&& (avx || !leaf7[i].needs_avx)) {
				caps |= leaf7[i].cap;
			}
		}
		if (avx && (xcr0() & 0xe0) == 0xe0) {
			struct {
				unsigned bit;
				uint64_t cap;
			} avx512[] = {
					{bit_AVX512F, kHasAVX512F},
					{bit_AVX512CD, kHasAVX512CD},
					{bit_AVX512DQ, kHasAVX512DQ},
					{bit_AVX512BW, kHasAVX512BW},
					{bit_AVX512IFMA, kHasAVX512IFMA},
					{bit_AVX512VL, kHasAVX512VL},
			};
			for (size_t i = 0;
					i < sizeof(avx512) / sizeof(avx512[0]);
					i++) {
				if (b & avx512[i].bit) {
					caps |= avx512[i].cap;
				}
			}
			if (c & bit_AVX512VBMI) {
				caps |= kHasAVX512VBMI;
			}
		}
	}
	return caps;
}

static uint64_t
xcr0(void)
{
	uint32_t lo, hi;
	asm volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	return (uint64_t)hi << 32 | lo;
}

static uint64_t
sample_clocks(uint64_t *tsc)
{
	uint64_t before = __rdtsc();
	uint64_t now = monotonic_ns();
	uint64_t after = __rdtsc();

	*tsc = before + (after - before) / 2;
	return now;
}

#else /* __arm64__ */

static uint64_t counter(void);

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

#define COMM_PAGE_CNTVCT_TIMEBASE      1
#define COMM_PAGE_TIMEBASE_OFFSET       0x88
#define COMM_PAGE_TIMEBASE_TYPE        0x90
#define COMM_PAGE_BOOTTIME_USEC        0xa0
#define COMM_PAGE_CONT_HW_TIMEBASE      0xa8
#define COMM_PAGE_APPROX_TIME_SUPPORTED 0xc8
#define COMM_PAGE_NEWTIMEOFDAY_TICK    0x120
#define COMM_PAGE_APRR_SUPPORT         0x10c
#define COMM_PAGE_CPU_CAPABILITIES64   0x10
#define COMM_PAGE_CPU_CAPABILITIES     0x20

#define CAPABILITY_AMX_VERSION 0x78000000ULL

#define CAPABILITY_SME  (1ULL << 60)
#define CAPABILITY_SME2 (1ULL << 61)
#ifndef HWCAP2_SME
#define HWCAP2_SME (1UL << 23)
#endif

static const uintptr_t _COMM_PAGE_RO_ADDRESS = 0xfffff4000ULL;
static const uint8_t host_cpu_count = 14;
#define COMM_PAGE_RO_LOGICAL_CPUS  0x24
#define COMM_PAGE_RO_PHYSICAL_CPUS 0x25
#define COMM_PAGE_RO_ACTIVE_CPUS   0x37

static int map_fixed_page(uintptr_t address, size_t length, uint8_t **page);

static uint64_t boot_ticks;

static void
start_counting(struct timebase *base)
{
	base->boot_ticks = counter();
	base->boot_ns = monotonic_ns();
}

static uint64_t
counter(void)
{
	uint64_t ticks;
	asm volatile("isb\n"
		     "mrs %0, cntvct_el0"
			: "=r"(ticks));
	return ticks;
}

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
	struct timebase base;
	take_timebase(&base, start_counting);
	boot_ticks = base.boot_ticks;
	commpage[COMM_PAGE_TIMEBASE_TYPE] = COMM_PAGE_CNTVCT_TIMEBASE;
	*(uint64_t *)(commpage + COMM_PAGE_TIMEBASE_OFFSET) = -boot_ticks;
	*(uint64_t *)(commpage + COMM_PAGE_CONT_HW_TIMEBASE) = -boot_ticks;

	commpage[COMM_PAGE_APPROX_TIME_SUPPORTED] = 0;

	commpage[COMM_PAGE_APRR_SUPPORT] = 0;

	uint64_t *capabilities64
			= (uint64_t *)(commpage + COMM_PAGE_CPU_CAPABILITIES64);
	uint32_t *capabilities
			= (uint32_t *)(commpage + COMM_PAGE_CPU_CAPABILITIES);
	if (!(getauxval(AT_HWCAP2) & HWCAP2_SME)) {
		*capabilities64 &= ~(CAPABILITY_SME | CAPABILITY_SME2);
	}
	*capabilities64 &= ~CAPABILITY_AMX_VERSION;
	*capabilities &= ~(uint32_t)CAPABILITY_AMX_VERSION;
	*(uint64_t *)(commpage + COMM_PAGE_NEWTIMEOFDAY_TICK) = 0;
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	uint64_t uptime_ns = commpage_absolute_to_nanoseconds(
			commpage_absolute_time());
	*(uint64_t *)(commpage + COMM_PAGE_BOOTTIME_USEC)
			= ((uint64_t)now.tv_sec * 1000000000 + now.tv_nsec
					  - uptime_ns)
			/ 1000;

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
	return counter() - boot_ticks;
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

static uint64_t
monotonic_ns(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * 1000000000ULL + now.tv_nsec;
}
