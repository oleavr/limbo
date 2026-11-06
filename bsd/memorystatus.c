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

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "memorystatus.h"

#define WARN_BELOW     100
#define CRITICAL_BELOW 50
#define NORMAL_ABOVE   150
#define WARN_ABOVE     70

static unsigned int ram_free(void);
static uint32_t next_level(uint32_t level, unsigned int free);

uint32_t
memorystatus_level(void)
{
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	static uint32_t level = MEMORYSTATUS_NORMAL;
	static struct timespec last;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	pthread_mutex_lock(&lock);
	if (last.tv_sec == 0 || now.tv_sec - last.tv_sec >= 1) {
		last = now;
		level = next_level(level, ram_free());
	}
	uint32_t current = level;
	pthread_mutex_unlock(&lock);
	return current;
}

unsigned int
memorystatus_free_share(void)
{
	return ram_free();
}

static uint32_t
next_level(uint32_t level, unsigned int free)
{
	switch (level) {
	case MEMORYSTATUS_NORMAL:
		if (free < CRITICAL_BELOW) {
			return MEMORYSTATUS_CRITICAL;
		}
		return free < WARN_BELOW ? MEMORYSTATUS_WARN : level;
	case MEMORYSTATUS_WARN:
		if (free < CRITICAL_BELOW) {
			return MEMORYSTATUS_CRITICAL;
		}
		return free > NORMAL_ABOVE ? MEMORYSTATUS_NORMAL : level;
	default:
		if (free > NORMAL_ABOVE) {
			return MEMORYSTATUS_NORMAL;
		}
		return free > WARN_ABOVE ? MEMORYSTATUS_WARN : level;
	}
}

static unsigned int
ram_free(void)
{
	unsigned long long total = 0, available = 0;
	FILE *meminfo = fopen("/proc/meminfo", "r");
	char line[256];
	while (fgets(line, sizeof(line), meminfo) != NULL) {
		sscanf(line, "MemTotal: %llu kB", &total);
		sscanf(line, "MemAvailable: %llu kB", &available);
	}
	fclose(meminfo);
	return (unsigned int)(available * 1000 / total);
}
