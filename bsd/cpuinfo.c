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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpuinfo.h"

static struct host_cpu cpu;
static pthread_once_t once = PTHREAD_ONCE_INIT;

static void read_cpuinfo(void);
static uint64_t cpufreq_khz(const char *name);

const struct host_cpu *
host_cpu(void)
{
	pthread_once(&once, read_cpuinfo);
	return &cpu;
}

static void
read_cpuinfo(void)
{
	FILE *file = fopen("/proc/cpuinfo", "re");
	if (file == NULL) {
		return;
	}
	char line[512];
	int64_t last_package = -1;
	while (fgets(line, sizeof(line), file) != NULL) {
		char *value = strchr(line, ':');
		if (value == NULL) {
			continue;
		}
		value += value[1] == ' ' ? 2 : 1;
		value[strcspn(value, "\n")] = '\0';
		if (strncmp(line, "model name", 10) == 0
				&& cpu.brand[0] == '\0') {
			snprintf(cpu.brand, sizeof(cpu.brand), "%s", value);
		} else if (strncmp(line, "cpu cores", 9) == 0
				&& cpu.cores == 0) {
			cpu.cores = (uint32_t)strtoul(value, NULL, 10);
		} else if (strncmp(line, "physical id", 11) == 0) {
			int64_t package = strtoll(value, NULL, 10);
			if (package > last_package) {
				cpu.packages++;
				last_package = package;
			}
		}
	}
	fclose(file);
	uint64_t khz = cpufreq_khz("base_frequency");
	const char *at = strstr(cpu.brand, "@ ");
	if (khz != 0) {
		cpu.frequency = khz * 1000;
	} else if (at != NULL && strstr(at, "GHz") != NULL) {
		cpu.frequency = (uint64_t)(strtod(at + 2, NULL) * 1e9);
	} else {
		cpu.frequency = cpufreq_khz("cpuinfo_max_freq") * 1000;
	}
	cpu.cores *= cpu.packages != 0 ? cpu.packages : 1;
}

static uint64_t
cpufreq_khz(const char *name)
{
	char path[128];
	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu0/cpufreq/%s",
			name);
	FILE *file = fopen(path, "re");
	unsigned long long khz = 0;
	if (file != NULL) {
		if (fscanf(file, "%llu", &khz) != 1) {
			khz = 0;
		}
		fclose(file);
	}
	return khz;
}
