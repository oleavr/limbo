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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "broker_jetsam.h"

#define JETSAM_PRIORITY_AGING_BAND1 10
#define JETSAM_PRIORITY_FOREGROUND  100
#define JETSAM_PRIORITY_MAX         210

#define PRESSURE_PERCENT 30
#define CRITICAL_PERCENT 15
#define CRITICAL_STALL   20
#define TICK_MS          250
#define SETTLE_MS        1000

struct band_member {
	pid_t pid;
	int32_t priority;
	uint64_t since;
	unsigned long long start;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct band_member *members;
static size_t member_count, member_capacity;

static struct band_member *find(pid_t pid);
static void forget_at(size_t i);
static bool is_guest(pid_t pid);
static unsigned long long start_time(pid_t pid);
static uint64_t now_ns(void);
static void set_oom_score_adj(pid_t pid, int32_t priority);
static void *watch(void *unused);
static bool memory(unsigned long long *total, unsigned long long *available);
static double memory_stall(void);
static bool choose(int32_t limit, struct band_member *chosen);
static bool ranks_lower(
		const struct band_member *a, const struct band_member *b);
static void command_of(pid_t pid, char *command, size_t size);

void
jetsam_set_priority(pid_t pid, int32_t priority)
{
	if (pid <= 0) {
		return;
	}
	pthread_mutex_lock(&lock);
	struct band_member *member = find(pid);
	if (priority < 0 || priority > JETSAM_PRIORITY_MAX) {
		bool known = member != NULL;
		if (known) {
			forget_at((size_t)(member - members));
		}
		pthread_mutex_unlock(&lock);
		if (known) {
			set_oom_score_adj(pid, -1);
		}
		return;
	}
	if (member == NULL) {
		if (!is_guest(pid)) {
			pthread_mutex_unlock(&lock);
			return;
		}
		if (member_count == member_capacity) {
			size_t capacity = member_capacity == 0
					? 64
					: member_capacity * 2;
			struct band_member *grown = realloc(
					members, capacity * sizeof(*grown));
			if (grown == NULL) {
				pthread_mutex_unlock(&lock);
				return;
			}
			members = grown;
			member_capacity = capacity;
		}
		member = &members[member_count++];
		*member = (struct band_member){.pid = pid, .priority = -1};
		member->start = start_time(pid);
	}
	if (member->priority != priority) {
		member->priority = priority;
		member->since = now_ns();
	}
	pthread_mutex_unlock(&lock);
	set_oom_score_adj(pid, priority);
}

void
jetsam_start(void)
{
	pthread_t thread;
	if (pthread_create(&thread, NULL, watch, NULL) == 0) {
		pthread_detach(thread);
	}
}

static struct band_member *
find(pid_t pid)
{
	for (size_t i = 0; i < member_count; i++) {
		if (members[i].pid == pid) {
			return &members[i];
		}
	}
	return NULL;
}

static void
forget_at(size_t i)
{
	members[i] = members[--member_count];
}

static bool
is_guest(pid_t pid)
{
	char path[64], target[PATH_MAX];
	snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
	ssize_t n = readlink(path, target, sizeof(target) - 1);
	if (n <= 0) {
		return false;
	}
	target[n] = '\0';
	const char *name = strrchr(target, '/');
	return strcmp(name != NULL ? name + 1 : target, "limbo") == 0;
}

static unsigned long long
start_time(pid_t pid)
{
	char path[64], line[1024];
	snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		return 0;
	}
	bool read = fgets(line, sizeof(line), file) != NULL;
	fclose(file);
	char *field = read ? strrchr(line, ')') : NULL;
	unsigned long long start = 0;
	if (field != NULL) {
		field += 2;
		for (int i = 3; i < 22 && field != NULL; i++) {
			field = strchr(field, ' ');
			if (field != NULL) {
				field++;
			}
		}
		if (field != NULL) {
			start = strtoull(field, NULL, 10);
		}
	}
	return start;
}

static uint64_t
now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void
set_oom_score_adj(pid_t pid, int32_t priority)
{
	int adj = priority < 0 ? 0
			       : 1000 - priority * 1000 / JETSAM_PRIORITY_MAX;
	char path[64], value[16];
	snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", (int)pid);
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd != -1) {
		int n = snprintf(value, sizeof(value), "%d", adj);
		(void)!write(fd, value, (size_t)n);
		close(fd);
	}
}

static void *
watch(void *unused)
{
	(void)unused;
	for (;;) {
		usleep(TICK_MS * 1000);
		unsigned long long total, available;
		if (!memory(&total, &available)) {
			continue;
		}
		unsigned long long percent = available * 100 / total;
		double stall = memory_stall();
		int32_t limit;
		if (percent < CRITICAL_PERCENT || stall >= CRITICAL_STALL) {
			limit = JETSAM_PRIORITY_FOREGROUND;
		} else if (percent < PRESSURE_PERCENT) {
			limit = JETSAM_PRIORITY_AGING_BAND1 + 1;
		} else {
			continue;
		}
		struct band_member chosen;
		pthread_mutex_lock(&lock);
		bool found = choose(limit, &chosen);
		if (found) {
			forget_at((size_t)(find(chosen.pid) - members));
		}
		pthread_mutex_unlock(&lock);
		if (!found) {
			continue;
		}
		char command[32];
		command_of(chosen.pid, command, sizeof(command));
		if (kill(chosen.pid, SIGKILL) == 0) {
			fprintf(stderr,
					"limbo-broker: jetsam: ended %d (%s), "
					"band "
					"%d, %llu MiB available (%llu%%), "
					"%.0f%% "
					"stalled\n",
					(int)chosen.pid, command,
					chosen.priority, available / 1024,
					percent, stall);
		}
		usleep(SETTLE_MS * 1000);
	}
	return NULL;
}

static bool
memory(unsigned long long *total, unsigned long long *available)
{
	FILE *file = fopen("/proc/meminfo", "r");
	if (file == NULL) {
		return false;
	}
	unsigned long long mem_total = 0, mem_available = 0, swap_free = 0;
	char line[128];
	while (fgets(line, sizeof(line), file) != NULL) {
		sscanf(line, "MemTotal: %llu", &mem_total);
		sscanf(line, "MemAvailable: %llu", &mem_available);
		sscanf(line, "SwapFree: %llu", &swap_free);
	}
	fclose(file);
	*total = mem_total;
	*available = mem_available + swap_free / 2;
	return mem_total != 0;
}

static double
memory_stall(void)
{
	FILE *file = fopen("/proc/pressure/memory", "r");
	double some = 0;
	if (file != NULL) {
		if (fscanf(file, "some avg10=%lf", &some) != 1) {
			some = 0;
		}
		fclose(file);
	}
	return some;
}

static bool
choose(int32_t limit, struct band_member *chosen)
{
	bool found = false;
	for (size_t i = 0; i < member_count;) {
		struct band_member *m = &members[i];
		if (start_time(m->pid) != m->start) {
			forget_at(i);
			continue;
		}
		if (m->priority < limit && (!found || ranks_lower(m, chosen))) {
			*chosen = *m;
			found = true;
		}
		i++;
	}
	return found;
}

static bool
ranks_lower(const struct band_member *a, const struct band_member *b)
{
	return a->priority < b->priority
			|| (a->priority == b->priority && a->since < b->since);
}

static void
command_of(pid_t pid, char *command, size_t size)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
	FILE *file = fopen(path, "r");
	command[0] = '\0';
	if (file != NULL) {
		if (fgets(command, (int)size, file) != NULL) {
			command[strcspn(command, "\n")] = '\0';
		}
		fclose(file);
	}
}
