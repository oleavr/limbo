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

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "broker.h"
#include "process.h"

static void read_ids(FILE *status, const char *key, uint32_t ids[3]);
static uint64_t boot_time(void);
static ssize_t read_process_file(
		int32_t pid, const char *file, char *buffer, size_t size);
static ssize_t read_file(const char *name, char *buffer, size_t size);

int
process_lookup(int32_t pid, struct process *process)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	FILE *stat = fopen(path, "r");
	if (stat == NULL) {
		return 1;
	}
	char line[1024];
	char *fields = (fgets(line, sizeof(line), stat) != NULL)
			? strrchr(line, ')')
			: NULL;
	fclose(stat);
	if (fields == NULL) {
		return 1;
	}

	memset(process, 0, sizeof(*process));
	process->pid = pid;
	char *comm = strchr(line, '(') + 1;
	snprintf(process->comm, sizeof(process->comm), "%.*s",
			(int)(fields - comm), comm);
	long resident = 0;
	sscanf(fields + 2,
			"%*c %d %d %d %u %d %*u %*u %*u %*u %*u %lu %lu %*d "
			"%*d %*d %d %d %*d %lu %lu %ld",
			&process->ppid, &process->pgid, &process->session,
			&process->tty, &process->tpgid, &process->user_ticks,
			&process->system_ticks, &process->nice,
			&process->threads, &process->start_ticks,
			&process->virtual_size, &resident);
	process->resident_pages = resident > 0 ? (uint64_t)resident : 0;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	FILE *status = fopen(path, "r");
	if (status == NULL) {
		return 1;
	}
	read_ids(status, "Uid:", process->uid);
	read_ids(status, "Gid:", process->gid);
	fclose(status);
	return 0;
}

int32_t
process_terminal(const struct process *process)
{
	if (process->tty == 0) {
		return -1;
	}
	uint32_t major = (process->tty >> 8) & 0xfff;
	uint32_t minor = (process->tty & 0xff)
			| ((process->tty >> 12) & 0xfff00);
	return (int32_t)(major << 24 | minor);
}

void
process_start_time(const struct process *process, uint64_t *sec, uint64_t *usec)
{
	long ticks_per_second = sysconf(_SC_CLK_TCK);
	*sec = boot_time() + process->start_ticks / ticks_per_second;
	*usec = process->start_ticks % ticks_per_second * 1000000
			/ ticks_per_second;
}

uint64_t
process_ticks_to_nanoseconds(uint64_t ticks)
{
	return ticks * (1000000000 / (uint64_t)sysconf(_SC_CLK_TCK));
}

static void
read_ids(FILE *status, const char *key, uint32_t ids[3])
{
	char line[256];
	size_t key_length = strlen(key);
	while (fgets(line, sizeof(line), status) != NULL) {
		if (strncmp(line, key, key_length) == 0) {
			sscanf(line + key_length, "%u %u %u", &ids[0], &ids[1],
					&ids[2]);
			return;
		}
	}
}

static uint64_t
boot_time(void)
{
	FILE *stat = fopen("/proc/stat", "r");
	char line[256];
	uint64_t btime = 0;
	while (fgets(line, sizeof(line), stat) != NULL) {
		if (sscanf(line, "btime %lu", &btime) == 1) {
			break;
		}
	}
	fclose(stat);
	return btime;
}

bool
process_executable_path(int32_t pid, char *path)
{
	char arguments[PATH_MAX * 2];
	ssize_t size = read_process_file(
			pid, "cmdline", arguments, sizeof(arguments) - 1);
	if (size <= 0) {
		return false;
	}
	arguments[size] = '\0';
	size_t first = strlen(arguments) + 1;
	if ((ssize_t)first >= size) {
		return false;
	}
	return realpath(arguments + first, path) != NULL;
}

ssize_t
process_cmdline(int32_t pid, char *buffer, size_t size)
{
	return read_process_file(pid, "cmdline", buffer, size);
}

bool
process_environment_value(
		int32_t pid, const char *name, char *value, size_t size)
{
	size_t capacity = 64 * 1024;
	char *environment = malloc(capacity);
	ssize_t length = read_process_file(
			pid, "environ", environment, capacity - 1);
	if (length > 0) {
		environment[length] = '\0';
	}
	bool found = false;
	size_t name_length = strlen(name);
	for (char *entry = environment; !found && entry < environment + length;
			entry += strlen(entry) + 1) {
		if (strncmp(entry, name, name_length) == 0
				&& entry[name_length] == '=') {
			snprintf(value, size, "%s", entry + name_length + 1);
			found = true;
		}
	}
	free(environment);
	return found;
}

static ssize_t
read_process_file(int32_t pid, const char *file, char *buffer, size_t size)
{
	char name[32 + NAME_MAX];
	snprintf(name, sizeof(name), "/proc/%d/%s", (int)pid, file);
	ssize_t length = read_file(name, buffer, size);
	if (length != 0) {
		return length;
	}

	snprintf(name, sizeof(name), "/proc/%d/task", (int)pid);
	DIR *tasks = opendir(name);
	if (tasks == NULL) {
		return -1;
	}
	struct dirent *task;
	while (length <= 0 && (task = readdir(tasks)) != NULL) {
		if (task->d_name[0] == '.') {
			continue;
		}
		snprintf(name, sizeof(name), "/proc/%d/task/%s/%s", (int)pid,
				task->d_name, file);
		length = read_file(name, buffer, size);
	}
	closedir(tasks);
	return length;
}

static ssize_t
read_file(const char *name, char *buffer, size_t size)
{
	int fd = open(name, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return -1;
	}
	ssize_t length = read(fd, buffer, size);
	close(fd);
	return length;
}
