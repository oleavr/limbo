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

#include <dirent.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"
#include "trace.h"
#include "trace_reader.h"

#define THREADS     8
#define PER_THREAD  20000
#define SHORT_LIVED 600
#define RING_SIZE   131072

static char directory[PATH_MAX];
static pthread_barrier_t started;

static void test_records(void);
static void test_wrap(void);
static void test_threads(void);
static void *record_many(void *argument);
static void test_short_lived_threads(void);
static void *record_one(void *argument);
static void test_fork(void);
static void test_exec(const char *self);
static void remove_trace(void);
static void open_trace(struct trace_file *file, pid_t pid, unsigned image);
static uint64_t count_calls(const struct trace_file *file, uint32_t ring,
		uint32_t syscall_class);

int
main(int argc, char *argv[])
{
	if (argc > 1) {
		trace_start("/second", argv);
		trace_path("/second", "/image");
		return 0;
	}

	const uint64_t arguments[6] = {0};
	trace_syscall_enter(TRACE_CLASS_BSD, 1, arguments);

	snprintf(directory, sizeof(directory), "trace_test.XXXXXX");
	CHECK(mkdtemp(directory) != NULL);
	setenv("LIMBO_TRACE", directory, 1);
	setenv("LIMBO_TRACE_SIZE", "100000", 1);
	char *first_arguments[] = {"first", "second argument", NULL};
	trace_start("/bin/program", first_arguments);

	test_records();
	test_wrap();
	test_threads();
	test_short_lived_threads();
	test_fork();
	test_exec(argv[0]);
	remove_trace();
	return 0;
}

static void
test_records(void)
{
	const uint64_t arguments[6] = {1, 2, 3, 4, 5, UINT64_MAX};
	const char *guest = "/guest", *name = "name";
	trace_syscall_enter(TRACE_CLASS_BSD, 5, arguments);
	trace_path(guest, "/sysroot/guest");
	trace_string(name);
	trace_syscall_return(TRACE_CLASS_BSD, 5, -2, TRACE_RESULT);

	struct trace_file file;
	open_trace(&file, getpid(), 0);
	const struct trace_header *header = file.header;
	CHECK(header->parent == getppid());
	CHECK(header->start != 0);
	CHECK(header->ring_size == RING_SIZE);
	CHECK(strcmp(header->program, "/bin/program") == 0);
	CHECK(header->arguments_size == sizeof("first\0second argument"));
	CHECK(memcmp(header->arguments, "first\0second argument",
			      header->arguments_size)
			== 0);
	CHECK(header->dropped == 0);

	struct trace_run run = trace_ring_copy(&file, 0);
	CHECK(run.start == 0);
	uint64_t position = 0;

	const struct trace_syscall_enter *enter
			= (const void *)trace_run_next(&run, &position);
	CHECK(enter->record.type == TRACE_SYSCALL_ENTER);
	CHECK(enter->record.size == sizeof(*enter));
	CHECK(enter->record.tid == (uint32_t)gettid());
	CHECK(enter->record.time >= header->start);
	CHECK(enter->syscall_class == TRACE_CLASS_BSD && enter->number == 5);
	CHECK(memcmp(enter->arguments, arguments, sizeof(arguments)) == 0);

	const struct trace_string *string
			= (const void *)trace_run_next(&run, &position);
	CHECK(string->record.type == TRACE_STRING);
	CHECK(string->address == (uintptr_t)guest);
	CHECK(string->size == strlen(guest));
	CHECK(string->host_size == strlen("/sysroot/guest"));
	CHECK(strcmp(string->bytes, guest) == 0);
	CHECK(strcmp(string->bytes + string->size + 1, "/sysroot/guest") == 0);

	string = (const void *)trace_run_next(&run, &position);
	CHECK(string->record.type == TRACE_STRING);
	CHECK(string->address == (uintptr_t)name);
	CHECK(strcmp(string->bytes, name) == 0);
	CHECK(string->host_size == 0);

	const struct trace_syscall_return *returned
			= (const void *)trace_run_next(&run, &position);
	CHECK(returned->record.type == TRACE_SYSCALL_RETURN);
	CHECK(returned->record.time >= enter->record.time);
	CHECK(returned->number == 5 && returned->result == -2);
	CHECK(returned->outcome == TRACE_RESULT);

	CHECK(trace_run_next(&run, &position) == NULL);
	CHECK(position == run.end);
	free(run.bytes);
	trace_file_close(&file);
}

static void
test_wrap(void)
{
	uint64_t fit = RING_SIZE / sizeof(struct trace_syscall_enter);
	uint64_t arguments[6] = {0};
	for (uint64_t i = 0; i < 3 * fit; i++) {
		trace_syscall_enter(TRACE_CLASS_MACH, i, arguments);
		if (i % 5 == 0) {
			trace_path("/a/path/of/some/length", "/another");
		}
	}

	struct trace_file file;
	open_trace(&file, getpid(), 0);
	struct trace_run run = trace_ring_copy(&file, 0);
	CHECK(run.start != 0 && run.start % TRACE_BLOCK_SIZE == 0);
	CHECK(run.end - run.start <= RING_SIZE);
	CHECK(run.end - run.start > RING_SIZE - 3 * TRACE_BLOCK_SIZE);
	uint64_t position = run.start, last = 0;
	const struct trace_record *record;
	while ((record = trace_run_next(&run, &position)) != NULL) {
		if (record->type == TRACE_SYSCALL_ENTER) {
			last = ((const struct trace_syscall_enter *)record)
					       ->number;
		}
	}
	CHECK(position == run.end);
	CHECK(last == 3 * fit - 1);
	free(run.bytes);
	CHECK(count_calls(&file, 0, TRACE_CLASS_MACH) > fit / 2);
	trace_file_close(&file);
}

static void
test_threads(void)
{
	char path[PATH_MAX + 32];
	snprintf(path, sizeof(path), "%s/%d.0", directory, getpid());
	CHECK(chmod(path, 0444) == 0);
	pthread_t threads[THREADS];
	CHECK(pthread_barrier_init(&started, NULL, THREADS) == 0);
	for (int i = 0; i < THREADS; i++) {
		CHECK(pthread_create(&threads[i], NULL, record_many, NULL)
				== 0);
	}
	for (int i = 0; i < THREADS; i++) {
		CHECK(pthread_join(threads[i], NULL) == 0);
	}

	struct trace_file file;
	open_trace(&file, getpid(), 0);
	uint64_t fit = RING_SIZE / sizeof(struct trace_syscall_enter);
	for (uint32_t ring = 1; ring <= THREADS; ring++) {
		uint64_t calls = count_calls(&file, ring, TRACE_CLASS_BSD);
		CHECK(calls > fit / 2 && calls <= PER_THREAD);
	}
	CHECK(file.header->dropped == 0);
	trace_file_close(&file);
}

static void *
record_many(void *argument)
{
	uint64_t arguments[6] = {0};
	for (uint64_t i = 0; i < PER_THREAD; i++) {
		trace_syscall_enter(TRACE_CLASS_BSD, i, arguments);
		if (i == 0) {
			pthread_barrier_wait(&started);
		}
	}
	return NULL;
}

static void
test_short_lived_threads(void)
{
	for (int i = 0; i < SHORT_LIVED; i++) {
		pthread_t thread;
		CHECK(pthread_create(&thread, NULL, record_one, NULL) == 0);
		CHECK(pthread_join(thread, NULL) == 0);
	}
	struct trace_file file;
	open_trace(&file, getpid(), 0);
	CHECK(file.header->dropped == 0);
	trace_file_close(&file);
}

static void *
record_one(void *argument)
{
	trace_path("/short", "/lived");
	return NULL;
}

static void
test_fork(void)
{
	const uint64_t arguments[6] = {0};
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		trace_fork_child();
		trace_syscall_enter(TRACE_CLASS_MDEP, 4242, arguments);
		_exit(0);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child && status == 0);

	struct trace_file file;
	open_trace(&file, child, 0);
	CHECK(file.header->parent == getpid());
	CHECK(strcmp(file.header->program, "/bin/program") == 0);
	struct trace_run run = trace_ring_copy(&file, 0);
	uint64_t position = 0;
	const struct trace_syscall_enter *enter
			= (const void *)trace_run_next(&run, &position);
	CHECK(enter->number == 4242 && enter->record.tid == (uint32_t)child);
	CHECK(trace_run_next(&run, &position) == NULL);
	free(run.bytes);
	trace_file_close(&file);

	open_trace(&file, getpid(), 0);
	CHECK(count_calls(&file, 0, TRACE_CLASS_MDEP) == 0);
	trace_file_close(&file);
}

static void
test_exec(const char *self)
{
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		trace_fork_child();
		execl(self, self, "second", NULL);
		_exit(1);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child && status == 0);

	struct trace_file file;
	open_trace(&file, child, 0);
	CHECK(strcmp(file.header->program, "/bin/program") == 0);
	trace_file_close(&file);
	open_trace(&file, child, 1);
	CHECK(strcmp(file.header->program, "/second") == 0);
	struct trace_run run = trace_ring_copy(&file, 0);
	uint64_t position = 0;
	CHECK(trace_run_next(&run, &position)->type == TRACE_STRING);
	free(run.bytes);
	trace_file_close(&file);
}

static void
remove_trace(void)
{
	DIR *entries = opendir(directory);
	struct dirent *entry;
	while ((entry = readdir(entries)) != NULL) {
		unlinkat(dirfd(entries), entry->d_name, 0);
	}
	closedir(entries);
	CHECK(rmdir(directory) == 0);
}

static void
open_trace(struct trace_file *file, pid_t pid, unsigned image)
{
	char path[PATH_MAX + 32];
	snprintf(path, sizeof(path), "%s/%d.%u", directory, pid, image);
	CHECK(trace_file_open(file, path) == 0);
	CHECK(file->header->pid == pid);
}

static uint64_t
count_calls(const struct trace_file *file, uint32_t ring,
		uint32_t syscall_class)
{
	struct trace_run run = trace_ring_copy(file, ring);
	uint64_t position = run.start, calls = 0, expected = 0;
	const struct trace_record *record;
	while ((record = trace_run_next(&run, &position)) != NULL) {
		const struct trace_syscall_enter *enter = (const void *)record;
		if (record->type != TRACE_SYSCALL_ENTER
				|| enter->syscall_class != syscall_class) {
			continue;
		}
		CHECK(calls == 0 || enter->number == expected);
		expected = enter->number + 1;
		calls++;
	}
	free(run.bytes);
	return calls;
}
