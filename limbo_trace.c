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
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trace_names.h"
#include "trace_reader.h"

#define NONE         UINT32_MAX
#define INDIRECT     0
#define ARM64_MDEP   0x80000000
#define X86_64_MDEP  3
#define NANOSECONDS  1000000000
#define LARGE_RESULT (1ULL << 32)
#define LENGTH(a)    (sizeof(a) / sizeof((a)[0]))

struct process {
	struct trace_file file;
	const char *name;
	uint64_t overwritten;
};

struct event {
	const struct trace_record *record;
	uint64_t time;
	uint32_t process;
	uint32_t ring;
	uint32_t link;
	bool printed;
};

static struct process *processes;
static uint32_t process_count;
static struct event *events;
static uint32_t event_count, event_capacity;
static uint32_t ring_count;
static bool resolved;

static void add_path(const char *path);
static bool add_file(const char *path);
static void collect(uint32_t process);
static uint32_t add_event(const struct trace_record *record, uint64_t time,
		uint32_t process, uint32_t ring);
static int compare(const void *a, const void *b);
static void print_event(uint32_t index);
static void print_start(const struct event *event);
static void print_call(uint32_t index);
static void print_return(const struct event *event);
static void print_string(const struct event *event);
static void print_prefix(const struct event *event, uint32_t tid);
static void print_arguments(const char *format, const uint64_t *arguments,
		size_t count, uint32_t index);
static void print_name(const struct event *event, uint32_t syscall_class,
		uint32_t number);
static uint32_t string_read_at(uint32_t index, uint64_t address);
static uint32_t next_string(uint32_t index, uint32_t after);
static void print_result(const struct trace_syscall_return *returned);
static const char *call_format(const struct event *event,
		uint32_t syscall_class, uint32_t number);

int
main(int argc, char *argv[])
{
	resolved = getopt(argc, argv, "r") == 'r';
	if (optind == argc) {
		fprintf(stderr, "Usage: limbo-trace [-r] path...\n");
		return 1;
	}
	for (int i = optind; i < argc; i++) {
		add_path(argv[i]);
	}
	for (uint32_t i = 0; i < process_count; i++) {
		collect(i);
	}

	uint32_t *order = malloc(event_count * sizeof(*order));
	for (uint32_t i = 0; i < event_count; i++) {
		order[i] = i;
	}
	qsort(order, event_count, sizeof(*order), compare);
	for (uint32_t i = 0; i < event_count; i++) {
		print_event(order[i]);
	}
	return 0;
}

static void
add_path(const char *path)
{
	struct dirent **entries;
	int count = scandir(path, &entries, NULL, versionsort);
	if (count == -1) {
		if (!add_file(path)) {
			fprintf(stderr, "limbo-trace: %s is not a trace\n",
					path);
			exit(1);
		}
		return;
	}
	for (int i = 0; i < count; i++) {
		char *file;
		asprintf(&file, "%s/%s", path, entries[i]->d_name);
		add_file(file);
	}
}

static bool
add_file(const char *path)
{
	struct trace_file file;
	if (trace_file_open(&file, path) == -1) {
		return false;
	}
	const char *slash = strrchr(file.header->program, '/');
	processes = realloc(
			processes, (process_count + 1) * sizeof(*processes));
	processes[process_count++] = (struct process){
			.file = file,
			.name
			= slash != NULL ? slash + 1 : file.header->program,
	};
	return true;
}

static void
collect(uint32_t process)
{
	const struct trace_file *file = &processes[process].file;
	add_event(NULL, file->header->start, process, NONE);

	for (uint32_t i = 0; i < TRACE_RING_COUNT; i++) {
		struct trace_run run = trace_ring_copy(file, i);
		processes[process].overwritten += run.start;
		uint32_t ring = ring_count++;
		uint32_t open = NONE;
		uint64_t position = run.start;
		const struct trace_record *record;
		while ((record = trace_run_next(&run, &position)) != NULL) {
			uint32_t added = add_event(
					record, record->time, process, ring);
			if (open != NONE
					&& events[open].record->tid
							!= record->tid) {
				open = NONE;
			}
			if (record->type == TRACE_SYSCALL_ENTER) {
				open = added;
			} else if (record->type == TRACE_STRING) {
				events[added].link = open;
			} else if (open != NONE) {
				events[added].link = open;
				events[open].link = added;
				open = NONE;
			}
		}
	}
}

static uint32_t
add_event(const struct trace_record *record, uint64_t time, uint32_t process,
		uint32_t ring)
{
	if (event_count == event_capacity) {
		event_capacity = 2 * event_capacity + 1024;
		events = realloc(events, event_capacity * sizeof(*events));
	}
	events[event_count] = (struct event){
			.record = record,
			.time = time,
			.process = process,
			.ring = ring,
			.link = NONE,
	};
	return event_count++;
}

static int
compare(const void *a, const void *b)
{
	uint32_t first = *(const uint32_t *)a, second = *(const uint32_t *)b;
	if (events[first].time != events[second].time) {
		return events[first].time < events[second].time ? -1 : 1;
	}
	return first < second ? -1 : 1;
}

static void
print_event(uint32_t index)
{
	const struct event *event = &events[index];
	bool linked = event->link != NONE;
	if (event->record == NULL) {
		print_start(event);
	} else if (event->record->type == TRACE_SYSCALL_ENTER) {
		print_call(index);
	} else if (event->record->type == TRACE_SYSCALL_RETURN && !linked) {
		print_return(event);
	} else if (event->record->type == TRACE_STRING && !linked) {
		print_string(event);
	}
}

static void
print_start(const struct event *event)
{
	const struct process *process = &processes[event->process];
	const struct trace_header *header = process->file.header;
	print_prefix(event, header->pid);
	printf("+++ started by %d: %s", header->parent, header->program);
	for (size_t i = 0; i < header->arguments_size;
			i += strlen(header->arguments + i) + 1) {
		printf(" %s", header->arguments + i);
	}
	if (process->overwritten != 0) {
		printf(" (%" PRIu64 " bytes of records overwritten)",
				process->overwritten);
	}
	if (header->dropped != 0) {
		printf(" (%" PRIu64 " records dropped)", header->dropped);
	}
	printf(" +++\n");
}

static void
print_call(uint32_t index)
{
	const struct event *event = &events[index];
	const struct trace_syscall_enter *enter = (const void *)event->record;
	uint32_t number = enter->number;
	const uint64_t *arguments = enter->arguments;
	size_t count = LENGTH(enter->arguments);
	print_prefix(event, enter->record.tid);
	if (enter->syscall_class == TRACE_CLASS_BSD && number == INDIRECT) {
		printf("indirect ");
		number = *arguments++;
		count--;
	}

	const char *format = call_format(event, enter->syscall_class, number);
	if (format != NULL) {
		print_arguments(format, arguments, count, index);
	} else {
		print_name(event, enter->syscall_class, number);
		print_arguments("(%p, %p, %p, %p, %p, %p)", arguments, count,
				index);
	}
	bool listed = false;
	for (uint32_t i = next_string(index, index); i != NONE;
			i = next_string(index, i)) {
		const struct trace_string *string
				= (const void *)events[i].record;
		if (!events[i].printed) {
			printf("%s\"%s\"", listed ? ", " : " {", string->bytes);
			listed = true;
		}
	}
	if (listed) {
		printf("}");
	}

	if (event->link == NONE) {
		printf(" ...\n");
		return;
	}
	const struct trace_syscall_return *returned
			= (const void *)events[event->link].record;
	uint64_t duration = returned->record.time - enter->record.time;
	print_result(returned);
	printf(" <%" PRIu64 ".%06" PRIu64 ">", duration / NANOSECONDS,
			duration % NANOSECONDS / 1000);
	for (uint32_t i = next_string(index, index); resolved && i != NONE;
			i = next_string(index, i)) {
		const struct trace_string *string
				= (const void *)events[i].record;
		if (string->host_size != 0) {
			printf(" [%s -> %s]", string->bytes,
					string->bytes + string->size + 1);
		}
	}
	printf("\n");
}

static void
print_return(const struct event *event)
{
	const struct trace_syscall_return *returned
			= (const void *)event->record;
	print_prefix(event, returned->record.tid);
	printf("... ");
	print_name(event, returned->syscall_class, returned->number);
	print_result(returned);
	printf("\n");
}

static void
print_string(const struct event *event)
{
	const struct trace_string *string = (const void *)event->record;
	print_prefix(event, string->record.tid);
	printf("\"%s\"", string->bytes);
	if (string->host_size != 0) {
		printf(" -> \"%s\"", string->bytes + string->size + 1);
	}
	printf("\n");
}

static void
print_prefix(const struct event *event, uint32_t tid)
{
	const struct process *process = &processes[event->process];
	uint32_t pid = process->file.header->pid;
	printf("%6" PRIu64 ".%06" PRIu64 " %s[%u", event->time / NANOSECONDS,
			event->time % NANOSECONDS / 1000, process->name, pid);
	if (tid != pid) {
		printf("/%u", tid);
	}
	printf("] ");
}

static void
print_arguments(const char *format, const uint64_t *arguments, size_t count,
		uint32_t index)
{
	size_t used = 0;
	for (const char *c = format; *c != '\0'; c++) {
		if (*c != '%') {
			putchar(*c);
			continue;
		}
		bool wide = false;
		for (c++; *c == '#' || *c == 'l'; c++) {
			wide |= *c == 'l';
		}
		uint64_t value = used < count ? arguments[used] : 0;
		uint32_t string = *c == 's' ? string_read_at(index, value)
					    : NONE;
		if (string != NONE) {
			printf("%s",
					((const struct trace_string *)events[string]
									.record)
							->bytes);
			events[string].printed = true;
		} else if (used >= count) {
			printf("?");
		} else if (*c == 'd') {
			printf("%" PRId64,
					wide ? (int64_t)value : (int32_t)value);
		} else if (*c == 'u') {
			printf("%" PRIu64, wide ? value : (uint32_t)value);
		} else {
			printf("%#" PRIx64,
					*c == 'x' && !wide ? (uint32_t)value
							   : value);
		}
		used++;
	}
}

static void
print_name(const struct event *event, uint32_t syscall_class, uint32_t number)
{
	static const char *const classes[] = {
			[TRACE_CLASS_MACH] = "mach",
			[TRACE_CLASS_BSD] = "bsd",
			[TRACE_CLASS_MDEP] = "mdep",
	};
	const char *format = call_format(event, syscall_class, number);
	if (format != NULL) {
		printf("%.*s", (int)strcspn(format, "("), format);
	} else {
		printf("%s#%u", classes[syscall_class], number);
	}
}

static uint32_t
string_read_at(uint32_t index, uint64_t address)
{
	for (uint32_t i = next_string(index, index); i != NONE;
			i = next_string(index, i)) {
		const struct trace_string *string
				= (const void *)events[i].record;
		if (string->address == address && !events[i].printed) {
			return i;
		}
	}
	return NONE;
}

static uint32_t
next_string(uint32_t index, uint32_t after)
{
	uint32_t end = events[index].link != NONE ? events[index].link
						  : event_count;
	for (uint32_t i = after + 1;
			i < end && events[i].ring == events[index].ring; i++) {
		if (events[i].link == index) {
			return i;
		}
	}
	return NONE;
}

static void
print_result(const struct trace_syscall_return *returned)
{
	int64_t result = returned->result;
	switch (returned->outcome) {
	case TRACE_RESULT:
		if (result < 0 && result > -(int64_t)LENGTH(error_names)) {
			printf(" = -1 %s", error_names[-result]);
		} else if ((uint64_t)result < LARGE_RESULT) {
			printf(" = %" PRId64, result);
		} else {
			printf(" = %#" PRIx64, (uint64_t)result);
		}
		break;
	case TRACE_RAW_RESULT:
		printf(" = %#" PRIx64, (uint64_t)result);
		break;
	case TRACE_KEPT_CONTEXT:
		printf(" = ? (context replaced)");
		break;
	case TRACE_RESTARTED:
		printf(" = ? (restarted)");
		break;
	}
}

static const char *
call_format(const struct event *event, uint32_t syscall_class, uint32_t number)
{
	uint32_t arch = processes[event->process].file.header->arch;
	uint32_t mdep = arch == TRACE_ARCH_ARM64 ? ARM64_MDEP : X86_64_MDEP;
	switch (syscall_class) {
	case TRACE_CLASS_BSD:
		return number < LENGTH(bsd_calls) ? bsd_calls[number] : NULL;
	case TRACE_CLASS_MACH:
		return number < LENGTH(mach_calls) ? mach_calls[number] : NULL;
	default:
		return number == mdep ? mdep_call : NULL;
	}
}
