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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsd/responsibility.h"
#include "check.h"

#define ASKED       5001
#define RESPONSIBLE 5002
#define STARTED     100

static struct process *find(int32_t pid);
static void check_named(void);
static void check_taken(void);
static bool leads(const char *variable);
static void check_another(void);
static void check_malformed(void);
static void check_gone(void);
static int32_t said(const char *value);

extern char **environ;
static struct process processes[3];
static const char *environment;

int
main(void)
{
	processes[0] = (struct process){
			.pid = getpid(), .state = 'R', .start_ticks = STARTED};
	processes[1] = (struct process){
			.pid = ASKED, .state = 'S', .start_ticks = STARTED + 1};
	processes[2] = (struct process){.pid = RESPONSIBLE,
			.state = 'S',
			.start_ticks = STARTED + 2};

	check_named();
	check_taken();
	check_another();
	check_malformed();
	check_gone();
	return 0;
}

int
process_lookup(int32_t pid, struct process *process)
{
	const struct process *found = find(pid);
	if (found == NULL) {
		return 1;
	}
	*process = *found;
	return 0;
}

bool
process_exited(const struct process *process)
{
	return process->state == 'Z';
}

bool
process_environment_value(
		int32_t pid, const char *name, char *value, size_t size)
{
	CHECK(pid == ASKED && strcmp(name, RESPONSIBILITY_VARIABLE) == 0);
	if (environment == NULL) {
		return false;
	}
	snprintf(value, size, "%s", environment);
	return true;
}

static struct process *
find(int32_t pid)
{
	for (size_t i = 0; i != sizeof(processes) / sizeof(processes[0]); i++) {
		if (processes[i].pid == pid) {
			return &processes[i];
		}
	}
	return NULL;
}

static void
check_named(void)
{
	CHECK(unsetenv(RESPONSIBILITY_VARIABLE) == 0);
	CHECK(!responsibility_named());
	CHECK(responsibility_of(find(getpid())) == getpid());
	CHECK(setenv(RESPONSIBILITY_VARIABLE, "", 1) == 0);
	CHECK(!responsibility_named());
	CHECK(setenv(RESPONSIBILITY_VARIABLE, "5002:102", 1) == 0);
	CHECK(responsibility_named());
	CHECK(responsibility_of(find(getpid())) == RESPONSIBLE);
	CHECK(setenv(RESPONSIBILITY_VARIABLE, "5002:103", 1) == 0);
	CHECK(responsibility_named());
	CHECK(responsibility_of(find(getpid())) == getpid());
	CHECK(setenv(RESPONSIBILITY_VARIABLE, "1:1", 1) == 0);
	CHECK(responsibility_named());
	CHECK(responsibility_of(find(getpid())) == getpid());
}

static void
check_taken(void)
{
	char value[64];
	snprintf(value, sizeof(value), RESPONSIBILITY_VARIABLE "=%d:%d",
			getpid(), STARTED);
	CHECK(setenv("OTHER", "1", 1) == 0);
	CHECK(setenv(RESPONSIBILITY_VARIABLE, "5002:", 1) == 0);
	CHECK(leads(value));
	CHECK(unsetenv(RESPONSIBILITY_VARIABLE) == 0);
	CHECK(leads(value));
	CHECK(setenv(RESPONSIBILITY_VARIABLE, "5002:102", 1) == 0);
	CHECK(leads(RESPONSIBILITY_VARIABLE "=5002:102"));
	CHECK(unsetenv(RESPONSIBILITY_VARIABLE) == 0);
	processes[0].pid = 0;
	CHECK(responsibility_environment(environ) == NULL);
	processes[0].pid = getpid();
}

static bool
leads(const char *variable)
{
	char **taken = responsibility_environment(environ);
	CHECK(taken != NULL);
	size_t naming = 0;
	bool other = false;
	for (char **entry = taken; *entry != NULL; entry++) {
		naming += responsibility_names(*entry);
		other = other || strcmp(*entry, "OTHER=1") == 0;
	}
	bool led = strcmp(taken[0], variable) == 0 && naming == 1 && other;
	free(taken);
	return led;
}

static void
check_another(void)
{
	char value[64];
	environment = NULL;
	CHECK(responsibility_of(find(ASKED)) == ASKED);
	CHECK(said("5002:102") == RESPONSIBLE);
	CHECK(said("5001:101") == ASKED);
	snprintf(value, sizeof(value), "%d:%d", getpid(), STARTED);
	CHECK(said(value) == getpid());
	CHECK(setenv(RESPONSIBILITY_VARIABLE, "5001:101", 1) == 0);
	CHECK(said("5002:102") == RESPONSIBLE);
}

static void
check_malformed(void)
{
	static const char *const values[] = {"", "5002", "5002:", ":102",
			"5002:102:", "5002:102:1", "5002;102", "5002:102 ",
			" 5002:102", "5002 :102", "5002: 102", "+5002:102",
			"-5002:102", "5002:+102", "5002:-102", "05002:102",
			"5002:0102", "0x138a:102", "5002:0x66", "5002:1e2",
			"5002.0:102", "0:102", "4294972298:102",
			"18446744073709556618:102", "5002:18446744073709551718",
			"5002:102000000000000000000000000",
			"5002:1020000000000000000000000000000000000000",
			"5002:102\n"};
	for (size_t i = 0; i != sizeof(values) / sizeof(values[0]); i++) {
		CHECK(said(values[i]) == ASKED);
		CHECK(setenv(RESPONSIBILITY_VARIABLE, values[i], 1) == 0);
		CHECK(!responsibility_named());
		CHECK(responsibility_of(find(getpid())) == getpid());
	}
	CHECK(said("5002:102") == RESPONSIBLE);
}

static void
check_gone(void)
{
	struct process *responsible = find(RESPONSIBLE);
	responsible->state = 'Z';
	CHECK(said("5002:102") == ASKED);
	responsible->state = 'S';
	responsible->start_ticks++;
	CHECK(said("5002:102") == ASKED);
	CHECK(said("5002:103") == RESPONSIBLE);
	responsible->pid++;
	CHECK(said("5002:103") == ASKED);
}

static int32_t
said(const char *value)
{
	environment = value;
	return responsibility_of(find(ASKED));
}
