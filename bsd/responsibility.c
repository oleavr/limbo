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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsd/responsibility.h"

#define VALUE_SIZE    sizeof("2147483647:18446744073709551615")
#define VARIABLE_SIZE (sizeof(RESPONSIBILITY_VARIABLE "=") + VALUE_SIZE)

struct named {
	int32_t pid;
	uint64_t start_ticks;
};

static bool parse(const char *value, struct named *named);
static bool parse_number(const char **text, char end, uint64_t *number);

bool
responsibility_names(const char *variable)
{
	return strncmp(variable, RESPONSIBILITY_VARIABLE "=",
			       sizeof(RESPONSIBILITY_VARIABLE))
			== 0;
}

bool
responsibility_named(void)
{
	struct named named;
	return parse(getenv(RESPONSIBILITY_VARIABLE), &named);
}

char **
responsibility_environment(char **envp)
{
	struct named named;
	struct process self;
	if (!parse(getenv(RESPONSIBILITY_VARIABLE), &named)) {
		if (process_lookup(getpid(), &self) != 0) {
			return NULL;
		}
		named.pid = self.pid;
		named.start_ticks = self.start_ticks;
	}
	size_t count = 0;
	while (envp[count] != NULL) {
		count++;
	}
	char **result = malloc((count + 2) * sizeof(char *) + VARIABLE_SIZE);
	if (result == NULL) {
		return NULL;
	}
	char *variable = (char *)(result + count + 2);
	snprintf(variable, VARIABLE_SIZE, RESPONSIBILITY_VARIABLE "=%d:%llu",
			named.pid, (unsigned long long)named.start_ticks);
	size_t kept = 0;
	result[kept++] = variable;
	for (size_t i = 0; i != count; i++) {
		if (!responsibility_names(envp[i])) {
			result[kept++] = envp[i];
		}
	}
	result[kept] = NULL;
	return result;
}

int32_t
responsibility_of(const struct process *process)
{
	char said[VALUE_SIZE + 1];
	const char *value = getenv(RESPONSIBILITY_VARIABLE);
	if (process->pid != getpid()) {
		value = process_environment_value(process->pid,
					RESPONSIBILITY_VARIABLE, said,
					sizeof(said))
				? said
				: NULL;
	}
	struct named named;
	struct process responsible;
	if (parse(value, &named) && process_lookup(named.pid, &responsible) == 0
			&& responsible.start_ticks == named.start_ticks
			&& !process_exited(&responsible)) {
		return named.pid;
	}
	return process->pid;
}

static bool
parse(const char *value, struct named *named)
{
	uint64_t pid;
	if (value == NULL || !parse_number(&value, ':', &pid)
			|| !parse_number(&value, '\0', &named->start_ticks)
			|| pid == 0 || pid > INT32_MAX) {
		return false;
	}
	named->pid = (int32_t)pid;
	return true;
}

static bool
parse_number(const char **text, char end, uint64_t *number)
{
	const char *digit = *text;
	*number = 0;
	while (*digit >= '0' && *digit <= '9'
			&& *number <= (UINT64_MAX - 9) / 10) {
		*number = *number * 10 + (uint64_t)(*digit++ - '0');
	}
	if (digit == *text || *digit != end
			|| (**text == '0' && digit != *text + 1)) {
		return false;
	}
	*text = digit + 1;
	return true;
}
