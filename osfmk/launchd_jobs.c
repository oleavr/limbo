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

#include "launchd_jobs.h"
#include "xpc_service.h"

#define SERVICE_LABEL_VARIABLE      "LIMBO_LAUNCHD_SERVICE_LABEL"
#define SERVICE_DICTIONARY_VARIABLE "LIMBO_LAUNCHD_SERVICE_DICTIONARY"

static const char *own_label;
static uint8_t *own_dictionary;
static size_t own_dictionary_size;

void
launchd_jobs_init(void)
{
	own_label = getenv(SERVICE_LABEL_VARIABLE);
	const char *hex = getenv(SERVICE_DICTIONARY_VARIABLE);
	if (own_label == NULL || hex == NULL) {
		return;
	}
	own_dictionary_size = strlen(hex) / 2;
	own_dictionary = malloc(own_dictionary_size ? own_dictionary_size : 1);
	for (size_t i = 0; i < own_dictionary_size; i++) {
		unsigned int byte;
		sscanf(hex + i * 2, "%2x", &byte);
		own_dictionary[i] = (uint8_t)byte;
	}
}

bool
launchd_jobs_own_variable(const char *variable)
{
	if (own_dictionary == NULL) {
		return false;
	}
	struct xpc_object dictionary = {
			.data = own_dictionary,
			.end = own_dictionary + own_dictionary_size,
	};
	struct xpc_object variables;
	if (!xpc_dictionary_get_dictionary(
			    &dictionary, "EnvironmentVariables", &variables)) {
		return false;
	}
	char name[256];
	size_t length = strcspn(variable, "=");
	if (length >= sizeof(name)) {
		return false;
	}
	memcpy(name, variable, length);
	name[length] = '\0';
	return xpc_dictionary_get_string(&variables, name) != NULL;
}
