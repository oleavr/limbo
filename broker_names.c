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

#include <stdlib.h>
#include <string.h>

#include "broker_names.h"

struct service {
	uint64_t global_id;
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
};

static struct service *service_named(const char *name);

static struct service *services;
static size_t service_count;

void
broker_names_register(const struct broker_register *reg)
{
	struct service *service = service_named(reg->name);
	if (service == NULL) {
		services = reallocarray(
				services, service_count + 1, sizeof(*services));
		service = &services[service_count++];
		strncpy(service->name, reg->name, sizeof(service->name) - 1);
	}
	service->global_id = reg->global_id;
}

struct broker_lookup_reply
broker_names_look_up(const struct broker_lookup *req)
{
	struct service *service = service_named(req->name);
	return (struct broker_lookup_reply){
			.found = service != NULL,
			.global_id = (service != NULL) ? service->global_id : 0,
	};
}

void
broker_names_forget(uint32_t guest_id)
{
	size_t kept = 0;
	for (size_t i = 0; i != service_count; i++) {
		if (broker_guest_of(services[i].global_id) != guest_id) {
			services[kept++] = services[i];
		}
	}
	service_count = kept;
}

static struct service *
service_named(const char *name)
{
	for (size_t i = 0; i != service_count; i++) {
		if (strcmp(services[i].name, name) == 0) {
			return &services[i];
		}
	}
	return NULL;
}
