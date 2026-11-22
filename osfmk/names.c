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
#include <stdlib.h>
#include <string.h>

#include "bootstrap/bootstrap_defs.h"
#include "broker.h"
#include "broker_client.h"
#include "ipc.h"
#include "names.h"

struct own_name {
	uint64_t global_id;
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
};

static void names_fork_prepare(void);
static void names_fork_parent(void);
static void names_fork_child(void);
static uint32_t register_name(const char *name, uint64_t global_id);
static uint64_t own_name(const char *name);
static void add_own_name(const char *name, uint64_t global_id);

static pthread_mutex_t own_lock = PTHREAD_MUTEX_INITIALIZER;
static struct own_name *own_names;
static size_t own_name_count;

__attribute__((constructor)) static void
names_init(void)
{
	pthread_atfork(names_fork_prepare, names_fork_parent, names_fork_child);
}

static void
names_fork_prepare(void)
{
	pthread_mutex_lock(&own_lock);
}

static void
names_fork_parent(void)
{
	pthread_mutex_unlock(&own_lock);
}

static void
names_fork_child(void)
{
	free(own_names);
	own_names = NULL;
	own_name_count = 0;
	pthread_mutex_unlock(&own_lock);
}

kern_return_t
names_check_in(const char *name, mach_port_name_t *port)
{
	broker_client_ensure();
	ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, port);
	uint32_t holder = register_name(name, ipc_names_hold(*port));
	if (holder == BROKER_NAME_FREE) {
		return KERN_SUCCESS;
	}
	ipc_port_mod_refs(*port, MACH_PORT_RIGHT_RECEIVE, -1);
	*port = MACH_PORT_NULL;
	return holder == BROKER_NAME_ASKERS ? BOOTSTRAP_SERVICE_ACTIVE
					    : BOOTSTRAP_NOT_PRIVILEGED;
}

kern_return_t
names_register(const char *name, mach_port_name_t port)
{
	broker_client_ensure();
	uint32_t holder = register_name(name, ipc_names_hold(port));
	if (holder == BROKER_NAME_FREE) {
		return KERN_SUCCESS;
	}
	ipc_names_release(port);
	return holder == BROKER_NAME_ASKERS ? BOOTSTRAP_NAME_IN_USE
					    : BOOTSTRAP_NOT_PRIVILEGED;
}

kern_return_t
names_look_up(const char *name, mach_port_name_t *port)
{
	*port = MACH_PORT_NULL;
	pthread_mutex_lock(&own_lock);
	uint64_t own = own_name(name);
	pthread_mutex_unlock(&own_lock);
	if (own != 0) {
		*port = ipc_names_send_right(own);
		return KERN_SUCCESS;
	}

	broker_client_ensure();
	if (!broker_client_available()) {
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}

	struct broker_lookup request = {0};
	strncpy(request.name, name, sizeof(request.name) - 1);
	struct broker_lookup_reply reply = {0};
	if (!broker_client_call(BROKER_LOOKUP, &request, sizeof(request),
			    BROKER_LOOKUP_REPLY, &reply, sizeof(reply))
			|| !reply.found) {
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}
	*port = ipc_names_send_right(reply.global_id);
	return KERN_SUCCESS;
}

static uint32_t
register_name(const char *name, uint64_t global_id)
{
	struct broker_register request = {.global_id = global_id};
	strncpy(request.name, name, sizeof(request.name) - 1);
	struct broker_registered reply = {.holder = BROKER_NAME_FREE};
	pthread_mutex_lock(&own_lock);
	if (own_name(name) != 0) {
		reply.holder = BROKER_NAME_ASKERS;
	} else {
		broker_client_call(BROKER_REGISTER, &request, sizeof(request),
				BROKER_REGISTERED, &reply, sizeof(reply));
	}
	if (reply.holder == BROKER_NAME_FREE
			&& broker_guest_of(global_id)
					== broker_client_guest_id()) {
		add_own_name(name, global_id);
	}
	pthread_mutex_unlock(&own_lock);
	return reply.holder;
}

static uint64_t
own_name(const char *name)
{
	for (size_t i = 0; i != own_name_count; i++) {
		if (strncmp(own_names[i].name, name,
				    sizeof(own_names[i].name) - 1)
				!= 0) {
			continue;
		}
		uint64_t global_id = own_names[i].global_id;
		if (ipc_names_lives(global_id)) {
			return global_id;
		}
		own_names[i] = own_names[--own_name_count];
		return 0;
	}
	return 0;
}

static void
add_own_name(const char *name, uint64_t global_id)
{
	own_names = reallocarray(
			own_names, own_name_count + 1, sizeof(*own_names));
	struct own_name *own = &own_names[own_name_count++];
	*own = (struct own_name){.global_id = global_id};
	strncpy(own->name, name, sizeof(own->name) - 1);
}
