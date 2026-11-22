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

#include <string.h>

#include "bootstrap/bootstrap_defs.h"
#include "broker.h"
#include "broker_client.h"
#include "ipc.h"
#include "names.h"

static uint32_t register_name(const char *name, uint64_t global_id);

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
	broker_client_call(BROKER_REGISTER, &request, sizeof(request),
			BROKER_REGISTERED, &reply, sizeof(reply));
	return reply.holder;
}
