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
#include <string.h>

#include "bootstrap/bootstrap_defs.h"
#include "ipc.h"
#include "libinfo.h"
#include "xpc_service.h"

#define XPC_HANDSHAKE_ID 0x77303074

struct service_port {
	const struct xpc_service *service;
	mach_port_name_t port;
};

static void adopt_connection(
		struct service_port *service, mach_msg_header_t *request);

static struct service_port services[] = {
		{.service = &libinfo_service},
};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

kern_return_t
xpc_service_look_up(const char *name, mach_port_name_t *port)
{
	kern_return_t kr = names_look_up(name, port);
	if (kr != BOOTSTRAP_UNKNOWN_SERVICE) {
		return kr;
	}
	*port = xpc_service_stand_in(name);
	return *port != MACH_PORT_NULL ? KERN_SUCCESS : kr;
}

mach_port_name_t
xpc_service_stand_in(const char *name)
{
	for (size_t i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
		struct service_port *service = &services[i];
		if (strcmp(service->service->name, name) != 0) {
			continue;
		}
		pthread_mutex_lock(&lock);
		if (service->port == MACH_PORT_NULL
				|| ipc_kobject_lookup(service->port,
						   IPC_KOBJECT_XPC_SERVICE)
						!= service) {
			service->port = ipc_kobject_alloc(
					IPC_KOBJECT_XPC_SERVICE, service);
		}
		mach_port_name_t port = ipc_kobject_copy_send(service->port);
		pthread_mutex_unlock(&lock);
		return port;
	}
	return MACH_PORT_NULL;
}

void
xpc_service_serve(void *kobject, mach_msg_header_t *request)
{
	struct service_port *service = kobject;
	if (request->msgh_id == XPC_HANDSHAKE_ID) {
		adopt_connection(service, request);
		return;
	}

	struct xpc_object message;
	if (xpc_serial_payload(request, &message)) {
		service->service->handler(request, &message);
	}
}

mach_msg_return_t
xpc_service_reply(mach_msg_header_t *request, const struct xpc_encoder *encoder)
{
	return xpc_serial_reply(request, encoder, ipc_kernel_send);
}

void
xpc_launchd_reply(mach_msg_header_t *request, const struct xpc_encoder *encoder)
{
	xpc_serial_reply(request, encoder, ipc_launchd_send);
}

void
xpc_launchd_send(mach_port_name_t port, mach_msg_type_name_t disposition,
		const struct xpc_encoder *encoder)
{
	xpc_serial_send(port, disposition, encoder, ipc_launchd_send);
}

static void
adopt_connection(struct service_port *service, mach_msg_header_t *request)
{
	if (!(request->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}

	const uint8_t *end = (const uint8_t *)request + request->msgh_size;
	mach_msg_body_t *body = (mach_msg_body_t *)(request + 1);
	mach_msg_port_descriptor_t *descriptor
			= (mach_msg_port_descriptor_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count
			&& (const uint8_t *)(descriptor + 1) <= end;
			i++, descriptor++) {
		if (descriptor->type == MACH_MSG_PORT_DESCRIPTOR
				&& descriptor->disposition
						== MACH_MSG_TYPE_PORT_RECEIVE) {
			ipc_port_adopt_kobject(descriptor->name,
					IPC_KOBJECT_XPC_SERVICE, service);
		}
	}
}
