/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2026 Ole André Vadla Ravnås
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

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "ipc.h"
#include "names.h"
#include "xpc_bootstrap.h"
#include "xpc_serial.h"

#define REPLY_MAX 256

enum xpc_routine {
	XPC_ROUTINE_LOOK_UP = 0x324,
	XPC_ROUTINE_CHECK_IN = 0x325,
	XPC_ROUTINE_LOOK_UP_LEGACY = 0xcf,
	XPC_ROUTINE_CHECK_IN_LEGACY = 0xce,
	XPC_ROUTINE_EVENT_PUBLISH = 0x193,
};

static bool look_up(mach_msg_header_t *request, const char *name);
static bool check_in(mach_msg_header_t *request, const char *name);
static bool reply_event_publish(mach_msg_header_t *request);
static void reply_with_port(mach_msg_header_t *request, mach_port_name_t port,
		mach_msg_type_name_t disposition, bool with_metadata);
static void reply_with_error(mach_msg_header_t *request, kern_return_t error);

bool
xpc_bootstrap_is_message(mach_msg_id_t id)
{
	return (id & 0x40000000) != 0;
}

bool
xpc_bootstrap_serve(mach_msg_header_t *request)
{
	struct xpc_object payload;
	const char *name = xpc_serial_payload(request, &payload)
			? xpc_serial_get_string(&payload, "name")
			: NULL;

	switch (request->msgh_id & 0xffff) {
	case XPC_ROUTINE_LOOK_UP:
	case XPC_ROUTINE_LOOK_UP_LEGACY:
		return look_up(request, name != NULL ? name : "");
	case XPC_ROUTINE_CHECK_IN:
	case XPC_ROUTINE_CHECK_IN_LEGACY:
		return check_in(request, name != NULL ? name : "");
	case XPC_ROUTINE_EVENT_PUBLISH:
		return reply_event_publish(request);
	default:
		return false;
	}
}

static bool
look_up(mach_msg_header_t *request, const char *name)
{
	if (strcmp(name, "com.apple.system.opendirectoryd.libinfo") == 0) {
		reply_with_port(request, ipc_libinfo_self(),
				MACH_MSG_TYPE_COPY_SEND, true);
		return true;
	}
	mach_port_name_t service;
	kern_return_t kr = names_look_up(name, &service);
	if (kr != KERN_SUCCESS) {
		reply_with_error(request, kr);
	} else {
		reply_with_port(request, service, MACH_MSG_TYPE_MOVE_SEND,
				true);
	}
	return true;
}

static bool
check_in(mach_msg_header_t *request, const char *name)
{
	mach_port_name_t service;
	kern_return_t kr = names_check_in(name, &service);
	if (kr != KERN_SUCCESS) {
		reply_with_error(request, kr);
		return true;
	}
	reply_with_port(request, service, MACH_MSG_TYPE_MOVE_RECEIVE, false);
	return true;
}

static void
reply_with_port(mach_msg_header_t *request, mach_port_name_t port,
		mach_msg_type_name_t disposition, bool with_metadata)
{
	uint8_t buffer[REPLY_MAX];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	if (with_metadata) {
		xpc_encoder_uint64(&encoder, "rec_execcnt", 10);
		xpc_encoder_uint64(&encoder, "req_pid", getpid());
	}
	xpc_encoder_port(&encoder, "port", port, disposition);
	xpc_encoder_end(&encoder);
	xpc_serial_reply(request, &encoder, ipc_launchd_send);
}

static bool
reply_event_publish(mach_msg_header_t *request)
{
	uint8_t buffer[REPLY_MAX];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_begin_array(&encoder, "events");
	xpc_encoder_end(&encoder);
	xpc_encoder_bool(&encoder, "initial-load-completed", true);
	xpc_encoder_end(&encoder);
	xpc_serial_reply(request, &encoder, ipc_launchd_send);
	return true;
}

static void
reply_with_error(mach_msg_header_t *request, kern_return_t error)
{
	uint8_t buffer[REPLY_MAX];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_int64(&encoder, "error", error);
	xpc_encoder_end(&encoder);
	xpc_serial_reply(request, &encoder, ipc_launchd_send);
}
