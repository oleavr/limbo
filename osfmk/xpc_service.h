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

#pragma once

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "xpc_serial.h"

struct xpc_service {
	const char *name;
	void (*handler)(mach_msg_header_t *request,
			const struct xpc_object *message);
};

kern_return_t xpc_service_look_up(const char *name, mach_port_name_t *port);
kern_return_t xpc_service_look_up_in(
		const char *name, uint32_t domain, mach_port_name_t *port);
mach_port_name_t xpc_service_stand_in(const char *name);
void xpc_service_serve(void *kobject, mach_msg_header_t *request);
mach_msg_return_t xpc_service_reply(
		mach_msg_header_t *request, const struct xpc_encoder *encoder);
void xpc_launchd_reply(
		mach_msg_header_t *request, const struct xpc_encoder *encoder);
void xpc_launchd_send(mach_port_name_t port, mach_msg_type_name_t disposition,
		const struct xpc_encoder *encoder);

static inline bool
xpc_message_payload(
		const mach_msg_header_t *message, struct xpc_object *payload)
{
	return xpc_serial_payload(message, payload);
}

static inline bool
xpc_dictionary_find(const struct xpc_object *dictionary, const char *key,
		uint32_t *type, struct xpc_object *value)
{
	return xpc_serial_find(dictionary, key, type, value);
}

static inline bool
xpc_dictionary_get_uint64(const struct xpc_object *dictionary, const char *key,
		uint64_t *value)
{
	return xpc_serial_get_int(dictionary, key, value);
}

static inline bool
xpc_dictionary_get_bool(const struct xpc_object *dictionary, const char *key,
		bool *value)
{
	return xpc_serial_get_bool(dictionary, key, value);
}

static inline const char *
xpc_dictionary_get_string(const struct xpc_object *dictionary, const char *key)
{
	return xpc_serial_get_string(dictionary, key);
}

static inline bool
xpc_dictionary_get_uuid(const struct xpc_object *dictionary, const char *key,
		uint8_t value[16])
{
	return xpc_serial_get_uuid(dictionary, key, value);
}

static inline bool
xpc_dictionary_get_dictionary(const struct xpc_object *dictionary,
		const char *key, struct xpc_object *value)
{
	return xpc_serial_get_dictionary(dictionary, key, value);
}

static inline bool
xpc_dictionary_get_array(const struct xpc_object *dictionary, const char *key,
		struct xpc_object *value)
{
	return xpc_serial_get_array(dictionary, key, value);
}

static inline bool
xpc_array_get_uint64(
		const struct xpc_object *array, uint32_t index, uint64_t *value)
{
	return xpc_serial_array_get_int(array, index, value);
}

static inline void
xpc_array_apply_strings(const struct xpc_object *array,
		bool (*apply)(void *context, const char *string), void *context)
{
	xpc_serial_array_apply_strings(array, apply, context);
}

static inline void
xpc_dictionary_apply_strings(const struct xpc_object *dictionary,
		void (*apply)(void *context, const char *key,
				const char *string),
		void *context)
{
	xpc_serial_dictionary_apply_strings(dictionary, apply, context);
}

static inline size_t
xpc_object_size(const struct xpc_object *object)
{
	return xpc_serial_object_size(object);
}

static inline void
xpc_encoder_end_dictionary(struct xpc_encoder *encoder)
{
	xpc_encoder_end(encoder);
}

static inline void
xpc_encoder_end_array(struct xpc_encoder *encoder)
{
	xpc_encoder_end(encoder);
}

static inline void
xpc_encoder_mach_send(struct xpc_encoder *encoder, const char *key,
		mach_port_name_t port)
{
	xpc_encoder_port(encoder, key, port, MACH_MSG_TYPE_MOVE_SEND);
}

static inline void
xpc_encoder_mach_recv(struct xpc_encoder *encoder, const char *key,
		mach_port_name_t port)
{
	xpc_encoder_port(encoder, key, port, MACH_MSG_TYPE_MOVE_RECEIVE);
}
