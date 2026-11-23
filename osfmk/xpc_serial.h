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

#define XPC_SERIAL_MAGIC   0x40585043
#define XPC_SERIAL_VERSION 5
#define XPC_REPLY_ID       0x20000000

#define XPC_SERIAL_PORTS_MAX 8
#define XPC_SERIAL_DEPTH_MAX 8

enum xpc_serial_type {
	XPC_SERIAL_NULL = 0x1000,
	XPC_SERIAL_BOOL = 0x2000,
	XPC_SERIAL_INT64 = 0x3000,
	XPC_SERIAL_UINT64 = 0x4000,
	XPC_SERIAL_DOUBLE = 0x5000,
	XPC_SERIAL_DATE = 0x7000,
	XPC_SERIAL_DATA = 0x8000,
	XPC_SERIAL_STRING = 0x9000,
	XPC_SERIAL_UUID = 0xa000,
	XPC_SERIAL_FD = 0xb000,
	XPC_SERIAL_SHMEM = 0xc000,
	XPC_SERIAL_MACH_SEND = 0xd000,
	XPC_SERIAL_ARRAY = 0xe000,
	XPC_SERIAL_DICTIONARY = 0xf000,
	XPC_SERIAL_MACH_RECV = 0x15000,
	XPC_SERIAL_MACH_SEND_ONCE = 0x1b000,
};

/* An object from its type on, and the end of the bytes it may take */
struct xpc_object {
	const uint8_t *data;
	const uint8_t *end;
};

struct xpc_encoder {
	uint8_t *buffer;
	uint32_t offset;
	uint32_t capacity;
	uint32_t containers[XPC_SERIAL_DEPTH_MAX];
	uint32_t counts[XPC_SERIAL_DEPTH_MAX];
	uint32_t depth;
	mach_port_name_t ports[XPC_SERIAL_PORTS_MAX];
	mach_msg_type_name_t dispositions[XPC_SERIAL_PORTS_MAX];
	uint32_t port_count;
};

bool xpc_serial_payload(
		const mach_msg_header_t *message, struct xpc_object *payload);
bool xpc_serial_find(const struct xpc_object *dictionary, const char *key,
		uint32_t *type, struct xpc_object *value);
bool xpc_serial_get_int(const struct xpc_object *dictionary, const char *key,
		uint64_t *value);
const char *xpc_serial_get_string(
		const struct xpc_object *dictionary, const char *key);
bool xpc_serial_get_port(const mach_msg_header_t *message,
		const struct xpc_object *payload, const char *key,
		mach_port_name_t *port);

void xpc_encoder_init(
		struct xpc_encoder *encoder, void *buffer, uint32_t capacity);
void xpc_encoder_begin_dictionary(struct xpc_encoder *encoder, const char *key);
void xpc_encoder_begin_array(struct xpc_encoder *encoder, const char *key);
void xpc_encoder_end(struct xpc_encoder *encoder);
void xpc_encoder_bool(struct xpc_encoder *encoder, const char *key, bool value);
void xpc_encoder_int64(
		struct xpc_encoder *encoder, const char *key, int64_t value);
void xpc_encoder_uint64(
		struct xpc_encoder *encoder, const char *key, uint64_t value);
void xpc_encoder_string(struct xpc_encoder *encoder, const char *key,
		const char *value);
void xpc_encoder_uuid(struct xpc_encoder *encoder, const char *key,
		const uint8_t value[16]);
void xpc_encoder_port(struct xpc_encoder *encoder, const char *key,
		mach_port_name_t port, mach_msg_type_name_t disposition);
bool xpc_serial_get_bool(const struct xpc_object *dictionary, const char *key,
		bool *value);
bool xpc_serial_get_uuid(const struct xpc_object *dictionary, const char *key,
		uint8_t value[16]);
bool xpc_serial_get_dictionary(const struct xpc_object *dictionary,
		const char *key, struct xpc_object *value);
bool xpc_serial_get_array(const struct xpc_object *dictionary, const char *key,
		struct xpc_object *value);
bool xpc_serial_array_get_int(const struct xpc_object *array, uint32_t index,
		uint64_t *value);
void xpc_serial_array_apply_strings(const struct xpc_object *array,
		bool (*apply)(void *context, const char *string),
		void *context);
void xpc_serial_dictionary_apply_strings(const struct xpc_object *dictionary,
		void (*apply)(void *context, const char *key,
				const char *string),
		void *context);
size_t xpc_serial_object_size(const struct xpc_object *object);
void xpc_encoder_begin_element_dictionary(struct xpc_encoder *encoder);
void xpc_encoder_double(
		struct xpc_encoder *encoder, const char *key, double value);
void xpc_encoder_data(struct xpc_encoder *encoder, const char *key,
		const void *value, uint32_t length);
void xpc_encoder_element_uuid(
		struct xpc_encoder *encoder, const uint8_t value[16]);
void xpc_encoder_object(struct xpc_encoder *encoder, const char *key,
		const void *object, size_t size);
void xpc_encoder_shmem(struct xpc_encoder *encoder, const char *key,
		mach_port_name_t memory_entry, uint64_t size);
void xpc_encoder_fd(struct xpc_encoder *encoder, const char *key,
		mach_port_name_t fileport);
mach_msg_return_t xpc_serial_send(mach_port_name_t port,
		mach_msg_type_name_t disposition,
		const struct xpc_encoder *encoder,
		mach_msg_return_t (*send)(mach_msg_header_t *message));
mach_msg_return_t xpc_serial_reply(const mach_msg_header_t *request,
		const struct xpc_encoder *encoder,
		mach_msg_return_t (*send)(mach_msg_header_t *message));
