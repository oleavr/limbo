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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xpc_serial.h"

static bool skip_object(struct xpc_object *cursor, uint32_t type);
static bool read_u32(struct xpc_object *cursor, uint32_t *value);
static bool read_key(struct xpc_object *cursor, const char **key);
static bool skip_bytes(struct xpc_object *cursor, uint64_t length);
static void begin_container(struct xpc_encoder *encoder, uint32_t type);
static void append_key(struct xpc_encoder *encoder, const char *key);
static void append_u32(struct xpc_encoder *encoder, uint32_t value);
static void append_bytes(struct xpc_encoder *encoder, const void *bytes,
		uint32_t length);

bool
xpc_serial_payload(const mach_msg_header_t *message, struct xpc_object *payload)
{
	const uint8_t *cursor = (const uint8_t *)(message + 1);
	const uint8_t *end = (const uint8_t *)message + message->msgh_size;
	if (message->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		const mach_msg_body_t *body = (const mach_msg_body_t *)cursor;
		if (end - cursor < (ptrdiff_t)sizeof(*body)) {
			return false;
		}
		cursor = (const uint8_t *)(body + 1);
		for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count;
				i++) {
			const mach_msg_type_descriptor_t *descriptor
					= (const mach_msg_type_descriptor_t *)
							cursor;
			if (end - cursor < (ptrdiff_t)sizeof(
					    mach_msg_port_descriptor_t)) {
				return false;
			}
			size_t size = descriptor->type == MACH_MSG_PORT_DESCRIPTOR
					? sizeof(mach_msg_port_descriptor_t)
					: sizeof(mach_msg_ool_descriptor64_t);
			if (end - cursor < (ptrdiff_t)size) {
				return false;
			}
			cursor += size;
		}
	}

	struct xpc_object read = {.data = cursor, .end = end};
	uint32_t magic;
	uint32_t version;
	if (!read_u32(&read, &magic) || magic != XPC_SERIAL_MAGIC
			|| !read_u32(&read, &version)) {
		return false;
	}
	*payload = read;
	return true;
}

bool
xpc_serial_find(const struct xpc_object *dictionary, const char *key,
		uint32_t *type, struct xpc_object *value)
{
	struct xpc_object cursor = *dictionary;
	uint32_t found;
	uint32_t size;
	uint32_t count;
	if (!read_u32(&cursor, &found) || found != XPC_SERIAL_DICTIONARY
			|| !read_u32(&cursor, &size)
			|| size > (uint64_t)(cursor.end - cursor.data)) {
		return false;
	}
	cursor.end = cursor.data + size;
	if (!read_u32(&cursor, &count)) {
		return false;
	}
	for (uint32_t i = 0; i < count; i++) {
		const char *candidate;
		if (!read_key(&cursor, &candidate)
				|| !read_u32(&cursor, &found)) {
			return false;
		}
		if (strcmp(candidate, key) == 0) {
			*type = found;
			*value = cursor;
			return true;
		}
		if (!skip_object(&cursor, found)) {
			return false;
		}
	}
	return false;
}

bool
xpc_serial_get_int(const struct xpc_object *dictionary, const char *key,
		uint64_t *value)
{
	uint32_t type;
	struct xpc_object object;
	if (!xpc_serial_find(dictionary, key, &type, &object)
			|| (type != XPC_SERIAL_INT64
					&& type != XPC_SERIAL_UINT64)
			|| object.end - object.data
					< (ptrdiff_t)sizeof(*value)) {
		return false;
	}
	memcpy(value, object.data, sizeof(*value));
	return true;
}

const char *
xpc_serial_get_string(const struct xpc_object *dictionary, const char *key)
{
	uint32_t type;
	struct xpc_object object;
	uint32_t length;
	if (!xpc_serial_find(dictionary, key, &type, &object)
			|| type != XPC_SERIAL_STRING
			|| !read_u32(&object, &length) || length == 0
			|| length > (uint64_t)(object.end - object.data)
			|| object.data[length - 1] != '\0') {
		return NULL;
	}
	return (const char *)object.data;
}

static bool
skip_object(struct xpc_object *cursor, uint32_t type)
{
	uint32_t length;
	switch (type) {
	case XPC_SERIAL_NULL:
	case XPC_SERIAL_FD:
	case XPC_SERIAL_MACH_SEND:
	case XPC_SERIAL_MACH_RECV:
	case XPC_SERIAL_MACH_SEND_ONCE:
		return true;
	case XPC_SERIAL_BOOL:
		return skip_bytes(cursor, sizeof(uint32_t));
	case XPC_SERIAL_INT64:
	case XPC_SERIAL_UINT64:
	case XPC_SERIAL_DOUBLE:
	case XPC_SERIAL_DATE:
		return skip_bytes(cursor, sizeof(uint64_t));
	case XPC_SERIAL_UUID:
		return skip_bytes(cursor, 16);
	case XPC_SERIAL_DATA:
	case XPC_SERIAL_STRING:
	case XPC_SERIAL_ARRAY:
	case XPC_SERIAL_DICTIONARY:
		return read_u32(cursor, &length) && skip_bytes(cursor, length);
	default:
		return false;
	}
}

static bool
read_u32(struct xpc_object *cursor, uint32_t *value)
{
	if (cursor->end - cursor->data < (ptrdiff_t)sizeof(*value)) {
		return false;
	}
	memcpy(value, cursor->data, sizeof(*value));
	cursor->data += sizeof(*value);
	return true;
}

static bool
read_key(struct xpc_object *cursor, const char **key)
{
	const uint8_t *nul = memchr(
			cursor->data, '\0', cursor->end - cursor->data);
	if (nul == NULL) {
		return false;
	}
	*key = (const char *)cursor->data;
	return skip_bytes(cursor, nul + 1 - cursor->data);
}

static bool
skip_bytes(struct xpc_object *cursor, uint64_t length)
{
	uint64_t padded = (length + 3) & ~(uint64_t)3;
	uint64_t room = cursor->end - cursor->data;
	if (length > room) {
		return false;
	}
	cursor->data += padded < room ? padded : room;
	return true;
}

void
xpc_encoder_init(struct xpc_encoder *encoder, void *buffer, uint32_t capacity)
{
	*encoder = (struct xpc_encoder){
			.buffer = buffer,
			.capacity = capacity,
	};
	append_u32(encoder, XPC_SERIAL_MAGIC);
	append_u32(encoder, XPC_SERIAL_VERSION);
}

void
xpc_encoder_begin_dictionary(struct xpc_encoder *encoder, const char *key)
{
	if (encoder->depth != 0) {
		append_key(encoder, key);
	}
	begin_container(encoder, XPC_SERIAL_DICTIONARY);
}

void
xpc_encoder_begin_array(struct xpc_encoder *encoder, const char *key)
{
	append_key(encoder, key);
	begin_container(encoder, XPC_SERIAL_ARRAY);
}

void
xpc_encoder_end(struct xpc_encoder *encoder)
{
	encoder->depth--;
	uint32_t at = encoder->containers[encoder->depth];
	uint32_t size = encoder->offset - (at + sizeof(uint32_t));
	memcpy(encoder->buffer + at, &size, sizeof(size));
	memcpy(encoder->buffer + at + sizeof(uint32_t),
			&encoder->counts[encoder->depth], sizeof(uint32_t));
}

void
xpc_encoder_bool(struct xpc_encoder *encoder, const char *key, bool value)
{
	append_key(encoder, key);
	append_u32(encoder, XPC_SERIAL_BOOL);
	append_u32(encoder, value);
}

void
xpc_encoder_int64(struct xpc_encoder *encoder, const char *key, int64_t value)
{
	append_key(encoder, key);
	append_u32(encoder, XPC_SERIAL_INT64);
	append_bytes(encoder, &value, sizeof(value));
}

void
xpc_encoder_uint64(struct xpc_encoder *encoder, const char *key, uint64_t value)
{
	append_key(encoder, key);
	append_u32(encoder, XPC_SERIAL_UINT64);
	append_bytes(encoder, &value, sizeof(value));
}

void
xpc_encoder_string(
		struct xpc_encoder *encoder, const char *key, const char *value)
{
	uint32_t length = strlen(value) + 1;
	append_key(encoder, key);
	append_u32(encoder, XPC_SERIAL_STRING);
	append_u32(encoder, length);
	append_bytes(encoder, value, length);
}

void
xpc_encoder_uuid(struct xpc_encoder *encoder, const char *key,
		const uint8_t value[16])
{
	append_key(encoder, key);
	append_u32(encoder, XPC_SERIAL_UUID);
	append_bytes(encoder, value, 16);
}

void
xpc_encoder_port(struct xpc_encoder *encoder, const char *key,
		mach_port_name_t port, mach_msg_type_name_t disposition)
{
	if (encoder->port_count == XPC_SERIAL_PORTS_MAX) {
		fprintf(stderr, "limbo: too many ports in an XPC message\n");
		abort();
	}
	append_key(encoder, key);
	append_u32(encoder,
			disposition == MACH_MSG_TYPE_MOVE_RECEIVE
					? XPC_SERIAL_MACH_RECV
					: XPC_SERIAL_MACH_SEND);
	encoder->ports[encoder->port_count] = port;
	encoder->dispositions[encoder->port_count++] = disposition;
}

mach_msg_return_t
xpc_serial_reply(const mach_msg_header_t *request,
		const struct xpc_encoder *encoder,
		mach_msg_return_t (*send)(mach_msg_header_t *message))
{
	size_t descriptors = encoder->port_count == 0 ? 0
						      : sizeof(mach_msg_body_t)
					+ encoder->port_count
							* sizeof(mach_msg_port_descriptor_t);
	size_t size = sizeof(mach_msg_header_t) + descriptors + encoder->offset;
	uint8_t *storage = malloc(size);
	mach_msg_header_t *reply = (mach_msg_header_t *)storage;
	*reply = (mach_msg_header_t){
			.msgh_bits
			= MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(
							 request->msgh_bits),
					0),
			.msgh_size = size,
			.msgh_remote_port = request->msgh_remote_port,
			.msgh_id = XPC_REPLY_ID,
	};
	uint8_t *cursor = (uint8_t *)(reply + 1);
	if (encoder->port_count != 0) {
		reply->msgh_bits |= MACH_MSGH_BITS_COMPLEX;
		mach_msg_body_t *body = (mach_msg_body_t *)cursor;
		body->msgh_descriptor_count = encoder->port_count;
		mach_msg_port_descriptor_t *port
				= (mach_msg_port_descriptor_t *)(body + 1);
		for (uint32_t i = 0; i < encoder->port_count; i++) {
			port[i] = (mach_msg_port_descriptor_t){
					.name = encoder->ports[i],
					.disposition = encoder->dispositions[i],
					.type = MACH_MSG_PORT_DESCRIPTOR,
			};
		}
		cursor += descriptors;
	}
	memcpy(cursor, encoder->buffer, encoder->offset);
	mach_msg_return_t mr = send(reply);
	free(storage);
	return mr;
}

static void
begin_container(struct xpc_encoder *encoder, uint32_t type)
{
	if (encoder->depth
			== sizeof(encoder->containers)
					/ sizeof(encoder->containers[0])) {
		fprintf(stderr, "limbo: XPC message nested too deep\n");
		abort();
	}
	append_u32(encoder, type);
	encoder->containers[encoder->depth] = encoder->offset;
	encoder->counts[encoder->depth] = 0;
	encoder->depth++;
	append_u32(encoder, 0);
	append_u32(encoder, 0);
}

static void
append_key(struct xpc_encoder *encoder, const char *key)
{
	encoder->counts[encoder->depth - 1]++;
	append_bytes(encoder, key, strlen(key) + 1);
}

static void
append_u32(struct xpc_encoder *encoder, uint32_t value)
{
	append_bytes(encoder, &value, sizeof(value));
}

static void
append_bytes(struct xpc_encoder *encoder, const void *bytes, uint32_t length)
{
	uint32_t padded = (length + 3) & ~3u;
	if (padded > encoder->capacity - encoder->offset) {
		fprintf(stderr, "limbo: XPC message too large\n");
		abort();
	}
	memcpy(encoder->buffer + encoder->offset, bytes, length);
	memset(encoder->buffer + encoder->offset + length, 0, padded - length);
	encoder->offset += padded;
}
