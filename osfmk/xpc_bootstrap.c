/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2026 Ole André Vadla Ravnås
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "broker.h"
#include "broker_client.h"
#include "ipc.h"
#include <stdio.h>
#include "xpc_bootstrap.h"

#define XPC_SERIAL_MAGIC 0x40585043
#define XPC_SERIAL_VERSION 5
#define XPC_REPLY_ID 0x20000000

enum xpc_routine {
	XPC_ROUTINE_LOOK_UP = 0x324,
	XPC_ROUTINE_CHECK_IN = 0x325,
	XPC_ROUTINE_LOOK_UP_LEGACY = 0xcf,
	XPC_ROUTINE_CHECK_IN_LEGACY = 0xce,
	XPC_ROUTINE_EVENT_PUBLISH = 0x193,
};

enum xpc_serial_type {
	XPC_SERIAL_NULL = 0x1000,
	XPC_SERIAL_BOOL = 0x2000,
	XPC_SERIAL_INT64 = 0x3000,
	XPC_SERIAL_UINT64 = 0x4000,
	XPC_SERIAL_DOUBLE = 0x5000,
	XPC_SERIAL_DATA = 0x8000,
	XPC_SERIAL_STRING = 0x9000,
	XPC_SERIAL_UUID = 0xa000,
	XPC_SERIAL_MACH_SEND = 0xd000,
	XPC_SERIAL_ARRAY = 0xe000,
	XPC_SERIAL_MACH_RECV = 0x15000,
	XPC_SERIAL_DICTIONARY = 0xf000,
};

struct xpc_request {
	uint64_t type;
	char name[256];
};

struct xpc_cursor {
	const uint8_t *position;
	const uint8_t *end;
};

struct xpc_builder {
	uint8_t *buffer;
	uint32_t offset;
	uint32_t dictionary_size_offset;
};

static bool look_up(mach_msg_header_t *request, const char *name);
static bool check_in(mach_msg_header_t *request, const char *name);
static bool reply_event_publish(mach_msg_header_t *request);
static void reply_with_port(mach_msg_header_t *request, mach_port_name_t port,
		mach_msg_type_name_t disposition, uint32_t port_type,
		bool with_metadata);
static void reply_with_error(mach_msg_header_t *request);
static void parse_request(const void *body, uint32_t length,
		struct xpc_request *out);
static bool read_member(struct xpc_cursor *cursor, const char *name,
		struct xpc_request *out);
static uint32_t read_u32(struct xpc_cursor *cursor);
static uint64_t read_u64(struct xpc_cursor *cursor);
static const char *read_key(struct xpc_cursor *cursor);
static void cursor_align(struct xpc_cursor *cursor);
static void begin_dictionary(struct xpc_builder *builder, uint32_t count);
static void end_dictionary(struct xpc_builder *builder);
static void append_key(struct xpc_builder *builder, const char *key);
static void append_port(struct xpc_builder *builder, const char *key,
		uint32_t port_type);
static void append_string(struct xpc_builder *builder, const char *key,
		const char *value);
static void append_bool(struct xpc_builder *builder, const char *key,
		bool value);
static void append_empty_array(struct xpc_builder *builder, const char *key);
static void append_u32(struct xpc_builder *builder, uint32_t value);
static void append_u64(struct xpc_builder *builder, uint64_t value);
static void append_uint64(struct xpc_builder *builder, const char *key, uint64_t value);
static void builder_align(struct xpc_builder *builder);

bool
xpc_bootstrap_is_message(mach_msg_id_t id)
{
	return (id & 0x40000000) != 0;
}

bool
xpc_bootstrap_serve(mach_msg_header_t *request)
{
	struct xpc_request parsed = { 0 };
	parse_request(request + 1, request->msgh_size - sizeof(*request),
			&parsed);

	switch (request->msgh_id & 0xffff) {
	case XPC_ROUTINE_LOOK_UP:
	case XPC_ROUTINE_LOOK_UP_LEGACY:
		return look_up(request, parsed.name);
	case XPC_ROUTINE_CHECK_IN:
	case XPC_ROUTINE_CHECK_IN_LEGACY:
		return check_in(request, parsed.name);
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
				MACH_MSG_TYPE_COPY_SEND, XPC_SERIAL_MACH_SEND,
				true);
		return true;
	}
	mach_port_name_t service = ipc_service_look_up(name);
	if (service == MACH_PORT_NULL) {
		reply_with_error(request);
	} else {
		reply_with_port(request, service, MACH_MSG_TYPE_MOVE_SEND,
				XPC_SERIAL_MACH_SEND, true);
	}
	return true;
}

static bool
check_in(mach_msg_header_t *request, const char *name)
{
	mach_port_name_t service = ipc_service_check_in(name);
	reply_with_port(request, service, MACH_MSG_TYPE_MOVE_RECEIVE,
			XPC_SERIAL_MACH_RECV, false);
	return true;
}

static void
reply_with_port(mach_msg_header_t *request, mach_port_name_t port,
		mach_msg_type_name_t disposition, uint32_t port_type,
		bool with_metadata)
{
	uint8_t storage[256] = { 0 };
	mach_msg_header_t *reply = (mach_msg_header_t *)storage;
	mach_msg_body_t *body = (mach_msg_body_t *)(reply + 1);
	mach_msg_port_descriptor_t *descriptor
			= (mach_msg_port_descriptor_t *)(body + 1);

	body->msgh_descriptor_count = 1;
	descriptor->name = port;
	descriptor->disposition = disposition;
	descriptor->type = MACH_MSG_PORT_DESCRIPTOR;

	struct xpc_builder builder = {
		.buffer = (uint8_t *)(descriptor + 1),
		.offset = 0,
	};
	append_u32(&builder, XPC_SERIAL_MAGIC);
	append_u32(&builder, XPC_SERIAL_VERSION);
	begin_dictionary(&builder, with_metadata ? 3 : 1);
	if (with_metadata) {
		append_uint64(&builder, "rec_execcnt", 10);
		append_uint64(&builder, "req_pid", getpid());
	}
	append_port(&builder, "port", port_type);
	end_dictionary(&builder);

	reply->msgh_bits = MACH_MSGH_BITS(
			MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0)
			| MACH_MSGH_BITS_COMPLEX;
	reply->msgh_remote_port = request->msgh_remote_port;
	reply->msgh_local_port = MACH_PORT_NULL;
	reply->msgh_id = XPC_REPLY_ID;
	reply->msgh_size = (mach_msg_size_t)((uint8_t *)builder.buffer
			+ builder.offset - storage);

	ipc_launchd_send(reply);
}

static bool
reply_event_publish(mach_msg_header_t *request)
{
	uint8_t storage[128] = { 0 };
	mach_msg_header_t *reply = (mach_msg_header_t *)storage;

	struct xpc_builder builder = {
		.buffer = (uint8_t *)(reply + 1),
		.offset = 0,
	};
	append_u32(&builder, XPC_SERIAL_MAGIC);
	append_u32(&builder, XPC_SERIAL_VERSION);
	begin_dictionary(&builder, 2);
	append_empty_array(&builder, "events");
	append_bool(&builder, "initial-load-completed", true);
	end_dictionary(&builder);

	reply->msgh_bits = MACH_MSGH_BITS(
			MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0);
	reply->msgh_remote_port = request->msgh_remote_port;
	reply->msgh_local_port = MACH_PORT_NULL;
	reply->msgh_id = XPC_REPLY_ID;
	reply->msgh_size = sizeof(*reply) + builder.offset;

	ipc_launchd_send(reply);
	return true;
}

static void
reply_with_error(mach_msg_header_t *request)
{
	uint8_t storage[256] = { 0 };
	mach_msg_header_t *reply = (mach_msg_header_t *)storage;

	struct xpc_builder builder = {
		.buffer = (uint8_t *)(reply + 1),
		.offset = 0,
	};
	append_u32(&builder, XPC_SERIAL_MAGIC);
	append_u32(&builder, XPC_SERIAL_VERSION);
	begin_dictionary(&builder, 1);
	append_string(&builder, "error", "unknown service");
	end_dictionary(&builder);

	reply->msgh_bits = MACH_MSGH_BITS(
			MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0);
	reply->msgh_remote_port = request->msgh_remote_port;
	reply->msgh_local_port = MACH_PORT_NULL;
	reply->msgh_id = XPC_REPLY_ID;
	reply->msgh_size = sizeof(*reply) + builder.offset;

	ipc_launchd_send(reply);
}

static void
parse_request(const void *body, uint32_t length, struct xpc_request *out)
{
	const uint8_t *scan = body;
	const uint8_t *limit = (const uint8_t *)body + length;
	while (scan + sizeof(uint32_t) <= limit) {
		uint32_t word;
		memcpy(&word, scan, sizeof(word));
		if (word == XPC_SERIAL_MAGIC) {
			break;
		}
		scan += sizeof(uint32_t);
	}

	struct xpc_cursor cursor = {
		.position = scan,
		.end = limit,
	};
	if (read_u32(&cursor) != XPC_SERIAL_MAGIC) {
		return;
	}
	read_u32(&cursor);
	if (read_u32(&cursor) != XPC_SERIAL_DICTIONARY) {
		return;
	}
	read_u32(&cursor);
	uint32_t count = read_u32(&cursor);
	for (uint32_t i = 0; i != count; i++) {
		const char *key = read_key(&cursor);
		if (!read_member(&cursor, key, out)) {
			return;
		}
	}
}

static bool
read_member(struct xpc_cursor *cursor, const char *name, struct xpc_request *out)
{
	uint32_t type = read_u32(cursor);
	switch (type) {
	case XPC_SERIAL_UINT64:
	case XPC_SERIAL_INT64: {
		uint64_t value = read_u64(cursor);
		if (strcmp(name, "type") == 0) {
			out->type = value;
		}
		return true;
	}
	case XPC_SERIAL_STRING:
	case XPC_SERIAL_DATA: {
		uint32_t length = read_u32(cursor);
		if (type == XPC_SERIAL_STRING && strcmp(name, "name") == 0) {
			strncpy(out->name, (const char *)cursor->position,
					sizeof(out->name) - 1);
		}
		cursor->position += length;
		cursor_align(cursor);
		return true;
	}
	case XPC_SERIAL_BOOL:
		read_u32(cursor);
		return true;
	case XPC_SERIAL_DOUBLE:
		read_u64(cursor);
		return true;
	case XPC_SERIAL_UUID:
		cursor->position += 16;
		return true;
	case XPC_SERIAL_NULL:
	case XPC_SERIAL_MACH_SEND:
	case XPC_SERIAL_MACH_RECV:
		return true;
	default:
		return false;
	}
}

static uint32_t
read_u32(struct xpc_cursor *cursor)
{
	uint32_t value;
	memcpy(&value, cursor->position, sizeof(value));
	cursor->position += sizeof(value);
	return value;
}

static uint64_t
read_u64(struct xpc_cursor *cursor)
{
	uint64_t value;
	memcpy(&value, cursor->position, sizeof(value));
	cursor->position += sizeof(value);
	return value;
}

static const char *
read_key(struct xpc_cursor *cursor)
{
	const char *key = (const char *)cursor->position;
	cursor->position += strlen(key) + 1;
	cursor_align(cursor);
	return key;
}

static void
cursor_align(struct xpc_cursor *cursor)
{
	while (((cursor->position - (const uint8_t *)0) & 3) != 0) {
		cursor->position++;
	}
}

static void
begin_dictionary(struct xpc_builder *builder, uint32_t count)
{
	append_u32(builder, XPC_SERIAL_DICTIONARY);
	builder->dictionary_size_offset = builder->offset;
	append_u32(builder, 0);
	append_u32(builder, count);
}

static void
end_dictionary(struct xpc_builder *builder)
{
	uint32_t size = builder->offset - (builder->dictionary_size_offset + 4);
	memcpy(builder->buffer + builder->dictionary_size_offset, &size,
			sizeof(size));
}

static void
append_key(struct xpc_builder *builder, const char *key)
{
	uint32_t length = strlen(key) + 1;
	memcpy(builder->buffer + builder->offset, key, length);
	builder->offset += length;
	builder_align(builder);
}

static void
append_port(struct xpc_builder *builder, const char *key, uint32_t port_type)
{
	append_key(builder, key);
	append_u32(builder, port_type);
}

static void
append_u32(struct xpc_builder *builder, uint32_t value)
{
	memcpy(builder->buffer + builder->offset, &value, sizeof(value));
	builder->offset += sizeof(value);
}

static void
append_u64(struct xpc_builder *builder, uint64_t value)
{
	memcpy(builder->buffer + builder->offset, &value, sizeof(value));
	builder->offset += sizeof(value);
}

static void
append_uint64(struct xpc_builder *builder, const char *key, uint64_t value)
{
	append_key(builder, key);
	append_u32(builder, XPC_SERIAL_UINT64);
	append_u64(builder, value);
}

static void
append_string(struct xpc_builder *builder, const char *key, const char *value)
{
	append_key(builder, key);
	append_u32(builder, XPC_SERIAL_STRING);
	uint32_t length = strlen(value) + 1;
	append_u32(builder, length);
	memcpy(builder->buffer + builder->offset, value, length);
	builder->offset += length;
	builder_align(builder);
}

static void
append_bool(struct xpc_builder *builder, const char *key, bool value)
{
	append_key(builder, key);
	append_u32(builder, XPC_SERIAL_BOOL);
	append_u32(builder, value ? 1 : 0);
}

static void
append_empty_array(struct xpc_builder *builder, const char *key)
{
	append_key(builder, key);
	append_u32(builder, XPC_SERIAL_ARRAY);
	append_u32(builder, sizeof(uint32_t));
	append_u32(builder, 0);
}

static void
builder_align(struct xpc_builder *builder)
{
	while ((builder->offset & 3) != 0) {
		builder->buffer[builder->offset++] = 0;
	}
}
