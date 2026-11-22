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

#include "check.h"
#include "osfmk/xpc_serial.h"

#define BUFFER_SIZE 512
#define PORT_NAME   0x1203

static void check_round_trip(void);
static void check_truncated(void);
static void check_malformed(void);
static mach_msg_return_t keep(mach_msg_header_t *message);
static mach_msg_header_t *encode_sample(void);
static bool decodes(const uint8_t *bytes);

static uint8_t kept[BUFFER_SIZE];

int
main(void)
{
	check_round_trip();
	check_truncated();
	check_malformed();
	return 0;
}

static void
check_round_trip(void)
{
	mach_msg_header_t *message = encode_sample();
	CHECK(message->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	CHECK(message->msgh_id == XPC_REPLY_ID);
	const mach_msg_port_descriptor_t *port = (const mach_msg_port_descriptor_t
					*)((const mach_msg_body_t *)(message
							   + 1)
			+ 1);
	CHECK(port->name == PORT_NAME);
	CHECK(port->disposition == MACH_MSG_TYPE_MOVE_SEND);

	struct xpc_object payload;
	CHECK(xpc_serial_payload(message, &payload));
	const char *name = xpc_serial_get_string(&payload, "name");
	CHECK(name != NULL && strcmp(name, "com.example.service") == 0);
	uint64_t value = 0;
	CHECK(xpc_serial_get_int(&payload, "uid", &value) && value == 501);
	CHECK(xpc_serial_get_int(&payload, "pid", &value) && value == 7);
	CHECK(!xpc_serial_get_int(&payload, "name", &value));
	CHECK(xpc_serial_get_string(&payload, "uid") == NULL);
	CHECK(xpc_serial_get_string(&payload, "absent") == NULL);

	uint32_t type;
	struct xpc_object inner;
	CHECK(xpc_serial_find(&payload, "inner", &type, &inner));
	CHECK(type == XPC_SERIAL_DICTIONARY);
	inner.data -= sizeof(uint32_t);
	CHECK(xpc_serial_get_int(&inner, "depth", &value) && value == 2);
	CHECK(xpc_serial_find(&payload, "events", &type, &inner));
	CHECK(type == XPC_SERIAL_ARRAY);
	CHECK(xpc_serial_find(&payload, "port", &type, &inner));
	CHECK(type == XPC_SERIAL_MACH_SEND);
	CHECK(xpc_serial_find(&payload, "last", &type, &inner));
	CHECK(type == XPC_SERIAL_BOOL);

	mach_port_name_t name_of_port = MACH_PORT_NULL;
	CHECK(xpc_serial_get_port(message, &payload, "port", &name_of_port));
	CHECK(name_of_port == PORT_NAME);
	CHECK(!xpc_serial_get_port(message, &payload, "name", &name_of_port));
	CHECK(!xpc_serial_get_port(message, &payload, "absent", &name_of_port));
}

static void
check_truncated(void)
{
	mach_msg_header_t *message = encode_sample();
	mach_msg_size_t size = message->msgh_size;
	uint8_t *copy = malloc(size);
	memcpy(copy, message, size);
	for (mach_msg_size_t length = sizeof(mach_msg_header_t); length < size;
			length++) {
		uint8_t *cut = malloc(length);
		memcpy(cut, copy, length);
		((mach_msg_header_t *)cut)->msgh_size = length;
		CHECK(!decodes(cut));
		free(cut);
	}
	CHECK(decodes(copy));
	free(copy);
}

static void
check_malformed(void)
{
	uint32_t unterminated[] = {
			XPC_SERIAL_DICTIONARY,
			24,
			1,
			0x656d616e,
			0,
			XPC_SERIAL_STRING,
			4,
			0x41414141,
	};
	struct xpc_object object = {
			.data = (const uint8_t *)unterminated,
			.end = (const uint8_t *)(unterminated + 8),
	};
	CHECK(xpc_serial_get_string(&object, "name") == NULL);

	uint32_t oversized[] = {
			XPC_SERIAL_DICTIONARY,
			0xffffff00,
			1,
	};
	object = (struct xpc_object){
			.data = (const uint8_t *)oversized,
			.end = (const uint8_t *)(oversized + 3),
	};
	uint32_t type;
	struct xpc_object value;
	CHECK(!xpc_serial_find(&object, "name", &type, &value));

	uint32_t keyless[] = {
			XPC_SERIAL_DICTIONARY,
			8,
			1,
			0x41414141,
	};
	object = (struct xpc_object){
			.data = (const uint8_t *)keyless,
			.end = (const uint8_t *)(keyless + 4),
	};
	CHECK(!xpc_serial_find(&object, "name", &type, &value));

	uint32_t long_data[] = {
			XPC_SERIAL_DICTIONARY,
			28,
			2,
			0x61,
			XPC_SERIAL_DATA,
			0x7fffffff,
			0x62,
			XPC_SERIAL_BOOL,
			1,
	};
	object = (struct xpc_object){
			.data = (const uint8_t *)long_data,
			.end = (const uint8_t *)(long_data + 9),
	};
	CHECK(!xpc_serial_find(&object, "b", &type, &value));
}

static mach_msg_return_t
keep(mach_msg_header_t *message)
{
	CHECK(message->msgh_size <= sizeof(kept));
	memcpy(kept, message, message->msgh_size);
	return MACH_MSG_SUCCESS;
}

static mach_msg_header_t *
encode_sample(void)
{
	uint8_t buffer[BUFFER_SIZE];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_string(&encoder, "name", "com.example.service");
	xpc_encoder_int64(&encoder, "uid", 501);
	xpc_encoder_begin_dictionary(&encoder, "inner");
	xpc_encoder_uint64(&encoder, "depth", 2);
	xpc_encoder_end(&encoder);
	xpc_encoder_begin_array(&encoder, "events");
	xpc_encoder_end(&encoder);
	xpc_encoder_port(&encoder, "port", PORT_NAME, MACH_MSG_TYPE_MOVE_SEND);
	xpc_encoder_uint64(&encoder, "pid", 7);
	xpc_encoder_bool(&encoder, "last", true);
	xpc_encoder_end(&encoder);

	mach_msg_header_t request = {
			.msgh_bits
			= MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0),
			.msgh_remote_port = 0x1103,
	};
	CHECK(xpc_serial_reply(&request, &encoder, keep) == MACH_MSG_SUCCESS);
	return (mach_msg_header_t *)kept;
}

static bool
decodes(const uint8_t *bytes)
{
	struct xpc_object payload;
	uint64_t value;
	return xpc_serial_payload((const mach_msg_header_t *)bytes, &payload)
			&& xpc_serial_get_int(&payload, "pid", &value)
			&& value == 7;
}
