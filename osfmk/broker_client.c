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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "broker.h"
#include "broker_client.h"
#include "ipc.h"

static void connect_to_broker(const char *path);
static void *read_frames(void *user);
static void dispatch_frame(const struct broker_frame *header, const void *payload);
static uint32_t least_length(uint32_t type);
static void expect_reply(void);
static struct broker_lookup_reply await_reply(void);
static int send_frame(uint32_t type, const void *payload, uint32_t length);
static int send_parts(uint32_t type, const struct iovec *parts, int part_count);
static mach_msg_return_t send_result(int error);

static int broker_fd = -1;
static uint32_t guest_id;
static pthread_mutex_t call_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t reply_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reply_ready = PTHREAD_COND_INITIALIZER;
static bool reply_pending;
static struct broker_lookup_reply pending_lookup_reply;
static struct broker_welcome pending_welcome;

void
broker_client_ensure(void)
{
	pthread_mutex_lock(&call_lock);
	if (broker_fd == -1) {
		const char *path = getenv(LIMBO_BROKER_SOCKET_ENV);
		if (path != NULL) {
			connect_to_broker(path);
		}
	}
	pthread_mutex_unlock(&call_lock);
}

void
broker_client_reset(void)
{
	if (broker_fd != -1) {
		close(broker_fd);
		broker_fd = -1;
	}
	guest_id = 0;
	reply_pending = false;
	pthread_mutex_init(&call_lock, NULL);
	pthread_mutex_init(&reply_lock, NULL);
	pthread_cond_init(&reply_ready, NULL);
}

bool
broker_client_available(void)
{
	return broker_fd != -1;
}

uint32_t
broker_client_guest_id(void)
{
	return guest_id;
}

void
broker_client_register(const char *name, uint64_t global_id)
{
	struct broker_register reg = { .global_id = global_id };
	strncpy(reg.name, name, sizeof(reg.name) - 1);
	pthread_mutex_lock(&call_lock);
	send_frame(BROKER_REGISTER, &reg, sizeof(reg));
	pthread_mutex_unlock(&call_lock);
}

bool
broker_client_look_up(const char *name, uint64_t *global_id)
{
	struct broker_lookup req = { 0 };
	strncpy(req.name, name, sizeof(req.name) - 1);
	pthread_mutex_lock(&call_lock);
	expect_reply();
	send_frame(BROKER_LOOKUP, &req, sizeof(req));
	struct broker_lookup_reply reply = await_reply();
	pthread_mutex_unlock(&call_lock);
	*global_id = reply.global_id;
	return reply.found;
}

mach_msg_return_t
broker_client_send(uint64_t dest_global_id, const void *blob, uint32_t length)
{
	if (length > BROKER_FRAME_MAX - sizeof(struct broker_send)) {
		return MACH_SEND_TOO_LARGE;
	}

	struct broker_send send = {
			.dest_global_id = dest_global_id,
			.blob_length = length,
	};
	struct iovec parts[2] = {
			{.iov_base = &send, .iov_len = sizeof(send)},
			{.iov_base = (void *)blob, .iov_len = length},
	};
	pthread_mutex_lock(&call_lock);
	int error = send_parts(BROKER_SEND, parts, 2);
	pthread_mutex_unlock(&call_lock);
	return send_result(error);
}

static void
connect_to_broker(const char *path)
{
	broker_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	connect(broker_fd, (struct sockaddr *)&addr, sizeof(addr));

	pthread_t thread;
	pthread_create(&thread, NULL, read_frames, NULL);

	expect_reply();
	send_parts(BROKER_HELLO, NULL, 0);
	await_reply();
	guest_id = pending_welcome.guest_id;
}

static void *
read_frames(void *user)
{
	for (;;) {
		struct broker_wire_frame *frame;
		int received = broker_wire_receive(broker_fd, &frame);
		if (received == -1) {
			return NULL;
		}
		if (received == 0) {
			continue;
		}

		struct broker_frame header = {
				.type = frame->type & ~BROKER_FRAME_OOL,
				.length = frame->length,
		};
		char loaded[BROKER_FRAME_MAX];
		if (!(frame->type & BROKER_FRAME_OOL)) {
			dispatch_frame(&header, frame->payload);
		} else if (broker_wire_read(frame, 0, loaded, frame->length)) {
			dispatch_frame(&header, loaded);
		}
		broker_wire_free(frame);
	}
}

static void
dispatch_frame(const struct broker_frame *header, const void *payload)
{
	if (header->length < least_length(header->type)) {
		return;
	}

	switch (header->type) {
	case BROKER_WELCOME:
		pthread_mutex_lock(&reply_lock);
		pending_welcome = *(const struct broker_welcome *)payload;
		reply_pending = false;
		pthread_cond_signal(&reply_ready);
		pthread_mutex_unlock(&reply_lock);
		break;
	case BROKER_LOOKUP_REPLY:
		pthread_mutex_lock(&reply_lock);
		pending_lookup_reply = *(const struct broker_lookup_reply *)payload;
		reply_pending = false;
		pthread_cond_signal(&reply_ready);
		pthread_mutex_unlock(&reply_lock);
		break;
	case BROKER_DELIVER: {
		const struct broker_send *send = (const struct broker_send *)payload;
		if (send->blob_length <= header->length - sizeof(*send)) {
			ipc_remote_deliver(send->dest_global_id, send + 1,
					send->blob_length);
		}
		break;
	}
	}
}

static uint32_t
least_length(uint32_t type)
{
	switch (type) {
	case BROKER_WELCOME:
		return sizeof(struct broker_welcome);
	case BROKER_LOOKUP_REPLY:
		return sizeof(struct broker_lookup_reply);
	case BROKER_DELIVER:
		return sizeof(struct broker_send);
	default:
		return 0;
	}
}

static void
expect_reply(void)
{
	pthread_mutex_lock(&reply_lock);
	reply_pending = true;
	pthread_mutex_unlock(&reply_lock);
}

static struct broker_lookup_reply
await_reply(void)
{
	pthread_mutex_lock(&reply_lock);
	while (reply_pending) {
		pthread_cond_wait(&reply_ready, &reply_lock);
	}
	struct broker_lookup_reply reply = pending_lookup_reply;
	pthread_mutex_unlock(&reply_lock);
	return reply;
}

static int
send_frame(uint32_t type, const void *payload, uint32_t length)
{
	struct iovec part = {.iov_base = (void *)payload, .iov_len = length};
	return send_parts(type, &part, 1);
}

static int
send_parts(uint32_t type, const struct iovec *parts, int part_count)
{
	struct broker_wire_frame *frame
			= broker_wire_new(type, parts, part_count);
	if (frame == NULL) {
		return errno;
	}
	int error = broker_wire_send(broker_fd, frame, 0);
	broker_wire_free(frame);
	return error;
}

static mach_msg_return_t
send_result(int error)
{
	switch (error) {
	case 0:
		return MACH_MSG_SUCCESS;
	case EMSGSIZE:
		return MACH_SEND_TOO_LARGE;
	case ENOBUFS:
	case ENOMEM:
	case EMFILE:
	case ENFILE:
		return MACH_SEND_NO_BUFFER;
	default:
		return MACH_SEND_INVALID_DEST;
	}
}
