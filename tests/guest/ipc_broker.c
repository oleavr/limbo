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

#include <mach/mach.h>
#include <mach/ndr.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

#define PORT_COUNT 32

typedef struct {
	mach_msg_header_t Head;
	NDR_record_t NDR;
	char name[128];
} bootstrap_request_t;

typedef struct {
	mach_msg_header_t Head;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t port;
	mach_msg_trailer_t trailer;
	char padding[64];
} bootstrap_reply_t;

static const char SERVICE_NAME[] = "com.limbo.test.ipc";
static const mach_msg_id_t CHECK_IN = 402;
static const mach_msg_id_t LOOK_UP = 404;
static const mach_msg_id_t REQUEST_ID = 7777;
static const mach_msg_id_t REPLY_ID = 7877;

static mach_port_t
bootstrap_call(mach_msg_id_t id)
{
	mach_port_t reply_port;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);

	mach_port_t bootstrap;
	task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap);

	union {
		bootstrap_request_t request;
		bootstrap_reply_t reply;
	} message;
	memset(&message, 0, sizeof(message));
	message.request.Head.msgh_bits = MACH_MSGH_BITS(
			MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	message.request.Head.msgh_remote_port = bootstrap;
	message.request.Head.msgh_local_port = reply_port;
	message.request.Head.msgh_id = id;
	message.request.Head.msgh_size = sizeof(bootstrap_request_t);
	message.request.NDR = NDR_record;
	strncpy(message.request.name, SERVICE_NAME, sizeof(message.request.name) - 1);

	kern_return_t kr = mach_msg(&message.request.Head,
			MACH_SEND_MSG | MACH_RCV_MSG, sizeof(bootstrap_request_t),
			sizeof(message), reply_port, 5000, MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	if (!(message.reply.Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return MACH_PORT_NULL;
	}
	return message.reply.port.name;
}

static mach_port_t
receive_request(mach_port_t service)
{
	struct {
		mach_msg_header_t Head;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t ports[PORT_COUNT];
		mach_msg_trailer_t trailer;
		char padding[64];
	} request;
	memset(&request, 0, sizeof(request));
	kern_return_t kr = mach_msg(&request.Head, MACH_RCV_MSG, 0,
			sizeof(request), service, MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	CHECK(request.Head.msgh_id == REQUEST_ID);
	CHECK(request.body.msgh_descriptor_count == PORT_COUNT);
	CHECK(MACH_PORT_VALID(request.ports[0].name));
	for (int i = 1; i != PORT_COUNT; i++) {
		CHECK(request.ports[i].name == request.ports[0].name);
	}
	return request.Head.msgh_remote_port;
}

static void
send_reply(mach_port_t port, mach_port_t reply_port)
{
	mach_msg_header_t reply;
	memset(&reply, 0, sizeof(reply));
	reply.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE,
			MACH_MSG_TYPE_MOVE_SEND_ONCE);
	reply.msgh_remote_port = port;
	reply.msgh_local_port = reply_port;
	reply.msgh_size = sizeof(reply);
	reply.msgh_id = REPLY_ID;
	kern_return_t kr = mach_msg(&reply, MACH_SEND_MSG, sizeof(reply), 0,
			MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
}

static void
serve(void)
{
	mach_port_t service = bootstrap_call(CHECK_IN);
	CHECK(service != MACH_PORT_NULL);

	mach_port_t abandoned = receive_request(service);
	mach_port_t gone = receive_request(service);
	mach_port_t awaited = receive_request(service);
	send_reply(abandoned, MACH_PORT_NULL);
	send_reply(awaited, gone);
}

static void
send_request(mach_msg_header_t *request)
{
	kern_return_t kr = mach_msg(request, MACH_SEND_MSG, request->msgh_size,
			0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
}

static void
call(void)
{
	mach_port_t service = MACH_PORT_NULL;
	for (int attempt = 0; attempt != 50 && service == MACH_PORT_NULL; attempt++) {
		service = bootstrap_call(LOOK_UP);
		if (service == MACH_PORT_NULL) {
			usleep(100000);
		}
	}
	CHECK(service != MACH_PORT_NULL);

	mach_port_t abandoned;
	mach_port_allocate(
			mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &abandoned);
	mach_port_t reply_port;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
	union {
		struct {
			mach_msg_header_t Head;
			mach_msg_body_t body;
			mach_msg_port_descriptor_t ports[PORT_COUNT];
		} request;
		struct {
			mach_msg_header_t Head;
			mach_msg_trailer_t trailer;
			char padding[64];
		} reply;
	} message;
	memset(&message, 0, sizeof(message));
	message.request.Head.msgh_bits = MACH_MSGH_BITS_SET(
			MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			0, MACH_MSGH_BITS_COMPLEX);
	message.request.Head.msgh_remote_port = service;
	message.request.Head.msgh_local_port = abandoned;
	message.request.Head.msgh_size = sizeof(message.request);
	message.request.Head.msgh_id = REQUEST_ID;
	message.request.body.msgh_descriptor_count = PORT_COUNT;
	for (int i = 0; i != PORT_COUNT; i++) {
		message.request.ports[i] = (mach_msg_port_descriptor_t){
				.name = reply_port,
				.disposition = MACH_MSG_TYPE_MAKE_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
	send_request(&message.request.Head);
	send_request(&message.request.Head);
	kern_return_t kr = mach_port_mod_refs(mach_task_self(), abandoned,
			MACH_PORT_RIGHT_RECEIVE, -1);
	CHECK(kr == KERN_SUCCESS);

	message.request.Head.msgh_local_port = reply_port;
	kr = mach_msg(&message.request.Head, MACH_SEND_MSG | MACH_RCV_MSG,
			sizeof(message.request), sizeof(message), reply_port,
			8000, MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	CHECK(message.reply.Head.msgh_id == REPLY_ID);
	CHECK(message.reply.Head.msgh_remote_port == MACH_PORT_DEAD);
}

int
main(void)
{
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		call();
		_exit(0);
	}

	serve();

	int status;
	waitpid(pid, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	return 0;
}
