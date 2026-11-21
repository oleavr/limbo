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
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

#define PORT_COUNT   32
#define OVERSIZED    (2u << 20)
#define GUARD_TICKS  1000
#define REAP_TICKS   100
#define PEER_IDLE_MS 30000

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
static const char PEER_NAME[] = "com.limbo.test.ipc.peer";
static const mach_msg_id_t CHECK_IN = 402;
static const mach_msg_id_t LOOK_UP = 404;
static const mach_msg_id_t REQUEST_ID = 7777;
static const mach_msg_id_t REPLY_ID = 7877;
static const mach_msg_id_t QUIT_ID = 7900;
static const char REQUEST_DATA[] = "out of line";

static mach_port_t
bootstrap_call(mach_msg_id_t id, const char *name)
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
	strncpy(message.request.name, name, sizeof(message.request.name) - 1);

	kern_return_t kr = mach_msg(&message.request.Head,
			MACH_SEND_MSG | MACH_RCV_MSG, sizeof(bootstrap_request_t),
			sizeof(message), reply_port, 5000, MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	if (!(message.reply.Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return MACH_PORT_NULL;
	}
	return message.reply.port.name;
}

static void
receive_dead_names(mach_port_t service)
{
	struct {
		mach_msg_header_t Head;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
		mach_msg_trailer_t trailer;
	} request;
	kern_return_t kr = mach_msg(&request.Head,
			MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(request),
			service, 8000, MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	CHECK(request.Head.msgh_remote_port == MACH_PORT_DEAD);
	CHECK(request.port.name == MACH_PORT_DEAD);
}

static mach_port_t
receive_request(mach_port_t service)
{
	struct {
		mach_msg_header_t Head;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t ports[PORT_COUNT];
		mach_msg_ool_descriptor_t data;
		mach_msg_trailer_t trailer;
		char padding[64];
	} request;
	memset(&request, 0, sizeof(request));
	kern_return_t kr = mach_msg(&request.Head, MACH_RCV_MSG, 0,
			sizeof(request), service, MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	CHECK(request.Head.msgh_id == REQUEST_ID);
	CHECK(request.body.msgh_descriptor_count == PORT_COUNT + 1);
	CHECK(MACH_PORT_VALID(request.ports[0].name));
	for (int i = 1; i != PORT_COUNT; i++) {
		CHECK(request.ports[i].name == request.ports[0].name);
	}
	CHECK(request.data.size == sizeof(REQUEST_DATA));
	CHECK(memcmp(request.data.address, REQUEST_DATA, sizeof(REQUEST_DATA))
			== 0);
	mach_port_type_t type;
	kr = mach_port_type(
			mach_task_self(), request.Head.msgh_remote_port, &type);
	CHECK(kr == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_SEND_ONCE);
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
destroy_with_queued_request(mach_port_t service)
{
	mach_msg_header_t queued;
	kern_return_t kr = mach_msg(&queued, MACH_RCV_MSG | MACH_RCV_LARGE, 0,
			sizeof(queued), service, MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	CHECK(kr == MACH_RCV_TOO_LARGE);
	kr = mach_port_mod_refs(
			mach_task_self(), service, MACH_PORT_RIGHT_RECEIVE, -1);
	CHECK(kr == KERN_SUCCESS);
}

static void
serve(void)
{
	mach_port_t service = bootstrap_call(CHECK_IN, SERVICE_NAME);
	CHECK(service != MACH_PORT_NULL);

	receive_dead_names(service);
	mach_port_t abandoned = receive_request(service);
	mach_port_t gone = receive_request(service);
	mach_port_t dead_name = receive_request(service);
	mach_port_t returned = receive_request(service);
	mach_port_t awaited = receive_request(service);
	mach_port_t unanswered = receive_request(service);
	destroy_with_queued_request(service);
	mach_port_urefs_t unanswered_refs;
	kern_return_t kr = mach_port_get_refs(mach_task_self(), unanswered,
			MACH_PORT_RIGHT_SEND_ONCE, &unanswered_refs);
	CHECK(kr == KERN_SUCCESS);
	CHECK(unanswered_refs == 1);
	send_reply(abandoned, MACH_PORT_NULL);
	send_reply(dead_name, returned);
	mach_msg_header_t copied = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = sizeof(copied),
			.msgh_remote_port = awaited,
	};
	kr = mach_msg(&copied, MACH_SEND_MSG, sizeof(copied), 0, MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	CHECK(kr == MACH_SEND_INVALID_DEST);
	send_reply(awaited, gone);
	mach_port_type_t type;
	kr = mach_port_type(mach_task_self(), awaited, &type);
	CHECK(kr == KERN_INVALID_NAME);
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
send_dead_names(mach_port_t service)
{
	struct {
		mach_msg_header_t Head;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
	} request = {
			.Head = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_COPY_SEND,
							MACH_MSG_TYPE_MAKE_SEND_ONCE,
							0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(request),
					.msgh_remote_port = service,
					.msgh_local_port = MACH_PORT_DEAD,
			},
			.body = {.msgh_descriptor_count = 1},
			.port = {
					.name = MACH_PORT_DEAD,
					.disposition = MACH_MSG_TYPE_COPY_SEND,
					.type = MACH_MSG_PORT_DESCRIPTOR,
			},
	};
	send_request(&request.Head);
}

static void *
receive_nothing(void *arg)
{
	struct {
		mach_msg_header_t Head;
		mach_msg_trailer_t trailer;
	} message;
	return (void *)(uintptr_t)mach_msg(&message.Head,
			MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(message),
			(mach_port_t)(uintptr_t)arg, 3000, MACH_PORT_NULL);
}

static void
move_receive_right_away(mach_port_t service)
{
	void *result = (void *)(uintptr_t)MACH_RCV_INVALID_NAME;
	while ((uintptr_t)result == MACH_RCV_INVALID_NAME) {
		mach_port_t moved;
		mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
				&moved);
		pthread_t receiver;
		CHECK(pthread_create(&receiver, NULL, receive_nothing,
				      (void *)(uintptr_t)moved)
				== 0);
		usleep(100000);
		struct {
			mach_msg_header_t Head;
			mach_msg_body_t body;
			mach_msg_port_descriptor_t port;
		} carrier = {
			.Head = {
				.msgh_bits = MACH_MSGH_BITS_SET(
						MACH_MSG_TYPE_COPY_SEND, 0, 0,
						MACH_MSGH_BITS_COMPLEX),
				.msgh_size = sizeof(carrier),
				.msgh_remote_port = service,
			},
			.body = {.msgh_descriptor_count = 1},
			.port = {
				.name = moved,
				.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
				.type = MACH_MSG_PORT_DESCRIPTOR,
			},
		};
		send_request(&carrier.Head);
		CHECK(pthread_join(receiver, &result) == 0);
	}
	CHECK((uintptr_t)result == MACH_RCV_PORT_CHANGED);
}

static mach_port_t
look_up(const char *name)
{
	mach_port_t service = MACH_PORT_NULL;
	for (int attempt = 0; attempt != 50 && service == MACH_PORT_NULL; attempt++) {
		service = bootstrap_call(LOOK_UP, name);
		if (service == MACH_PORT_NULL) {
			usleep(100000);
		}
	}
	CHECK(service != MACH_PORT_NULL);
	return service;
}

static void
call(void)
{
	mach_port_t service = look_up(SERVICE_NAME);

	send_dead_names(service);
	mach_port_t abandoned;
	mach_port_allocate(
			mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &abandoned);
	mach_port_t dead_name;
	mach_port_allocate(
			mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &dead_name);
	mach_port_insert_right(mach_task_self(), dead_name, dead_name,
			MACH_MSG_TYPE_MAKE_SEND);
	mach_port_t carried;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &carried);
	mach_port_insert_right(mach_task_self(), carried, carried,
			MACH_MSG_TYPE_MAKE_SEND);
	mach_port_t unanswered;
	mach_port_allocate(
			mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &unanswered);
	mach_port_t reply_port;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
	union {
		struct {
			mach_msg_header_t Head;
			mach_msg_body_t body;
			mach_msg_port_descriptor_t ports[PORT_COUNT];
			mach_msg_ool_descriptor_t data;
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
	message.request.body.msgh_descriptor_count = PORT_COUNT + 1;
	for (int i = 0; i != PORT_COUNT; i++) {
		message.request.ports[i] = (mach_msg_port_descriptor_t){
				.name = carried,
				.disposition = MACH_MSG_TYPE_MAKE_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
	message.request.data = (mach_msg_ool_descriptor_t){
			.address = (void *)REQUEST_DATA,
			.size = sizeof(REQUEST_DATA),
			.copy = MACH_MSG_VIRTUAL_COPY,
			.type = MACH_MSG_OOL_DESCRIPTOR,
	};
	send_request(&message.request.Head);
	send_request(&message.request.Head);
	kern_return_t kr = mach_port_mod_refs(mach_task_self(), abandoned,
			MACH_PORT_RIGHT_RECEIVE, -1);
	CHECK(kr == KERN_SUCCESS);
	kr = mach_msg(&message.request.Head, MACH_SEND_MSG,
			sizeof(message.request), 0, MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	CHECK(kr == MACH_SEND_INVALID_REPLY);

	message.request.Head.msgh_local_port = dead_name;
	message.request.ports[0].name = abandoned;
	kr = mach_msg(&message.request.Head, MACH_SEND_MSG,
			sizeof(message.request), 0, MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	CHECK(kr == MACH_SEND_INVALID_RIGHT);
	message.request.ports[0].name = carried;
	send_request(&message.request.Head);
	send_request(&message.request.Head);
	kr = mach_port_mod_refs(mach_task_self(), dead_name,
			MACH_PORT_RIGHT_RECEIVE, -1);
	CHECK(kr == KERN_SUCCESS);

	message.request.Head.msgh_local_port = reply_port;
	send_request(&message.request.Head);
	message.request.Head.msgh_local_port = unanswered;
	send_request(&message.request.Head);
	message.request.ports[0].disposition = MACH_MSG_TYPE_MOVE_SEND;
	vm_address_t given = 0;
	kr = vm_allocate(mach_task_self(), &given, vm_page_size,
			VM_FLAGS_ANYWHERE);
	CHECK(kr == KERN_SUCCESS);
	message.request.data.address = (void *)given;
	message.request.data.deallocate = TRUE;
	kr = mach_msg(&message.request.Head,
			MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT,
			sizeof(message.request), sizeof(message), reply_port,
			8000, MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	CHECK(message.reply.Head.msgh_id == REPLY_ID);
	CHECK(message.reply.Head.msgh_remote_port == MACH_PORT_DEAD);
	mach_port_type_t type;
	kr = mach_port_type(mach_task_self(), dead_name, &type);
	CHECK(kr == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);
	mach_port_urefs_t carried_refs;
	kr = mach_port_get_refs(mach_task_self(), carried, MACH_PORT_RIGHT_SEND,
			&carried_refs);
	CHECK(kr == KERN_SUCCESS);
	CHECK(carried_refs == 0);
	kr = vm_allocate(
			mach_task_self(), &given, vm_page_size, VM_FLAGS_FIXED);
	CHECK(kr == KERN_SUCCESS);

	mach_port_t notify;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify);
	mach_port_t previous;
	kr = mach_port_request_notification(mach_task_self(), carried,
			MACH_NOTIFY_NO_SENDERS, 0, notify,
			MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
	CHECK(kr == KERN_SUCCESS);
	kr = mach_msg(&message.reply.Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			sizeof(message), notify, 100, MACH_PORT_NULL);
	CHECK(kr == MACH_RCV_TIMED_OUT);

	move_receive_right_away(service);
}

static void
serve_peer(void)
{
	mach_port_t service = bootstrap_call(CHECK_IN, PEER_NAME);
	CHECK(service != MACH_PORT_NULL);

	for (;;) {
		struct {
			mach_msg_header_t Head;
			mach_msg_trailer_t trailer;
		} message;
		kern_return_t kr = mach_msg(&message.Head,
				MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
				sizeof(message), service, PEER_IDLE_MS,
				MACH_PORT_NULL);
		CHECK(kr == MACH_MSG_SUCCESS);
		if (message.Head.msgh_id == QUIT_ID) {
			return;
		}
	}
}

static pid_t
start(void (*role)(void))
{
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		role();
		_exit(0);
	}
	return pid;
}

static pid_t
guard(pid_t child)
{
	pid_t parent = getpid();
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		int ticks = 0;
		while (ticks != GUARD_TICKS && getppid() == parent) {
			usleep(100000);
			ticks++;
		}
		kill(child, SIGKILL);
		if (ticks == GUARD_TICKS) {
			kill(parent, SIGKILL);
		}
		_exit(0);
	}
	return pid;
}

static int
reap(pid_t pid)
{
	int status = 0;
	pid_t reaped = 0;
	for (int ticks = 0; ticks != REAP_TICKS && reaped == 0; ticks++) {
		reaped = waitpid(pid, &status, WNOHANG);
		if (reaped == 0) {
			usleep(100000);
		}
	}
	CHECK(reaped == pid);
	return status;
}

static void
send_quit(mach_port_t port)
{
	mach_msg_header_t quit = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = sizeof(quit),
			.msgh_remote_port = port,
			.msgh_id = QUIT_ID,
	};
	send_request(&quit);
}

static void
check_oversized(mach_port_t port)
{
	static union {
		mach_msg_header_t Head;
		char bytes[OVERSIZED];
	} message;
	message.Head = (mach_msg_header_t){
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = sizeof(message),
			.msgh_remote_port = port,
	};
	kern_return_t kr = mach_msg(&message.Head, MACH_SEND_MSG,
			sizeof(message), 0, MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	CHECK(kr == MACH_SEND_TOO_LARGE);
}

static void
check_transport(void)
{
	pid_t peer = start(serve_peer);
	pid_t guardian = guard(peer);
	mach_port_t port = look_up(PEER_NAME);

	check_oversized(port);

	send_quit(port);
	int status = reap(peer);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	kill(guardian, SIGKILL);
	reap(guardian);
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

	check_transport();
	return 0;
}
