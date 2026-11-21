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

#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/ndr.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../broker.h"
#include "check.h"

#define PORT_COUNT   32
#define FDS_SEEN     256
#define SETTLE_USEC  200000
#define OVERSIZED    (2u << 20)
#define GUARD_TICKS  1000
#define REAP_TICKS   100
#define PEER_IDLE_MS 30000
#define ANSWER_MS    20000
#define BULK_SIZE    4096
#define BULK_COUNT   1000
#define LARGE_SIZE   (300 * 1024)
#define LARGEST_SIZE ((1 << 20) - 4096)
#define INLINE_EDGE  (64 * 1024)
#define PEER_ROOM    (1 << 20)
#define MANY_PORTS   300
#define FDS_MAX      1024
#define WAITING      5

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

typedef struct {
	mach_msg_header_t Head;
	int32_t value;
} valued_t;

typedef struct {
	mach_msg_header_t Head;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t port;
} carrier_t;

typedef struct {
	mach_msg_header_t Head;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t ports[FDS_MAX + 1];
} carriers_t;

typedef struct {
	pid_t pid;
	pid_t guardian;
	mach_port_t port;
} child_t;

typedef struct {
	uint32_t message_size;
	mach_msg_type_name_t dest_disposition;
	mach_msg_type_name_t reply_disposition;
	uint64_t reply_global_id;
	pid_t sender_pid;
	uint32_t descriptor_count;
	uint32_t sender_guest_id;
} remote_header_t;

typedef struct {
	struct broker_send send;
	remote_header_t remote;
	struct {
		mach_msg_header_t Head;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
		mach_msg_ool_descriptor_t data;
	} message;
	uint64_t id;
	char data[8];
} raw_message_t;

static const char SERVICE_NAME[] = "com.limbo.test.ipc";
static const char LOST_NAME[] = "com.limbo.test.ipc.lost";
static const char *program;
static const char PEER_NAME[] = "com.limbo.test.ipc.peer";
static const char VICTIM_NAME[] = "com.limbo.test.ipc.victim";
static const char GONE_NAME[] = "com.limbo.test.ipc.gone";
static const char HOME_NAME[] = "com.limbo.test.ipc.home";
static const char HOLDER_NAME[] = "com.limbo.test.ipc.holder";
static const char THIRD_NAME[] = "com.limbo.test.ipc.third";
static const char DOOMED_NAME[] = "com.limbo.test.ipc.doomed";
static const mach_msg_id_t CHECK_IN = 402;
static const mach_msg_id_t LOOK_UP = 404;
static const mach_msg_id_t REQUEST_ID = 7777;
static const mach_msg_id_t REPLY_ID = 7877;
static const mach_msg_id_t QUIT_ID = 7900;
static const mach_msg_id_t ANSWER_ID = 7901;
static const mach_msg_id_t COUNT_ID = 7902;
static const mach_msg_id_t REPORT_ID = 7903;
static const mach_msg_id_t LARGE_ID = 7904;
static const mach_msg_id_t MARK_ID = 7905;
static const mach_msg_id_t MARKED_ID = 7906;
static const mach_msg_id_t FILEPORT_ID = 7907;
static const mach_msg_id_t OFFSETS_ID = 7908;
static const mach_msg_id_t ENTRY_ID = 7909;
static const mach_msg_id_t DATA_ENTRY_ID = 7910;
static const mach_msg_id_t KEEP_ID = 7911;
static const mach_msg_id_t DROP_ID = 7912;
static const mach_msg_id_t FORWARD_ID = 7913;
static const mach_msg_id_t TYPE_ID = 7914;
static const mach_msg_id_t HOLD_REPLY_ID = 7915;
static const mach_msg_id_t DROP_REPLY_ID = 7916;
static const mach_msg_id_t CHECK_IN_ID = 7917;
static const mach_msg_id_t DESTROY_ID = 7918;
static const mach_msg_id_t WATCH_ID = 7919;
static const mach_msg_id_t WATCHED_ID = 7920;
static const char FROM_SENDER[] = "from the sender";
static const char FROM_RECEIVER[] = "from the receiver";

static const char *peer_name = PEER_NAME;

int fileport_makeport(int fd, mach_port_t *port);
int fileport_makefd(mach_port_t port);
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

static int
open_descriptors(void)
{
	int count = 0;
	for (int fd = 0; fd != FDS_SEEN; fd++) {
		count += fcntl(fd, F_GETFD) != -1;
	}
	return count;
}

static void
connect_and_exec(void)
{
	char before[16];
	snprintf(before, sizeof(before), "%d", open_descriptors());
	bootstrap_call(LOOK_UP, SERVICE_NAME);
	execl(program, program, "descriptors", before, NULL);
	_exit(1);
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
answer(const mach_msg_header_t *request, int32_t value)
{
	if (request->msgh_remote_port == MACH_PORT_NULL) {
		return;
	}
	valued_t reply = {
			.Head = {
					.msgh_bits = MACH_MSGH_BITS(
							MACH_MSG_TYPE_MOVE_SEND_ONCE,
							0),
					.msgh_size = sizeof(reply),
					.msgh_remote_port = request->msgh_remote_port,
					.msgh_id = ANSWER_ID,
			},
			.value = value,
	};
	send_request(&reply.Head);
}

static char
pattern(mach_msg_size_t offset, mach_msg_size_t size)
{
	return (char)(offset * 7 + size);
}

static int32_t
patterned(const char *bytes, mach_msg_size_t size)
{
	for (mach_msg_size_t i = sizeof(mach_msg_header_t); i < size; i++) {
		if (bytes[i] != pattern(i, size)) {
			return -1;
		}
	}
	return (int32_t)size;
}

static int32_t
write_through(mach_port_t fileport)
{
	int fd = fileport_makefd(fileport);
	char byte = 'x';
	ssize_t written = write(fd, &byte, sizeof(byte));
	close(fd);
	mach_port_deallocate(mach_task_self(), fileport);
	return (int32_t)written;
}

static int32_t
count_offsets(const carriers_t *carriers)
{
	int32_t found = 0;
	for (uint32_t i = 0; i != carriers->body.msgh_descriptor_count; i++) {
		int fd = fileport_makefd(carriers->ports[i].name);
		found += lseek(fd, 0, SEEK_CUR) == (off_t)i;
		close(fd);
		mach_port_deallocate(mach_task_self(), carriers->ports[i].name);
	}
	return found;
}

static int32_t
write_to_entry(mach_port_t entry, int flags)
{
	mach_vm_address_t address = 0;
	mach_vm_size_t size = flags != VM_FLAGS_ANYWHERE ? sizeof(FROM_SENDER)
							 : 2 * vm_page_size;
	vm_prot_t rw = VM_PROT_READ | VM_PROT_WRITE;
	kern_return_t kr = mach_vm_map(mach_task_self(), &address, size, 0,
			flags, entry, 0, false, rw, rw, VM_INHERIT_NONE);
	if (kr != KERN_SUCCESS
			|| memcmp((void *)address, FROM_SENDER,
					   sizeof(FROM_SENDER))
					!= 0) {
		return -1;
	}
	if (flags == VM_FLAGS_ANYWHERE) {
		memcpy((char *)address + vm_page_size, FROM_RECEIVER,
				sizeof(FROM_RECEIVER));
	}
	mach_vm_deallocate(mach_task_self(), address, size);
	mach_port_deallocate(mach_task_self(), entry);
	return 1;
}

static carrier_t
carrier_of(mach_port_t port, mach_msg_id_t id, mach_port_t carried)
{
	return (carrier_t){
		.Head = {
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
					0, 0, MACH_MSGH_BITS_COMPLEX),
			.msgh_size = sizeof(carrier_t),
			.msgh_remote_port = port,
			.msgh_id = id,
		},
		.body = {.msgh_descriptor_count = 1},
		.port = {
			.name = carried,
			.disposition = MACH_MSG_TYPE_MOVE_SEND,
			.type = MACH_MSG_PORT_DESCRIPTOR,
		},
	};
}

static mach_port_t
request_notification(mach_port_t name, mach_msg_id_t id)
{
	mach_port_t notify;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify);
	mach_port_t previous = MACH_PORT_NULL;
	kern_return_t kr = mach_port_request_notification(mach_task_self(),
			name, id, 0, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			&previous);
	CHECK(kr == KERN_SUCCESS && previous == MACH_PORT_NULL);
	return notify;
}

static mach_msg_return_t
receive_notification(mach_port_t notify, mach_msg_id_t id,
		mach_msg_timeout_t timeout, mach_port_name_t *name)
{
	struct {
		mach_dead_name_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	kern_return_t kr = mach_msg(&message.notification.not_header,
			MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(message),
			notify, timeout, MACH_PORT_NULL);
	if (kr == MACH_MSG_SUCCESS) {
		CHECK(message.notification.not_header.msgh_id == id);
		*name = message.notification.not_port;
	}
	return kr;
}

static int32_t
type_of(mach_port_t name)
{
	mach_port_type_t type = 0;
	mach_port_type(mach_task_self(), name, &type);
	return (int32_t)type;
}

static void
forward(mach_port_t to, mach_port_t right)
{
	carrier_t carrier = carrier_of(to, KEEP_ID, right);
	send_request(&carrier.Head);
	mach_port_deallocate(mach_task_self(), to);
}

static void
serve_peer(void)
{
	mach_port_t service = bootstrap_call(CHECK_IN, peer_name);
	CHECK(service != MACH_PORT_NULL);

	int32_t counted = 0;
	int32_t marked = 0;
	mach_port_t kept = MACH_PORT_NULL;
	mach_port_t held_reply = MACH_PORT_NULL;
	mach_port_t doomed = MACH_PORT_NULL;
	mach_port_t watch = MACH_PORT_NULL;
	mach_port_name_t seen;
	for (;;) {
		static union {
			mach_msg_header_t Head;
			valued_t valued;
			carrier_t carrier;
			carriers_t carriers;
			char bytes[PEER_ROOM];
		} message;
		kern_return_t kr = mach_msg(&message.Head,
				MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
				sizeof(message), service, PEER_IDLE_MS,
				MACH_PORT_NULL);
		CHECK(kr == MACH_MSG_SUCCESS);
		if (message.Head.msgh_id == QUIT_ID) {
			return;
		}
		if (message.Head.msgh_id == COUNT_ID) {
			CHECK(message.Head.msgh_size == BULK_SIZE);
			CHECK(message.valued.value == counted);
			counted++;
		} else if (message.Head.msgh_id == REPORT_ID) {
			answer(&message.Head, counted);
			counted = 0;
		} else if (message.Head.msgh_id == MARK_ID) {
			marked++;
		} else if (message.Head.msgh_id == MARKED_ID) {
			answer(&message.Head, marked);
			marked = 0;
		} else if (message.Head.msgh_id == FILEPORT_ID) {
			answer(&message.Head,
					write_through(message.carrier.port
									.name));
		} else if (message.Head.msgh_id == OFFSETS_ID) {
			answer(&message.Head, count_offsets(&message.carriers));
		} else if (message.Head.msgh_id == ENTRY_ID) {
			answer(&message.Head,
					write_to_entry(message.carrier.port
									.name,
							VM_FLAGS_ANYWHERE));
		} else if (message.Head.msgh_id == DATA_ENTRY_ID) {
			answer(&message.Head,
					write_to_entry(message.carrier.port
									.name,
							VM_FLAGS_ANYWHERE
									| VM_FLAGS_RETURN_DATA_ADDR));
		} else if (message.Head.msgh_id == KEEP_ID) {
			kept = message.carrier.port.name;
			answer(&message.Head, 1);
		} else if (message.Head.msgh_id == DROP_ID) {
			answer(&message.Head,
					mach_port_deallocate(mach_task_self(),
							kept));
		} else if (message.Head.msgh_id == FORWARD_ID) {
			forward(message.carrier.port.name, kept);
			answer(&message.Head, 1);
		} else if (message.Head.msgh_id == TYPE_ID) {
			answer(&message.Head, type_of(kept));
		} else if (message.Head.msgh_id == HOLD_REPLY_ID) {
			held_reply = message.Head.msgh_remote_port;
		} else if (message.Head.msgh_id == DROP_REPLY_ID) {
			answer(&message.Head,
					mach_port_deallocate(mach_task_self(),
							held_reply));
		} else if (message.Head.msgh_id == CHECK_IN_ID) {
			doomed = bootstrap_call(CHECK_IN, DOOMED_NAME);
			answer(&message.Head, doomed != MACH_PORT_NULL);
		} else if (message.Head.msgh_id == DESTROY_ID) {
			answer(&message.Head,
					mach_port_mod_refs(mach_task_self(),
							doomed,
							MACH_PORT_RIGHT_RECEIVE,
							-1));
		} else if (message.Head.msgh_id == WATCH_ID) {
			watch = request_notification(
					kept, MACH_NOTIFY_NO_SENDERS);
			answer(&message.Head, 1);
		} else if (message.Head.msgh_id == WATCHED_ID) {
			answer(&message.Head,
					receive_notification(watch,
							MACH_NOTIFY_NO_SENDERS,
							200, &seen)
							== MACH_MSG_SUCCESS);
		} else if (message.Head.msgh_id == LARGE_ID) {
			answer(&message.Head,
					patterned(message.bytes,
							message.Head.msgh_size));
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

static mach_port_t
post(mach_msg_header_t *request)
{
	mach_port_t reply_port;
	mach_port_allocate(
			mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
	request->msgh_bits |= MACH_MSGH_BITS(0, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	request->msgh_local_port = reply_port;
	send_request(request);
	return reply_port;
}

static int32_t
collect(mach_port_t reply_port)
{

	struct {
		valued_t reply;
		mach_msg_trailer_t trailer;
	} message;
	kern_return_t kr = mach_msg(&message.reply.Head,
			MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(message),
			reply_port, ANSWER_MS, MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	CHECK(message.reply.Head.msgh_id == ANSWER_ID);
	kr = mach_port_mod_refs(mach_task_self(), reply_port,
			MACH_PORT_RIGHT_RECEIVE, -1);
	CHECK(kr == KERN_SUCCESS);
	return message.reply.value;
}

static int32_t
ask(mach_msg_header_t *request)
{
	return collect(post(request));
}

static int32_t
ask_for(mach_port_t port, mach_msg_id_t id)
{
	mach_msg_header_t request = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = sizeof(request),
			.msgh_remote_port = port,
			.msgh_id = id,
	};
	return ask(&request);
}

static void
stop(pid_t pid)
{
	CHECK(kill(pid, SIGSTOP) == 0);
	int status = 0;
	pid_t stopped = 0;
	for (int ticks = 0; ticks != REAP_TICKS && stopped == 0; ticks++) {
		stopped = waitpid(pid, &status, WNOHANG | WUNTRACED);
		if (stopped == 0) {
			usleep(100000);
		}
	}
	CHECK(stopped == pid && WIFSTOPPED(status));
}

static void
lose_connection(void)
{
	bool open_before[FDS_SEEN];
	for (int fd = 0; fd != FDS_SEEN; fd++) {
		open_before[fd] = fcntl(fd, F_GETFD) != -1;
	}
	CHECK(bootstrap_call(LOOK_UP, LOST_NAME) != MACH_PORT_NULL);
	int violated = 0;
	for (int fd = 0; fd != FDS_SEEN; fd++) {
		if (!open_before[fd] && fcntl(fd, F_GETFD) != -1) {
			violated += write(fd, "", 1) == 1;
		}
	}
	CHECK(violated == 1);
	usleep(SETTLE_USEC);
	CHECK(bootstrap_call(LOOK_UP, LOST_NAME) == MACH_PORT_NULL);
}

static void
check_lost_connection(void)
{
	CHECK(bootstrap_call(CHECK_IN, LOST_NAME) != MACH_PORT_NULL);
	pid_t child = start(lose_connection);
	pid_t guardian = guard(child);
	int status = reap(child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	kill(guardian, SIGKILL);
	reap(guardian);
}

static void
check_exec(void)
{
	pid_t child = start(connect_and_exec);
	pid_t guardian = guard(child);
	int status = reap(child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	kill(guardian, SIGKILL);
	reap(guardian);
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
check_large(mach_port_t port, mach_msg_size_t size)
{
	static union {
		mach_msg_header_t Head;
		char bytes[LARGEST_SIZE];
	} message;
	message.Head = (mach_msg_header_t){
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = size,
			.msgh_remote_port = port,
			.msgh_id = LARGE_ID,
	};
	for (mach_msg_size_t i = sizeof(message.Head); i < size; i++) {
		message.bytes[i] = pattern(i, size);
	}
	CHECK(ask(&message.Head) == (int32_t)size);
}

static void
check_large_frames(mach_port_t port)
{
	check_large(port, LARGE_SIZE);
	check_large(port, LARGEST_SIZE);
	for (mach_msg_size_t size = INLINE_EDGE - 128; size <= INLINE_EDGE;
			size += 4) {
		check_large(port, size);
	}
}

static int
connect_raw(void)
{
	const char *path = getenv(LIMBO_BROKER_SOCKET_ENV);
	CHECK(path != NULL);
	const char *name = strrchr(path, '/');
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	strncpy(address.sun_path, name != NULL ? name + 1 : path,
			sizeof(address.sun_path) - 1);
	int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	CHECK(fd != -1);
	CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
	return fd;
}

static void
send_raw(int fd, uint32_t type, const void *payload, uint32_t length)
{
	struct broker_frame header = {.type = type, .length = length};
	struct iovec parts[2] = {
			{.iov_base = &header, .iov_len = sizeof(header)},
			{.iov_base = (void *)payload, .iov_len = length},
	};
	struct msghdr message = {.msg_iov = parts, .msg_iovlen = 2};
	CHECK(sendmsg(fd, &message, 0) == (ssize_t)(sizeof(header) + length));
}

static void
check_short_frames(mach_port_t port)
{
	int fd = connect_raw();
	uint32_t word = 0;
	send_raw(fd, BROKER_REGISTER, &word, sizeof(word));
	send_raw(fd, BROKER_LOOKUP, &word, sizeof(word));
	send_raw(fd, BROKER_SEND, &word, sizeof(word));
	send_raw(fd, BROKER_SEND | BROKER_FRAME_OOL, &word, 0);
	close(fd);
	CHECK(bootstrap_call(LOOK_UP, PEER_NAME) == port);
}

static uint64_t
look_up_raw(int fd, const char *name)
{
	struct broker_lookup request = {0};
	strncpy(request.name, name, sizeof(request.name) - 1);
	send_raw(fd, BROKER_LOOKUP, &request, sizeof(request));

	struct {
		struct broker_frame header;
		struct broker_lookup_reply reply;
	} answer;
	CHECK(recv(fd, &answer, sizeof(answer), 0) == sizeof(answer));
	CHECK(answer.header.type == BROKER_LOOKUP_REPLY && answer.reply.found);
	return answer.reply.global_id;
}

static raw_message_t
raw_message(uint64_t dest_global_id)
{
	raw_message_t valid = {
		.send = {
			.dest_global_id = dest_global_id,
			.blob_length = sizeof(valid) - sizeof(valid.send),
		},
		.remote = {
			.message_size = sizeof(valid.message),
			.dest_disposition = MACH_MSG_TYPE_COPY_SEND,
			.descriptor_count = 1,
		},
		.message = {
			.Head = {
				.msgh_bits = MACH_MSGH_BITS_COMPLEX,
				.msgh_size = sizeof(valid.message),
				.msgh_id = MARK_ID,
			},
			.body = {.msgh_descriptor_count = 2},
			.port = {
				.disposition = MACH_MSG_TYPE_PORT_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
			},
			.data = {
				.size = sizeof(valid.data),
				.type = MACH_MSG_OOL_DESCRIPTOR,
			},
		},
	};
	return valid;
}

static void
check_malformed_messages(mach_port_t port)
{
	int fd = connect_raw();
	const raw_message_t valid = raw_message(look_up_raw(fd, PEER_NAME));

	raw_message_t raw = valid;
	raw.send.blob_length = 8;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw.send) + 8);
	raw = valid;
	raw.send.blob_length = 1 << 20;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.remote.message_size = INT32_MAX;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.remote.message_size = 8;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.remote.descriptor_count = 1000;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.remote.reply_global_id = raw.send.dest_global_id;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.message.body.msgh_descriptor_count = 1 << 28;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.message.port.disposition = 0;
	raw.id = raw.send.dest_global_id;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.message.port.type = 77;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.message.data.size = INT32_MAX;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.id = UINT64_MAX - 1;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	raw = valid;
	raw.id = UINT64_MAX - 2;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));

	send_raw(fd, BROKER_SEND, &valid, sizeof(valid));
	CHECK(look_up_raw(fd, PEER_NAME) == valid.send.dest_global_id);
	close(fd);
	CHECK(ask_for(port, MARKED_ID) == 1);
}

static mach_port_t
fileport_of_pipe(int *read_end)
{
	int ends[2];
	CHECK(pipe(ends) == 0);
	mach_port_t fileport;
	CHECK(fileport_makeport(ends[1], &fileport) == 0);
	CHECK(close(ends[1]) == 0);
	*read_end = ends[0];
	return fileport;
}

static void
check_fileport(mach_port_t port)
{
	int read_end;
	mach_port_t fileport = fileport_of_pipe(&read_end);
	carrier_t carrier = carrier_of(port, FILEPORT_ID, fileport);
	CHECK(ask(&carrier.Head) == 1);

	mach_port_type_t type;
	CHECK(mach_port_type(mach_task_self(), fileport, &type)
			== KERN_INVALID_NAME);
	char byte = 0;
	CHECK(read(read_end, &byte, sizeof(byte)) == 1 && byte == 'x');
	CHECK(read(read_end, &byte, sizeof(byte)) == 0);
	CHECK(close(read_end) == 0);
}

static void
carry(carriers_t *carriers, mach_port_t port, uint32_t count)
{
	carriers->Head = (mach_msg_header_t){
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
					0, 0, MACH_MSGH_BITS_COMPLEX),
			.msgh_size = sizeof(carriers->Head)
					+ sizeof(carriers->body)
					+ count * sizeof(carriers->ports[0]),
			.msgh_remote_port = port,
			.msgh_id = OFFSETS_ID,
	};
	carriers->body.msgh_descriptor_count = count;
}

static void
carry_offsets(carriers_t *carriers, mach_msg_type_name_t disposition)
{
	char path[] = "/tmp/limbo-fileports-XXXXXX";
	int first = mkstemp(path);
	CHECK(first != -1);
	for (uint32_t i = 0; i != MANY_PORTS; i++) {
		int fd = open(path, O_RDONLY);
		CHECK(fd != -1 && lseek(fd, i, SEEK_SET) == (off_t)i);
		mach_port_t fileport;
		CHECK(fileport_makeport(fd, &fileport) == 0);
		CHECK(close(fd) == 0);
		carriers->ports[i] = (mach_msg_port_descriptor_t){
				.name = fileport,
				.disposition = disposition,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
	CHECK(unlink(path) == 0 && close(first) == 0);
}

static void
check_many_fileports(mach_port_t port)
{
	static carriers_t carriers;
	carry(&carriers, port, MANY_PORTS);
	carry_offsets(&carriers, MACH_MSG_TYPE_MOVE_SEND);
	CHECK(ask(&carriers.Head) == MANY_PORTS);

	int read_end;
	mach_port_t fileport = fileport_of_pipe(&read_end);
	carry(&carriers, port, FDS_MAX + 1);
	for (uint32_t i = 0; i != FDS_MAX + 1; i++) {
		carriers.ports[i] = (mach_msg_port_descriptor_t){
				.name = fileport,
				.disposition = MACH_MSG_TYPE_COPY_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
	kern_return_t kr = mach_msg(&carriers.Head, MACH_SEND_MSG,
			carriers.Head.msgh_size, 0, MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	CHECK(kr == MACH_SEND_TOO_LARGE);
	CHECK(mach_port_deallocate(mach_task_self(), fileport) == KERN_SUCCESS);
	char byte;
	CHECK(read(read_end, &byte, sizeof(byte)) == 0);
	CHECK(close(read_end) == 0);
}

static void
check_memory_entry(mach_port_t port)
{
	memory_object_size_t size = 2 * vm_page_size;
	mach_port_t entry = MACH_PORT_NULL;
	vm_prot_t rw = VM_PROT_READ | VM_PROT_WRITE;
	CHECK(mach_make_memory_entry_64(mach_task_self(), &size, 0,
			      MAP_MEM_NAMED_CREATE | rw, &entry, MACH_PORT_NULL)
			== KERN_SUCCESS);
	mach_vm_address_t address = 0;
	CHECK(mach_vm_map(mach_task_self(), &address, size, 0,
			      VM_FLAGS_ANYWHERE, entry, 0, false, rw, rw,
			      VM_INHERIT_NONE)
			== KERN_SUCCESS);
	memcpy((void *)address, FROM_SENDER, sizeof(FROM_SENDER));

	carrier_t carrier = carrier_of(port, ENTRY_ID, entry);
	CHECK(ask(&carrier.Head) == 1);
	CHECK(memcmp((char *)address + vm_page_size, FROM_RECEIVER,
			      sizeof(FROM_RECEIVER))
			== 0);

	memory_object_size_t within = sizeof(FROM_SENDER);
	mach_port_t data_entry = MACH_PORT_NULL;
	memcpy((char *)address + 100, FROM_SENDER, sizeof(FROM_SENDER));
	CHECK(mach_make_memory_entry_64(mach_task_self(), &within,
			      address + 100, MAP_MEM_USE_DATA_ADDR | rw,
			      &data_entry, MACH_PORT_NULL)
			== KERN_SUCCESS);
	carrier = carrier_of(port, DATA_ENTRY_ID, data_entry);
	CHECK(ask(&carrier.Head) == 1);
	CHECK(mach_vm_deallocate(mach_task_self(), address, size)
			== KERN_SUCCESS);
}

static void
flood(mach_port_t port)
{
	static union {
		valued_t valued;
		char bytes[BULK_SIZE];
	} message;
	for (int32_t i = 0; i != BULK_COUNT; i++) {
		message.valued = (valued_t){
				.Head = {
						.msgh_bits = MACH_MSGH_BITS(
								MACH_MSG_TYPE_COPY_SEND,
								0),
						.msgh_size = sizeof(message),
						.msgh_remote_port = port,
						.msgh_id = COUNT_ID,
				},
				.value = i,
		};
		send_request(&message.valued.Head);
	}
}

static void
check_stopped_receiver(pid_t peer, mach_port_t port)
{
	stop(peer);
	flood(port);
	CHECK(bootstrap_call(LOOK_UP, PEER_NAME) == port);

	CHECK(kill(peer, SIGCONT) == 0);
	CHECK(ask_for(port, REPORT_ID) == BULK_COUNT);
}

static void
check_killed_receiver(void)
{
	peer_name = VICTIM_NAME;
	pid_t victim = start(serve_peer);
	pid_t guardian = guard(victim);
	mach_port_t port = look_up(VICTIM_NAME);

	stop(victim);
	flood(port);
	int read_end;
	carrier_t carrier = carrier_of(
			port, FILEPORT_ID, fileport_of_pipe(&read_end));
	send_request(&carrier.Head);
	CHECK(bootstrap_call(LOOK_UP, VICTIM_NAME) == port);
	CHECK(kill(victim, SIGKILL) == 0);
	int status = reap(victim);
	CHECK(WIFSIGNALED(status));

	char byte;
	CHECK(read(read_end, &byte, sizeof(byte)) == 0);
	CHECK(close(read_end) == 0);
	kill(guardian, SIGKILL);
	reap(guardian);
}

static void
check_descriptors_wait(pid_t peer, mach_port_t port)
{
	static carriers_t carriers;
	carry(&carriers, port, MANY_PORTS);
	carry_offsets(&carriers, MACH_MSG_TYPE_COPY_SEND);

	stop(peer);
	flood(port);
	mach_port_t replies[WAITING];
	for (int i = 0; i != WAITING; i++) {
		replies[i] = post(&carriers.Head);
	}
	CHECK(bootstrap_call(LOOK_UP, PEER_NAME) == port);

	CHECK(kill(peer, SIGCONT) == 0);
	for (int i = 0; i != WAITING; i++) {
		CHECK(collect(replies[i]) == MANY_PORTS);
	}
	CHECK(ask_for(port, REPORT_ID) == BULK_COUNT);
	for (int i = 0; i != MANY_PORTS; i++) {
		CHECK(mach_port_deallocate(
				      mach_task_self(), carriers.ports[i].name)
				== KERN_SUCCESS);
	}
}

static child_t
start_peer(const char *name)
{
	peer_name = name;
	child_t child = {.pid = start(serve_peer)};
	child.guardian = guard(child.pid);
	child.port = look_up(name);
	return child;
}

static void
end_peer(const child_t *child)
{
	kill(child->pid, SIGKILL);
	int status = reap(child->pid);
	CHECK(WIFSIGNALED(status));
	kill(child->guardian, SIGKILL);
	reap(child->guardian);
}

static mach_port_name_t
receive_raw_port(mach_port_t home)
{
	struct {
		mach_msg_header_t Head;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
		mach_msg_ool_descriptor_t data;
		mach_msg_trailer_t trailer;
	} message;
	kern_return_t kr = mach_msg(&message.Head,
			MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(message),
			home, ANSWER_MS, MACH_PORT_NULL);
	CHECK(kr == MACH_MSG_SUCCESS);
	return message.port.name;
}

static void
check_gone_process(void)
{
	mach_port_t home = bootstrap_call(CHECK_IN, HOME_NAME);
	CHECK(home != MACH_PORT_NULL);
	child_t gone = start_peer(GONE_NAME);
	int fd = connect_raw();
	raw_message_t raw = raw_message(look_up_raw(fd, HOME_NAME));
	raw.id = look_up_raw(fd, GONE_NAME);
	mach_port_t notify = request_notification(
			gone.port, MACH_NOTIFY_DEAD_NAME);
	mach_port_name_t name;
	CHECK(receive_notification(notify, MACH_NOTIFY_DEAD_NAME, 100, &name)
			== MACH_RCV_TIMED_OUT);

	end_peer(&gone);
	CHECK(receive_notification(
			      notify, MACH_NOTIFY_DEAD_NAME, ANSWER_MS, &name)
			== MACH_MSG_SUCCESS);
	CHECK(name == gone.port);
	CHECK(bootstrap_call(LOOK_UP, GONE_NAME) == MACH_PORT_NULL);
	mach_port_type_t type;
	CHECK(mach_port_type(mach_task_self(), gone.port, &type)
			== KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);

	mach_msg_header_t message = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = sizeof(message),
			.msgh_remote_port = gone.port,
	};
	kern_return_t kr = mach_msg(&message, MACH_SEND_MSG, sizeof(message), 0,
			MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	CHECK(kr == MACH_SEND_INVALID_DEST);

	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	CHECK(receive_raw_port(home) == MACH_PORT_DEAD);
	raw.id++;
	send_raw(fd, BROKER_SEND, &raw, sizeof(raw));
	CHECK(receive_raw_port(home) == MACH_PORT_DEAD);
	CHECK(close(fd) == 0);
	kr = mach_port_mod_refs(mach_task_self(), gone.port,
			MACH_PORT_RIGHT_DEAD_NAME, -2);
	CHECK(kr == KERN_SUCCESS);
	kr = mach_port_mod_refs(
			mach_task_self(), notify, MACH_PORT_RIGHT_RECEIVE, -1);
	CHECK(kr == KERN_SUCCESS);
}

static bool
has_senders(mach_port_t port)
{
	mach_port_status_t status;
	mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
	kern_return_t kr = mach_port_get_attributes(mach_task_self(), port,
			MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status,
			&count);
	CHECK(kr == KERN_SUCCESS);
	return status.mps_srights;
}

static void
destroy_port(mach_port_t port)
{
	kern_return_t kr = mach_port_mod_refs(
			mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
	CHECK(kr == KERN_SUCCESS);
}

static mach_port_t
give_send_right(mach_port_t to)
{
	mach_port_t port;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	carrier_t carrier = carrier_of(to, KEEP_ID, port);
	carrier.port.disposition = MACH_MSG_TYPE_MAKE_SEND;
	CHECK(ask(&carrier.Head) == 1);
	return port;
}

static void
check_sender_counts(void)
{
	child_t holder = start_peer(HOLDER_NAME);
	mach_port_t port = give_send_right(holder.port);
	mach_port_t notify = request_notification(port, MACH_NOTIFY_NO_SENDERS);
	mach_port_name_t count;
	CHECK(receive_notification(notify, MACH_NOTIFY_NO_SENDERS, 100, &count)
			== MACH_RCV_TIMED_OUT);
	CHECK(has_senders(port));

	CHECK(ask_for(holder.port, DROP_ID) == KERN_SUCCESS);
	CHECK(receive_notification(
			      notify, MACH_NOTIFY_NO_SENDERS, ANSWER_MS, &count)
			== MACH_MSG_SUCCESS);
	CHECK(count == 1);
	CHECK(!has_senders(port));
	destroy_port(notify);
	destroy_port(port);

	child_t third = start_peer(THIRD_NAME);
	port = give_send_right(holder.port);
	notify = request_notification(port, MACH_NOTIFY_NO_SENDERS);
	carrier_t carrier = carrier_of(holder.port, FORWARD_ID, third.port);
	carrier.port.disposition = MACH_MSG_TYPE_COPY_SEND;
	CHECK(ask(&carrier.Head) == 1);
	CHECK(receive_notification(notify, MACH_NOTIFY_NO_SENDERS, 100, &count)
			== MACH_RCV_TIMED_OUT);
	CHECK(has_senders(port));
	CHECK(ask_for(third.port, DROP_ID) == KERN_SUCCESS);
	CHECK(receive_notification(
			      notify, MACH_NOTIFY_NO_SENDERS, ANSWER_MS, &count)
			== MACH_MSG_SUCCESS);
	destroy_port(notify);
	destroy_port(port);
	end_peer(&third);

	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	carrier = carrier_of(holder.port, KEEP_ID, port);
	carrier.port.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
	CHECK(ask(&carrier.Head) == 1);
	CHECK(ask_for(holder.port, WATCH_ID) == 1);
	CHECK(ask_for(holder.port, WATCHED_ID) == 0);
	CHECK(mach_port_deallocate(mach_task_self(), port) == KERN_SUCCESS);
	CHECK(ask_for(holder.port, WATCHED_ID) == 1);

	port = give_send_right(holder.port);
	CHECK(ask_for(holder.port, TYPE_ID) == MACH_PORT_TYPE_SEND);
	destroy_port(port);
	CHECK(ask_for(holder.port, TYPE_ID) == MACH_PORT_TYPE_DEAD_NAME);
	CHECK(ask_for(holder.port, DROP_ID) == KERN_SUCCESS);

	port = give_send_right(holder.port);
	notify = request_notification(port, MACH_NOTIFY_NO_SENDERS);
	end_peer(&holder);
	CHECK(receive_notification(
			      notify, MACH_NOTIFY_NO_SENDERS, ANSWER_MS, &count)
			== MACH_MSG_SUCCESS);
	CHECK(!has_senders(port));
	destroy_port(notify);
	destroy_port(port);
}

static void
check_failed_send(mach_port_t to)
{
	mach_port_t port;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	mach_port_t reply;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply);
	static union {
		carrier_t carrier;
		char bytes[OVERSIZED];
	} message;
	message.carrier = carrier_of(to, KEEP_ID, port);
	message.carrier.Head.msgh_bits
			|= MACH_MSGH_BITS(0, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	message.carrier.Head.msgh_local_port = reply;
	message.carrier.Head.msgh_size = sizeof(message);
	message.carrier.port.disposition = MACH_MSG_TYPE_MAKE_SEND;
	kern_return_t kr = mach_msg(&message.carrier.Head, MACH_SEND_MSG,
			sizeof(message), 0, MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	CHECK(kr == MACH_SEND_TOO_LARGE);

	CHECK(!has_senders(port));
	mach_port_name_t unused;
	CHECK(receive_notification(
			      reply, MACH_NOTIFY_SEND_ONCE, ANSWER_MS, &unused)
			== MACH_MSG_SUCCESS);
	destroy_port(reply);
	destroy_port(port);
}

static mach_port_t
post_for(mach_port_t port, mach_msg_id_t id)
{
	mach_msg_header_t request = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = sizeof(request),
			.msgh_remote_port = port,
			.msgh_id = id,
	};
	return post(&request);
}

static void
check_send_once_rights(void)
{
	child_t holder = start_peer(HOLDER_NAME);
	mach_port_t reply = post_for(holder.port, HOLD_REPLY_ID);
	mach_port_name_t unused;
	CHECK(receive_notification(reply, MACH_NOTIFY_SEND_ONCE, 100, &unused)
			== MACH_RCV_TIMED_OUT);
	CHECK(ask_for(holder.port, DROP_REPLY_ID) == KERN_SUCCESS);
	CHECK(receive_notification(
			      reply, MACH_NOTIFY_SEND_ONCE, ANSWER_MS, &unused)
			== MACH_MSG_SUCCESS);
	destroy_port(reply);

	check_failed_send(holder.port);
	CHECK(ask_for(holder.port, CHECK_IN_ID) == 1);
	mach_port_t doomed = look_up(DOOMED_NAME);
	CHECK(ask_for(holder.port, DESTROY_ID) == KERN_SUCCESS);
	reply = post_for(doomed, MARK_ID);
	CHECK(receive_notification(
			      reply, MACH_NOTIFY_SEND_ONCE, ANSWER_MS, &unused)
			== MACH_MSG_SUCCESS);
	destroy_port(reply);

	reply = post_for(holder.port, HOLD_REPLY_ID);
	CHECK(ask_for(holder.port, TYPE_ID) == 0);
	end_peer(&holder);
	CHECK(receive_notification(
			      reply, MACH_NOTIFY_SEND_ONCE, ANSWER_MS, &unused)
			== MACH_MSG_SUCCESS);
	destroy_port(reply);
}

static void
check_transport(void)
{
	pid_t peer = start(serve_peer);
	pid_t guardian = guard(peer);
	mach_port_t port = look_up(PEER_NAME);

	check_oversized(port);
	check_stopped_receiver(peer, port);
	check_large_frames(port);
	check_short_frames(port);
	check_malformed_messages(port);
	check_fileport(port);
	check_many_fileports(port);
	check_memory_entry(port);
	check_descriptors_wait(peer, port);

	send_quit(port);
	int status = reap(peer);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	kill(guardian, SIGKILL);
	reap(guardian);
	check_killed_receiver();
}

int
main(int argc, char *argv[])
{
	if (argc == 3 && strcmp(argv[1], "descriptors") == 0) {
		return open_descriptors() != atoi(argv[2]);
	}
	program = argv[0];
	check_exec();
	check_lost_connection();

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
	check_gone_process();
	check_sender_counts();
	check_send_once_rights();
	return 0;
}
