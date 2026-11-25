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
#include <fcntl.h>
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
#include "launchd.h"
#include "thread.h"

static void connect_to_broker(const char *path);
static void *read_until_end(void *user);
static void *read_frames(void *user);
static void dispatch_frame(const struct broker_frame *header,
		const void *payload, const int *fds, size_t fd_count);
static void discard_frame(
		const struct broker_frame *header, const void *payload);
static uint32_t least_length(uint32_t type);
static void take_reply(const struct broker_frame *header, const void *payload);
static void expect_reply(uint32_t type, void *reply, uint32_t length);
static void stop_expecting(void);
static bool await_reply(void);
static int send_frame(uint32_t type, const void *payload, uint32_t length);
static int send_parts(uint32_t type, const struct iovec *parts, int part_count,
		const int *fds, size_t fd_count);
static mach_msg_return_t send_result(int error);
static int duplicate_fds(const int *fds, size_t fd_count, int *copies);

static int broker_fd = -1;
static uint32_t guest_id;
static pid_t launchd_pid;
static pthread_mutex_t call_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t port_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t reply_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reply_ready = PTHREAD_COND_INITIALIZER;
static bool reply_pending;
static bool reply_taken;
static bool reader_ended;
static uint32_t reply_type;
static void *reply_buffer;
static uint32_t reply_length;

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
	reader_ended = false;
	broker_client_fork_child();
}

void
broker_client_fork_child(void)
{
	pthread_mutex_init(&call_lock, NULL);
	pthread_mutex_init(&send_lock, NULL);
	pthread_mutex_init(&reply_lock, NULL);
	pthread_cond_init(&reply_ready, NULL);
}

bool
broker_client_available(void)
{
	return broker_fd != -1;
}

bool
broker_client_owns_fd(int fd)
{
	return fd != -1 && fd == broker_fd;
}

void
broker_client_fd_moved(int from, int to)
{
	if (from != -1 && broker_fd == from) {
		broker_fd = to;
	}
}

uint32_t
broker_client_guest_id(void)
{
	return guest_id;
}

bool
broker_client_call(uint32_t type, const void *request, uint32_t length,
		uint32_t reply_type, void *reply, uint32_t reply_length)
{
	pthread_mutex_lock(&call_lock);
	expect_reply(reply_type, reply, reply_length);
	bool answered = false;
	if (send_frame(type, request, length) == 0) {
		answered = await_reply();
	} else {
		stop_expecting();
	}
	pthread_mutex_unlock(&call_lock);
	return answered;
}

bool
broker_client_send_frame(int fd, int flags, uint32_t type, const void *payload,
		uint32_t length, const int *fds, size_t fd_count)
{
	int *copies = malloc(sizeof(int) * (fd_count + 1));
	int error = duplicate_fds(fds, fd_count, copies);
	struct broker_wire_frame *frame = NULL;
	if (error == 0) {
		struct iovec part = {
				.iov_base = (void *)payload, .iov_len = length};
		frame = broker_wire_new(type, &part, 1, copies, fd_count);
		if (frame == NULL) {
			error = errno;
		}
	}
	free(copies);
	if (frame != NULL) {
		error = broker_wire_send(fd, frame, flags);
		broker_wire_free(frame);
	}
	errno = error;
	return error == 0;
}

int
broker_client_receive_frame(int fd, struct broker_wire_ahead *ahead,
		struct broker_frame *header, void *payload, int *fds,
		size_t *fd_count, bool *lost)
{
	struct broker_wire_frame *frame;
	int received = broker_wire_receive(fd, ahead, &frame);
	*fd_count = 0;
	*lost = false;
	if (received != 1) {
		return received;
	}
	header->type = frame->type & ~BROKER_FRAME_OOL;
	header->length = frame->length;
	*lost = frame->lost
			|| !broker_wire_read(frame, 0, payload, frame->length);
	if (!*lost) {
		size_t own = frame->fd_count
				- ((frame->type & BROKER_FRAME_OOL) != 0);
		memcpy(fds, frame->fds, sizeof(int) * own);
		*fd_count = own;
		memmove(frame->fds, frame->fds + own,
				sizeof(int) * (frame->fd_count - own));
		frame->fd_count -= own;
	}
	broker_wire_free(frame);
	return 1;
}

static int
duplicate_fds(const int *fds, size_t fd_count, int *copies)
{
	for (size_t i = 0; i != fd_count; i++) {
		copies[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 0);
		if (copies[i] == -1) {
			int error = errno;
			while (i-- != 0) {
				close(copies[i]);
			}
			return error;
		}
	}
	return 0;
}

bool
broker_client_carries(uint64_t length, size_t fd_count)
{
	return broker_wire_carries(
			sizeof(struct broker_send) + length, fd_count);
}

pid_t
broker_client_pid(void)
{
	if (broker_fd == -1) {
		broker_client_ensure();
	}
	struct ucred peer;
	socklen_t length = sizeof(peer);
	if (broker_fd == -1
			|| getsockopt(broker_fd, SOL_SOCKET, SO_PEERCRED, &peer,
					   &length)
					!= 0) {
		return 0;
	}
	return peer.pid;
}

pid_t
broker_client_launchd_pid(void)
{
	pid_t broker = broker_client_pid();
	return broker != 0 && launchd_pid > 0 ? launchd_pid : broker;
}

bool
broker_client_is_launchd(pid_t pid)
{
	pid_t broker = broker_client_pid();
	return broker != 0
			&& (pid == broker
					|| (launchd_pid > 0
							&& pid == launchd_pid));
}

uint64_t
broker_client_launchd_port(void)
{
	static bool asked;
	static uint64_t port;
	pthread_mutex_lock(&port_lock);
	if (!asked) {
		broker_client_ensure();
		struct broker_lookup_reply reply = {0};
		asked = broker_fd == -1
				|| broker_client_call(BROKER_LAUNCHD_PORT, NULL,
						0, BROKER_LOOKUP_REPLY, &reply,
						sizeof(reply));
		port = reply.found ? reply.global_id : 0;
	}
	pthread_mutex_unlock(&port_lock);
	return port;
}

void
broker_client_hold(const char *name)
{
	struct broker_hold hold = {0};
	strncpy(hold.name, name, sizeof(hold.name) - 1);
	send_frame(BROKER_HOLD, &hold, sizeof(hold));
}

void
broker_client_jetsam_priority(int32_t pid, int32_t priority)
{
	struct broker_jetsam_priority jetsam = {pid, priority};
	send_frame(BROKER_JETSAM_PRIORITY, &jetsam, sizeof(jetsam));
}

void
broker_client_submit_service(const char *bundle)
{
	uint64_t port = broker_client_launchd_port();
	mach_port_name_t launchd = port != 0 ? ipc_names_send_right(port)
					     : MACH_PORT_NULL;
	mach_port_name_t reply = MACH_PORT_NULL;
	if (!MACH_PORT_VALID(launchd)
			|| ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, &reply)
					!= KERN_SUCCESS) {
		if (MACH_PORT_VALID(launchd)) {
			ipc_port_deallocate(launchd);
		}
		return;
	}
	union {
		struct {
			mach_msg_header_t header;
			struct broker_submit_service submit;
		} asked;
		struct {
			mach_msg_header_t header;
			mach_msg_max_trailer_t trailer;
		} answer;
	} message = {
			.asked.header = {
					.msgh_bits = MACH_MSGH_BITS(
							MACH_MSG_TYPE_MOVE_SEND,
							MACH_MSG_TYPE_MAKE_SEND_ONCE),
					.msgh_size = sizeof(message.asked),
					.msgh_remote_port = launchd,
					.msgh_local_port = reply,
					.msgh_id = LAUNCHD_SUBMIT_SERVICE_ID,
			},
	};
	strncpy(message.asked.submit.bundle, bundle,
			sizeof(message.asked.submit.bundle) - 1);
	mach_msg_return_t mr = ipc_mach_msg_kernel(&message.asked.header,
			MACH64_SEND_MSG | MACH64_RCV_MSG, sizeof(message.asked),
			sizeof(message), reply, 0);
	ipc_port_mod_refs(reply, MACH_PORT_RIGHT_RECEIVE, -1);
	if (mr >= MACH_SEND_IN_PROGRESS && mr < MACH_RCV_IN_PROGRESS) {
		ipc_port_deallocate(launchd);
	}
}

uint64_t
broker_client_task_for_pid(int32_t pid)
{
	broker_client_ensure();
	if (broker_fd == -1) {
		return 0;
	}
	struct broker_task_for_pid req = {.pid = pid};
	struct broker_lookup_reply reply = {0};
	broker_client_call(BROKER_TASK_FOR_PID, &req, sizeof(req),
			BROKER_LOOKUP_REPLY, &reply, sizeof(reply));
	return reply.found ? reply.global_id : 0;
}

mach_msg_return_t
broker_client_send(uint64_t dest_global_id, const void *blob, uint32_t length,
		const int *fds, size_t fd_count, const uint64_t *moved,
		size_t moved_count)
{

	struct broker_send send = {
			.dest_global_id = dest_global_id,
			.blob_length = length,
	};
	struct iovec parts[3] = {
			{.iov_base = &send, .iov_len = sizeof(send)},
			{.iov_base = (void *)blob, .iov_len = length},
			{.iov_base = (void *)moved,
					.iov_len
					= moved_count * sizeof(*moved)},
	};
	return send_result(send_parts(BROKER_SEND, parts,
			moved_count != 0 ? 3 : 2, fds, fd_count));
}

static void
connect_to_broker(const char *path)
{
	broker_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (broker_fd != -1 && broker_fd < 512) {
		int high = fcntl(broker_fd, F_DUPFD_CLOEXEC, 512);
		if (high != -1) {
			close(broker_fd);
			broker_fd = high;
		}
	}
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	if (connect(broker_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(broker_fd);
		broker_fd = -1;
		return;
	}

	pthread_t thread;
	thread_create_own(&thread, NULL, read_until_end, NULL);

	struct broker_welcome welcome = {0};
	expect_reply(BROKER_WELCOME, &welcome, sizeof(welcome));
	const char *domain = getenv(BROKER_DOMAIN_VARIABLE);
	struct broker_hello hello = {
			.domain = domain != NULL
					? (uint32_t)strtoul(domain, NULL, 0)
					: broker_client_domain(),
			.uid = (uint32_t)geteuid(),
	};
	struct iovec part = {.iov_base = &hello, .iov_len = sizeof(hello)};
	if (send_parts(BROKER_HELLO, &part, 1, NULL, 0) == 0) {
		await_reply();
	} else {
		stop_expecting();
	}
	guest_id = welcome.guest_id;
	launchd_pid = welcome.launchd_pid;
}

static void *
read_until_end(void *user)
{
	read_frames(user);

	pthread_mutex_lock(&reply_lock);
	reader_ended = true;
	reply_pending = false;
	pthread_cond_signal(&reply_ready);
	pthread_mutex_unlock(&reply_lock);
	ipc_remote_all_gone();
	return NULL;
}

static void *
read_frames(void *user)
{
	struct broker_wire_ahead ahead = {0};
	for (;;) {
		struct broker_wire_frame *frame;
		int received = broker_wire_receive(broker_fd, &ahead, &frame);
		if (received == -1) {
			broker_wire_forget(&ahead);
			return NULL;
		}
		if (received == 0) {
			continue;
		}

		struct broker_frame header = {
				.type = frame->type & ~BROKER_FRAME_OOL,
				.length = frame->length,
		};
		if (frame->lost) {
			discard_frame(&header, frame->payload);
			broker_wire_free(frame);
			continue;
		}
		if (!(frame->type & BROKER_FRAME_OOL)) {
			dispatch_frame(&header, frame->payload, frame->fds,
					frame->fd_count);
			broker_wire_free(frame);
			continue;
		}
		char *loaded = malloc(frame->length);
		if (broker_wire_read(frame, 0, loaded, frame->length)) {
			dispatch_frame(&header, loaded, frame->fds,
					frame->fd_count - 1);
		}
		free(loaded);
		broker_wire_free(frame);
	}
}

static void
dispatch_frame(const struct broker_frame *header, const void *payload,
		const int *fds, size_t fd_count)
{
	if (header->length < least_length(header->type)) {
		return;
	}

	switch (header->type) {
	case BROKER_WELCOME:
	case BROKER_LOOKUP_REPLY:
		take_reply(header, payload);
		break;
	case BROKER_REGISTERED: {
		const struct broker_registered *registered = payload;
		if (registered->holder == BROKER_NAME_FREE
				&& registered->held_global_id != 0) {
			ipc_names_keep(registered->global_id,
					registered->held_global_id);
		}
		take_reply(header, payload);
		break;
	}
	case BROKER_MOVED:
		ipc_remote_port_moved(((const struct broker_moved *)payload)
						      ->global_id,
				((const struct broker_moved *)payload)
						->guest_id);
		break;
	case BROKER_GUEST_GONE:
		ipc_remote_guest_gone(
				((const struct broker_guest_gone *)payload)
						->guest_id);
		break;
	case BROKER_DELIVER: {
		const struct broker_send *send = (const struct broker_send *)payload;
		if (send->blob_length <= header->length - sizeof(*send)) {
			ipc_remote_deliver(send->dest_global_id, &send->sender,
					send + 1, send->blob_length, fds,
					fd_count);
		}
		break;
	}
	}
}

static void
discard_frame(const struct broker_frame *header, const void *payload)
{
	const struct broker_send *send = payload;
	if (header->type == BROKER_DELIVER && header->length >= sizeof(*send)
			&& send->blob_length
					<= header->length - sizeof(*send)) {
		ipc_remote_lost(send->dest_global_id, send + 1,
				send->blob_length);
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
	case BROKER_REGISTERED:
		return sizeof(struct broker_registered);
	case BROKER_DELIVER:
		return sizeof(struct broker_send);
	case BROKER_MOVED:
		return sizeof(struct broker_moved);
	case BROKER_GUEST_GONE:
		return sizeof(struct broker_guest_gone);
	default:
		return 0;
	}
}

static void
take_reply(const struct broker_frame *header, const void *payload)
{
	pthread_mutex_lock(&reply_lock);
	if (reply_pending && header->type == reply_type) {
		if (reply_buffer != NULL) {
			memcpy(reply_buffer, payload,
					header->length < reply_length
							? header->length
							: reply_length);
		}
		reply_pending = false;
		reply_taken = true;
		pthread_cond_signal(&reply_ready);
	}
	pthread_mutex_unlock(&reply_lock);
}

static void
expect_reply(uint32_t type, void *reply, uint32_t length)
{
	pthread_mutex_lock(&reply_lock);
	reply_type = type;
	reply_buffer = reply;
	reply_length = length;
	reply_pending = !reader_ended;
	reply_taken = false;
	pthread_mutex_unlock(&reply_lock);
}

static void
stop_expecting(void)
{
	pthread_mutex_lock(&reply_lock);
	reply_pending = false;
	pthread_mutex_unlock(&reply_lock);
}

static bool
await_reply(void)
{
	pthread_mutex_lock(&reply_lock);
	while (reply_pending) {
		pthread_cond_wait(&reply_ready, &reply_lock);
	}
	bool taken = reply_taken;
	pthread_mutex_unlock(&reply_lock);
	return taken;
}

static int
send_frame(uint32_t type, const void *payload, uint32_t length)
{
	struct iovec part = {.iov_base = (void *)payload, .iov_len = length};
	return send_parts(type, &part, 1, NULL, 0);
}

static int
send_parts(uint32_t type, const struct iovec *parts, int part_count,
		const int *fds, size_t fd_count)
{
	struct broker_wire_frame *frame = broker_wire_new(
			type, parts, part_count, fds, fd_count);
	if (frame == NULL) {
		return errno;
	}
	pthread_mutex_lock(&send_lock);
	int error = broker_wire_send(broker_fd, frame, MSG_NOSIGNAL);
	pthread_mutex_unlock(&send_lock);
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
	case EPIPE:
	case ENOTCONN:
	case ECONNRESET:
	case EBADF:
		return MACH_SEND_INVALID_DEST;
	default:
		return MACH_SEND_NO_BUFFER;
	}
}

uint32_t
broker_client_domain(void)
{
	return geteuid() < 500 ? BROKER_DOMAIN_SYSTEM : BROKER_DOMAIN_USER;
}
