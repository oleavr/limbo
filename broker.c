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
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "broker.h"
#include "osfmk/ipc_remote.h"

#define CONNECTION_FDS  (2 * BROKER_FDS_MAX)
#define ACCEPT_RETRY_MS 1000

struct connection {
	int fd;
	uint32_t guest_id;
	pid_t pid;
	uid_t peer_uid;
	gid_t peer_gid;
	size_t queued_fds;
	struct broker_wire_frame *pending;
	struct broker_wire_frame *last_pending;
	struct broker_wire_ahead ahead;
};

union broker_request {
	struct broker_register reg;
	struct broker_lookup lookup;
	struct broker_task_for_pid task_for_pid;
};

struct held_send {
	struct held_send *next;
	struct broker_wire_frame *frame;
};

struct route {
	uint64_t global_id;
	uint32_t guest_id;
	uint32_t mover_id;
	struct held_send *held;
};

struct service {
	uint32_t guest_id;
	uint64_t global_id;
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
};

static void raise_file_limit(void);
static void run(int listen_fd);
static bool accept_guest(int listen_fd);
static size_t fds_ahead(void);
static void release_queued(struct connection *conn, size_t fd_count);
static void handle_guest(int fd);
static void welcome_guest(struct connection *conn);
static struct broker_registered broker_names_register(
		uint32_t guest_id, const struct broker_register *reg);
static struct broker_lookup_reply broker_names_look_up(
		const struct broker_lookup *req);
static void look_up_service(struct connection *conn,
		const struct broker_lookup *req);
static void task_for_pid(
		struct connection *conn, const struct broker_task_for_pid *req);
static void route_send(
		struct connection *conn, struct broker_wire_frame *frame);
static void pass_on(struct broker_wire_frame *frame, struct broker_send *send,
		uint32_t mover_id);
static void set_route(uint64_t global_id, uint32_t guest_id, uint32_t mover_id);
static void release_held(uint64_t global_id);
static struct route *route_for(uint64_t global_id);
static uint32_t route_of(uint64_t global_id);
static void forget_routes(uint32_t guest_id);
static void take_notice(
		struct connection *conn, const struct broker_wire_frame *frame);
static struct connection *connection_for_fd(int fd);
static struct connection *connection_for_guest(uint32_t guest_id);
static struct service *service_named(const char *name);
static void broker_names_forget(uint32_t guest_id);
static void broker_names_forget_port(uint64_t global_id);
static void add_connection(int fd);
static void remove_connection(size_t index);
static void send_frame(struct connection *conn, uint32_t type,
		const void *payload, uint32_t length);
static void queue_frame(
		struct connection *conn, struct broker_wire_frame *frame);
static void send_pending(struct connection *conn);
static bool send_data(int fd, struct broker_wire_frame *frame);

static struct connection *connections;
static struct route *routes;
static size_t route_count;
static size_t connection_count;
static struct service *services;
static size_t service_count;
static uint32_t next_guest_id = 1;
static size_t descriptor_room;
static size_t queued_fds;

int
main(int argc, char *argv[])
{
	const char *path = (argc > 1) ? argv[1] : getenv(LIMBO_BROKER_SOCKET_ENV);
	if (path == NULL) {
		fprintf(stderr, "limbo-broker: no socket path\n");
		return 1;
	}

	int listen_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	unlink(path);
	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
		return 1;
	}
	listen(listen_fd, 64);

	raise_file_limit();
	run(listen_fd);
	return 0;
}

static void
raise_file_limit(void)
{
	struct rlimit limit;
	if (getrlimit(RLIMIT_NOFILE, &limit) == 0
			&& limit.rlim_cur < limit.rlim_max) {
		limit.rlim_cur = limit.rlim_max;
		setrlimit(RLIMIT_NOFILE, &limit);
	}
	getrlimit(RLIMIT_NOFILE, &limit);
	descriptor_room = limit.rlim_cur / 2;
}

static void
run(int listen_fd)
{
	bool listening = true;
	for (;;) {
		size_t polled = connection_count;
		struct pollfd *fds = calloc(polled + 1, sizeof(*fds));
		fds[0] = (struct pollfd){
				.fd = listen_fd,
				.events = listening ? POLLIN : 0,
		};
		for (size_t i = 0; i != polled; i++) {
			fds[i + 1] = (struct pollfd){
					.fd = connections[i].fd,
					.events
					= POLLIN | (connections[i].pending != NULL ? POLLOUT : 0),
			};
		}

		poll(fds, polled + 1, listening ? -1 : ACCEPT_RETRY_MS);

		listening = !(fds[0].revents & POLLIN)
				|| accept_guest(listen_fd);
		for (size_t i = 0; i != polled; i++) {
			if (fds[i + 1].revents & POLLOUT) {
				send_pending(connection_for_fd(fds[i + 1].fd));
			}
			if (fds[i + 1].revents & (POLLIN | POLLHUP)) {
				handle_guest(fds[i + 1].fd);
			}
		}

		free(fds);
	}
}

static bool
accept_guest(int listen_fd)
{
	int fd = accept(listen_fd, NULL, NULL);
	if (fd >= 0) {
		add_connection(fd);
	}
	return fd >= 0;
}

static void
handle_guest(int fd)
{
	size_t index = 0;
	while (connections[index].fd != fd) {
		index++;
	}
	struct connection *conn = &connections[index];

	struct broker_wire_frame *frame;
	int received = broker_wire_receive(fd, &conn->ahead, &frame);
	if (received == -1) {
		remove_connection(index);
		return;
	}
	if (received == 0) {
		if (conn->ahead.count != 0
				&& queued_fds + fds_ahead() > descriptor_room) {
			broker_wire_forget(&conn->ahead);
			conn->ahead.lost = true;
		}
		return;
	}
	uint32_t type = frame->type & ~BROKER_FRAME_OOL;
	if (type == BROKER_SEND && !frame->lost) {
		route_send(conn, frame);
		return;
	}

	uint32_t length = frame->length;
	char *payload = calloc(1,
			length > sizeof(union broker_request)
					? length
					: sizeof(union broker_request));
	if (frame->lost || !broker_wire_read(frame, 0, payload, length)) {
		free(payload);
		broker_wire_free(frame);
		return;
	}

	switch (type) {
	case BROKER_HELLO:
		welcome_guest(conn);
		break;
	case BROKER_REGISTER: {
		if (length < sizeof(struct broker_register)) {
			break;
		}
		struct broker_register *reg = (struct broker_register *)payload;
		reg->name[sizeof(reg->name) - 1] = '\0';
		struct broker_registered registered
				= broker_names_register(conn->guest_id, reg);
		send_frame(conn, BROKER_REGISTERED, &registered,
				sizeof(registered));
		break;
	}
	case BROKER_LOOKUP: {
		if (length < sizeof(struct broker_lookup)) {
			break;
		}
		struct broker_lookup *lookup = (struct broker_lookup *)payload;
		lookup->name[sizeof(lookup->name) - 1] = '\0';
		look_up_service(conn, lookup);
		break;
	}
	case BROKER_TASK_FOR_PID:
		task_for_pid(conn, (const struct broker_task_for_pid *)payload);
		break;
	}
	free(payload);
	broker_wire_free(frame);
}

static void
welcome_guest(struct connection *conn)
{
	if (conn->guest_id == 0) {
		conn->guest_id = next_guest_id++;
	}
	struct broker_welcome welcome = { .guest_id = conn->guest_id };
	send_frame(conn, BROKER_WELCOME, &welcome, sizeof(welcome));
}

static struct broker_registered
broker_names_register(uint32_t guest_id, const struct broker_register *reg)
{
	struct service *service = service_named(reg->name);
	if (service != NULL) {
		return (struct broker_registered){
				.holder = service->guest_id == guest_id
						? BROKER_NAME_ASKERS
						: BROKER_NAME_ANOTHERS,
		};
	}

	services = reallocarray(services, service_count + 1, sizeof(*services));
	service = &services[service_count++];
	*service = (struct service){
			.guest_id = guest_id,
			.global_id = reg->global_id,
	};
	strncpy(service->name, reg->name, sizeof(service->name) - 1);
	return (struct broker_registered){.holder = BROKER_NAME_FREE};
}

static struct broker_lookup_reply
broker_names_look_up(const struct broker_lookup *req)
{
	struct service *service = service_named(req->name);
	return (struct broker_lookup_reply){
			.found = service != NULL,
			.global_id = (service != NULL) ? service->global_id : 0,
	};
}

static void
look_up_service(struct connection *conn, const struct broker_lookup *req)
{
	struct broker_lookup_reply reply = broker_names_look_up(req);
	send_frame(conn, BROKER_LOOKUP_REPLY, &reply, sizeof(reply));
}

static void
task_for_pid(struct connection *conn, const struct broker_task_for_pid *req)
{
	struct connection *target = NULL;
	for (size_t i = 0; i != connection_count; i++) {
		struct connection *candidate = &connections[i];
		if (candidate->pid == req->pid && candidate->guest_id != 0
				&& (target == NULL
						|| candidate->guest_id
								> target->guest_id)) {
			target = candidate;
		}
	}
	bool allowed = target != NULL
			&& (conn->peer_uid == 0
					|| conn->peer_uid == target->peer_uid);
	struct broker_lookup_reply reply = {
			.found = allowed,
			.global_id
			= allowed ? broker_global_id(target->guest_id,
						    BROKER_TASK_PORT_LOCAL)
				  : 0,
	};
	send_frame(conn, BROKER_LOOKUP_REPLY, &reply, sizeof(reply));
}

static void
route_send(struct connection *conn, struct broker_wire_frame *frame)
{
	struct broker_send send;
	if (frame->inline_length < sizeof(send)
			|| !broker_wire_read(frame, 0, &send, sizeof(send))) {
		broker_wire_free(frame);
		return;
	}
	uint32_t guest_id = broker_guest_of(send.dest_global_id);
	if (guest_id == BROKER_GUEST_ID) {
		take_notice(conn, frame);
		broker_wire_free(frame);
		return;
	}
	struct route *route = route_for(send.dest_global_id);
	if (route != NULL && route->mover_id != 0
			&& route->mover_id != conn->guest_id) {
		struct held_send **tail = &route->held;
		while (*tail != NULL) {
			tail = &(*tail)->next;
		}
		*tail = malloc(sizeof(**tail));
		**tail = (struct held_send){.frame = frame};
		return;
	}
	pass_on(frame, &send, conn->guest_id);
}

static void
pass_on(struct broker_wire_frame *frame, struct broker_send *send,
		uint32_t mover_id)
{
	struct connection *owner
			= connection_for_guest(route_of(send->dest_global_id));
	if (owner == NULL) {
		broker_wire_free(frame);
		return;
	}
	uint32_t moved_at = sizeof(*send) + send->blob_length;
	uint32_t moved_count
			= send->blob_length <= frame->length - sizeof(*send)
			? (frame->length - moved_at) / sizeof(uint64_t)
			: 0;
	uint64_t *moved = moved_count != 0
			? malloc(moved_count * sizeof(*moved))
			: NULL;
	if (moved != NULL
			&& !broker_wire_read(frame, moved_at, moved,
					moved_count * sizeof(*moved))) {
		moved_count = 0;
	}

	send->sender = (struct broker_sender){0};
	memcpy(frame->payload, send, sizeof(*send));
	frame->type = BROKER_DELIVER | (frame->type & BROKER_FRAME_OOL);
	uint32_t guest_id = owner->guest_id;
	queue_frame(owner, frame);
	for (uint32_t i = 0; i != moved_count; i++) {
		set_route(moved[i], guest_id, mover_id);
	}
	free(moved);
}

static void
set_route(uint64_t global_id, uint32_t guest_id, uint32_t mover_id)
{
	struct route *route = route_for(global_id);
	if (route == NULL && guest_id == broker_guest_of(global_id)
			&& mover_id == 0) {
		return;
	}
	if (route == NULL) {
		routes = reallocarray(routes, route_count + 1, sizeof(*routes));
		route = &routes[route_count++];
		*route = (struct route){.global_id = global_id};
	}
	route->guest_id = guest_id;
	route->mover_id = mover_id;
	if (route->held == NULL && mover_id == 0
			&& guest_id == broker_guest_of(global_id)) {
		*route = routes[--route_count];
	}
}

static void
release_held(uint64_t global_id)
{
	struct route *route = route_for(global_id);
	if (route == NULL) {
		return;
	}
	struct held_send *held = route->held;
	route->held = NULL;
	set_route(global_id, route->guest_id, 0);
	while (held != NULL) {
		struct held_send *next = held->next;
		struct broker_send send;
		broker_wire_read(held->frame, 0, &send, sizeof(send));
		pass_on(held->frame, &send, 0);
		free(held);
		held = next;
	}
}

static struct route *
route_for(uint64_t global_id)
{
	for (size_t i = 0; i != route_count; i++) {
		if (routes[i].global_id == global_id) {
			return &routes[i];
		}
	}
	return NULL;
}

static uint32_t
route_of(uint64_t global_id)
{
	struct route *route = route_for(global_id);
	return route != NULL ? route->guest_id : broker_guest_of(global_id);
}

static void
take_notice(struct connection *conn, const struct broker_wire_frame *frame)
{
	struct {
		struct broker_send send;
		struct remote_header header;
		struct remote_notice notice;
	} blob;
	if (frame->inline_length >= sizeof(blob)
			&& broker_wire_read(frame, 0, &blob, sizeof(blob))
			&& blob.header.message_size == 0
			&& blob.notice.kind == REMOTE_NOTICE_DEAD) {
		broker_names_forget_port(blob.notice.count);
	} else if (frame->inline_length >= sizeof(blob)
			&& blob.header.message_size == 0
			&& blob.notice.kind == REMOTE_NOTICE_RETURNED) {
		release_held(blob.notice.count);
		set_route(blob.notice.count, conn->guest_id, 0);
	} else if (frame->inline_length >= sizeof(blob)
			&& blob.header.message_size == 0
			&& blob.notice.kind == REMOTE_NOTICE_QUEUE_SENT
			&& route_for(blob.notice.count) != NULL
			&& route_for(blob.notice.count)->mover_id
					== conn->guest_id) {
		release_held(blob.notice.count);
	}
}

static struct connection *
connection_for_fd(int fd)
{
	for (size_t i = 0; i != connection_count; i++) {
		if (connections[i].fd == fd) {
			return &connections[i];
		}
	}
	return NULL;
}

static struct connection *
connection_for_guest(uint32_t guest_id)
{
	for (size_t i = 0; i != connection_count; i++) {
		if (connections[i].guest_id == guest_id) {
			return &connections[i];
		}
	}
	return NULL;
}

static struct service *
service_named(const char *name)
{
	for (size_t i = 0; i != service_count; i++) {
		if (strcmp(services[i].name, name) == 0) {
			return &services[i];
		}
	}
	return NULL;
}

static void
broker_names_forget(uint32_t guest_id)
{
	size_t kept = 0;
	for (size_t i = 0; i != service_count; i++) {
		if (services[i].guest_id != guest_id
				&& broker_guest_of(services[i].global_id)
						!= guest_id) {
			services[kept++] = services[i];
		}
	}
	service_count = kept;
}

static void
broker_names_forget_port(uint64_t global_id)
{
	size_t kept = 0;
	for (size_t i = 0; i != service_count; i++) {
		if (services[i].global_id != global_id) {
			services[kept++] = services[i];
		}
	}
	service_count = kept;
}

static void
add_connection(int fd)
{
	connections = reallocarray(connections, connection_count + 1,
			sizeof(*connections));
	struct ucred cred = {.uid = (uid_t)-1, .gid = (gid_t)-1};
	socklen_t cred_length = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_length) != 0) {
		cred = (struct ucred){.uid = (uid_t)-1, .gid = (gid_t)-1};
	}
	connections[connection_count++] = (struct connection){
			.fd = fd,
			.pid = cred.pid,
			.peer_uid = cred.uid,
			.peer_gid = cred.gid,
	};
}

static void
remove_connection(size_t index)
{
	while (connections[index].pending != NULL) {
		struct broker_wire_frame *frame = connections[index].pending;
		connections[index].pending = frame->next;
		broker_wire_free(frame);
	}
	release_queued(&connections[index], connections[index].queued_fds);
	broker_wire_forget(&connections[index].ahead);
	close(connections[index].fd);
	struct broker_guest_gone gone = {
			.guest_id = connections[index].guest_id,
	};
	connections[index] = connections[--connection_count];

	broker_names_forget(gone.guest_id);
	if (gone.guest_id != 0) {
		forget_routes(gone.guest_id);
	}
	for (size_t i = 0; gone.guest_id != 0 && i != connection_count; i++) {
		send_frame(&connections[i], BROKER_GUEST_GONE, &gone,
				sizeof(gone));
	}
}

static void
forget_routes(uint32_t guest_id)
{
	for (size_t i = 0; i < route_count;) {
		if (routes[i].mover_id != guest_id) {
			i++;
			continue;
		}
		release_held(routes[i].global_id);
		i = 0;
	}
	for (size_t i = 0; i != route_count;) {
		struct broker_moved moved = {
				.global_id = routes[i].global_id,
				.guest_id = routes[i].guest_id,
		};
		bool lost = routes[i].guest_id == guest_id;
		bool outlives = !lost
				&& broker_guest_of(routes[i].global_id)
						== guest_id;
		if (lost) {
			broker_names_forget_port(routes[i].global_id);
			while (routes[i].held != NULL) {
				struct held_send *held = routes[i].held;
				routes[i].held = held->next;
				broker_wire_free(held->frame);
				free(held);
			}
			moved.guest_id = 0;
			routes[i] = routes[--route_count];
		} else {
			i++;
		}
		for (size_t c = 0; (lost || outlives) && c != connection_count;
				c++) {
			send_frame(&connections[c], BROKER_MOVED, &moved,
					sizeof(moved));
		}
	}
}

static void
send_frame(struct connection *conn, uint32_t type, const void *payload,
		uint32_t length)
{
	struct iovec part = {.iov_base = (void *)payload, .iov_len = length};
	queue_frame(conn, broker_wire_new(type, &part, 1, NULL, 0));
}

static void
queue_frame(struct connection *conn, struct broker_wire_frame *frame)
{
	if (conn->pending == NULL && send_data(conn->fd, frame)) {
		broker_wire_free(frame);
		return;
	}
	size_t share = descriptor_room / 2 < CONNECTION_FDS
			? descriptor_room / 2
			: CONNECTION_FDS;
	bool room = frame->fd_count == 0
			|| (conn->queued_fds + frame->fd_count <= share
					&& queued_fds + fds_ahead() + frame->fd_count
							<= descriptor_room);
	if (!room && frame->fds_sent == 0) {
		broker_wire_free(frame);
		return;
	}
	conn->queued_fds += frame->fd_count;
	queued_fds += frame->fd_count;
	frame->next = NULL;
	if (conn->pending == NULL) {
		conn->pending = frame;
	} else {
		conn->last_pending->next = frame;
	}
	conn->last_pending = frame;
}

static void
send_pending(struct connection *conn)
{
	while (conn->pending != NULL) {
		struct broker_wire_frame *frame = conn->pending;
		size_t held = frame->fd_count;
		if (!send_data(conn->fd, frame)) {
			release_queued(conn, held - frame->fd_count);
			return;
		}
		release_queued(conn, held);
		conn->pending = frame->next;
		broker_wire_free(frame);
	}
}

static void
release_queued(struct connection *conn, size_t fd_count)
{
	conn->queued_fds -= fd_count;
	queued_fds -= fd_count;
}

static size_t
fds_ahead(void)
{
	size_t count = 0;
	for (size_t i = 0; i != connection_count; i++) {
		count += connections[i].ahead.count;
	}
	return count;
}

static bool
send_data(int fd, struct broker_wire_frame *frame)
{
	int error = broker_wire_send(fd, frame, MSG_DONTWAIT);
	return error != EAGAIN && error != EWOULDBLOCK;
}
