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

struct connection {
	int fd;
	uint32_t guest_id;
	struct broker_wire_frame *pending;
	struct broker_wire_frame *last_pending;
	struct broker_wire_ahead ahead;
};

struct service {
	uint64_t global_id;
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
};

static void raise_file_limit(void);
static void run(int listen_fd);
static void accept_guest(int listen_fd);
static void handle_guest(int fd);
static void welcome_guest(struct connection *conn);
static void register_service(const struct broker_register *reg);
static void look_up_service(struct connection *conn,
		const struct broker_lookup *req);
static void route_send(struct broker_wire_frame *frame);
static struct connection *connection_for_fd(int fd);
static struct connection *connection_for_guest(uint32_t guest_id);
static struct service *service_named(const char *name);
static void forget_services(uint32_t guest_id);
static void add_connection(int fd);
static void remove_connection(size_t index);
static void send_frame(struct connection *conn, uint32_t type,
		const void *payload, uint32_t length);
static void queue_frame(
		struct connection *conn, struct broker_wire_frame *frame);
static void send_pending(struct connection *conn);
static bool send_data(int fd, struct broker_wire_frame *frame);

static struct connection *connections;
static size_t connection_count;
static struct service *services;
static size_t service_count;
static uint32_t next_guest_id = 1;

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
}

static void
run(int listen_fd)
{
	for (;;) {
		size_t polled = connection_count;
		struct pollfd *fds = calloc(polled + 1, sizeof(*fds));
		fds[0] = (struct pollfd){ .fd = listen_fd, .events = POLLIN };
		for (size_t i = 0; i != polled; i++) {
			fds[i + 1] = (struct pollfd){
					.fd = connections[i].fd,
					.events
					= POLLIN | (connections[i].pending != NULL ? POLLOUT : 0),
			};
		}

		poll(fds, polled + 1, -1);

		if (fds[0].revents & POLLIN) {
			accept_guest(listen_fd);
		}
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

static void
accept_guest(int listen_fd)
{
	int fd = accept(listen_fd, NULL, NULL);
	if (fd >= 0) {
		add_connection(fd);
	}
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
		return;
	}

	union {
		struct broker_register reg;
		struct broker_lookup lookup;
	} request;
	switch (frame->type & ~BROKER_FRAME_OOL) {
	case BROKER_HELLO:
		welcome_guest(conn);
		break;
	case BROKER_REGISTER:
		if (broker_wire_read(frame, 0, &request.reg,
				    sizeof(request.reg))) {
			request.reg.name[sizeof(request.reg.name) - 1] = '\0';
			register_service(&request.reg);
		}
		break;
	case BROKER_LOOKUP:
		if (broker_wire_read(frame, 0, &request.lookup,
				    sizeof(request.lookup))) {
			request.lookup.name[sizeof(request.lookup.name) - 1]
					= '\0';
			look_up_service(conn, &request.lookup);
		}
		break;
	case BROKER_SEND:
		route_send(frame);
		return;
	}
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

static void
register_service(const struct broker_register *reg)
{
	struct service *service = service_named(reg->name);
	if (service == NULL) {
		services = reallocarray(services, service_count + 1,
				sizeof(*services));
		service = &services[service_count++];
		strncpy(service->name, reg->name, sizeof(service->name) - 1);
	}
	service->global_id = reg->global_id;
}

static void
look_up_service(struct connection *conn, const struct broker_lookup *req)
{
	struct service *service = service_named(req->name);
	struct broker_lookup_reply reply = {
		.found = service != NULL,
		.global_id = (service != NULL) ? service->global_id : 0,
	};
	send_frame(conn, BROKER_LOOKUP_REPLY, &reply, sizeof(reply));
}

static void
route_send(struct broker_wire_frame *frame)
{
	struct broker_send send;
	struct connection *owner = frame->inline_length >= sizeof(send)
					&& broker_wire_read(frame, 0, &send,
							sizeof(send))
			? connection_for_guest(
					  broker_guest_of(send.dest_global_id))
			: NULL;
	if (owner == NULL) {
		broker_wire_free(frame);
		return;
	}

	frame->type = BROKER_DELIVER | (frame->type & BROKER_FRAME_OOL);
	queue_frame(owner, frame);
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
forget_services(uint32_t guest_id)
{
	size_t kept = 0;
	for (size_t i = 0; i != service_count; i++) {
		if (broker_guest_of(services[i].global_id) != guest_id) {
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
	connections[connection_count++] = (struct connection){ .fd = fd };
}

static void
remove_connection(size_t index)
{
	while (connections[index].pending != NULL) {
		struct broker_wire_frame *frame = connections[index].pending;
		connections[index].pending = frame->next;
		broker_wire_free(frame);
	}
	broker_wire_forget(&connections[index].ahead);
	close(connections[index].fd);
	struct broker_guest_gone gone = {
			.guest_id = connections[index].guest_id,
	};
	connections[index] = connections[--connection_count];

	forget_services(gone.guest_id);
	for (size_t i = 0; gone.guest_id != 0 && i != connection_count; i++) {
		send_frame(&connections[i], BROKER_GUEST_GONE, &gone,
				sizeof(gone));
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
		if (!send_data(conn->fd, frame)) {
			return;
		}
		conn->pending = frame->next;
		broker_wire_free(frame);
	}
}

static bool
send_data(int fd, struct broker_wire_frame *frame)
{
	int error = broker_wire_send(fd, frame, MSG_DONTWAIT);
	return error != EAGAIN && error != EWOULDBLOCK;
}
