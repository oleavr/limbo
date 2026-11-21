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
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "broker.h"

#define BROKER_FRAME_MAX (1 << 20)

struct pending_frame {
	struct pending_frame *next;
	size_t length;
	char data[];
};

struct connection {
	int fd;
	uint32_t guest_id;
	struct pending_frame *pending;
	struct pending_frame *last_pending;
};

struct service {
	uint64_t global_id;
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
};

static void run(int listen_fd);
static void accept_guest(int listen_fd);
static void handle_guest(int fd);
static void welcome_guest(struct connection *conn);
static void register_service(const struct broker_register *reg);
static void look_up_service(struct connection *conn,
		const struct broker_lookup *req);
static void route_send(const struct broker_send *send, const void *blob);
static struct connection *connection_for_fd(int fd);
static struct connection *connection_for_guest(uint32_t guest_id);
static struct service *service_named(const char *name);
static void add_connection(int fd);
static void remove_connection(size_t index);
static void send_frame(struct connection *conn, uint32_t type,
		const void *payload, uint32_t length);
static void send_pending(struct connection *conn);
static bool send_data(int fd, const struct pending_frame *frame);
static ssize_t receive_frame(int fd, struct broker_frame *header, void *payload);

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

	run(listen_fd);
	return 0;
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

	struct broker_frame header;
	char payload[BROKER_FRAME_MAX];
	ssize_t n = receive_frame(fd, &header, payload);
	if (n <= 0) {
		remove_connection(index);
		return;
	}

	switch (header.type) {
	case BROKER_HELLO:
		welcome_guest(conn);
		break;
	case BROKER_REGISTER:
		register_service((const struct broker_register *)payload);
		break;
	case BROKER_LOOKUP:
		look_up_service(conn, (const struct broker_lookup *)payload);
		break;
	case BROKER_SEND: {
		const struct broker_send *send = (const struct broker_send *)payload;
		route_send(send, send + 1);
		break;
	}
	}
}

static void
welcome_guest(struct connection *conn)
{
	conn->guest_id = next_guest_id++;
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
route_send(const struct broker_send *send, const void *blob)
{
	struct connection *owner = connection_for_guest(
			broker_guest_of(send->dest_global_id));
	if (owner == NULL) {
		return;
	}

	size_t length = sizeof(*send) + send->blob_length;
	char *frame = malloc(length);
	memcpy(frame, send, sizeof(*send));
	memcpy(frame + sizeof(*send), blob, send->blob_length);
	send_frame(owner, BROKER_DELIVER, frame, length);
	free(frame);
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
		struct pending_frame *frame = connections[index].pending;
		connections[index].pending = frame->next;
		free(frame);
	}
	close(connections[index].fd);
	connections[index] = connections[--connection_count];
}

static void
send_frame(struct connection *conn, uint32_t type, const void *payload,
		uint32_t length)
{
	struct broker_frame header = { .type = type, .length = length };
	struct pending_frame *frame
			= malloc(sizeof(*frame) + sizeof(header) + length);
	frame->next = NULL;
	frame->length = sizeof(header) + length;
	memcpy(frame->data, &header, sizeof(header));
	memcpy(frame->data + sizeof(header), payload, length);

	if (conn->pending == NULL && send_data(conn->fd, frame)) {
		free(frame);
		return;
	}
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
		struct pending_frame *frame = conn->pending;
		if (!send_data(conn->fd, frame)) {
			return;
		}
		conn->pending = frame->next;
		free(frame);
	}
}

static bool
send_data(int fd, const struct pending_frame *frame)
{
	ssize_t n = send(fd, frame->data, frame->length, MSG_DONTWAIT);
	return n != -1 || (errno != EAGAIN && errno != EWOULDBLOCK);
}

static ssize_t
receive_frame(int fd, struct broker_frame *header, void *payload)
{
	struct iovec iov[2] = {
		{ .iov_base = header, .iov_len = sizeof(*header) },
		{ .iov_base = payload, .iov_len = BROKER_FRAME_MAX },
	};
	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };
	return recvmsg(fd, &msg, 0);
}
