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
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "broker.h"
#include "osfmk/ipc_remote.h"

#define CONNECTION_FDS  (2 * BROKER_FDS_MAX)
#define ACCEPT_RETRY_MS 1000

struct connection {
	int fd;
	uint32_t guest_id;
	uint32_t domain;
	pid_t pid;
	uid_t peer_uid;
	gid_t peer_gid;
	size_t queued_fds;
	struct broker_wire_frame *pending;
	struct broker_wire_frame *last_pending;
	struct broker_wire_ahead ahead;
};

union broker_request {
	struct broker_hello hello;
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

struct held_name {
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
	struct held_send *queued;
	bool hidden;
	bool hides;
};

struct service {
	uint32_t guest_id;
	uint32_t domain;
	uint64_t global_id;
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
};

static void raise_file_limit(void);
static void start_launchd(const char *table);
static int launchd_wait(void);
static int64_t now_ms(void);
static void run(int listen_fd);
static void launchd_frames(void);
static bool accept_guest(int listen_fd);
static size_t fds_ahead(void);
static void release_queued(struct connection *conn, size_t fd_count);
static void handle_guest(int fd);
static void welcome_guest(
		struct connection *conn, const struct broker_hello *hello);
static void read_held_names(const char *path);
static struct held_name *name_made(const char *name);
static struct held_name *held_named(const char *name);
static void register_service(
		struct connection *conn, const struct broker_register *reg);
static struct broker_registered broker_names_register(uint32_t guest_id,
		uint32_t domain, const struct broker_register *reg);
static struct broker_lookup_reply broker_names_look_up(
		const struct broker_lookup *req);
static void look_up_service(struct connection *conn,
		const struct broker_lookup *req);
static void task_for_pid(
		struct connection *conn, const struct broker_task_for_pid *req);
static void route_send(
		struct connection *conn, struct broker_wire_frame *frame);
static void send_held(struct connection *conn, struct broker_wire_frame *frame,
		struct broker_send *send);
static struct held_name *held_of(uint64_t global_id);
static struct service *held_service(const struct held_name *held);
static uint64_t held_port(const struct held_name *held);
static void release_held_sends(struct held_name *held);
static void pass_on(struct broker_wire_frame *frame, struct broker_send *send,
		uint32_t mover_id);
static void set_route(uint64_t global_id, uint32_t guest_id, uint32_t mover_id);
static void release_held(uint64_t global_id);
static struct route *route_for(uint64_t global_id);
static uint32_t route_of(uint64_t global_id);
static void forget_routes(uint32_t guest_id);
static void tell_guests(uint32_t type, const void *payload, uint32_t length);
static uint64_t *moved_ids(const struct broker_wire_frame *frame,
		const struct broker_send *send, uint32_t *count);
static void drop_frame(struct broker_wire_frame *frame);
static void settle_moved(uint64_t global_id);
static void take_notice(
		struct connection *conn, const struct broker_wire_frame *frame);
static void hide_again(void);
static struct connection *connection_for_fd(int fd);
static struct connection *connection_for_guest(uint32_t guest_id);
static struct service *service_named(const char *name, uint32_t domain);
static void broker_names_forget(uint32_t guest_id);
static void broker_names_forget_port(uint64_t global_id);
static void add_connection(int fd);
static void remove_connection(size_t index);
static void send_frame(struct connection *conn, uint32_t type,
		const void *payload, uint32_t length);
static bool queue_frame(
		struct connection *conn, struct broker_wire_frame *frame);
static void send_pending(struct connection *conn);
static bool send_data(int fd, struct broker_wire_frame *frame);

static struct connection *connections;
static struct route *routes;
static size_t route_count;
static size_t connection_count;
static struct service *services;
static size_t service_count;
static struct held_name *held_names;
static size_t held_count;
static uint32_t next_guest_id = 1;
static size_t descriptor_room;
static size_t queued_fds;
static pid_t launchd_pid;
static int launchd_fd = -1;
static bool launchd_loaded;
static int64_t launchd_deadline;

int
main(int argc, char *argv[])
{
	const char *path = (argc > 1) ? argv[1] : getenv(LIMBO_BROKER_SOCKET_ENV);
	if (path == NULL) {
		fprintf(stderr, "limbo-broker: no socket path\n");
		return 1;
	}
	if (argc > 2) {
		read_held_names(argv[2]);
	}

	int listen_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	unlink(path);
	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
		return 1;
	}
	listen(listen_fd, 64);

	raise_file_limit();
	char socket_path[PATH_MAX];
	if (path[0] != '/'
			&& getcwd(socket_path, sizeof(socket_path)) != NULL) {
		size_t length = strlen(socket_path);
		snprintf(socket_path + length, sizeof(socket_path) - length,
				"/%s", path);
	} else {
		snprintf(socket_path, sizeof(socket_path), "%s", path);
	}
	setenv(LIMBO_BROKER_SOCKET_ENV, socket_path, 1);
	start_launchd(argc > 3 ? argv[3] : NULL);
	run(listen_fd);
	return 0;
}

static void
read_held_names(const char *path)
{
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		perror(path);
		return;
	}
	char line[LIMBO_BROKER_SERVICE_NAME_MAX + 1];
	while (fgets(line, sizeof(line), file) != NULL) {
		line[strcspn(line, "\r\n")] = '\0';
		size_t length = strlen(line);
		if (length == 0 || line[0] == '#') {
			continue;
		}
		bool hides = length > 1 && line[length - 1] == '!';
		if (hides) {
			line[length - 1] = '\0';
		}
		struct held_name *held = name_made(line);
		held->hides = hides;
		held->hidden = hides;
	}
	fclose(file);
}

static struct held_name *
name_made(const char *name)
{
	struct held_name *held = held_named(name);
	if (held != NULL) {
		return held;
	}
	held_names = reallocarray(
			held_names, held_count + 1, sizeof(*held_names));
	held = &held_names[held_count++];
	*held = (struct held_name){0};
	strncpy(held->name, name, sizeof(held->name) - 1);
	return held;
}

static struct held_name *
held_named(const char *name)
{
	for (size_t i = 0; i != held_count; i++) {
		if (strcmp(held_names[i].name, name) == 0) {
			return &held_names[i];
		}
	}
	return NULL;
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
start_launchd(const char *table)
{
	char self[PATH_MAX], limbo[PATH_MAX];
	ssize_t length = readlink("/proc/self/exe", self, sizeof(self) - 1);
	self[length > 0 ? length : 0] = '\0';
	snprintf(limbo, sizeof(limbo), "%s/limbo", dirname(self));
	int ends[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, ends) != 0) {
		perror("limbo-broker: socketpair");
		exit(1);
	}
	pid_t pid = fork();
	if (pid == 0) {
		fcntl(ends[1], F_SETFD, 0);
		char fd[16];
		snprintf(fd, sizeof(fd), "%d", ends[1]);
		char *const argv[] = {LIMBO_LAUNCHD, fd, (char *)table, NULL};
		execv(limbo, argv);
		fprintf(stderr, "limbo-broker: %s: %s\n", limbo,
				strerror(errno));
		_exit(127);
	}
	close(ends[1]);
	if (pid < 0) {
		perror("limbo-broker: fork");
		exit(1);
	}
	launchd_pid = pid;
	launchd_fd = ends[0];
	add_connection(launchd_fd);
	launchd_deadline = now_ms() + LIMBO_LAUNCHD_DEADLINE_MS;
	while (!launchd_loaded && launchd_fd != -1) {
		struct pollfd fd = {.fd = launchd_fd, .events = POLLIN};
		poll(&fd, 1, launchd_wait());
		if (fd.revents & (POLLIN | POLLHUP)) {
			handle_guest(launchd_fd);
			launchd_deadline = now_ms() + LIMBO_LAUNCHD_DEADLINE_MS;
		}
	}
	if (!launchd_loaded) {
		fprintf(stderr, "limbo-broker: %s ended as it started\n",
				LIMBO_LAUNCHD);
		exit(1);
	}
	launchd_deadline = 0;
}

static int
launchd_wait(void)
{
	if (launchd_deadline == 0) {
		return -1;
	}
	int64_t left = launchd_deadline - now_ms();
	if (left > 0) {
		return (int)left;
	}
	fprintf(stderr, "limbo-broker: %s did not load in %d s\n",
			LIMBO_LAUNCHD, LIMBO_LAUNCHD_DEADLINE_MS / 1000);
	kill(launchd_pid, SIGKILL);
	exit(1);
}

static int64_t
now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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

		launchd_frames();
		listening = !(fds[0].revents & POLLIN)
				|| accept_guest(listen_fd);
		for (size_t i = 0; i != polled; i++) {
			if (fds[i + 1].revents & POLLOUT) {
				send_pending(connection_for_fd(fds[i + 1].fd));
			}
			if (fds[i + 1].fd == launchd_fd) {
				continue;
			}
			if (fds[i + 1].revents & (POLLIN | POLLHUP)) {
				handle_guest(fds[i + 1].fd);
			}
		}

		free(fds);
	}
}

static void
launchd_frames(void)
{
	while (launchd_fd != -1) {
		struct pollfd fd = {.fd = launchd_fd, .events = POLLIN};
		if (poll(&fd, 1, 0) <= 0
				|| !(fd.revents
						& (POLLIN | POLLHUP
								| POLLERR))) {
			return;
		}
		handle_guest(launchd_fd);
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
	if (type == BROKER_SEND) {
		drop_frame(frame);
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
		welcome_guest(conn, (const struct broker_hello *)payload);
		break;
	case BROKER_REGISTER: {
		if (length < sizeof(struct broker_register)) {
			break;
		}
		struct broker_register *reg = (struct broker_register *)payload;
		reg->name[sizeof(reg->name) - 1] = '\0';
		register_service(conn, reg);
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
	case BROKER_JOBS_LOADED:
		if (conn->fd == launchd_fd) {
			launchd_loaded = true;
		}
		break;
	case BROKER_TASK_FOR_PID:
		task_for_pid(conn, (const struct broker_task_for_pid *)payload);
		break;
	}
	free(payload);
	broker_wire_free(frame);
}

static void
welcome_guest(struct connection *conn, const struct broker_hello *hello)
{
	if (conn->guest_id == 0) {
		conn->guest_id = next_guest_id++;
		conn->domain = hello->domain;
	}
	struct broker_welcome welcome = {
			.guest_id = conn->guest_id,
			.launchd_pid = launchd_pid,
	};
	send_frame(conn, BROKER_WELCOME, &welcome, sizeof(welcome));
}

static void
register_service(struct connection *conn, const struct broker_register *reg)
{
	struct held_name *held = held_named(reg->name);
	struct broker_register adopted = *reg;
	if (held != NULL && held_service(held) == NULL) {
		adopted.global_id = held_port(held);
	}
	struct broker_registered registered = broker_names_register(
			conn->guest_id, conn->domain, &adopted);
	registered.global_id = reg->global_id;
	registered.held_global_id = adopted.global_id != reg->global_id
			? adopted.global_id
			: 0;
	send_frame(conn, BROKER_REGISTERED, &registered, sizeof(registered));
	if (registered.holder == BROKER_NAME_FREE
			&& registered.held_global_id != 0) {
		held->hidden = false;
		set_route(adopted.global_id, conn->guest_id, 0);
		release_held_sends(held);
	}
}

static struct broker_registered
broker_names_register(uint32_t guest_id, uint32_t domain,
		const struct broker_register *reg)
{
	struct service *service = service_named(reg->name, domain);
	if (service != NULL && service->domain == domain) {
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
			.domain = domain,
			.global_id = reg->global_id,
	};
	strncpy(service->name, reg->name, sizeof(service->name) - 1);
	return (struct broker_registered){.holder = BROKER_NAME_FREE};
}

static struct broker_lookup_reply
broker_names_look_up(const struct broker_lookup *req)
{
	struct service *service = service_named(req->name, req->domain);
	return (struct broker_lookup_reply){
			.found = service != NULL,
			.global_id = (service != NULL) ? service->global_id : 0,
	};
}

static void
look_up_service(struct connection *conn, const struct broker_lookup *req)
{
	struct held_name *held = held_named(req->name);
	struct broker_lookup_reply reply = broker_names_look_up(req);
	if (held != NULL) {
		reply.found = !held->hidden;
		reply.global_id = held_port(held);
	}
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
	if (guest_id == BROKER_GUEST_ID && (uint32_t)send.dest_global_id != 0) {
		send_held(conn, frame, &send);
		return;
	}
	if (guest_id == BROKER_GUEST_ID) {
		take_notice(conn, frame);
		broker_wire_free(frame);
		return;
	}
	struct route *route = route_for(send.dest_global_id);
	bool waits = route != NULL && route->mover_id != 0
			&& route->mover_id != conn->guest_id;
	if (waits || (route != NULL && route->guest_id == BROKER_GUEST_ID)) {
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
send_held(struct connection *conn, struct broker_wire_frame *frame,
		struct broker_send *send)
{
	struct held_name *held = held_of(send->dest_global_id);
	if (held == NULL) {
		drop_frame(frame);
		return;
	}
	if (held_service(held) != NULL) {
		pass_on(frame, send, conn->guest_id);
		return;
	}
	struct held_send **tail = &held->queued;
	while (*tail != NULL) {
		tail = &(*tail)->next;
	}
	*tail = malloc(sizeof(**tail));
	**tail = (struct held_send){.frame = frame};
	uint32_t count;
	uint64_t *moved = moved_ids(frame, send, &count);
	for (uint32_t i = 0; i != count; i++) {
		set_route(moved[i], BROKER_GUEST_ID, 0);
	}
	free(moved);
}

static struct held_name *
held_of(uint64_t global_id)
{
	uint32_t index = (uint32_t)global_id - 1;
	return index < held_count ? &held_names[index] : NULL;
}

static struct service *
held_service(const struct held_name *held)
{
	uint64_t global_id = held_port(held);
	for (size_t i = 0; i != service_count; i++) {
		if (services[i].global_id == global_id) {
			return &services[i];
		}
	}
	return NULL;
}

static uint64_t
held_port(const struct held_name *held)
{
	return broker_global_id(
			BROKER_GUEST_ID, (uint32_t)(held - held_names) + 1);
}

static void
release_held_sends(struct held_name *held)
{
	while (held->queued != NULL) {
		struct held_send *queued = held->queued;
		held->queued = queued->next;
		struct broker_send send;
		broker_wire_read(queued->frame, 0, &send, sizeof(send));
		uint32_t count;
		uint64_t *moved = moved_ids(queued->frame, &send, &count);
		pass_on(queued->frame, &send, 0);
		for (uint32_t i = 0; i != count; i++) {
			release_held(moved[i]);
		}
		free(moved);
		free(queued);
	}
}

static void
pass_on(struct broker_wire_frame *frame, struct broker_send *send,
		uint32_t mover_id)
{
	struct connection *owner
			= connection_for_guest(route_of(send->dest_global_id));
	if (owner == NULL) {
		drop_frame(frame);
		return;
	}
	uint32_t moved_count;
	uint64_t *moved = moved_ids(frame, send, &moved_count);

	send->sender = (struct broker_sender){0};
	memcpy(frame->payload, send, sizeof(*send));
	frame->type = BROKER_DELIVER | (frame->type & BROKER_FRAME_OOL);
	uint32_t guest_id = owner->guest_id;
	bool queued = queue_frame(owner, frame);
	for (uint32_t i = 0; i != moved_count; i++) {
		if (queued) {
			set_route(moved[i], guest_id, mover_id);
		} else {
			settle_moved(moved[i]);
		}
	}
	free(moved);
}

static uint64_t *
moved_ids(const struct broker_wire_frame *frame, const struct broker_send *send,
		uint32_t *count)
{
	uint32_t moved_at = sizeof(*send) + send->blob_length;
	*count = send->blob_length <= frame->length - sizeof(*send)
			? (frame->length - moved_at) / sizeof(uint64_t)
			: 0;
	uint64_t *moved = *count != 0 ? malloc(*count * sizeof(*moved)) : NULL;
	if (moved != NULL
			&& !broker_wire_read(frame, moved_at, moved,
					*count * sizeof(*moved))) {
		*count = 0;
	}
	if (*count == 0) {
		free(moved);
		moved = NULL;
	}
	return moved;
}

static void
drop_frame(struct broker_wire_frame *frame)
{
	struct broker_send send;
	uint32_t count = 0;
	uint64_t *moved = frame->inline_length >= sizeof(send)
					&& broker_wire_read(frame, 0, &send,
							sizeof(send))
			? moved_ids(frame, &send, &count)
			: NULL;
	broker_wire_free(frame);
	for (uint32_t i = 0; i != count; i++) {
		settle_moved(moved[i]);
	}
	free(moved);
}

static void
settle_moved(uint64_t global_id)
{
	struct route *route = route_for(global_id);
	struct held_send *held = NULL;
	if (route != NULL) {
		held = route->held;
		*route = routes[--route_count];
	}
	broker_names_forget_port(global_id);
	struct broker_moved moved = {.global_id = global_id};
	tell_guests(BROKER_MOVED, &moved, sizeof(moved));
	while (held != NULL) {
		struct held_send *next = held->next;
		drop_frame(held->frame);
		free(held);
		held = next;
	}
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
		bool held = false;
		for (size_t i = 0; i != service_count && !held; i++) {
			held = services[i].global_id == blob.notice.count
					&& held_named(services[i].name) != NULL;
		}
		broker_names_forget_port(blob.notice.count);
		if (!held) {
			hide_again();
		}
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

static void
hide_again(void)
{
	for (size_t i = 0; i != held_count; i++) {
		if (held_names[i].hides && !held_names[i].hidden
				&& service_named(held_names[i].name,
						   BROKER_DOMAIN_USER)
						== NULL) {
			held_names[i].hidden = true;
		}
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
service_named(const char *name, uint32_t domain)
{
	struct service *other = NULL;
	for (size_t i = service_count; i != 0; i--) {
		if (strcmp(services[i - 1].name, name) != 0) {
			continue;
		}
		if (services[i - 1].domain == domain) {
			return &services[i - 1];
		}
		if (other == NULL) {
			other = &services[i - 1];
		}
	}
	return other;
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
	if (connections[index].fd == launchd_fd) {
		launchd_fd = -1;
	}
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
	hide_again();
	if (gone.guest_id != 0) {
		forget_routes(gone.guest_id);
	}
	if (gone.guest_id != 0) {
		tell_guests(BROKER_GUEST_GONE, &gone, sizeof(gone));
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
	for (size_t i = 0; i < route_count;) {
		struct broker_moved moved = {
				.global_id = routes[i].global_id,
				.guest_id
				= routes[i].guest_id != BROKER_GUEST_ID
						? routes[i].guest_id
						: guest_id,
		};
		bool lost = routes[i].guest_id == guest_id;
		if (lost
				&& broker_guest_of(routes[i].global_id)
						== BROKER_GUEST_ID) {
			routes[i] = routes[--route_count];
			continue;
		}
		bool outlives = !lost
				&& broker_guest_of(routes[i].global_id)
						== guest_id;
		struct held_send *held = NULL;
		if (lost) {
			broker_names_forget_port(routes[i].global_id);
			held = routes[i].held;
			moved.guest_id = 0;
			routes[i] = routes[--route_count];
		} else {
			i++;
		}
		if (lost || outlives) {
			tell_guests(BROKER_MOVED, &moved, sizeof(moved));
		}
		while (held != NULL) {
			struct held_send *next = held->next;
			drop_frame(held->frame);
			free(held);
			held = next;
		}
	}
}

static void
tell_guests(uint32_t type, const void *payload, uint32_t length)
{
	for (size_t i = 0; i != connection_count; i++) {
		if (connections[i].guest_id != BROKER_GUEST_ID) {
			send_frame(&connections[i], type, payload, length);
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

static bool
queue_frame(struct connection *conn, struct broker_wire_frame *frame)
{
	if (conn->pending == NULL && send_data(conn->fd, frame)) {
		broker_wire_free(frame);
		return true;
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
		return false;
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
	return true;
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
