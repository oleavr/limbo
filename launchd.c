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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "broker.h"
#include "launchd.h"
#include "launchd_engine.h"
#include "osfmk/broker_client.h"
#include "osfmk/ipc.h"
#include "sysroot.h"
#include "thread.h"

static void open_port(void);
static void *receive_requests(void *unused);
static void answer_requests(void);
static void handle_broker(void);
static void handle_commands(const struct pollfd *ready);
static void answer_command(int fd);
static char *control(uid_t uid, char *words, uint32_t length, uint32_t *status);
static bool send_frame(uint32_t type, const void *payload, size_t length,
		const int *fds, size_t fd_count);
static int broker_fd = -1;
static struct broker_wire_ahead broker_ahead;
static bool broker_gone;
static int control_fd = -1;
static int *commands;
static size_t command_count;
static mach_port_name_t port;
static int requests[2] = {-1, -1};

#define REQUEST_MAX (64 * 1024)

int
launchd_main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "%s: started by limbo-broker, not by hand\n",
				LIMBO_LAUNCHD);
		return 1;
	}
	broker_fd = atoi(argv[1]);
	control_fd = atoi(argv[2]);
	struct ucred maker;
	socklen_t maker_length = sizeof(maker);
	if (fcntl(broker_fd, F_SETFD, FD_CLOEXEC) == -1
			|| getsockopt(broker_fd, SOL_SOCKET, SO_PEERCRED,
					   &maker, &maker_length)
					!= 0
			|| maker.pid != getppid()) {
		fprintf(stderr, "%s: not started by its broker\n",
				LIMBO_LAUNCHD);
		return 1;
	}
	if (control_fd != -1 && fcntl(control_fd, F_SETFD, FD_CLOEXEC) == -1) {
		control_fd = -1;
	}
	prctl(PR_SET_NAME, LIMBO_LAUNCHD, 0, 0, 0);
	sysroot_open();

	jobs_init(maker.pid);
	if (argc > 3) {
		jobs_load(argv[3]);
	}
	send_frame(BROKER_JOBS_LOADED, NULL, 0, NULL, 0);
	open_port();

	for (;;) {
		size_t job_fds = jobs_poll_count();
		size_t own = 3 + command_count;
		struct pollfd *fds = calloc(own + job_fds, sizeof(*fds));
		fds[0] = (struct pollfd){.fd = broker_fd, .events = POLLIN};
		fds[1] = (struct pollfd){.fd = requests[0], .events = POLLIN};
		fds[2] = (struct pollfd){.fd = control_fd, .events = POLLIN};
		for (size_t i = 0; i != command_count; i++) {
			fds[3 + i] = (struct pollfd){
					.fd = commands[i], .events = POLLIN};
		}
		jobs_poll_fill(fds + own);

		poll(fds, own + job_fds, jobs_poll_timeout());

		if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
			handle_broker();
		}
		if (fds[1].revents & POLLIN) {
			answer_requests();
		}
		handle_commands(fds + 2);
		jobs_poll_handle(fds + own, job_fds);

		free(fds);
		if (jobs_done()) {
			break;
		}
	}
	if (broker_gone) {
		return 1;
	}
	return jobs_rebooting() ? BROKER_EXIT_REBOOT : 0;
}

static void
open_port(void)
{
	broker_client_ensure();
	if (!broker_client_available() || pipe2(requests, O_CLOEXEC) != 0
			|| ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, &port)
					!= KERN_SUCCESS) {
		fprintf(stderr, "%s: no port of launchd's: %s\n", LIMBO_LAUNCHD,
				strerror(errno));
		requests[0] = -1;
		struct broker_launchd_port none = {0};
		send_frame(BROKER_LAUNCHD_PORT, &none, sizeof(none), NULL, 0);
		return;
	}
	struct broker_launchd_port told = {.global_id = ipc_names_hold(port)};
	send_frame(BROKER_LAUNCHD_PORT, &told, sizeof(told), NULL, 0);
	pthread_t thread;
	thread_create_own(&thread, NULL, receive_requests, NULL);
}

static void *
receive_requests(void *unused)
{
	(void)unused;
	for (;;) {
		mach_msg_header_t *request = malloc(REQUEST_MAX);
		mach_msg_return_t mr = ipc_mach_msg_kernel(request,
				MACH_RCV_MSG
						| MACH_RCV_TRAILER_TYPE(
								MACH_MSG_TRAILER_FORMAT_0)
						| MACH_RCV_TRAILER_ELEMENTS(
								MACH_RCV_TRAILER_AUDIT),
				0, REQUEST_MAX, port, MACH_MSG_TIMEOUT_NONE);
		if (mr != MACH_MSG_SUCCESS
				|| write(requests[1], &request, sizeof(request))
						!= sizeof(request)) {
			free(request);
		}
	}
	return NULL;
}

static void
answer_requests(void)
{
	mach_msg_header_t *request;
	struct pollfd ready = {.fd = requests[0], .events = POLLIN};
	while (poll(&ready, 1, 0) == 1
			&& read(requests[0], &request, sizeof(request))
					== sizeof(request)) {
		launchd_answer(request);
		free(request);
	}
}

static void
handle_broker(void)
{
	static char payload[BROKER_FRAME_MAX + 1];
	static int fds[BROKER_FDS_MAX];
	for (;;) {
		struct pollfd ready = {.fd = broker_fd, .events = POLLIN};
		if (broker_fd == -1 || poll(&ready, 1, 0) != 1) {
			return;
		}
		struct broker_frame header;
		size_t fd_count;
		bool lost;
		int n = broker_client_receive_frame(broker_fd, &broker_ahead,
				&header, payload, fds, &fd_count, &lost);
		if (n == 0) {
			continue;
		}
		if (n < 0) {
			fprintf(stderr, "%s: the broker has gone\n",
					LIMBO_LAUNCHD);
			close(broker_fd);
			broker_fd = -1;
			broker_wire_forget(&broker_ahead);
			broker_gone = true;
			jobs_broker_gone();
			return;
		}
		for (size_t i = 0; i != fd_count; i++) {
			close(fds[i]);
		}
		uint32_t type = header.type;
		if (lost) {
			continue;
		}
		switch (type) {
		case BROKER_NAME_AWAITED: {
			struct broker_name_awaited awaited = {0};
			memcpy(&awaited, payload,
					header.length < sizeof(awaited)
							? header.length
							: sizeof(awaited));
			awaited.name[sizeof(awaited.name) - 1] = '\0';
			jobs_name_awaited(awaited.name, awaited.domain,
					awaited.flags, awaited.waiters);
			break;
		}
		case BROKER_PROCESS_EXITED: {
			struct broker_process_exited exited = {0};
			memcpy(&exited, payload,
					header.length < sizeof(exited)
							? header.length
							: sizeof(exited));
			jobs_process_exited(exited.pid);
			break;
		}
		default:
			break;
		}
	}
}

static void
handle_commands(const struct pollfd *ready)
{
	for (size_t i = command_count; i-- != 0;) {
		if (ready[1 + i].revents & (POLLIN | POLLHUP | POLLERR)) {
			answer_command(commands[i]);
			close(commands[i]);
			commands[i] = commands[--command_count];
		}
	}
	if (!(ready[0].revents & POLLIN)) {
		return;
	}
	int fd = accept4(control_fd, NULL, NULL, SOCK_CLOEXEC);
	int *grown = fd != -1 ? reallocarray(commands, command_count + 1,
						sizeof(*commands))
			      : NULL;
	if (grown == NULL) {
		if (fd != -1) {
			close(fd);
		}
		return;
	}
	commands = grown;
	commands[command_count++] = fd;
}

static void
answer_command(int fd)
{
	static char payload[BROKER_FRAME_MAX + 1];
	static int fds[BROKER_FDS_MAX];
	struct broker_wire_ahead ahead = {0};
	struct broker_frame header;
	size_t fd_count = 0;
	bool lost = false;
	int n = broker_client_receive_frame(
			fd, &ahead, &header, payload, fds, &fd_count, &lost);
	broker_wire_forget(&ahead);
	for (size_t i = 0; i != fd_count; i++) {
		close(fds[i]);
	}
	struct ucred asker;
	socklen_t asker_length = sizeof(asker);
	if (n != 1 || header.type != BROKER_CONTROL
			|| getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &asker,
					   &asker_length)
					!= 0) {
		return;
	}
	uint32_t status = 1;
	char *text = lost ? strdup("the command could not be read\n") : NULL;
	if (text == NULL) {
		status = 0;
		text = control(asker.uid, payload, header.length, &status);
	}
	size_t text_length = strlen(text);
	if (text_length > BROKER_FRAME_MAX - sizeof(status)) {
		text_length = BROKER_FRAME_MAX - sizeof(status);
	}
	char *reply = malloc(sizeof(status) + text_length);
	memcpy(reply, &status, sizeof(status));
	memcpy(reply + sizeof(status), text, text_length);
	broker_client_send_frame(fd, MSG_NOSIGNAL, BROKER_CONTROL_REPLY, reply,
			(uint32_t)(sizeof(status) + text_length), NULL, 0);
	free(reply);
	free(text);
}

static char *
control(uid_t uid, char *words, uint32_t length, uint32_t *status)
{
	char *argv[64];
	size_t argc = 0;
	words[length] = '\0';
	for (char *word = words; word < words + length && argc != 64;
			word += strlen(word) + 1) {
		argv[argc++] = word;
	}
	return launchd_command(argv, argc, uid, status);
}

char *
launchd_command(char **argv, size_t argc, uid_t uid, uint32_t *status)
{
	if (argc != 0
			&& (strcmp(argv[0], "halt") == 0
					|| strcmp(argv[0], "reboot") == 0)) {
		if (uid != 0) {
			fprintf(stderr, "%s: %s refused: not root\n",
					LIMBO_LAUNCHD, argv[0]);
			*status = 1;
			return strdup("not root\n");
		}
		jobs_shut_down(strcmp(argv[0], "reboot") == 0);
		return strdup("");
	}
	return jobs_control(argv, argc, status);
}

void
broker_name(const struct broker_name *record)
{
	send_frame(BROKER_NAME, record,
			sizeof(*record)
					+ record->domain_count
							* sizeof(uint32_t),
			NULL, 0);
}

void
broker_jobs_stopping(void)
{
	send_frame(BROKER_JOBS_STOPPING, NULL, 0, NULL, 0);
}

void
broker_no_job(const char *name, uint32_t domain)
{
	struct broker_name_awaited which = {.domain = domain};
	strncpy(which.name, name, sizeof(which.name) - 1);
	send_frame(BROKER_NO_JOB, &which, sizeof(which), NULL, 0);
}

void
broker_process_exited(pid_t pid)
{
	struct broker_process_exited exited = {.pid = pid};
	send_frame(BROKER_PROCESS_EXITED, &exited, sizeof(exited), NULL, 0);
}

static bool
send_frame(uint32_t type, const void *payload, size_t length, const int *fds,
		size_t fd_count)
{
	if (broker_fd == -1) {
		return true;
	}
	while (!broker_client_send_frame(broker_fd, MSG_NOSIGNAL, type, payload,
			(uint32_t)length, fds, fd_count)) {
		if (errno == EINTR) {
			continue;
		}
		if (errno == EPIPE || errno == ECONNRESET) {
			return true;
		}
		fprintf(stderr, "%s: a frame (%#x) not sent: %s\n",
				LIMBO_LAUNCHD, type, strerror(errno));
		return false;
	}
	return true;
}
