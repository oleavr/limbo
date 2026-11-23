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

static void handle_broker(void);
static bool send_frame(uint32_t type, const void *payload, size_t length,
		const int *fds, size_t fd_count);
static int broker_fd = -1;
static struct broker_wire_ahead broker_ahead;
static bool broker_gone;

int
launchd_main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "%s: started by limbo-broker, not by hand\n",
				LIMBO_LAUNCHD);
		return 1;
	}
	broker_fd = atoi(argv[1]);
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
	prctl(PR_SET_NAME, LIMBO_LAUNCHD, 0, 0, 0);

	jobs_init(maker.pid);
	if (argc > 2) {
		jobs_load(argv[2]);
	}
	send_frame(BROKER_JOBS_LOADED, NULL, 0, NULL, 0);

	for (;;) {
		size_t job_fds = jobs_poll_count();
		struct pollfd *fds = calloc(1 + job_fds, sizeof(*fds));
		fds[0] = (struct pollfd){.fd = broker_fd, .events = POLLIN};
		jobs_poll_fill(fds + 1);

		poll(fds, 1 + job_fds, jobs_poll_timeout());

		if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
			handle_broker();
		}
		jobs_poll_handle(fds + 1, job_fds);

		free(fds);
		if (jobs_done()) {
			break;
		}
	}
	return broker_gone ? 1 : 0;
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
		default:
			break;
		}
	}
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
