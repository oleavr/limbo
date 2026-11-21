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
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "broker.h"
#include "check.h"

#define CLOSED_WITHIN_MS 5000
#define REFUSED          47

static void check_short_datagram(void);
static void check_last_frames(void);
static void check_cancel(void);
static void connect_pair(int pair[2]);
static int pipe_to(int *read_end);
static void send_datagram(int fd, const void *bytes, size_t length,
		const int *fds, size_t fd_count);
static bool is_closed(int read_end);

int
main(void)
{
	check_short_datagram();
	check_last_frames();
	check_cancel();
	return 0;
}

static void
check_short_datagram(void)
{
	int pair[2];
	connect_pair(pair);
	int read_end;
	int write_end = pipe_to(&read_end);
	send_datagram(pair[0], "", 1, &write_end, 1);
	CHECK(close(write_end) == 0);

	struct broker_wire_ahead ahead = {0};
	struct broker_wire_frame *frame;
	CHECK(broker_wire_receive(pair[1], &ahead, &frame) == -1);
	CHECK(is_closed(read_end));
	CHECK(close(read_end) == 0 && close(pair[0]) == 0
			&& close(pair[1]) == 0);
}

static void
check_last_frames(void)
{
	int pair[2];
	connect_pair(pair);
	struct broker_wire_frame *last
			= broker_wire_new(BROKER_HELLO, NULL, 0, NULL, 0);
	CHECK(broker_wire_send(pair[0], last, 0) == 0);
	broker_wire_free(last);
	send_datagram(pair[1], "unread", 6, NULL, 0);
	CHECK(close(pair[0]) == 0);

	struct broker_wire_ahead ahead = {0};
	struct broker_wire_frame *frame;
	CHECK(broker_wire_receive(pair[1], &ahead, &frame) == 1);
	CHECK(frame->type == BROKER_HELLO);
	broker_wire_free(frame);
	CHECK(broker_wire_receive(pair[1], &ahead, &frame) == -1);
	CHECK(close(pair[1]) == 0);
}

static void
check_cancel(void)
{
	int pair[2];
	connect_pair(pair);
	int read_end;
	int write_end = pipe_to(&read_end);
	int fds[BROKER_DATAGRAM_FDS + REFUSED];
	for (int i = 0; i != BROKER_DATAGRAM_FDS; i++) {
		fds[i] = fcntl(write_end, F_DUPFD_CLOEXEC, 0);
	}
	for (int i = 0; i != REFUSED; i++) {
		fds[BROKER_DATAGRAM_FDS + i] = -1;
	}
	CHECK(close(write_end) == 0);
	struct broker_wire_frame *failing = broker_wire_new(BROKER_SEND, NULL,
			0, fds, BROKER_DATAGRAM_FDS + REFUSED);
	CHECK(broker_wire_send(pair[0], failing, 0) == EBADF);
	broker_wire_free(failing);
	struct broker_wire_frame *next
			= broker_wire_new(BROKER_HELLO, NULL, 0, NULL, 0);
	CHECK(broker_wire_send(pair[0], next, 0) == 0);
	broker_wire_free(next);

	struct broker_wire_ahead ahead = {0};
	struct broker_wire_frame *frame;
	CHECK(broker_wire_receive(pair[1], &ahead, &frame) == 0);
	CHECK(ahead.count == BROKER_DATAGRAM_FDS);
	CHECK(broker_wire_receive(pair[1], &ahead, &frame) == 0);
	CHECK(ahead.count == 0 && is_closed(read_end));
	CHECK(broker_wire_receive(pair[1], &ahead, &frame) == 1);
	CHECK(frame->type == BROKER_HELLO && frame->fd_count == 0);
	broker_wire_free(frame);
	CHECK(close(read_end) == 0 && close(pair[0]) == 0
			&& close(pair[1]) == 0);
}

static void
connect_pair(int pair[2])
{
	CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0);
}

static int
pipe_to(int *read_end)
{
	int ends[2];
	CHECK(pipe2(ends, O_CLOEXEC) == 0);
	*read_end = ends[0];
	return ends[1];
}

static void
send_datagram(int fd, const void *bytes, size_t length, const int *fds,
		size_t fd_count)
{
	struct iovec iov = {.iov_base = (void *)bytes, .iov_len = length};
	union {
		char buffer[CMSG_SPACE(sizeof(int) * BROKER_DATAGRAM_FDS)];
		struct cmsghdr align;
	} control;
	struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
	if (fd_count != 0) {
		size_t size = sizeof(int) * fd_count;
		msg.msg_control = control.buffer;
		msg.msg_controllen = CMSG_SPACE(size);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(size);
		memcpy(CMSG_DATA(cmsg), fds, size);
	}
	CHECK(sendmsg(fd, &msg, 0) == (ssize_t)length);
}

static bool
is_closed(int read_end)
{
	struct pollfd polled = {.fd = read_end, .events = POLLIN};
	char byte;
	return poll(&polled, 1, CLOSED_WITHIN_MS) == 1
			&& read(read_end, &byte, sizeof(byte)) == 0;
}
