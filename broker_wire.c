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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "broker.h"

union fd_control {
	char buffer[CMSG_SPACE(sizeof(int) * BROKER_DATAGRAM_FDS)];
	struct cmsghdr align;
};

static int payload_file(const struct iovec *parts, int part_count);
static bool write_whole(int fd, const struct iovec *part);
static size_t take_fds(struct msghdr *msg, int *fds);

struct broker_wire_frame *
broker_wire_new(uint32_t type, const struct iovec *parts, int part_count)
{
	uint32_t length = 0;
	for (int i = 0; i != part_count; i++) {
		length += parts[i].iov_len;
	}

	bool out_of_line = length > BROKER_INLINE_MAX;
	struct broker_wire_frame *frame = calloc(
			1, sizeof(*frame) + (out_of_line ? 0 : length));
	frame->type = type;
	frame->length = length;
	if (!out_of_line) {
		for (int i = 0; i != part_count; i++) {
			memcpy(frame->payload + frame->inline_length,
					parts[i].iov_base, parts[i].iov_len);
			frame->inline_length += parts[i].iov_len;
		}
		return frame;
	}

	int fd = payload_file(parts, part_count);
	if (fd == -1) {
		free(frame);
		return NULL;
	}
	frame->type |= BROKER_FRAME_OOL;
	frame->fds = malloc(sizeof(*frame->fds));
	frame->fds[frame->fd_count++] = fd;
	return frame;
}

static int
payload_file(const struct iovec *parts, int part_count)
{
	int fd = memfd_create("limbo frame", MFD_CLOEXEC);
	for (int i = 0; fd != -1 && i != part_count; i++) {
		if (!write_whole(fd, &parts[i])) {
			int error = errno;
			close(fd);
			errno = error;
			return -1;
		}
	}
	return fd;
}

static bool
write_whole(int fd, const struct iovec *part)
{
	size_t written = 0;
	while (written != part->iov_len) {
		ssize_t n = write(fd, (const char *)part->iov_base + written,
				part->iov_len - written);
		if (n == -1 && errno != EINTR) {
			return false;
		}
		if (n != -1) {
			written += n;
		}
	}
	return true;
}

int
broker_wire_send(int fd, const struct broker_wire_frame *frame, int flags)
{
	struct broker_frame header = {
			.type = frame->type,
			.length = frame->length,
	};
	struct iovec iov[2] = {
			{.iov_base = &header, .iov_len = sizeof(header)},
			{.iov_base = (void *)frame->payload,
					.iov_len = frame->inline_length},
	};
	union fd_control control;
	struct msghdr msg = {.msg_iov = iov, .msg_iovlen = 2};
	if (frame->fd_count != 0) {
		size_t size = sizeof(int) * frame->fd_count;
		msg.msg_control = control.buffer;
		msg.msg_controllen = CMSG_SPACE(size);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(size);
		memcpy(CMSG_DATA(cmsg), frame->fds, size);
	}

	ssize_t n;
	do {
		n = sendmsg(fd, &msg, flags);
	} while (n == -1 && errno == EINTR);
	return n == -1 ? errno : 0;
}

int
broker_wire_receive(int fd, struct broker_wire_frame **received)
{
	struct broker_wire_frame *frame
			= calloc(1, sizeof(*frame) + BROKER_INLINE_MAX);
	struct broker_frame header;
	struct iovec iov[2] = {
			{.iov_base = &header, .iov_len = sizeof(header)},
			{.iov_base = frame->payload,
					.iov_len = BROKER_INLINE_MAX},
	};
	union fd_control control;
	struct msghdr msg = {
			.msg_iov = iov,
			.msg_iovlen = 2,
			.msg_control = control.buffer,
			.msg_controllen = sizeof(control.buffer),
	};

	ssize_t n;
	do {
		n = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
	} while (n == -1 && errno == EINTR);
	if (n < (ssize_t)sizeof(header)) {
		free(frame);
		return -1;
	}

	int fds[BROKER_DATAGRAM_FDS];
	frame->fd_count = take_fds(&msg, fds);
	if (frame->fd_count != 0) {
		frame->fds = malloc(sizeof(int) * frame->fd_count);
		memcpy(frame->fds, fds, sizeof(int) * frame->fd_count);
	}
	if (msg.msg_flags & MSG_CTRUNC) {
		broker_wire_free(frame);
		return 0;
	}

	size_t carried = (size_t)n - sizeof(header);
	bool out_of_line = header.type & BROKER_FRAME_OOL;
	bool whole = out_of_line ? carried == 0 && frame->fd_count != 0
					&& header.length <= BROKER_FRAME_MAX
				 : carried == header.length;
	if (!whole || (msg.msg_flags & MSG_TRUNC)) {
		broker_wire_free(frame);
		return -1;
	}

	frame->type = header.type;
	frame->length = header.length;
	frame->inline_length = out_of_line ? 0 : header.length;
	*received = realloc(frame, sizeof(*frame) + frame->inline_length);
	return 1;
}

static size_t
take_fds(struct msghdr *msg, int *fds)
{
	size_t count = 0;
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
			cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
				&& cmsg->cmsg_type == SCM_RIGHTS) {
			size_t taken = (cmsg->cmsg_len - CMSG_LEN(0))
					/ sizeof(int);
			memcpy(fds + count, CMSG_DATA(cmsg),
					taken * sizeof(int));
			count += taken;
		}
	}
	return count;
}

bool
broker_wire_read(const struct broker_wire_frame *frame, uint32_t offset,
		void *buffer, uint32_t length)
{
	if (offset > frame->length || length > frame->length - offset) {
		return false;
	}
	if (!(frame->type & BROKER_FRAME_OOL)) {
		memcpy(buffer, frame->payload + offset, length);
		return true;
	}

	int fd = frame->fds[frame->fd_count - 1];
	uint32_t done = 0;
	while (done != length) {
		ssize_t n = pread(fd, (char *)buffer + done, length - done,
				offset + done);
		if (n == -1 && errno == EINTR) {
			continue;
		}
		if (n <= 0) {
			return false;
		}
		done += n;
	}
	return true;
}

void
broker_wire_free(struct broker_wire_frame *frame)
{
	for (size_t i = 0; i != frame->fd_count; i++) {
		close(frame->fds[i]);
	}
	free(frame->fds);
	free(frame);
}
