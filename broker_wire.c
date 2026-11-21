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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "broker.h"

#define PAYLOAD_SEALS (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)

union fd_control {
	char buffer[CMSG_SPACE(sizeof(int) * BROKER_DATAGRAM_FDS)];
	struct cmsghdr align;
};

static int payload_file(const struct iovec *parts, int part_count);
static bool write_whole(int fd, const struct iovec *part);
static bool is_sealed(int fd);
static int send_datagram(int fd, struct iovec *iov, int iov_count,
		const int *fds, size_t fd_count, int flags);
static int cancel_ahead(int fd, struct broker_wire_frame *frame, int flags);
static bool would_block(int error);
static void take_ahead(struct broker_wire_ahead *ahead,
		struct broker_wire_frame *frame);
static void close_fds(const int *fds, size_t count);
static size_t take_fds(struct msghdr *msg, int *fds);

struct broker_wire_frame *
broker_wire_new(uint32_t type, const struct iovec *parts, int part_count,
		const int *fds, size_t fd_count)
{
	size_t length = 0;
	for (int i = 0; i != part_count; i++) {
		length += parts[i].iov_len;
	}
	bool out_of_line = length > BROKER_INLINE_MAX;
	int inline_parts = out_of_line ? part_count > 1 : part_count;
	size_t inline_length = out_of_line ? parts[0].iov_len * inline_parts
					   : length;

	struct broker_wire_frame *frame
			= calloc(1, sizeof(*frame) + inline_length);
	frame->type = type;
	frame->length = length;
	frame->fds = malloc(sizeof(*frame->fds) * (fd_count + 1));
	for (size_t i = 0; i != fd_count; i++) {
		frame->fds[frame->fd_count++] = fds[i];
	}
	if (!broker_wire_carries(length, fd_count)
			|| inline_length > BROKER_INLINE_MAX) {
		broker_wire_free(frame);
		errno = EMSGSIZE;
		return NULL;
	}
	for (int i = 0; i != inline_parts; i++) {
		memcpy(frame->payload + frame->inline_length, parts[i].iov_base,
				parts[i].iov_len);
		frame->inline_length += parts[i].iov_len;
	}
	if (!out_of_line) {
		return frame;
	}

	int fd = payload_file(parts + inline_parts, part_count - inline_parts);
	if (fd == -1) {
		int error = errno;
		broker_wire_free(frame);
		errno = error;
		return NULL;
	}
	frame->type |= BROKER_FRAME_OOL;
	frame->fds[frame->fd_count++] = fd;
	return frame;
}

bool
broker_wire_carries(uint64_t length, size_t fd_count)
{
	return length <= BROKER_FRAME_MAX
			&& fd_count + (length > BROKER_INLINE_MAX)
			<= BROKER_FDS_MAX;
}

static int
payload_file(const struct iovec *parts, int part_count)
{
	int fd = memfd_create("limbo frame", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	bool written = fd != -1;
	for (int i = 0; written && i != part_count; i++) {
		written = write_whole(fd, &parts[i]);
	}
	if (fd != -1
			&& (!written
					|| fcntl(fd, F_ADD_SEALS, PAYLOAD_SEALS)
							== -1)) {
		int error = errno;
		close(fd);
		errno = error;
		return -1;
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
broker_wire_send(int fd, struct broker_wire_frame *frame, int flags)
{
	struct broker_frame ahead = {.type = BROKER_FDS};
	struct iovec ahead_iov = {.iov_base = &ahead, .iov_len = sizeof(ahead)};
	int error = 0;
	while (error == 0
			&& frame->fd_count - frame->fds_sent
					> BROKER_DATAGRAM_FDS) {
		error = send_datagram(fd, &ahead_iov, 1,
				frame->fds + frame->fds_sent,
				BROKER_DATAGRAM_FDS, flags);
		if (error == 0) {
			frame->fds_sent += BROKER_DATAGRAM_FDS;
		}
	}

	struct broker_frame header = {
			.type = frame->type,
			.length = frame->length,
	};
	struct iovec iov[2] = {
			{.iov_base = &header, .iov_len = sizeof(header)},
			{.iov_base = frame->payload,
					.iov_len = frame->inline_length},
	};
	if (error == 0) {
		error = send_datagram(fd, iov, 2, frame->fds + frame->fds_sent,
				frame->fd_count - frame->fds_sent, flags);
	}
	if (error != 0 && !would_block(error) && frame->fds_sent != 0) {
		int cancel = cancel_ahead(fd, frame, flags);
		return would_block(cancel) ? cancel : error;
	}
	return error;
}

static int
cancel_ahead(int fd, struct broker_wire_frame *frame, int flags)
{
	close_fds(frame->fds, frame->fd_count);
	frame->fd_count = 0;
	frame->fds_sent = 0;
	frame->type = BROKER_CANCEL;
	frame->length = 0;
	frame->inline_length = 0;

	struct broker_frame header = {.type = BROKER_CANCEL};
	struct iovec iov = {.iov_base = &header, .iov_len = sizeof(header)};
	int error = send_datagram(fd, &iov, 1, NULL, 0, flags);
	if (error != 0 && !would_block(error)) {
		shutdown(fd, SHUT_RDWR);
	}
	return error;
}

static bool
would_block(int error)
{
	return error == EAGAIN || error == EWOULDBLOCK;
}

static int
send_datagram(int fd, struct iovec *iov, int iov_count, const int *fds,
		size_t fd_count, int flags)
{
	union fd_control control;
	struct msghdr msg = {.msg_iov = iov, .msg_iovlen = iov_count};
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

	ssize_t n;
	do {
		n = sendmsg(fd, &msg, flags);
	} while (n == -1 && errno == EINTR);
	return n == -1 ? errno : 0;
}

int
broker_wire_receive(int fd, struct broker_wire_ahead *ahead,
		struct broker_wire_frame **received)
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
	} while (n == -1 && (errno == EINTR || errno == ECONNRESET));
	if (n <= 0) {
		free(frame);
		return -1;
	}

	int fds[BROKER_DATAGRAM_FDS];
	frame->fd_count = take_fds(&msg, fds);
	if (frame->fd_count != 0) {
		frame->fds = malloc(sizeof(int) * frame->fd_count);
		memcpy(frame->fds, fds, sizeof(int) * frame->fd_count);
	}
	if (n < (ssize_t)sizeof(header)) {
		broker_wire_free(frame);
		return -1;
	}
	if (msg.msg_flags & MSG_CTRUNC) {
		ahead->lost = true;
	}

	size_t carried = (size_t)n - sizeof(header);
	bool out_of_line = header.type & BROKER_FRAME_OOL;
	bool whole = out_of_line ? carried <= header.length
					&& header.length <= BROKER_FRAME_MAX
					&& (frame->fd_count != 0 || ahead->lost)
				 : carried == header.length;
	if (!whole || (msg.msg_flags & MSG_TRUNC)
			|| ahead->count + frame->fd_count > BROKER_FDS_MAX) {
		broker_wire_free(frame);
		return -1;
	}

	take_ahead(ahead, frame);
	if (header.type == BROKER_CANCEL) {
		ahead->lost = false;
		broker_wire_free(frame);
		return 0;
	}
	if (header.type == BROKER_FDS) {
		ahead->fds = frame->fds;
		ahead->count = frame->fd_count;
		free(frame);
		return 0;
	}
	if (ahead->lost) {
		ahead->lost = false;
		broker_wire_free(frame);
		return 0;
	}

	frame->type = header.type;
	frame->length = header.length;
	frame->inline_length = carried;
	*received = realloc(frame, sizeof(*frame) + frame->inline_length);
	return 1;
}

static void
take_ahead(struct broker_wire_ahead *ahead, struct broker_wire_frame *frame)
{
	if (ahead->count == 0) {
		return;
	}

	ahead->fds = realloc(ahead->fds,
			sizeof(int) * (ahead->count + frame->fd_count));
	for (size_t i = 0; i != frame->fd_count; i++) {
		ahead->fds[ahead->count + i] = frame->fds[i];
	}
	free(frame->fds);
	frame->fds = ahead->fds;
	frame->fd_count += ahead->count;
	ahead->fds = NULL;
	ahead->count = 0;
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
	uint32_t done = 0;
	if (offset < frame->inline_length) {
		done = frame->inline_length - offset < length
				? frame->inline_length - offset
				: length;
		memcpy(buffer, frame->payload + offset, done);
	}
	if (done == length) {
		return true;
	}

	int fd = frame->fds[frame->fd_count - 1];
	if (!is_sealed(fd)) {
		return false;
	}
	while (done != length) {
		ssize_t n = pread(fd, (char *)buffer + done, length - done,
				offset + done - frame->inline_length);
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

static bool
is_sealed(int fd)
{
	int seals = fcntl(fd, F_GET_SEALS);
	return seals != -1 && (seals & PAYLOAD_SEALS) == PAYLOAD_SEALS;
}

void
broker_wire_free(struct broker_wire_frame *frame)
{
	close_fds(frame->fds, frame->fd_count);
	free(frame->fds);
	free(frame);
}

void
broker_wire_forget(struct broker_wire_ahead *ahead)
{
	close_fds(ahead->fds, ahead->count);
	free(ahead->fds);
	*ahead = (struct broker_wire_ahead){0};
}

static void
close_fds(const int *fds, size_t count)
{
	for (size_t i = 0; i != count; i++) {
		close(fds[i]);
	}
}
