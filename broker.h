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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#define LIMBO_BROKER_SOCKET_ENV "LIMBO_BROKER"
#define LIMBO_BROKER_SERVICE_NAME_MAX 128
#define BROKER_GUEST_ID               0

#define BROKER_FRAME_MAX    (1 << 20)
#define BROKER_INLINE_MAX   (64 * 1024)
#define BROKER_DATAGRAM_FDS 253
#define BROKER_FDS_MAX      1024
#define BROKER_FRAME_OOL    0x80000000u

enum broker_frame_type {
	BROKER_HELLO,
	BROKER_WELCOME,
	BROKER_REGISTER,
	BROKER_LOOKUP,
	BROKER_LOOKUP_REPLY,
	BROKER_SEND,
	BROKER_DELIVER,
	BROKER_FDS,
	BROKER_GUEST_GONE,
	BROKER_CANCEL,
};

struct broker_frame {
	uint32_t type;
	uint32_t length;
};

struct broker_welcome {
	uint32_t guest_id;
};

struct broker_register {
	uint64_t global_id;
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
};

struct broker_lookup {
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
};

struct broker_lookup_reply {
	uint32_t found;
	uint64_t global_id;
};

struct broker_send {
	uint64_t dest_global_id;
	uint32_t blob_length;
};

struct broker_guest_gone {
	uint32_t guest_id;
};

struct broker_wire_frame {
	struct broker_wire_frame *next;
	uint32_t type;
	uint32_t length;
	uint32_t inline_length;
	size_t fd_count;
	size_t fds_sent;
	int *fds;
	char payload[];
};

struct broker_wire_ahead {
	int *fds;
	size_t count;
	bool lost;
};

struct broker_wire_frame *broker_wire_new(uint32_t type,
		const struct iovec *parts, int part_count, const int *fds,
		size_t fd_count);
int broker_wire_send(int fd, struct broker_wire_frame *frame, int flags);
int broker_wire_receive(int fd, struct broker_wire_ahead *ahead,
		struct broker_wire_frame **received);
void broker_wire_forget(struct broker_wire_ahead *ahead);
bool broker_wire_read(const struct broker_wire_frame *frame, uint32_t offset,
		void *buffer, uint32_t length);
void broker_wire_free(struct broker_wire_frame *frame);

static inline uint32_t broker_guest_of(uint64_t global_id)
{
	return (uint32_t)(global_id >> 32);
}

static inline uint64_t broker_global_id(uint32_t guest_id, uint32_t local)
{
	return ((uint64_t)guest_id << 32) | local;
}
