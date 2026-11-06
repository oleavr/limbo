/*
 * Copyright © 2026 Ole André Vadla Ravnås
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

#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

struct kevent_qos_s {
	uint64_t ident;
	int16_t filter;
	uint16_t flags;
	int32_t qos;
	uint64_t udata;
	uint32_t fflags;
	uint32_t xflags;
	int64_t data;
	uint64_t ext[4];
};

struct kqueue;

int kevent_bind(struct kqueue *kq, bool manager, struct kevent_qos_s *events,
		int max_events, uint8_t *data, size_t data_size);
void kevent_unbind(struct kqueue *kq, bool manager,
		const struct kevent_qos_s *changes, int nchanges);
uint64_t kevent_kqid(struct kqueue *kq);
size_t kevent_dynamic_ids(uint64_t *ids, size_t capacity);
void kevent_close(int fd);
void kevent_dup(int from, int to);
void kevent_machport_arrival(mach_port_name_t name);
void kevent_signal(int sig, int64_t count);
