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

#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

struct broker_frame;
struct broker_wire_ahead;

void broker_client_ensure(void);
void broker_client_reset(void);
void broker_client_fork_child(void);
bool broker_client_available(void);
bool broker_client_owns_fd(int fd);
void broker_client_fd_moved(int from, int to);
uint32_t broker_client_guest_id(void);
bool broker_client_send_frame(int fd, int flags, uint32_t type,
		const void *payload, uint32_t length, const int *fds,
		size_t fd_count);
int broker_client_receive_frame(int fd, struct broker_wire_ahead *ahead,
		struct broker_frame *header, void *payload, int *fds,
		size_t *fd_count, bool *lost);
bool broker_client_call(uint32_t type, const void *request, uint32_t length,
		uint32_t reply_type, void *reply, uint32_t reply_length);
bool broker_client_carries(uint64_t length, size_t fd_count);
pid_t broker_client_pid(void);
uint64_t broker_client_task_for_pid(int32_t pid);
mach_msg_return_t broker_client_send(uint64_t dest_global_id, const void *blob,
		uint32_t length, const int *fds, size_t fd_count,
		const uint64_t *moved, size_t moved_count);
