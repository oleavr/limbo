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

#include <mach/mach_types.h>
#include <mach/message.h>
#include <stdbool.h>

typedef uint64_t mach_msg_option64_t;

#define MACH64_SEND_MSG          0x0000000000000001ULL
#define MACH64_RCV_MSG           0x0000000000000002ULL
#define MACH64_MSG_VECTOR        0x0000000100000000ULL
#define MACH64_SEND_KOBJECT_CALL 0x0000000200000000ULL

typedef struct {
	mach_vm_address_t msgv_data;
	mach_vm_address_t msgv_rcv_addr;
	mach_msg_size_t msgv_send_size;
	mach_msg_size_t msgv_rcv_size;
} mach_msg_vector_t;

typedef struct {
	mach_msg_size_t msgdh_size;
	uint32_t msgdh_reserved;
} mach_msg_aux_header_t;

typedef enum {
	IPC_KOBJECT_NONE,
	IPC_KOBJECT_TASK,
	IPC_KOBJECT_THREAD,
	IPC_KOBJECT_HOST,
	IPC_KOBJECT_CLOCK,
	IPC_KOBJECT_CALENDAR_CLOCK,
	IPC_KOBJECT_IO_MAIN,
	IPC_KOBJECT_IO_OBJECT,
	IPC_KOBJECT_SEMAPHORE,
	IPC_KOBJECT_BOOTSTRAP,
	IPC_KOBJECT_LIBINFO,
	IPC_KOBJECT_PROCESSOR_SET,
	IPC_KOBJECT_VOUCHER,
	IPC_KOBJECT_MEMORY_ENTRY,
	/* A file descriptor as a port, which goes to other processes */
	IPC_KOBJECT_FILEPORT,
} ipc_kobject_type_t;

mach_port_name_t ipc_task_self(void);
mach_port_name_t ipc_fileport_alloc(int fd);
int ipc_fileport_fd(mach_port_name_t name);
mach_port_name_t ipc_host_self(void);
mach_port_name_t ipc_bootstrap_self(void);
mach_port_name_t ipc_kobject_name(ipc_kobject_type_t type);
mach_port_name_t ipc_kobject_alloc(ipc_kobject_type_t type, void *kobject);
mach_port_name_t ipc_kobject_copy_send(mach_port_name_t name);
void *ipc_kobject_lookup(mach_port_name_t name, ipc_kobject_type_t type);
void ipc_kobject_destroy(mach_port_name_t name);

bool ipc_port_peek(mach_port_name_t name);

mach_msg_return_t ipc_mach_msg(mach_msg_header_t *msg,
		mach_msg_option64_t options, mach_msg_size_t send_size,
		mach_msg_size_t rcv_size, mach_port_name_t rcv_name,
		mach_msg_timeout_t timeout);
mach_msg_return_t ipc_kernel_send(mach_msg_header_t *msg);

mach_msg_return_t ipc_launchd_send(mach_msg_header_t *msg);

void ipc_remote_deliver(uint64_t dest_global_id, const void *blob,
		uint32_t length);
mach_port_name_t ipc_service_check_in(const char *name);
mach_port_name_t ipc_service_look_up(const char *name);
mach_port_name_t ipc_libinfo_self(void);
void ipc_port_adopt_kotype(mach_port_name_t name, ipc_kobject_type_t type);
void ipc_service_register(const char *name, mach_port_name_t port);

kern_return_t ipc_port_allocate(
		mach_port_right_t right, mach_port_name_t *name);
kern_return_t ipc_port_construct(mach_port_options_t *options,
		mach_port_context_t context, mach_port_name_t *name);
kern_return_t ipc_port_destruct(mach_port_name_t name,
		mach_port_delta_t srdelta, mach_port_context_t guard);
kern_return_t ipc_port_deallocate(mach_port_name_t name);
kern_return_t ipc_port_mod_refs(mach_port_name_t name, mach_port_right_t right,
		mach_port_delta_t delta);
kern_return_t ipc_port_insert_right(mach_port_name_t name,
		mach_port_name_t poly, mach_msg_type_name_t poly_poly);
kern_return_t ipc_port_extract_right(mach_port_name_t name,
		mach_msg_type_name_t msgt_name, mach_port_name_t *poly,
		mach_msg_type_name_t *poly_poly);
kern_return_t ipc_port_type(mach_port_name_t name, mach_port_type_t *type);
kern_return_t ipc_port_names(mach_port_name_t **names,
		mach_port_type_t **types, uint32_t *count);
kern_return_t ipc_port_get_refs(mach_port_name_t name, mach_port_right_t right,
		mach_port_urefs_t *refs);
kern_return_t ipc_port_get_context(
		mach_port_name_t name, mach_port_context_t *context);
kern_return_t ipc_port_set_context(
		mach_port_name_t name, mach_port_context_t context);
kern_return_t ipc_port_insert_member(
		mach_port_name_t member, mach_port_name_t pset);
kern_return_t ipc_port_extract_member(
		mach_port_name_t member, mach_port_name_t pset);
kern_return_t ipc_port_move_member(
		mach_port_name_t member, mach_port_name_t pset);
kern_return_t ipc_port_get_status(
		mach_port_name_t name, mach_port_status_t *status);
