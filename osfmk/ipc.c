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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "broker.h"
#include "broker_client.h"
#include "libinfo.h"
#include "mach_vm.h"
#include "xpc_bootstrap.h"
#include "bsd/kevent.h"
#include "ipc.h"

typedef enum {
	IPC_USER,
	IPC_KERNEL,
} ipc_side_t;

struct ipc_kmsg {
	struct ipc_kmsg *next;
	pid_t sender_pid;
	mach_msg_header_t header[];
};

struct ipc_port {
	mach_port_name_t name;
	ipc_kobject_type_t kotype;
	void *kobject;
	struct ipc_port **psets;
	uint32_t pset_count;
	bool is_pset;
	struct ipc_kmsg *messages;
	struct ipc_kmsg **messages_tail;
	mach_port_seqno_t seqno;
	mach_port_context_t context;
	uint64_t global_id;
	bool remote;
};

struct ipc_entry {
	struct ipc_port *port;
	mach_port_type_t type;
	mach_port_urefs_t urefs;
	mach_port_urefs_t sorights;
	uint32_t generation;
};

struct remote_header {
	uint32_t message_size;
	mach_msg_type_name_t dest_disposition;
	mach_msg_type_name_t reply_disposition;
	uint64_t reply_global_id;
	pid_t sender_pid;
	uint32_t descriptor_count;
};

struct task_subsystem;
struct mach_vm_subsystem;
struct mach_port_subsystem;
struct thread_act_subsystem;
struct mach_host_subsystem;
struct clock_subsystem;
struct task_restartable_subsystem;
struct host_priv_subsystem;
struct is_iokit_subsystem;
struct mach_voucher_subsystem;

extern const struct task_subsystem task_subsystem;
extern const struct mach_vm_subsystem mach_vm_subsystem;
extern const struct mach_port_subsystem mach_port_subsystem;
extern const struct thread_act_subsystem thread_act_subsystem;
extern const struct mach_host_subsystem mach_host_subsystem;
extern const struct clock_subsystem clock_subsystem;
extern const struct task_restartable_subsystem task_restartable_subsystem;
extern const struct host_priv_subsystem host_priv_subsystem;
extern const struct is_iokit_subsystem is_iokit_subsystem;
extern const struct mach_voucher_subsystem mach_voucher_subsystem;
extern const struct mig_subsystem x_bootstrap_subsystem;

static const struct mig_subsystem *const kobject_subsystems[] = {
		(const struct mig_subsystem *)&task_subsystem,
		(const struct mig_subsystem *)&mach_vm_subsystem,
		(const struct mig_subsystem *)&mach_port_subsystem,
		(const struct mig_subsystem *)&thread_act_subsystem,
		(const struct mig_subsystem *)&mach_host_subsystem,
		(const struct mig_subsystem *)&clock_subsystem,
		(const struct mig_subsystem *)&task_restartable_subsystem,
		&x_bootstrap_subsystem,
		(const struct mig_subsystem *)&host_priv_subsystem,
		(const struct mig_subsystem *)&is_iokit_subsystem,
		(const struct mig_subsystem *)&mach_voucher_subsystem,
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t arrival = PTHREAD_COND_INITIALIZER;
static struct ipc_entry *entries;
static uint32_t entry_count;
static struct ipc_port *kobjects[IPC_KOBJECT_VOUCHER + 1];
static uint32_t export_counter;
static uint32_t transfer_counter;

static mach_msg_return_t remote_send(mach_msg_header_t *header,
		mach_msg_size_t size, pid_t sender_pid);
static uint32_t export_body_ports(mach_msg_header_t *header,
		uint64_t *global_ids, uint32_t dest_guest_id);
static uint64_t export_body_port(mach_port_name_t name,
		mach_msg_type_name_t disposition, uint32_t dest_guest_id);
static void import_body_ports(mach_msg_header_t *header,
		const uint64_t *global_ids);
static mach_port_name_t import_body_port(uint64_t global_id,
		mach_msg_type_name_t type);
static uint64_t export_local_port(mach_port_name_t name);
static struct ipc_port *port_for_global_id(uint64_t global_id);
static mach_port_name_t import_remote_send(uint64_t global_id);

static mach_port_name_t kobject_send_right(ipc_kobject_type_t type);
static struct ipc_port *kobject_port(ipc_kobject_type_t type);
static mach_msg_return_t send(mach_msg_header_t *msg, mach_msg_size_t size,
		ipc_side_t sender, pid_t sender_pid);
static mach_msg_return_t copyin(mach_msg_header_t *header, ipc_side_t sender,
		struct ipc_port **dest);
static mach_msg_return_t copyin_body(mach_msg_header_t *header,
		ipc_side_t sender, ipc_side_t receiver);
static mach_msg_return_t transfer_right(mach_port_name_t name,
		mach_msg_type_name_t disposition, ipc_side_t sender,
		ipc_side_t receiver, mach_msg_type_name_t *type);
static bool has_right(
		struct ipc_entry *entry, mach_msg_type_name_t disposition);
static mach_msg_type_name_t received_type(mach_msg_type_name_t disposition);
static void *copy_ool(const void *address, mach_msg_size_t size);
static void enqueue(struct ipc_port *port, struct ipc_kmsg *kmsg);
static void release_unused_entries(mach_msg_header_t *header);
static void release_unused_entry(mach_port_name_t name);
static void unlock_and_notify_arrival(struct ipc_port *port);
static void serve_kobject(mach_msg_header_t *request);
static mach_msg_header_t *kobject_server(mach_msg_header_t *request);
static const struct mig_subsystem *kobject_subsystem(mach_msg_id_t id);
static mach_msg_return_t receive(mach_msg_header_t *msg,
		mach_msg_option64_t options, mach_msg_size_t rcv_size,
		mach_port_name_t rcv_name, mach_msg_timeout_t timeout);
static struct ipc_port *port_with_message(struct ipc_entry *entry);
static int wait_for_arrival(mach_msg_option64_t options,
		mach_msg_timeout_t timeout, struct timespec *deadline);
static void write_trailer(mach_msg_header_t *msg, struct ipc_port *port,
		pid_t sender_pid);
static void destroy_receive_right(struct ipc_entry *entry);
static struct ipc_entry *lookup(mach_port_name_t name);
static struct ipc_port *port_alloc(ipc_kobject_type_t kotype);
static struct ipc_entry *entry_alloc(struct ipc_port *port);
static void entry_release_if_unused(struct ipc_entry *entry);
static kern_return_t member_and_set(mach_port_name_t member,
		mach_port_name_t pset, struct ipc_port **member_port,
		struct ipc_port **pset_port);
static bool port_in_set(
		const struct ipc_port *port, const struct ipc_port *pset);
static void port_join_set(struct ipc_port *port, struct ipc_port *pset);
static void port_leave_all_sets(struct ipc_port *port);
static void pset_release_members(const struct ipc_port *pset);
static bool port_leave_set(struct ipc_port *port, const struct ipc_port *pset);

mach_port_name_t
ipc_task_self(void)
{
	return kobject_send_right(IPC_KOBJECT_TASK);
}

mach_port_name_t
ipc_host_self(void)
{
	return kobject_send_right(IPC_KOBJECT_HOST);
}

mach_port_name_t
ipc_bootstrap_self(void)
{
	return kobject_send_right(IPC_KOBJECT_BOOTSTRAP);
}

mach_port_name_t
ipc_libinfo_self(void)
{
	return kobject_send_right(IPC_KOBJECT_LIBINFO);
}

void
ipc_port_adopt_kotype(mach_port_name_t name, ipc_kobject_type_t type)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	if (entry != NULL) {
		entry->port->kotype = type;
	}
	pthread_mutex_unlock(&lock);
}

mach_port_name_t
ipc_kobject_name(ipc_kobject_type_t type)
{
	pthread_mutex_lock(&lock);
	mach_port_name_t name = kobject_port(type)->name;
	pthread_mutex_unlock(&lock);
	return name;
}

mach_port_name_t
ipc_kobject_alloc(ipc_kobject_type_t type, void *kobject)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port = port_alloc(type);
	port->kobject = kobject;
	entry_alloc(port);
	pthread_mutex_unlock(&lock);
	return port->name;
}

mach_port_name_t
ipc_kobject_copy_send(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	entry->type |= MACH_PORT_TYPE_SEND;
	entry->urefs++;
	pthread_mutex_unlock(&lock);
	return name;
}

/* A send right to a fileport that owns the descriptor */
mach_port_name_t
ipc_fileport_alloc(int fd)
{
	int *kobject = malloc(sizeof(*kobject));
	*kobject = fd;
	pthread_mutex_lock(&lock);
	struct ipc_port *port = port_alloc(IPC_KOBJECT_FILEPORT);
	port->kobject = kobject;
	struct ipc_entry *entry = entry_alloc(port);
	entry->type |= MACH_PORT_TYPE_SEND;
	entry->urefs++;
	pthread_mutex_unlock(&lock);
	return port->name;
}

/* The descriptor behind a fileport, or -1 */
int
ipc_fileport_fd(mach_port_name_t name)
{
	int *kobject = ipc_kobject_lookup(name, IPC_KOBJECT_FILEPORT);
	return kobject != NULL ? *kobject : -1;
}

void *
ipc_kobject_lookup(mach_port_name_t name, ipc_kobject_type_t type)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	void *kobject = (entry != NULL && entry->port->kotype == type)
			? entry->port->kobject
			: NULL;
	pthread_mutex_unlock(&lock);
	return kobject;
}

void
ipc_kobject_destroy(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	entry->port->kotype = IPC_KOBJECT_NONE;
	entry->port->kobject = NULL;
	if (entry->type & MACH_PORT_TYPE_SEND) {
		entry->type = MACH_PORT_TYPE_DEAD_NAME;
	}
	entry_release_if_unused(entry);
	pthread_mutex_unlock(&lock);
}

bool
ipc_port_peek(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	bool pending = entry != NULL
			&& (entry->type
					& (MACH_PORT_TYPE_RECEIVE
							| MACH_PORT_TYPE_PORT_SET))
			&& port_with_message(entry) != NULL;
	pthread_mutex_unlock(&lock);
	return pending;
}

static mach_port_name_t
kobject_send_right(ipc_kobject_type_t type)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port = kobject_port(type);
	struct ipc_entry *entry = lookup(port->name);
	entry->type |= MACH_PORT_TYPE_SEND;
	entry->urefs++;
	pthread_mutex_unlock(&lock);
	return port->name;
}

static struct ipc_port *
kobject_port(ipc_kobject_type_t type)
{
	struct ipc_port **slot = &kobjects[type];
	if (*slot == NULL) {
		*slot = port_alloc(type);
	}
	if ((*slot)->name == MACH_PORT_NULL) {
		entry_alloc(*slot);
	}
	return *slot;
}

mach_msg_return_t
ipc_mach_msg(mach_msg_header_t *msg, mach_msg_option64_t options,
		mach_msg_size_t send_size, mach_msg_size_t rcv_size,
		mach_port_name_t rcv_name, mach_msg_timeout_t timeout)
{
	if (options & MACH64_SEND_MSG) {
		mach_msg_return_t mr = send(msg, send_size, IPC_USER,
				getpid());
		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}
	}

	if (options & MACH64_RCV_MSG) {
		return receive(msg, options, rcv_size, rcv_name, timeout);
	}

	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
send(mach_msg_header_t *msg, mach_msg_size_t size, ipc_side_t sender,
		pid_t sender_pid)
{
	struct ipc_kmsg *kmsg = malloc(
			sizeof(*kmsg) + size + sizeof(mach_msg_max_trailer_t));
	kmsg->sender_pid = sender_pid;
	memcpy(kmsg->header, msg, size);
	kmsg->header->msgh_size = size;

	pthread_mutex_lock(&lock);
	struct ipc_entry *remote_entry = lookup(kmsg->header->msgh_remote_port);
	if (remote_entry != NULL && remote_entry->port->remote) {
		mach_msg_return_t rr = remote_send(kmsg->header, size,
				sender_pid);
		free(kmsg);
		return rr;
	}

	struct ipc_port *dest;
	mach_msg_return_t mr = copyin(kmsg->header, sender, &dest);
	if (mr != MACH_MSG_SUCCESS) {
		release_unused_entries(kmsg->header);
		pthread_mutex_unlock(&lock);
		free(kmsg);
		return mr;
	}

	if (dest->kotype == IPC_KOBJECT_NONE) {
		enqueue(dest, kmsg);
		release_unused_entries(kmsg->header);
		unlock_and_notify_arrival(dest);
		return MACH_MSG_SUCCESS;
	}

	write_trailer(kmsg->header, dest, kmsg->sender_pid);
	bool serve_xpc = dest->kotype == IPC_KOBJECT_BOOTSTRAP
			&& xpc_bootstrap_is_message(kmsg->header->msgh_id);
	bool serve_libinfo = dest->kotype == IPC_KOBJECT_LIBINFO;
	pthread_mutex_unlock(&lock);

	if (serve_libinfo) {
		libinfo_serve(kmsg->header);
	} else if (!serve_xpc || !xpc_bootstrap_serve(kmsg->header)) {
		serve_kobject(kmsg->header);
	}

	pthread_mutex_lock(&lock);
	release_unused_entries(kmsg->header);
	pthread_mutex_unlock(&lock);

	free(kmsg);
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
remote_send(mach_msg_header_t *header, mach_msg_size_t size, pid_t sender_pid)
{
	uint64_t dest_global_id = lookup(header->msgh_remote_port)->port->global_id;
	mach_msg_bits_t bits = header->msgh_bits;

	uint64_t global_ids[16];
	uint32_t descriptor_count = export_body_ports(header, global_ids,
			broker_guest_of(dest_global_id));

	struct remote_header rh = {
		.message_size = size,
		.dest_disposition = MACH_MSGH_BITS_REMOTE(bits),
		.reply_disposition = MACH_MSGH_BITS_LOCAL(bits),
		.reply_global_id = (header->msgh_local_port != MACH_PORT_NULL)
				? export_local_port(header->msgh_local_port)
				: 0,
		.sender_pid = sender_pid,
		.descriptor_count = descriptor_count,
	};

	uint32_t ids_length = descriptor_count * sizeof(global_ids[0]);
	uint32_t blob_length = sizeof(rh) + size + ids_length;
	char *blob = malloc(blob_length);
	memcpy(blob, &rh, sizeof(rh));
	memcpy(blob + sizeof(rh), header, size);
	memcpy(blob + sizeof(rh) + size, global_ids, ids_length);

	pthread_mutex_unlock(&lock);
	broker_client_send(dest_global_id, blob, blob_length);
	free(blob);
	return MACH_MSG_SUCCESS;
}

static uint32_t
export_body_ports(mach_msg_header_t *header, uint64_t *global_ids,
		uint32_t dest_guest_id)
{
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return 0;
	}

	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);
	uint32_t count = 0;
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_type_descriptor_t *descriptor
				= (mach_msg_type_descriptor_t *)cursor;
		if (descriptor->type == MACH_MSG_PORT_DESCRIPTOR) {
			mach_msg_port_descriptor_t *d
					= (mach_msg_port_descriptor_t *)cursor;
			global_ids[count++] = export_body_port(d->name,
					d->disposition, dest_guest_id);
			cursor += sizeof(*d);
		} else {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t *)
							cursor;
			global_ids[count++] = export_body_port(d->name,
					d->disposition, dest_guest_id);
			cursor += sizeof(*d);
		}
	}
	return count;
}

static uint64_t
export_body_port(mach_port_name_t name, mach_msg_type_name_t disposition,
		uint32_t dest_guest_id)
{
	if (!MACH_PORT_VALID(name)) {
		return 0;
	}

	if (disposition != MACH_MSG_TYPE_MOVE_RECEIVE) {
		return export_local_port(name);
	}

	struct ipc_entry *entry = lookup(name);
	entry->port->global_id = broker_global_id(dest_guest_id,
			0x80000000 | (broker_client_guest_id() & 0x7ff) << 20
					| (++transfer_counter & 0xfffff));
	entry->port->remote = true;
	entry->type = MACH_PORT_TYPE_SEND;
	if (entry->urefs == 0) {
		entry->urefs = 1;
	}
	return entry->port->global_id;
}

static uint64_t
export_local_port(mach_port_name_t name)
{
	struct ipc_port *port = lookup(name)->port;
	if (port->global_id == 0) {
		port->global_id = broker_global_id(
				broker_client_guest_id(), ++export_counter);
	}
	return port->global_id;
}

static struct ipc_port *
port_for_global_id(uint64_t global_id)
{
	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *port = entries[i].port;
		if (port != NULL && !port->remote
				&& port->global_id == global_id) {
			return port;
		}
	}
	return NULL;
}

static mach_port_name_t
import_remote_send(uint64_t global_id)
{
	if (broker_guest_of(global_id) == broker_client_guest_id()) {
		struct ipc_port *port = port_for_global_id(global_id);
		struct ipc_entry *entry = &entries[MACH_PORT_INDEX(port->name)];
		entry->type |= MACH_PORT_TYPE_SEND;
		entry->urefs++;
		return port->name;
	}

	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *port = entries[i].port;
		if (port != NULL && port->remote
				&& port->global_id == global_id) {
			entries[i].urefs++;
			return port->name;
		}
	}

	struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	entry->type = MACH_PORT_TYPE_SEND;
	entry->urefs = 1;
	entry->port->remote = true;
	entry->port->global_id = global_id;
	return entry->port->name;
}

void
ipc_remote_deliver(uint64_t dest_global_id, const void *blob, uint32_t length)
{
	const struct remote_header *rh = blob;
	const mach_msg_header_t *message
			= (const mach_msg_header_t *)((const char *)blob
					+ sizeof(*rh));

	const uint64_t *global_ids = (const uint64_t *)((const char *)message
			+ rh->message_size);

	pthread_mutex_lock(&lock);
	struct ipc_port *dest = port_for_global_id(dest_global_id);

	struct ipc_kmsg *kmsg = malloc(sizeof(*kmsg) + rh->message_size
			+ sizeof(mach_msg_max_trailer_t));
	kmsg->sender_pid = rh->sender_pid;
	memcpy(kmsg->header, message, rh->message_size);

	mach_port_name_t reply_name = (rh->reply_global_id != 0)
			? import_remote_send(rh->reply_global_id)
			: MACH_PORT_NULL;
	kmsg->header->msgh_bits = MACH_MSGH_BITS_SET(
			received_type(rh->reply_disposition),
			received_type(rh->dest_disposition), 0,
			message->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	kmsg->header->msgh_remote_port = reply_name;
	kmsg->header->msgh_local_port = dest->name;
	kmsg->header->msgh_voucher_port = MACH_PORT_NULL;
	kmsg->header->msgh_size = rh->message_size;

	import_body_ports(kmsg->header, global_ids);

	enqueue(dest, kmsg);
	unlock_and_notify_arrival(dest);
}

static void
import_body_ports(mach_msg_header_t *header, const uint64_t *global_ids)
{
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}

	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);
	uint32_t count = 0;
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_type_descriptor_t *descriptor
				= (mach_msg_type_descriptor_t *)cursor;
		if (descriptor->type == MACH_MSG_PORT_DESCRIPTOR) {
			mach_msg_port_descriptor_t *d
					= (mach_msg_port_descriptor_t *)cursor;
			mach_msg_type_name_t type = received_type(d->disposition);
			d->name = import_body_port(global_ids[count++], type);
			d->disposition = type;
			cursor += sizeof(*d);
		} else {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t *)
							cursor;
			mach_msg_type_name_t type = received_type(d->disposition);
			d->name = import_body_port(global_ids[count++], type);
			d->disposition = type;
			cursor += sizeof(*d);
		}
	}
}

static mach_port_name_t
import_body_port(uint64_t global_id, mach_msg_type_name_t type)
{
	if (global_id == 0) {
		return MACH_PORT_NULL;
	}

	if (type == MACH_MSG_TYPE_PORT_RECEIVE) {
		struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
		entry->type = MACH_PORT_TYPE_RECEIVE;
		entry->port->global_id = global_id;
		return entry->port->name;
	}
	return import_remote_send(global_id);
}

mach_port_name_t
ipc_service_check_in(const char *name)
{
	broker_client_ensure();
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	entry->type = MACH_PORT_TYPE_RECEIVE;
	entry->port->global_id = broker_global_id(
			broker_client_guest_id(), ++export_counter);
	mach_port_name_t name_out = entry->port->name;
	uint64_t global_id = entry->port->global_id;
	pthread_mutex_unlock(&lock);
	broker_client_register(name, global_id);
	return name_out;
}

mach_port_name_t
ipc_service_look_up(const char *name)
{
	broker_client_ensure();
	if (!broker_client_available()) {
		return MACH_PORT_NULL;
	}
	uint64_t global_id;
	if (!broker_client_look_up(name, &global_id)) {
		return MACH_PORT_NULL;
	}
	pthread_mutex_lock(&lock);
	mach_port_name_t name_out = import_remote_send(global_id);
	pthread_mutex_unlock(&lock);
	return name_out;
}

void
ipc_service_register(const char *name, mach_port_name_t port)
{
	broker_client_ensure();
	pthread_mutex_lock(&lock);
	uint64_t global_id = export_local_port(port);
	pthread_mutex_unlock(&lock);
	broker_client_register(name, global_id);
}

static mach_msg_return_t
copyin(mach_msg_header_t *header, ipc_side_t sender, struct ipc_port **dest)
{
	mach_msg_bits_t bits = header->msgh_bits;

	struct ipc_entry *dest_entry = lookup(header->msgh_remote_port);
	if (dest_entry == NULL || (dest_entry->type & MACH_PORT_TYPE_PORT_SET)
			|| (dest_entry->type & MACH_PORT_TYPE_DEAD_NAME)) {
		return MACH_SEND_INVALID_DEST;
	}
	*dest = dest_entry->port;
	ipc_side_t receiver = ((*dest)->kotype == IPC_KOBJECT_NONE)
			? IPC_USER
			: IPC_KERNEL;

	mach_msg_type_name_t dest_type;
	if (transfer_right(header->msgh_remote_port,
			    MACH_MSGH_BITS_REMOTE(bits), sender, IPC_KERNEL,
			    &dest_type)
			!= MACH_MSG_SUCCESS) {
		return MACH_SEND_INVALID_DEST;
	}

	mach_msg_type_name_t reply_type;
	if (transfer_right(header->msgh_local_port, MACH_MSGH_BITS_LOCAL(bits),
			    sender, receiver, &reply_type)
			!= MACH_MSG_SUCCESS) {
		return MACH_SEND_INVALID_REPLY;
	}

	header->msgh_bits = MACH_MSGH_BITS_SET(reply_type, dest_type, 0,
			bits & MACH_MSGH_BITS_COMPLEX);
	header->msgh_remote_port = header->msgh_local_port;
	header->msgh_local_port = (*dest)->name;
	header->msgh_voucher_port = MACH_PORT_NULL;

	if (bits & MACH_MSGH_BITS_COMPLEX) {
		return copyin_body(header, sender, receiver);
	}
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
copyin_body(mach_msg_header_t *header, ipc_side_t sender, ipc_side_t receiver)
{
	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);

	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_type_descriptor_t *descriptor
				= (mach_msg_type_descriptor_t *)cursor;
		switch (descriptor->type) {
		case MACH_MSG_PORT_DESCRIPTOR: {
			mach_msg_port_descriptor_t *d
					= (mach_msg_port_descriptor_t *)cursor;
			mach_msg_type_name_t type;
			if (transfer_right(d->name, d->disposition, sender,
					    receiver, &type)
					!= MACH_MSG_SUCCESS) {
				return MACH_SEND_INVALID_RIGHT;
			}
			d->disposition = type;
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t
									*)
							cursor;
			mach_msg_type_name_t type;
			if (transfer_right(d->name, d->disposition, sender,
					    receiver, &type)
					!= MACH_MSG_SUCCESS) {
				return MACH_SEND_INVALID_RIGHT;
			}
			d->disposition = type;
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
			mach_msg_ool_descriptor64_t *d
					= (mach_msg_ool_descriptor64_t *)cursor;
			if (sender == IPC_USER && receiver == IPC_USER
					&& !d->deallocate) {
				d->address = (uint64_t)copy_ool(
						(void *)d->address, d->size);
			}
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor64_t *d
					= (mach_msg_ool_ports_descriptor64_t *)
							cursor;
			mach_port_name_t *names
					= (mach_port_name_t *)d->address;
			mach_msg_type_name_t type
					= received_type(d->disposition);
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				if (transfer_right(names[j], d->disposition,
						    sender, receiver, &type)
						!= MACH_MSG_SUCCESS) {
					return MACH_SEND_INVALID_RIGHT;
				}
			}
			if (sender == IPC_USER && receiver == IPC_USER
					&& !d->deallocate) {
				d->address = (uint64_t)copy_ool(names,
						d->count * sizeof(*names));
			}
			d->disposition = type;
			cursor += sizeof(*d);
		} break;
		default:
			return MACH_SEND_INVALID_TYPE;
		}
	}

	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
transfer_right(mach_port_name_t name, mach_msg_type_name_t disposition,
		ipc_side_t sender, ipc_side_t receiver,
		mach_msg_type_name_t *type)
{
	*type = received_type(disposition);
	if (!MACH_PORT_VALID(name)) {
		return MACH_MSG_SUCCESS;
	}

	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		return MACH_SEND_INVALID_RIGHT;
	}

	if (sender == IPC_USER) {
		if (!has_right(entry, disposition)) {
			return MACH_SEND_INVALID_RIGHT;
		}
		if (receiver == IPC_KERNEL) {
			switch (disposition) {
			case MACH_MSG_TYPE_MOVE_SEND:
				if (--entry->urefs == 0) {
					entry->type &= ~MACH_PORT_TYPE_SEND;
				}
				break;
			case MACH_MSG_TYPE_MOVE_SEND_ONCE:
				if (--entry->sorights == 0) {
					entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
				}
				break;
			case MACH_MSG_TYPE_MOVE_RECEIVE:
				entry->type &= ~MACH_PORT_TYPE_RECEIVE;
				break;
			}
			return MACH_MSG_SUCCESS;
		}
	}

	if (receiver == IPC_USER) {
		bool created = sender == IPC_KERNEL
				|| (disposition != MACH_MSG_TYPE_MOVE_SEND
						&& disposition != MACH_MSG_TYPE_MOVE_SEND_ONCE
						&& disposition != MACH_MSG_TYPE_MOVE_RECEIVE);
		if (created) {
			switch (*type) {
			case MACH_MSG_TYPE_PORT_SEND:
				entry->type |= MACH_PORT_TYPE_SEND;
				entry->urefs++;
				break;
			case MACH_MSG_TYPE_PORT_SEND_ONCE:
				entry->type |= MACH_PORT_TYPE_SEND_ONCE;
				entry->sorights++;
				break;
			case MACH_MSG_TYPE_PORT_RECEIVE:
				entry->type |= MACH_PORT_TYPE_RECEIVE;
				break;
			default:
				unimplemented();
			}
		}
	}

	return MACH_MSG_SUCCESS;
}

static bool
has_right(struct ipc_entry *entry, mach_msg_type_name_t disposition)
{
	switch (disposition) {
	case MACH_MSG_TYPE_MOVE_RECEIVE:
	case MACH_MSG_TYPE_MAKE_SEND:
	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return entry->type & MACH_PORT_TYPE_RECEIVE;
	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_COPY_SEND:
		return entry->type & MACH_PORT_TYPE_SEND;
	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		return entry->type & MACH_PORT_TYPE_SEND_ONCE;
	default:
		return false;
	}
}

static mach_msg_type_name_t
received_type(mach_msg_type_name_t disposition)
{
	switch (disposition) {
	case MACH_MSG_TYPE_MOVE_RECEIVE:
		return MACH_MSG_TYPE_PORT_RECEIVE;
	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_COPY_SEND:
	case MACH_MSG_TYPE_MAKE_SEND:
		return MACH_MSG_TYPE_PORT_SEND;
	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return MACH_MSG_TYPE_PORT_SEND_ONCE;
	default:
		return MACH_MSG_TYPE_PORT_NONE;
	}
}

static void *
copy_ool(const void *address, mach_msg_size_t size)
{
	if (size == 0) {
		return NULL;
	}
	void *copy = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	memcpy(copy, address, size);
	return copy;
}

static void
enqueue(struct ipc_port *port, struct ipc_kmsg *kmsg)
{
	kmsg->next = NULL;
	if (port->messages == NULL) {
		port->messages_tail = &port->messages;
	}
	*port->messages_tail = kmsg;
	port->messages_tail = &kmsg->next;
	pthread_cond_broadcast(&arrival);
}

static void
release_unused_entries(mach_msg_header_t *header)
{
	release_unused_entry(header->msgh_remote_port);
	release_unused_entry(header->msgh_local_port);
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}

	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_type_descriptor_t *descriptor
				= (mach_msg_type_descriptor_t *)cursor;
		switch (descriptor->type) {
		case MACH_MSG_PORT_DESCRIPTOR: {
			mach_msg_port_descriptor_t *d
					= (mach_msg_port_descriptor_t *)cursor;
			release_unused_entry(d->name);
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t
									*)
							cursor;
			release_unused_entry(d->name);
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor64_t *d
					= (mach_msg_ool_ports_descriptor64_t *)
							cursor;
			mach_port_name_t *names
					= (mach_port_name_t *)d->address;
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				release_unused_entry(names[j]);
			}
			cursor += sizeof(*d);
		} break;
		default:
			cursor += sizeof(mach_msg_ool_descriptor64_t);
		}
	}
}

static void
release_unused_entry(mach_port_name_t name)
{
	struct ipc_entry *entry = lookup(name);
	if (entry != NULL) {
		entry_release_if_unused(entry);
	}
}

static void
unlock_and_notify_arrival(struct ipc_port *port)
{
	mach_port_name_t name = port->name;
	uint32_t count = port->pset_count;
	mach_port_name_t psets[count + 1];
	for (uint32_t i = 0; i < count; i++) {
		psets[i] = port->psets[i]->name;
	}
	pthread_mutex_unlock(&lock);

	kevent_machport_arrival(name);
	for (uint32_t i = 0; i < count; i++) {
		kevent_machport_arrival(psets[i]);
	}
}

static void
serve_kobject(mach_msg_header_t *request)
{
	mach_msg_header_t *reply = kobject_server(request);
	if (reply == NULL) {
		return;
	}

	if (reply->msgh_remote_port != MACH_PORT_NULL) {
		send(reply, reply->msgh_size, IPC_KERNEL, 0);
	}
	free(reply);
}

static mach_msg_header_t *
kobject_server(mach_msg_header_t *request)
{
	mach_msg_id_t id = request->msgh_id;
	const struct mig_subsystem *subsystem = kobject_subsystem(id);
	mig_stub_routine_t routine = (subsystem != NULL)
			? subsystem->routine[id - subsystem->start].stub_routine
			: NULL;
	mach_msg_size_t size = (subsystem != NULL) ? subsystem->maxsize
						   : sizeof(mig_reply_error_t);

	mig_reply_error_t *reply = calloc(1, size);
	reply->Head.msgh_bits = MACH_MSGH_BITS(
			MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0);
	reply->Head.msgh_size = sizeof(*reply);
	reply->Head.msgh_remote_port = request->msgh_remote_port;
	reply->Head.msgh_id = id + 100;
	reply->NDR = NDR_record;

	if (routine == NULL) {
		fprintf(stderr, "limbo: unknown kernel object message ID %d\n",
				id);
		reply->RetCode = MIG_BAD_ID;
	} else {
		routine(request, &reply->Head);
	}

	if (!(reply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)
			&& reply->RetCode == MIG_NO_REPLY) {
		free(reply);
		return NULL;
	}
	return &reply->Head;
}

static const struct mig_subsystem *
kobject_subsystem(mach_msg_id_t id)
{
	uint32_t count = sizeof(kobject_subsystems)
			/ sizeof(kobject_subsystems[0]);
	for (uint32_t i = 0; i < count; i++) {
		const struct mig_subsystem *subsystem = kobject_subsystems[i];
		if (id >= subsystem->start && id < subsystem->end) {
			return subsystem;
		}
	}
	return NULL;
}

static mach_msg_return_t
receive(mach_msg_header_t *msg, mach_msg_option64_t options,
		mach_msg_size_t rcv_size, mach_port_name_t rcv_name,
		mach_msg_timeout_t timeout)
{
	pthread_mutex_lock(&lock);

	struct timespec deadline = {0, 0};
	struct ipc_port *port;
	bool waited = false;
	while (true) {
		struct ipc_entry *entry = lookup(rcv_name);
		if (entry == NULL
				|| !(entry->type
						& (MACH_PORT_TYPE_RECEIVE
								| MACH_PORT_TYPE_PORT_SET))) {
			pthread_mutex_unlock(&lock);
			return waited ? MACH_RCV_PORT_DIED
				      : MACH_RCV_INVALID_NAME;
		}

		port = port_with_message(entry);
		if (port != NULL) {
			break;
		}

		if (wait_for_arrival(options, timeout, &deadline)
				== ETIMEDOUT) {
			pthread_mutex_unlock(&lock);
			return MACH_RCV_TIMED_OUT;
		}
		waited = true;
	}

	struct ipc_kmsg *kmsg = port->messages;
	mach_msg_size_t size = kmsg->header->msgh_size;
	mach_msg_size_t trailer_size
			= REQUESTED_TRAILER_SIZE((mach_msg_option_t)options);
	if (size + trailer_size > rcv_size && (options & MACH_RCV_LARGE)) {
		msg->msgh_size = size + trailer_size;
		if (options & MACH_RCV_LARGE_IDENTITY) {
			msg->msgh_local_port = port->name;
		}
		pthread_mutex_unlock(&lock);
		return MACH_RCV_TOO_LARGE;
	}

	port->messages = kmsg->next;
	write_trailer(kmsg->header, port, kmsg->sender_pid);
	pthread_mutex_unlock(&lock);

	mach_msg_return_t mr = MACH_RCV_TOO_LARGE;
	if (size + trailer_size <= rcv_size) {
		memcpy(msg, kmsg->header, size);
		mach_msg_max_trailer_t *trailer
				= (mach_msg_max_trailer_t *)((uint8_t *)msg
						+ size);
		memcpy(trailer, (uint8_t *)kmsg->header + size, trailer_size);
		trailer->msgh_trailer_size = trailer_size;
		mr = MACH_MSG_SUCCESS;
	}
	free(kmsg);
	return mr;
}

static struct ipc_port *
port_with_message(struct ipc_entry *entry)
{
	if (entry->type & MACH_PORT_TYPE_RECEIVE) {
		return (entry->port->messages != NULL) ? entry->port : NULL;
	}

	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *member = entries[i].port;
		if (member != NULL && member->messages != NULL
				&& port_in_set(member, entry->port)) {
			return member;
		}
	}
	return NULL;
}

static int
wait_for_arrival(mach_msg_option64_t options, mach_msg_timeout_t timeout,
		struct timespec *deadline)
{
	if (!(options & MACH_RCV_TIMEOUT)) {
		return pthread_cond_wait(&arrival, &lock);
	}

	if (timeout == 0) {
		return ETIMEDOUT;
	}

	if (deadline->tv_sec == 0) {
		clock_gettime(CLOCK_REALTIME, deadline);
		deadline->tv_sec += timeout / 1000;
		deadline->tv_nsec += (timeout % 1000) * 1000000;
		if (deadline->tv_nsec >= 1000000000) {
			deadline->tv_sec++;
			deadline->tv_nsec -= 1000000000;
		}
	}
	return pthread_cond_timedwait(&arrival, &lock, deadline);
}

static void
write_trailer(mach_msg_header_t *msg, struct ipc_port *port, pid_t sender_pid)
{
	mach_msg_max_trailer_t *trailer
			= (mach_msg_max_trailer_t *)((uint8_t *)msg
					+ msg->msgh_size);
	memset(trailer, 0, sizeof(*trailer));
	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
	trailer->msgh_trailer_size = sizeof(*trailer);
	trailer->msgh_seqno = port->seqno++;
	trailer->msgh_sender.val[0] = geteuid();
	trailer->msgh_sender.val[1] = getegid();
	trailer->msgh_audit.val[1] = geteuid();
	trailer->msgh_audit.val[2] = getegid();
	trailer->msgh_audit.val[3] = getuid();
	trailer->msgh_audit.val[4] = getgid();
	trailer->msgh_audit.val[5] = sender_pid;
	trailer->msgh_audit.val[7] = 10;
	trailer->msgh_context = port->context;
}

mach_msg_return_t
ipc_kernel_send(mach_msg_header_t *msg)
{
	return send(msg, msg->msgh_size, IPC_KERNEL, 0);
}

mach_msg_return_t
ipc_launchd_send(mach_msg_header_t *msg)
{
	return send(msg, msg->msgh_size, IPC_KERNEL, 1);
}

kern_return_t
ipc_port_allocate(mach_port_right_t right, mach_port_name_t *name)
{
	mach_port_type_t type;
	switch (right) {
	case MACH_PORT_RIGHT_RECEIVE:
		type = MACH_PORT_TYPE_RECEIVE;
		break;
	case MACH_PORT_RIGHT_PORT_SET:
		type = MACH_PORT_TYPE_PORT_SET;
		break;
	default:
		unimplemented();
	}

	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	entry->type = type;
	entry->port->is_pset = type == MACH_PORT_TYPE_PORT_SET;
	*name = entry->port->name;
	pthread_mutex_unlock(&lock);
	return KERN_SUCCESS;
}

kern_return_t
ipc_port_construct(mach_port_options_t *options, mach_port_context_t context,
		mach_port_name_t *name)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	entry->type = MACH_PORT_TYPE_RECEIVE;
	entry->port->context = context;
	if (options->flags & MPO_INSERT_SEND_RIGHT) {
		entry->type |= MACH_PORT_TYPE_SEND;
		entry->urefs = 1;
	}
	*name = entry->port->name;
	pthread_mutex_unlock(&lock);
	return KERN_SUCCESS;
}

kern_return_t
ipc_port_destruct(mach_port_name_t name, mach_port_delta_t srdelta,
		mach_port_context_t guard)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		entry->urefs += srdelta;
		if (entry->urefs == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND;
		}
		destroy_receive_right(entry);
		entry_release_if_unused(entry);
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_deallocate(mach_port_name_t name)
{
	if (!MACH_PORT_VALID(name)) {
		return KERN_SUCCESS;
	}

	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (entry->type
			& (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_DEAD_NAME)) {
		if (--entry->urefs == 0) {
			entry->type &= ~(MACH_PORT_TYPE_SEND
					| MACH_PORT_TYPE_DEAD_NAME);
		}
	} else if (entry->type & MACH_PORT_TYPE_SEND_ONCE) {
		if (--entry->sorights == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
		}
	} else {
		kr = KERN_INVALID_RIGHT;
	}
	if (entry != NULL) {
		entry_release_if_unused(entry);
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_mod_refs(mach_port_name_t name, mach_port_right_t right,
		mach_port_delta_t delta)
{
	if (!MACH_PORT_VALID(name)) {
		return (right == MACH_PORT_RIGHT_SEND
				       || right == MACH_PORT_RIGHT_SEND_ONCE)
				? KERN_SUCCESS
				: KERN_INVALID_NAME;
	}

	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
		goto out;
	}

	switch (right) {
	case MACH_PORT_RIGHT_SEND:
	case MACH_PORT_RIGHT_DEAD_NAME: {
		mach_port_type_t type = MACH_PORT_TYPE(right);
		if (!(entry->type & type)) {
			kr = KERN_INVALID_RIGHT;
			break;
		}
		entry->urefs += delta;
		if (entry->urefs == 0) {
			entry->type &= ~type;
		}
	} break;
	case MACH_PORT_RIGHT_SEND_ONCE:
		if (!(entry->type & MACH_PORT_TYPE_SEND_ONCE)) {
			kr = KERN_INVALID_RIGHT;
			break;
		}
		entry->sorights += delta;
		if (entry->sorights == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
		}
		break;
	case MACH_PORT_RIGHT_RECEIVE:
		if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
			kr = KERN_INVALID_RIGHT;
		} else if (delta < 0) {
			destroy_receive_right(entry);
		}
		break;
	case MACH_PORT_RIGHT_PORT_SET:
		if (!(entry->type & MACH_PORT_TYPE_PORT_SET)) {
			kr = KERN_INVALID_RIGHT;
		} else if (delta < 0) {
			entry->type &= ~MACH_PORT_TYPE_PORT_SET;
		}
		break;
	default:
		kr = KERN_INVALID_VALUE;
	}
	entry_release_if_unused(entry);
out:
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_insert_right(mach_port_name_t name, mach_port_name_t poly,
		mach_msg_type_name_t poly_poly)
{
	if (name != poly) {
		unimplemented();
	}

	pthread_mutex_lock(&lock);
	mach_msg_type_name_t type;
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!has_right(entry, poly_poly)) {
		kr = KERN_INVALID_RIGHT;
	} else if (poly_poly != MACH_MSG_TYPE_MOVE_SEND
			&& poly_poly != MACH_MSG_TYPE_MOVE_SEND_ONCE) {
		transfer_right(name, poly_poly, IPC_KERNEL, IPC_USER, &type);
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_extract_right(mach_port_name_t name, mach_msg_type_name_t msgt_name,
		mach_port_name_t *poly, mach_msg_type_name_t *poly_poly)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!has_right(entry, msgt_name)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		switch (msgt_name) {
		case MACH_MSG_TYPE_MOVE_SEND:
			if (--entry->urefs == 0) {
				entry->type &= ~MACH_PORT_TYPE_SEND;
			}
			break;
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
			if (--entry->sorights == 0) {
				entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
			}
			break;
		case MACH_MSG_TYPE_MOVE_RECEIVE:
			entry->type &= ~MACH_PORT_TYPE_RECEIVE;
			break;
		default:
			break;
		}
		*poly = name;
		*poly_poly = received_type(msgt_name);
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_type(mach_port_name_t name, mach_port_type_t *type)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else {
		*type = entry->type;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_names(mach_port_name_t **names, mach_port_type_t **types,
		uint32_t *count)
{
	pthread_mutex_lock(&lock);
	uint32_t used = 0;
	for (uint32_t index = 1; index < entry_count; index++) {
		if (entries[index].port != NULL) {
			used++;
		}
	}
	*names = NULL;
	*types = NULL;
	*count = used;
	if (used != 0) {
		mach_vm_address_t name_address = 0;
		mach_vm_address_t type_address = 0;
		_kernelrpc_mach_vm_allocate(0, &name_address,
				used * sizeof(**names), VM_FLAGS_ANYWHERE);
		_kernelrpc_mach_vm_allocate(0, &type_address,
				used * sizeof(**types), VM_FLAGS_ANYWHERE);
		*names = (mach_port_name_t *)name_address;
		*types = (mach_port_type_t *)type_address;
		uint32_t i = 0;
		for (uint32_t index = 1; index < entry_count; index++) {
			struct ipc_entry *entry = &entries[index];
			if (entry->port == NULL) {
				continue;
			}
			(*names)[i] = entry->port->name;
			(*types)[i] = entry->type;
			i++;
		}
	}
	pthread_mutex_unlock(&lock);
	return KERN_SUCCESS;
}

kern_return_t
ipc_port_get_refs(mach_port_name_t name, mach_port_right_t right,
		mach_port_urefs_t *refs)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else {
		switch (right) {
		case MACH_PORT_RIGHT_SEND:
		case MACH_PORT_RIGHT_DEAD_NAME:
			*refs = (entry->type & MACH_PORT_TYPE(right))
					? entry->urefs
					: 0;
			break;
		case MACH_PORT_RIGHT_SEND_ONCE:
			*refs = entry->sorights;
			break;
		default:
			*refs = (entry->type & MACH_PORT_TYPE(right)) ? 1 : 0;
		}
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_get_context(mach_port_name_t name, mach_port_context_t *context)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		*context = entry->port->context;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_set_context(mach_port_name_t name, mach_port_context_t context)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		entry->port->context = context;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_insert_member(mach_port_name_t member, mach_port_name_t pset)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port, *set;
	kern_return_t kr = member_and_set(member, pset, &port, &set);
	if (kr == KERN_SUCCESS && set == NULL) {
		kr = KERN_INVALID_RIGHT;
	} else if (kr == KERN_SUCCESS && port_in_set(port, set)) {
		kr = KERN_ALREADY_IN_SET;
	} else if (kr == KERN_SUCCESS) {
		port_join_set(port, set);
		pthread_cond_broadcast(&arrival);
		if (port->messages != NULL) {
			unlock_and_notify_arrival(port);
			return kr;
		}
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_extract_member(mach_port_name_t member, mach_port_name_t pset)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port, *set;
	kern_return_t kr = member_and_set(member, pset, &port, &set);
	if (kr == KERN_SUCCESS && (set == NULL || !port_leave_set(port, set))) {
		kr = KERN_NOT_IN_SET;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_move_member(mach_port_name_t member, mach_port_name_t pset)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port, *set;
	kern_return_t kr = member_and_set(member, pset, &port, &set);
	if (kr == KERN_SUCCESS) {
		port_leave_all_sets(port);
		if (set != NULL) {
			port_join_set(port, set);
			pthread_cond_broadcast(&arrival);
			if (port->messages != NULL) {
				unlock_and_notify_arrival(port);
				return kr;
			}
		}
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

static kern_return_t
member_and_set(mach_port_name_t member, mach_port_name_t pset,
		struct ipc_port **member_port, struct ipc_port **pset_port)
{
	struct ipc_entry *member_entry = lookup(member);
	struct ipc_entry *pset_entry = lookup(pset);
	if (member_entry == NULL
			|| (pset != MACH_PORT_NULL && pset_entry == NULL)) {
		return KERN_INVALID_NAME;
	}
	if (!(member_entry->type & MACH_PORT_TYPE_RECEIVE)
			|| (pset_entry != NULL
					&& !(pset_entry->type
							& MACH_PORT_TYPE_PORT_SET))) {
		return KERN_INVALID_RIGHT;
	}
	*member_port = member_entry->port;
	*pset_port = (pset_entry != NULL) ? pset_entry->port : NULL;
	return KERN_SUCCESS;
}

kern_return_t
ipc_port_get_status(mach_port_name_t name, mach_port_status_t *status)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		struct ipc_port *port = entry->port;
		memset(status, 0, sizeof(*status));
		status->mps_pset = (port->pset_count != 0)
				? port->psets[0]->name
				: MACH_PORT_NULL;
		status->mps_seqno = port->seqno;
		status->mps_qlimit = MACH_PORT_QLIMIT_DEFAULT;
		for (struct ipc_kmsg *kmsg = port->messages; kmsg != NULL;
				kmsg = kmsg->next) {
			status->mps_msgcount++;
		}
		status->mps_sorights = entry->sorights;
		status->mps_srights = (entry->type & MACH_PORT_TYPE_SEND) != 0;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

static void
destroy_receive_right(struct ipc_entry *entry)
{
	struct ipc_port *port = entry->port;
	while (port->messages != NULL) {
		struct ipc_kmsg *kmsg = port->messages;
		port->messages = kmsg->next;
		free(kmsg);
	}
	port_leave_all_sets(port);

	entry->type &= ~MACH_PORT_TYPE_RECEIVE;
	if (entry->type & MACH_PORT_TYPE_SEND) {
		entry->type = MACH_PORT_TYPE_DEAD_NAME;
	}
	pthread_cond_broadcast(&arrival);
}

static struct ipc_entry *
lookup(mach_port_name_t name)
{
	uint32_t index = MACH_PORT_INDEX(name);
	if (index == 0 || index >= entry_count) {
		return NULL;
	}

	struct ipc_entry *entry = &entries[index];
	if (entry->port == NULL || MACH_PORT_GEN(name) != entry->generation) {
		return NULL;
	}
	return entry;
}

static struct ipc_port *
port_alloc(ipc_kobject_type_t kotype)
{
	struct ipc_port *port = calloc(1, sizeof(*port));
	port->kotype = kotype;
	return port;
}

static struct ipc_entry *
entry_alloc(struct ipc_port *port)
{
	uint32_t index;
	for (index = 1; index < entry_count; index++) {
		if (entries[index].port == NULL) {
			break;
		}
	}

	if (index >= entry_count) {
		uint32_t count = (entry_count != 0) ? entry_count * 2 : 64;
		entries = realloc(entries, count * sizeof(*entries));
		memset(&entries[entry_count], 0,
				(count - entry_count) * sizeof(*entries));
		for (uint32_t i = entry_count; i < count; i++) {
			entries[i].generation = MACH_PORT_GEN(3);
		}
		entry_count = count;
	}

	struct ipc_entry *entry = &entries[index];
	entry->port = port;
	port->name = MACH_PORT_MAKE(index, entry->generation);
	return entry;
}

static void
entry_release_if_unused(struct ipc_entry *entry)
{
	if (entry->type != 0) {
		return;
	}

	struct ipc_port *port = entry->port;
	port->name = MACH_PORT_NULL;
	if (port->is_pset) {
		pset_release_members(port);
	}
	if (port->kotype == IPC_KOBJECT_NONE) {
		free(port->psets);
		free(port);
	} else if (port->kotype == IPC_KOBJECT_FILEPORT) {
		close(*(int *)port->kobject);
		free(port->kobject);
		free(port);
	}
	entry->port = NULL;
	entry->urefs = 0;
	entry->sorights = 0;
	entry->generation += MACH_PORT_GEN(4);
}

static bool
port_in_set(const struct ipc_port *port, const struct ipc_port *pset)
{
	for (uint32_t i = 0; i < port->pset_count; i++) {
		if (port->psets[i] == pset) {
			return true;
		}
	}
	return false;
}

static void
port_join_set(struct ipc_port *port, struct ipc_port *pset)
{
	port->psets = realloc(port->psets,
			(port->pset_count + 1) * sizeof(*port->psets));
	port->psets[port->pset_count++] = pset;
}

static void
port_leave_all_sets(struct ipc_port *port)
{
	free(port->psets);
	port->psets = NULL;
	port->pset_count = 0;
}

static void
pset_release_members(const struct ipc_port *pset)
{
	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *member = entries[i].port;
		if (member != NULL) {
			port_leave_set(member, pset);
		}
	}
}

static bool
port_leave_set(struct ipc_port *port, const struct ipc_port *pset)
{
	for (uint32_t i = 0; i < port->pset_count; i++) {
		if (port->psets[i] == pset) {
			port->psets[i] = port->psets[--port->pset_count];
			return true;
		}
	}
	return false;
}
