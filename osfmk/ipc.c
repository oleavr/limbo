/*
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <mach/notify.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "broker.h"
#include "broker_client.h"
#include "bsd/kevent.h"
#include "bsd/signals.h"
#include "eventlink.h"
#include "ipc.h"
#include "libinfo.h"
#include "mach_vm.h"
#include "trace.h"
#include "xpc_bootstrap.h"

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
	struct ipc_port **members;
	uint32_t member_count;
	struct ipc_kmsg *messages;
	struct ipc_kmsg **messages_tail;
	mach_port_seqno_t seqno;
	mach_port_mscount_t mscount;
	mach_port_urefs_t kernel_sorights;
	struct ipc_port *no_senders_notify;
	struct ipc_port *destroyed_notify;
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

struct arrival_waiter {
	struct arrival_waiter *next;
	const struct ipc_port *port;
	_Atomic uint32_t woken;
};

struct dead_name_request {
	struct dead_name_request *next;
	mach_port_name_t name;
	struct ipc_port *notify;
};

struct pending_notice {
	struct pending_notice *next;
	mach_msg_id_t id;
	struct ipc_port *notify;
	mach_port_name_t name;
	mach_port_mscount_t mscount;
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
struct processor_set_subsystem;
struct mach_voucher_subsystem;
struct memory_entry_subsystem;
struct mach_eventlink_subsystem;

extern const struct task_subsystem task_subsystem;
extern const struct mach_vm_subsystem mach_vm_subsystem;
extern const struct mach_port_subsystem mach_port_subsystem;
extern const struct thread_act_subsystem thread_act_subsystem;
extern const struct mach_host_subsystem mach_host_subsystem;
extern const struct clock_subsystem clock_subsystem;
extern const struct task_restartable_subsystem task_restartable_subsystem;
extern const struct host_priv_subsystem host_priv_subsystem;
extern const struct is_iokit_subsystem is_iokit_subsystem;
extern const struct processor_set_subsystem processor_set_subsystem;
extern const struct mach_voucher_subsystem mach_voucher_subsystem;
extern const struct memory_entry_subsystem memory_entry_subsystem;
extern const struct mach_eventlink_subsystem mach_eventlink_subsystem;
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
		(const struct mig_subsystem *)&processor_set_subsystem,
		(const struct mig_subsystem *)&mach_voucher_subsystem,
		(const struct mig_subsystem *)&memory_entry_subsystem,
		(const struct mig_subsystem *)&mach_eventlink_subsystem,
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct arrival_waiter *arrival_waiters;
static struct dead_name_request *dead_name_requests;
static struct pending_notice *pending_notices;
static struct pending_notice **pending_notices_tail = &pending_notices;
static struct ipc_entry *entries;
static uint32_t entry_count;
static struct ipc_port *kobjects[IPC_KOBJECT_VOUCHER + 1];
static uint32_t export_counter;
static uint32_t transfer_counter;
static const uint64_t dead_global_id = UINT64_MAX;

static void ipc_fork_prepare(void);
static void ipc_fork_parent(void);
static void ipc_fork_child(void);
static mach_msg_return_t remote_send(mach_msg_header_t *header,
		mach_msg_size_t size, ipc_side_t sender, pid_t sender_pid);
static mach_msg_return_t remote_copyin(
		mach_msg_header_t *header, ipc_side_t sender);
static uint32_t export_body_ports(mach_msg_header_t *header,
		uint64_t *global_ids, uint8_t **data, uint32_t *data_length,
		uint32_t dest_guest_id);
static uint64_t export_body_port(mach_port_name_t name,
		mach_msg_type_name_t disposition, uint32_t dest_guest_id);
static void import_body_ports(mach_msg_header_t *header,
		const uint64_t *global_ids, const uint8_t *data);
static mach_port_name_t import_body_port(uint64_t global_id,
		mach_msg_type_name_t type);
static uint64_t export_local_port(mach_port_name_t name);
static struct ipc_port *port_for_global_id(uint64_t global_id);
static mach_port_name_t import_remote_send(
		uint64_t global_id, mach_msg_type_name_t type);

static void kill_kobject_port(struct ipc_entry *entry);
static mach_port_name_t kobject_send_right(ipc_kobject_type_t type);
static struct ipc_port *kobject_port(ipc_kobject_type_t type);
static mach_msg_return_t send(mach_msg_header_t *msg, mach_msg_size_t size,
		ipc_side_t sender, pid_t sender_pid);
static bool has_valid_descriptors(const mach_msg_header_t *header);
static mach_msg_return_t copyin(mach_msg_header_t *header, ipc_side_t sender,
		struct ipc_port **dest);
static bool moves_one_right_twice(
		const struct ipc_entry *entry, mach_msg_bits_t bits);
static mach_msg_return_t copyin_body(mach_msg_header_t *header,
		ipc_side_t sender, ipc_side_t receiver);
static mach_msg_return_t transfer_right(mach_port_name_t name,
		mach_msg_type_name_t disposition, ipc_side_t sender,
		ipc_side_t receiver, mach_msg_type_name_t *type);
static bool has_right(
		struct ipc_entry *entry, mach_msg_type_name_t disposition);
static mach_msg_type_name_t received_type(mach_msg_type_name_t disposition);
static void mark_circular(mach_msg_header_t *header, mach_port_name_t name,
		mach_msg_type_name_t type, ipc_side_t receiver);
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
static int wait_for_arrival(const struct ipc_port *port,
		mach_msg_option64_t options, mach_msg_timeout_t timeout,
		struct timespec *deadline);
static void wake_waiters_for(const struct ipc_port *port);
static void wake_all_waiters(void);
static void write_trailer(mach_msg_header_t *msg, struct ipc_port *port,
		pid_t sender_pid);
static void flush_notices(void);
static void notify_port_deleted(struct ipc_port *notify, mach_port_name_t name);
static void notify_send_possible(
		struct ipc_port *notify, mach_port_name_t name);
static void notify_port_destroyed(
		struct ipc_port *notify, mach_port_name_t name);
static void notify_no_senders(
		struct ipc_port *notify, mach_port_mscount_t mscount);
static void notify_send_once(struct ipc_port *port);
static void notify_dead_name(struct ipc_port *notify, mach_port_name_t name);
static bool deliver_notification(
		struct ipc_port *port, const mach_msg_header_t *msg);
static kern_return_t request_notification(mach_port_name_t name,
		mach_msg_id_t id, mach_port_mscount_t sync,
		mach_port_name_t notify, mach_port_name_t *previous);
static kern_return_t request_port_destroyed(mach_port_name_t name,
		mach_port_mscount_t sync, mach_port_name_t notify);
static kern_return_t request_no_senders(mach_port_name_t name,
		mach_port_mscount_t sync, mach_port_name_t notify,
		struct ipc_port **replaced);
static kern_return_t request_dead_name(mach_port_name_t name, mach_msg_id_t id,
		mach_port_mscount_t sync, mach_port_name_t notify,
		struct ipc_port **replaced);
static void destroy_receive_right(struct ipc_entry *entry);
static void queue_dead_name_notification(struct ipc_entry *entry);
static void destroy_rights(mach_msg_header_t *header);
static void destroy_right(mach_port_name_t name, mach_msg_type_name_t type);
static struct ipc_entry *lookup(mach_port_name_t name);
static struct ipc_port *port_alloc(ipc_kobject_type_t kotype);
static struct ipc_entry *entry_alloc(struct ipc_port *port);
static void entry_release_if_unused(struct ipc_entry *entry);
static void destroy_requests(struct ipc_port *port);
static void destroy_send_once(struct ipc_port **right);
static void port_free_if_unheld(struct ipc_port *port);
static void queue_no_senders_notification(struct ipc_entry *entry);
static struct ipc_port *cancel_dead_name_request(mach_port_name_t name);
static struct ipc_port *hold_send_once(mach_port_name_t name);
static mach_port_name_t send_once_name(struct ipc_port *port);
static bool port_has_receiver(const struct ipc_port *port);
static void queue_send_once_notifications(
		struct ipc_entry *entry, uint32_t count);
static void queue_notice(struct pending_notice notice);
static kern_return_t member_and_set(mach_port_name_t member,
		mach_port_name_t pset, struct ipc_port **member_port,
		struct ipc_port **pset_port);
static bool port_in_set(
		const struct ipc_port *port, const struct ipc_port *pset);
static void port_join_set(struct ipc_port *port, struct ipc_port *pset);
static void port_leave_all_sets(struct ipc_port *port);
static void pset_release_members(struct ipc_port *pset);
static bool port_leave_set(struct ipc_port *port, struct ipc_port *pset);
static void pset_drop_member(
		struct ipc_port *pset, const struct ipc_port *port);

__attribute__((constructor)) static void
ipc_init(void)
{
	pthread_atfork(ipc_fork_prepare, ipc_fork_parent, ipc_fork_child);
}

static void
ipc_fork_prepare(void)
{
	pthread_mutex_lock(&lock);
}

static void
ipc_fork_parent(void)
{
	pthread_mutex_unlock(&lock);
}

static void
ipc_fork_child(void)
{
	arrival_waiters = NULL;
	pthread_mutex_unlock(&lock);
}

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
	kill_kobject_port(lookup(name));
	pthread_mutex_unlock(&lock);
	flush_notices();
}

void *
ipc_kobject_detach(mach_port_name_t name, ipc_kobject_type_t type)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	void *kobject = NULL;
	if (entry != NULL && entry->port->kotype == type) {
		kobject = entry->port->kobject;
		kill_kobject_port(entry);
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
	return kobject;
}

static void
kill_kobject_port(struct ipc_entry *entry)
{
	entry->port->kotype = IPC_KOBJECT_NONE;
	entry->port->kobject = NULL;
	if (entry->type & MACH_PORT_TYPE_SEND) {
		entry->type = MACH_PORT_TYPE_DEAD_NAME;
		queue_dead_name_notification(entry);
	}
	entry_release_if_unused(entry);
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
		trace_message(TRACE_MESSAGE_SENT, msg, send_size);
		mach_msg_return_t mr = send(msg, send_size, IPC_USER,
				getpid());
		flush_notices();
		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}
	}

	if (options & MACH64_RCV_MSG) {
		mach_msg_return_t mr = receive(
				msg, options, rcv_size, rcv_name, timeout);
		if (mr == MACH_MSG_SUCCESS) {
			trace_message(TRACE_MESSAGE_RECEIVED, msg,
					msg->msgh_size);
		}
		return mr;
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
	if (!has_valid_descriptors(kmsg->header)) {
		free(kmsg);
		return MACH_SEND_INVALID_TYPE;
	}

	pthread_mutex_lock(&lock);
	struct ipc_entry *remote_entry = lookup(kmsg->header->msgh_remote_port);
	if (remote_entry != NULL && remote_entry->port->remote) {
		mach_msg_return_t rr = remote_send(
				kmsg->header, size, sender, sender_pid);
		free(kmsg);
		return rr;
	}

	struct ipc_port *dest;
	mach_msg_return_t mr = copyin(kmsg->header, sender, &dest);
	if (mr != MACH_MSG_SUCCESS
			|| (kmsg->header->msgh_bits
					& MACH_MSGH_BITS_CIRCULAR)) {
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

static bool
has_valid_descriptors(const mach_msg_header_t *header)
{
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return true;
	}

	const mach_msg_body_t *body = (const mach_msg_body_t *)(header + 1);
	const uint8_t *cursor = (const uint8_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		const mach_msg_type_descriptor_t *descriptor
				= (const mach_msg_type_descriptor_t *)cursor;
		switch (descriptor->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			cursor += sizeof(mach_msg_port_descriptor_t);
			break;
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			cursor += sizeof(mach_msg_ool_descriptor64_t);
			break;
		default:
			return false;
		}
	}
	return true;
}

static mach_msg_return_t
remote_send(mach_msg_header_t *header, mach_msg_size_t size, ipc_side_t sender,
		pid_t sender_pid)
{
	uint64_t dest_global_id = lookup(header->msgh_remote_port)->port->global_id;
	mach_msg_bits_t bits = header->msgh_bits;

	mach_msg_return_t mr = remote_copyin(header, sender);
	if (mr != MACH_MSG_SUCCESS) {
		release_unused_entries(header);
		pthread_mutex_unlock(&lock);
		return mr;
	}

	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint32_t id_capacity = (bits & MACH_MSGH_BITS_COMPLEX)
			? body->msgh_descriptor_count
			: 0;
	uint64_t *global_ids = malloc(id_capacity * sizeof(*global_ids));
	uint8_t *data = NULL;
	uint32_t data_length = 0;
	uint32_t descriptor_count = export_body_ports(header, global_ids, &data,
			&data_length, broker_guest_of(dest_global_id));

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
	uint32_t blob_length = sizeof(rh) + size + ids_length + data_length;
	char *blob = malloc(blob_length);
	memcpy(blob, &rh, sizeof(rh));
	memcpy(blob + sizeof(rh), header, size);
	memcpy(blob + sizeof(rh) + size, global_ids, ids_length);
	free(global_ids);
	memcpy(blob + sizeof(rh) + size + ids_length, data, data_length);
	free(data);

	release_unused_entries(header);
	pthread_mutex_unlock(&lock);
	broker_client_send(dest_global_id, blob, blob_length);
	free(blob);
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
remote_copyin(mach_msg_header_t *header, ipc_side_t sender)
{
	mach_msg_bits_t bits = header->msgh_bits;

	struct ipc_entry *dest_entry = lookup(header->msgh_remote_port);
	if (sender == IPC_USER
			&& !has_right(dest_entry,
					MACH_MSGH_BITS_REMOTE(bits))) {
		return MACH_SEND_INVALID_DEST;
	}

	mach_msg_type_name_t type;
	if (transfer_right(header->msgh_local_port, MACH_MSGH_BITS_LOCAL(bits),
			    sender, IPC_KERNEL, &type)
			!= MACH_MSG_SUCCESS) {
		return MACH_SEND_INVALID_REPLY;
	}
	transfer_right(header->msgh_remote_port, MACH_MSGH_BITS_REMOTE(bits),
			sender, IPC_KERNEL, &type);

	if (!(bits & MACH_MSGH_BITS_COMPLEX)) {
		return MACH_MSG_SUCCESS;
	}
	return copyin_body(header, sender, IPC_KERNEL);
}

static uint32_t
export_body_ports(mach_msg_header_t *header, uint64_t *global_ids,
		uint8_t **data, uint32_t *data_length, uint32_t dest_guest_id)
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
		} else if (descriptor->type == MACH_MSG_OOL_DESCRIPTOR
				|| descriptor->type
						== MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
			mach_msg_ool_descriptor64_t *d
					= (mach_msg_ool_descriptor64_t *)cursor;
			*data = realloc(*data, *data_length + d->size);
			memcpy(*data + *data_length, (void *)d->address,
					d->size);
			*data_length += d->size;
			if (d->deallocate) {
				_kernelrpc_mach_vm_deallocate(
						0, d->address, d->size);
			}
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
	if (name == MACH_PORT_NULL) {
		return 0;
	}

	if (name == MACH_PORT_DEAD
			|| disposition != MACH_MSG_TYPE_MOVE_RECEIVE) {
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
	if (name == MACH_PORT_DEAD) {
		return dead_global_id;
	}

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
				&& port->global_id == global_id
				&& !(entries[i].type
						& MACH_PORT_TYPE_DEAD_NAME)) {
			return port;
		}
	}
	return NULL;
}

static mach_port_name_t
import_remote_send(uint64_t global_id, mach_msg_type_name_t type)
{
	if (global_id == dead_global_id) {
		return MACH_PORT_DEAD;
	}

	if (broker_guest_of(global_id) == broker_client_guest_id()) {
		struct ipc_port *port = port_for_global_id(global_id);
		if (port == NULL) {
			return MACH_PORT_DEAD;
		}
		transfer_right(port->name, type, IPC_KERNEL, IPC_USER, &type);
		return port->name;
	}

	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *port = entries[i].port;
		if (port != NULL && port->remote
				&& port->global_id == global_id) {
			transfer_right(port->name, type, IPC_KERNEL, IPC_USER,
					&type);
			return port->name;
		}
	}

	struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	entry->port->remote = true;
	entry->port->global_id = global_id;
	transfer_right(entry->port->name, type, IPC_KERNEL, IPC_USER, &type);
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
	if (dest == NULL) {
		pthread_mutex_unlock(&lock);
		return;
	}

	struct ipc_kmsg *kmsg = malloc(sizeof(*kmsg) + rh->message_size
			+ sizeof(mach_msg_max_trailer_t));
	kmsg->sender_pid = rh->sender_pid;
	memcpy(kmsg->header, message, rh->message_size);

	mach_msg_type_name_t reply_type = received_type(rh->reply_disposition);
	mach_port_name_t reply_name = (rh->reply_global_id != 0)
			? import_remote_send(rh->reply_global_id, reply_type)
			: MACH_PORT_NULL;
	kmsg->header->msgh_bits = MACH_MSGH_BITS_SET(reply_type,
			received_type(rh->dest_disposition), 0,
			message->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	kmsg->header->msgh_remote_port = reply_name;
	kmsg->header->msgh_local_port = dest->name;
	kmsg->header->msgh_voucher_port = MACH_PORT_NULL;
	kmsg->header->msgh_size = rh->message_size;

	import_body_ports(kmsg->header, global_ids,
			(const uint8_t *)&global_ids[rh->descriptor_count]);

	enqueue(dest, kmsg);
	unlock_and_notify_arrival(dest);
}

static void
import_body_ports(mach_msg_header_t *header, const uint64_t *global_ids,
		const uint8_t *data)
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
		} else if (descriptor->type == MACH_MSG_OOL_DESCRIPTOR
				|| descriptor->type
						== MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
			mach_msg_ool_descriptor64_t *d
					= (mach_msg_ool_descriptor64_t *)cursor;
			d->address = (uint64_t)copy_ool(data, d->size);
			data += d->size;
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

	if (type == MACH_MSG_TYPE_PORT_RECEIVE && global_id != dead_global_id) {
		struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
		entry->type = MACH_PORT_TYPE_RECEIVE;
		entry->port->global_id = global_id;
		return entry->port->name;
	}
	return import_remote_send(global_id, type);
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
	mach_port_name_t name_out = import_remote_send(
			global_id, MACH_MSG_TYPE_PORT_SEND);
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
	if (sender == IPC_USER
			&& !has_right(dest_entry,
					MACH_MSGH_BITS_REMOTE(bits))) {
		return MACH_SEND_INVALID_DEST;
	}
	if (header->msgh_local_port == header->msgh_remote_port
			&& moves_one_right_twice(dest_entry, bits)) {
		return MACH_SEND_INVALID_DEST;
	}
	*dest = dest_entry->port;
	ipc_side_t receiver = ((*dest)->kotype == IPC_KOBJECT_NONE)
			? IPC_USER
			: IPC_KERNEL;

	mach_msg_type_name_t reply_type;
	if (transfer_right(header->msgh_local_port, MACH_MSGH_BITS_LOCAL(bits),
			    sender, receiver, &reply_type)
			!= MACH_MSG_SUCCESS) {
		return MACH_SEND_INVALID_REPLY;
	}

	mach_msg_type_name_t dest_type;
	if (transfer_right(header->msgh_remote_port,
			    MACH_MSGH_BITS_REMOTE(bits), sender, IPC_KERNEL,
			    &dest_type)
			!= MACH_MSG_SUCCESS) {
		return MACH_SEND_INVALID_DEST;
	}

	header->msgh_bits = MACH_MSGH_BITS_SET(reply_type, dest_type, 0,
			bits & MACH_MSGH_BITS_COMPLEX);
	header->msgh_remote_port = header->msgh_local_port;
	header->msgh_local_port = (*dest)->name;
	header->msgh_voucher_port = MACH_PORT_NULL;

	if (!(bits & MACH_MSGH_BITS_COMPLEX)) {
		return MACH_MSG_SUCCESS;
	}

	mach_msg_return_t mr = copyin_body(header, sender, receiver);
	if ((mr == MACH_SEND_INVALID_RIGHT && receiver == IPC_USER)
			|| (header->msgh_bits & MACH_MSGH_BITS_CIRCULAR)) {
		destroy_rights(header);
	}
	return mr;
}

static bool
moves_one_right_twice(const struct ipc_entry *entry, mach_msg_bits_t bits)
{
	mach_msg_type_name_t disposition = MACH_MSGH_BITS_REMOTE(bits);
	if (MACH_MSGH_BITS_LOCAL(bits) != disposition) {
		return false;
	}

	switch (disposition) {
	case MACH_MSG_TYPE_MOVE_SEND:
		return entry->urefs < 2;
	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		return entry->sorights < 2;
	default:
		return false;
	}
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
				body->msgh_descriptor_count = i;
				return MACH_SEND_INVALID_RIGHT;
			}
			mark_circular(header, d->name, type, receiver);
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
				body->msgh_descriptor_count = i;
				return MACH_SEND_INVALID_RIGHT;
			}
			mark_circular(header, d->name, type, receiver);
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
					d->count = j;
					d->disposition = type;
					body->msgh_descriptor_count = i + 1;
					return MACH_SEND_INVALID_RIGHT;
				}
				mark_circular(header, names[j], type, receiver);
			}
			if (sender == IPC_USER && receiver == IPC_USER
					&& !d->deallocate) {
				d->address = (uint64_t)copy_ool(names,
						d->count * sizeof(*names));
			}
			d->disposition = type;
			cursor += sizeof(*d);
		} break;
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

	if (disposition == MACH_MSG_TYPE_MAKE_SEND
			&& (entry->type & MACH_PORT_TYPE_RECEIVE)) {
		entry->port->mscount++;
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
				wake_all_waiters();
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

static void
mark_circular(mach_msg_header_t *header, mach_port_name_t name,
		mach_msg_type_name_t type, ipc_side_t receiver)
{
	if (receiver == IPC_USER && type == MACH_MSG_TYPE_PORT_RECEIVE
			&& name == header->msgh_local_port) {
		header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
	}
}

static void *
copy_ool(const void *address, mach_msg_size_t size)
{
	if (size == 0) {
		return NULL;
	}
	mach_vm_address_t copy = 0;
	_kernelrpc_mach_vm_allocate(0, &copy, size, VM_FLAGS_ANYWHERE);
	memcpy((void *)copy, address, size);
	return (void *)copy;
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
	wake_waiters_for(port);
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
		bool complex = reply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX;
		trace_routine(id, complex ? KERN_SUCCESS : reply->RetCode);
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
			return waited ? MACH_RCV_PORT_CHANGED
				      : MACH_RCV_INVALID_NAME;
		}

		port = port_with_message(entry);
		if (port != NULL) {
			break;
		}

		int error = wait_for_arrival(
				entry->port, options, timeout, &deadline);
		if (error == ETIMEDOUT) {
			pthread_mutex_unlock(&lock);
			return MACH_RCV_TIMED_OUT;
		}
		if (error == EINTR) {
			pthread_mutex_unlock(&lock);
			return MACH_RCV_INTERRUPTED;
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

	struct ipc_port *pset = entry->port;
	for (uint32_t i = 0; i < pset->member_count; i++) {
		if (pset->members[i]->messages != NULL) {
			return pset->members[i];
		}
	}
	return NULL;
}

static int
wait_for_arrival(const struct ipc_port *port, mach_msg_option64_t options,
		mach_msg_timeout_t timeout, struct timespec *deadline)
{
	bool timed = options & MACH_RCV_TIMEOUT;
	if (timed && timeout == 0) {
		return ETIMEDOUT;
	}

	if (timed && deadline->tv_sec == 0) {
		clock_gettime(CLOCK_REALTIME, deadline);
		deadline->tv_sec += timeout / 1000;
		deadline->tv_nsec += (timeout % 1000) * 1000000;
		if (deadline->tv_nsec >= 1000000000) {
			deadline->tv_sec++;
			deadline->tv_nsec -= 1000000000;
		}
	}

	struct arrival_waiter waiter = {
			.next = arrival_waiters,
			.port = port,
	};
	arrival_waiters = &waiter;
	int error = signals_futex_wait(
			&waiter.woken, &lock, timed ? deadline : NULL);
	struct arrival_waiter **link = &arrival_waiters;
	while (*link != &waiter) {
		link = &(*link)->next;
	}
	*link = waiter.next;
	return error;
}

static void
wake_waiters_for(const struct ipc_port *port)
{
	for (struct arrival_waiter *waiter = arrival_waiters; waiter != NULL;
			waiter = waiter->next) {
		if (waiter->port == port || port_in_set(port, waiter->port)) {
			signals_futex_wake(&waiter->woken);
		}
	}
}

static void
wake_all_waiters(void)
{
	for (struct arrival_waiter *waiter = arrival_waiters; waiter != NULL;
			waiter = waiter->next) {
		signals_futex_wake(&waiter->woken);
	}
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
	mach_msg_return_t mr = send(msg, msg->msgh_size, IPC_KERNEL, 0);
	flush_notices();
	return mr;
}

mach_msg_return_t
ipc_launchd_send(mach_msg_header_t *msg)
{
	mach_msg_return_t mr = send(msg, msg->msgh_size, IPC_KERNEL, 1);
	flush_notices();
	return mr;
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
		entry->port->mscount = 1;
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
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
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
			queue_no_senders_notification(entry);
		}
	} else if (entry->type & MACH_PORT_TYPE_SEND_ONCE) {
		if (--entry->sorights == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
		}
		queue_send_once_notifications(entry, 1);
	} else {
		kr = KERN_INVALID_RIGHT;
	}
	if (entry != NULL) {
		entry_release_if_unused(entry);
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
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
		if (delta < 0 && (mach_port_urefs_t)-delta > entry->urefs) {
			kr = KERN_INVALID_VALUE;
			break;
		}
		entry->urefs += delta;
		if (entry->urefs == 0) {
			entry->type &= ~type;
			queue_no_senders_notification(entry);
		}
	} break;
	case MACH_PORT_RIGHT_SEND_ONCE:
		if (!(entry->type & MACH_PORT_TYPE_SEND_ONCE)) {
			kr = KERN_INVALID_RIGHT;
			break;
		}
		if (delta < 0 && (mach_port_urefs_t)-delta > entry->sorights) {
			kr = KERN_INVALID_VALUE;
			break;
		}
		entry->sorights += delta;
		if (entry->sorights == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
		}
		if (delta < 0) {
			queue_send_once_notifications(entry, -delta);
		}
		break;
	case MACH_PORT_RIGHT_RECEIVE:
		if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
			kr = KERN_INVALID_RIGHT;
		} else if (delta < 0) {
			destroy_receive_right(entry);
			goto out;
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
	flush_notices();
	return kr;
}

static void
flush_notices(void)
{
	pthread_mutex_lock(&lock);
	struct pending_notice *notices = pending_notices;
	pending_notices = NULL;
	pending_notices_tail = &pending_notices;
	pthread_mutex_unlock(&lock);

	while (notices != NULL) {
		struct pending_notice *notice = notices;
		notices = notice->next;
		switch (notice->id) {
		case MACH_NOTIFY_PORT_DELETED:
			notify_port_deleted(notice->notify, notice->name);
			break;
		case MACH_NOTIFY_SEND_POSSIBLE:
			notify_send_possible(notice->notify, notice->name);
			break;
		case MACH_NOTIFY_PORT_DESTROYED:
			notify_port_destroyed(notice->notify, notice->name);
			break;
		case MACH_NOTIFY_NO_SENDERS:
			notify_no_senders(notice->notify, notice->mscount);
			break;
		case MACH_NOTIFY_SEND_ONCE:
			notify_send_once(notice->notify);
			break;
		case MACH_NOTIFY_DEAD_NAME:
			notify_dead_name(notice->notify, notice->name);
			break;
		}
		free(notice);
	}
}

static void
notify_port_deleted(struct ipc_port *notify, mach_port_name_t name)
{
	mach_port_deleted_notification_t notification = {
		.not_header = {
			.msgh_size = sizeof(notification)
					- sizeof(notification.trailer),
			.msgh_id = MACH_NOTIFY_PORT_DELETED,
		},
		.NDR = NDR_record,
		.not_port = name,
	};
	deliver_notification(notify, &notification.not_header);
}

static void
notify_send_possible(struct ipc_port *notify, mach_port_name_t name)
{
	mach_send_possible_notification_t notification = {
		.not_header = {
			.msgh_size = sizeof(notification)
					- sizeof(notification.trailer),
			.msgh_id = MACH_NOTIFY_SEND_POSSIBLE,
		},
		.NDR = NDR_record,
		.not_port = name,
	};
	deliver_notification(notify, &notification.not_header);
}

static void
notify_port_destroyed(struct ipc_port *notify, mach_port_name_t name)
{
	mach_port_destroyed_notification_t notification = {
		.not_header = {
			.msgh_bits = MACH_MSGH_BITS_COMPLEX,
			.msgh_size = sizeof(notification)
					- sizeof(notification.trailer),
			.msgh_id = MACH_NOTIFY_PORT_DESTROYED,
		},
		.not_body = {.msgh_descriptor_count = 1},
		.not_port = {
			.name = name,
			.disposition = MACH_MSG_TYPE_PORT_RECEIVE,
			.type = MACH_MSG_PORT_DESCRIPTOR,
		},
	};
	if (!deliver_notification(notify, &notification.not_header)) {
		ipc_port_mod_refs(name, MACH_PORT_RIGHT_RECEIVE, -1);
	}
}

static void
notify_no_senders(struct ipc_port *notify, mach_port_mscount_t mscount)
{
	mach_no_senders_notification_t notification = {
		.not_header = {
			.msgh_size = sizeof(notification)
					- sizeof(notification.trailer),
			.msgh_id = MACH_NOTIFY_NO_SENDERS,
		},
		.NDR = NDR_record,
		.not_count = mscount,
	};
	deliver_notification(notify, &notification.not_header);
}

static void
notify_send_once(struct ipc_port *port)
{
	mach_send_once_notification_t notification = {
		.not_header = {
			.msgh_size = sizeof(notification.not_header),
			.msgh_id = MACH_NOTIFY_SEND_ONCE,
		},
	};
	deliver_notification(port, &notification.not_header);
}

static void
notify_dead_name(struct ipc_port *notify, mach_port_name_t name)
{
	mach_dead_name_notification_t notification = {
		.not_header = {
			.msgh_size = sizeof(notification)
					- sizeof(notification.trailer),
			.msgh_id = MACH_NOTIFY_DEAD_NAME,
		},
		.NDR = NDR_record,
		.not_port = name,
	};
	deliver_notification(notify, &notification.not_header);
}

static bool
deliver_notification(struct ipc_port *port, const mach_msg_header_t *msg)
{
	pthread_mutex_lock(&lock);
	port->kernel_sorights--;
	if (!port_has_receiver(port)) {
		port_free_if_unheld(port);
		pthread_mutex_unlock(&lock);
		return false;
	}

	struct ipc_kmsg *kmsg = malloc(sizeof(*kmsg) + msg->msgh_size
			+ sizeof(mach_msg_max_trailer_t));
	kmsg->sender_pid = 0;
	memcpy(kmsg->header, msg, msg->msgh_size);
	kmsg->header->msgh_bits = MACH_MSGH_BITS_SET(0,
			MACH_MSG_TYPE_PORT_SEND_ONCE, 0,
			msg->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	kmsg->header->msgh_local_port = port->name;
	enqueue(port, kmsg);
	unlock_and_notify_arrival(port);
	return true;
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
		case MACH_MSG_TYPE_MAKE_SEND:
			entry->port->mscount++;
			break;
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

void
ipc_space_counts(uint32_t *size, uint32_t *in_use)
{
	pthread_mutex_lock(&lock);
	uint32_t used = 0;
	for (uint32_t index = 1; index < entry_count; index++) {
		if (entries[index].port != NULL) {
			used++;
		}
	}
	*size = entry_count;
	*in_use = used;
	pthread_mutex_unlock(&lock);
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
ipc_port_set_mscount(mach_port_name_t name, mach_port_mscount_t mscount)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		entry->port->mscount = mscount;
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
		wake_all_waiters();
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
			wake_all_waiters();
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
		status->mps_mscount = port->mscount;
		status->mps_qlimit = MACH_PORT_QLIMIT_DEFAULT;
		for (struct ipc_kmsg *kmsg = port->messages; kmsg != NULL;
				kmsg = kmsg->next) {
			status->mps_msgcount++;
		}
		status->mps_sorights = entry->sorights + port->kernel_sorights;
		status->mps_srights = (entry->type & MACH_PORT_TYPE_SEND) != 0;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_request_notification(mach_port_name_t name, mach_msg_id_t id,
		mach_port_mscount_t sync, mach_port_name_t notify,
		mach_port_name_t *previous)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = (notify == MACH_PORT_NULL || lookup(notify) != NULL)
			? request_notification(name, id, sync, notify, previous)
			: KERN_INVALID_CAPABILITY;
	pthread_mutex_unlock(&lock);
	flush_notices();
	return kr;
}

kern_return_t
ipc_port_request_notification_trap(mach_port_name_t name, mach_msg_id_t id,
		mach_port_mscount_t sync, mach_port_name_t notify,
		mach_msg_type_name_t notify_poly, mach_port_name_t *previous)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr;
	mach_msg_type_name_t type;
	struct ipc_entry *entry = lookup(notify);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!has_right(entry, notify_poly)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		transfer_right(notify, notify_poly, IPC_USER, IPC_KERNEL,
				&type);
		kr = request_notification(name, id, sync, notify, previous);
		release_unused_entry(notify);
	}
	if (kr == KERN_SUCCESS) {
		transfer_right(*previous, MACH_MSG_TYPE_MOVE_SEND_ONCE,
				IPC_KERNEL, IPC_USER, &type);
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
	return kr;
}

static kern_return_t
request_notification(mach_port_name_t name, mach_msg_id_t id,
		mach_port_mscount_t sync, mach_port_name_t notify,
		mach_port_name_t *previous)
{
	struct ipc_port *replaced = NULL;
	kern_return_t kr;
	switch (id) {
	case MACH_NOTIFY_PORT_DESTROYED:
		kr = request_port_destroyed(name, sync, notify);
		break;
	case MACH_NOTIFY_NO_SENDERS:
		kr = request_no_senders(name, sync, notify, &replaced);
		break;
	case MACH_NOTIFY_SEND_POSSIBLE:
	case MACH_NOTIFY_DEAD_NAME:
		kr = request_dead_name(name, id, sync, notify, &replaced);
		break;
	default:
		kr = KERN_INVALID_VALUE;
	}
	if (kr != KERN_SUCCESS) {
		if (notify != MACH_PORT_NULL) {
			queue_notice((struct pending_notice){
					.id = MACH_NOTIFY_SEND_ONCE,
					.notify = hold_send_once(notify),
			});
		}
		return kr;
	}
	*previous = send_once_name(replaced);
	return KERN_SUCCESS;
}

static kern_return_t
request_port_destroyed(mach_port_name_t name, mach_port_mscount_t sync,
		mach_port_name_t notify)
{
	if (sync != 0) {
		return KERN_INVALID_VALUE;
	}
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		return KERN_INVALID_NAME;
	}
	if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		return KERN_INVALID_RIGHT;
	}
	if (entry->port->destroyed_notify != NULL) {
		return KERN_FAILURE;
	}

	entry->port->destroyed_notify = notify != MACH_PORT_NULL
			? hold_send_once(notify)
			: NULL;
	return KERN_SUCCESS;
}

static kern_return_t
request_no_senders(mach_port_name_t name, mach_port_mscount_t sync,
		mach_port_name_t notify, struct ipc_port **replaced)
{
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		return KERN_INVALID_NAME;
	}
	if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		return KERN_INVALID_RIGHT;
	}

	struct ipc_port *port = entry->port;
	*replaced = port->no_senders_notify;
	port->no_senders_notify = notify != MACH_PORT_NULL
			? hold_send_once(notify)
			: NULL;
	if (sync <= port->mscount) {
		queue_no_senders_notification(entry);
	}
	return KERN_SUCCESS;
}

static kern_return_t
request_dead_name(mach_port_name_t name, mach_msg_id_t id,
		mach_port_mscount_t sync, mach_port_name_t notify,
		struct ipc_port **replaced)
{
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		return KERN_INVALID_NAME;
	}
	if (entry->type & MACH_PORT_TYPE_PORT_RIGHTS) {
		*replaced = cancel_dead_name_request(name);
		if (notify != MACH_PORT_NULL && id == MACH_NOTIFY_SEND_POSSIBLE
				&& sync != 0) {
			queue_notice((struct pending_notice){
					.id = MACH_NOTIFY_SEND_POSSIBLE,
					.notify = hold_send_once(notify),
					.name = name,
			});
		} else if (notify != MACH_PORT_NULL) {
			struct dead_name_request *request
					= malloc(sizeof(*request));
			*request = (struct dead_name_request){
					.next = dead_name_requests,
					.name = name,
					.notify = hold_send_once(notify),
			};
			dead_name_requests = request;
		}
		return KERN_SUCCESS;
	}
	if (notify == MACH_PORT_NULL) {
		return KERN_SUCCESS;
	}
	if (id == MACH_NOTIFY_SEND_POSSIBLE
			&& (entry->type & MACH_PORT_TYPE_DEAD_NAME)) {
		entry->urefs++;
		queue_notice((struct pending_notice){
				.id = MACH_NOTIFY_DEAD_NAME,
				.notify = hold_send_once(notify),
				.name = name,
		});
		return KERN_SUCCESS;
	}
	return (entry->type & MACH_PORT_TYPE_PORT_OR_DEAD)
			? KERN_INVALID_ARGUMENT
			: KERN_INVALID_RIGHT;
}

static void
destroy_receive_right(struct ipc_entry *entry)
{
	struct ipc_port *port = entry->port;
	if (port->destroyed_notify != NULL) {
		port_leave_all_sets(port);
		queue_notice((struct pending_notice){
				.id = MACH_NOTIFY_PORT_DESTROYED,
				.notify = port->destroyed_notify,
				.name = port->name,
		});
		port->destroyed_notify = NULL;
		return;
	}

	struct ipc_kmsg *queued = port->messages;
	port->messages = NULL;
	port_leave_all_sets(port);
	destroy_requests(port);

	entry->type &= ~MACH_PORT_TYPE_RECEIVE;
	if (entry->type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE)) {
		entry->type = MACH_PORT_TYPE_DEAD_NAME;
		entry->urefs += entry->sorights;
		entry->sorights = 0;
		queue_dead_name_notification(entry);
	}
	wake_all_waiters();
	entry_release_if_unused(entry);

	while (queued != NULL) {
		struct ipc_kmsg *kmsg = queued;
		queued = kmsg->next;
		destroy_rights(kmsg->header);
		free(kmsg);
	}
}

static void
queue_dead_name_notification(struct ipc_entry *entry)
{
	mach_port_name_t name = entry->port->name;
	struct ipc_port *notify = cancel_dead_name_request(name);
	if (notify == NULL) {
		return;
	}

	entry->urefs++;
	queue_notice((struct pending_notice){
			.id = MACH_NOTIFY_DEAD_NAME,
			.notify = notify,
			.name = name,
	});
}

static void
destroy_rights(mach_msg_header_t *header)
{
	destroy_right(header->msgh_remote_port,
			MACH_MSGH_BITS_REMOTE(header->msgh_bits));
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
			destroy_right(d->name, d->disposition);
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t
									*)
							cursor;
			destroy_right(d->name, d->disposition);
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor64_t *d
					= (mach_msg_ool_ports_descriptor64_t *)
							cursor;
			mach_port_name_t *names
					= (mach_port_name_t *)d->address;
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				destroy_right(names[j], d->disposition);
			}
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
			mach_msg_ool_descriptor64_t *d
					= (mach_msg_ool_descriptor64_t *)cursor;
			_kernelrpc_mach_vm_deallocate(0, d->address, d->size);
			cursor += sizeof(*d);
		} break;
		}
	}
}

static void
destroy_right(mach_port_name_t name, mach_msg_type_name_t type)
{
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		return;
	}

	switch (type) {
	case MACH_MSG_TYPE_PORT_SEND:
		if (--entry->urefs == 0) {
			entry->type &= ~(MACH_PORT_TYPE_SEND
					| MACH_PORT_TYPE_DEAD_NAME);
			queue_no_senders_notification(entry);
		}
		break;
	case MACH_MSG_TYPE_PORT_SEND_ONCE:
		if (entry->type & MACH_PORT_TYPE_DEAD_NAME) {
			if (--entry->urefs == 0) {
				entry->type &= ~MACH_PORT_TYPE_DEAD_NAME;
			}
		} else if (--entry->sorights == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
		}
		queue_send_once_notifications(entry, 1);
		break;
	case MACH_MSG_TYPE_PORT_RECEIVE:
		destroy_receive_right(entry);
		return;
	}
	entry_release_if_unused(entry);
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
	struct ipc_port *notify = cancel_dead_name_request(port->name);
	if (notify != NULL) {
		queue_notice((struct pending_notice){
				.id = MACH_NOTIFY_PORT_DELETED,
				.notify = notify,
				.name = port->name,
		});
	}
	port->name = MACH_PORT_NULL;
	if (port->is_pset) {
		pset_release_members(port);
		wake_all_waiters();
	}
	if (port->kotype == IPC_KOBJECT_NONE) {
		port_leave_all_sets(port);
		destroy_requests(port);
		port_free_if_unheld(port);
	} else if (port->kotype == IPC_KOBJECT_FILEPORT) {
		close(*(int *)port->kobject);
		free(port->kobject);
		free(port);
	} else if (port->kotype == IPC_KOBJECT_EVENTLINK) {
		eventlink_port_gone(port->kobject);
		free(port);
	}
	entry->port = NULL;
	entry->urefs = 0;
	entry->sorights = 0;
	entry->generation += MACH_PORT_GEN(4);
}

static void
destroy_requests(struct ipc_port *port)
{
	destroy_send_once(&port->no_senders_notify);
	destroy_send_once(&port->destroyed_notify);
}

static void
destroy_send_once(struct ipc_port **right)
{
	if (*right == NULL) {
		return;
	}

	queue_notice((struct pending_notice){
			.id = MACH_NOTIFY_SEND_ONCE,
			.notify = *right,
	});
	*right = NULL;
}

static void
port_free_if_unheld(struct ipc_port *port)
{
	if (port->name == MACH_PORT_NULL && port->kernel_sorights == 0) {
		free(port);
	}
}

static void
queue_no_senders_notification(struct ipc_entry *entry)
{
	struct ipc_port *port = entry->port;
	if (!(entry->type & MACH_PORT_TYPE_RECEIVE)
			|| (entry->type & MACH_PORT_TYPE_SEND)
			|| port->global_id != 0
			|| port->no_senders_notify == NULL) {
		return;
	}

	queue_notice((struct pending_notice){
			.id = MACH_NOTIFY_NO_SENDERS,
			.notify = port->no_senders_notify,
			.mscount = port->mscount,
	});
	port->no_senders_notify = NULL;
}

static struct ipc_port *
cancel_dead_name_request(mach_port_name_t name)
{
	for (struct dead_name_request **link = &dead_name_requests;
			*link != NULL; link = &(*link)->next) {
		struct dead_name_request *request = *link;
		if (request->name == name) {
			struct ipc_port *notify = request->notify;
			*link = request->next;
			free(request);
			return notify;
		}
	}
	return NULL;
}

static struct ipc_port *
hold_send_once(mach_port_name_t name)
{
	struct ipc_port *port = lookup(name)->port;
	port->kernel_sorights++;
	return port;
}

static mach_port_name_t
send_once_name(struct ipc_port *port)
{
	if (port == NULL) {
		return MACH_PORT_NULL;
	}

	port->kernel_sorights--;
	if (port_has_receiver(port)) {
		return port->name;
	}
	port_free_if_unheld(port);
	return MACH_PORT_DEAD;
}

static bool
port_has_receiver(const struct ipc_port *port)
{
	const struct ipc_entry *entry = lookup(port->name);
	return entry != NULL && (entry->type & MACH_PORT_TYPE_RECEIVE);
}

static void
queue_send_once_notifications(struct ipc_entry *entry, uint32_t count)
{
	if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		return;
	}

	entry->port->kernel_sorights += count;
	for (uint32_t i = 0; i < count; i++) {
		queue_notice((struct pending_notice){
				.id = MACH_NOTIFY_SEND_ONCE,
				.notify = entry->port,
		});
	}
}

static void
queue_notice(struct pending_notice notice)
{
	struct pending_notice *queued = malloc(sizeof(*queued));
	*queued = notice;
	*pending_notices_tail = queued;
	pending_notices_tail = &queued->next;
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
	pset->members = realloc(pset->members,
			(pset->member_count + 1) * sizeof(*pset->members));
	pset->members[pset->member_count++] = port;
}

static void
port_leave_all_sets(struct ipc_port *port)
{
	for (uint32_t i = 0; i < port->pset_count; i++) {
		pset_drop_member(port->psets[i], port);
	}
	free(port->psets);
	port->psets = NULL;
	port->pset_count = 0;
}

static void
pset_release_members(struct ipc_port *pset)
{
	while (pset->member_count != 0) {
		port_leave_set(pset->members[pset->member_count - 1], pset);
	}
	free(pset->members);
	pset->members = NULL;
}

static bool
port_leave_set(struct ipc_port *port, struct ipc_port *pset)
{
	for (uint32_t i = 0; i < port->pset_count; i++) {
		if (port->psets[i] == pset) {
			port->psets[i] = port->psets[--port->pset_count];
			pset_drop_member(pset, port);
			return true;
		}
	}
	return false;
}

static void
pset_drop_member(struct ipc_port *pset, const struct ipc_port *port)
{
	uint32_t i = 0;
	while (pset->members[i] != port) {
		i++;
	}
	pset->member_count--;
	memmove(&pset->members[i], &pset->members[i + 1],
			(pset->member_count - i) * sizeof(*pset->members));
}
