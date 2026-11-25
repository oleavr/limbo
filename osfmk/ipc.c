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
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <mach/notify.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bootstrap/bootstrap_defs.h"
#include "broker.h"
#include "broker_client.h"
#include "bsd/credentials.h"
#include "bsd/gid.h"
#include "bsd/kevent.h"
#include "bsd/process.h"
#include "bsd/signals.h"
#include "eventlink.h"
#include "ipc.h"
#include "ipc_remote.h"
#include "mach_vm.h"
#include "trace.h"
#include "xpc_bootstrap.h"
#include "xpc_service.h"

typedef enum {
	IPC_USER,
	IPC_KERNEL,
} ipc_side_t;

struct ipc_kmsg {
	struct ipc_kmsg *next;
	struct ipc_sender sender;
	mach_msg_return_t body_error;
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
	bool held;
	uint32_t *sender_guests;
	uint64_t *sender_grants;
	uint32_t sender_guest_count;
	uint64_t grants;
	uint32_t *watchers;
	uint32_t watcher_count;
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
	uint64_t global_id;
	struct remote_notice notice;
	struct ipc_kmsg *kmsg;
};

struct remote_send_once {
	struct remote_send_once *next;
	mach_port_name_t port;
	uint32_t guest_id;
};

struct remote_fds {
	int *fds;
	size_t count;
	bool failed;
};

struct ipc_export {
	uint8_t **data;
	uint32_t *data_length;
	struct remote_fds *fds;
};

struct remote_object {
	uint32_t fd_count;
	uint32_t length;
};

struct remote_memory_entry {
	uint64_t size;
	uint64_t data_offset;
};

struct moved_port {
	struct moved_port *next;
	uint64_t global_id;
	struct ipc_kmsg *messages;
	struct ipc_port *destroyed_notify;
};

struct port_return {
	struct port_return *next;
	uint64_t global_id;
	struct ipc_port *notify;
};

struct moved_away {
	struct moved_away *next;
	uint64_t global_id;
};

struct own_name {
	uint64_t global_id;
	char name[LIMBO_BROKER_SERVICE_NAME_MAX];
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
static pthread_mutex_t notice_order = PTHREAD_MUTEX_INITIALIZER;
static struct arrival_waiter *arrival_waiters;
static __thread bool kernel_receive;
static __thread bool serving_remote;
static struct dead_name_request *dead_name_requests;
static struct remote_send_once *remote_send_onces;
static struct port_return *port_returns;
static struct pending_notice *pending_notices;
static struct pending_notice **pending_notices_tail = &pending_notices;
static struct ipc_entry *entries;
static uint32_t entry_count;
static struct ipc_port *kobjects[IPC_KOBJECT_VOUCHER + 1];
static uint32_t export_counter;
static struct moved_away *moved_aways;
static struct moved_away *outliving_ports;
static struct moved_away *returned_ports;
struct guest_pid {
	uint32_t guest_id;
	int32_t pid;
};
static struct guest_pid *guest_pids;
static size_t guest_pid_count;
static size_t guest_pid_capacity;
static uint32_t *gone_guests;
static size_t gone_guest_count;
static pthread_mutex_t own_lock = PTHREAD_MUTEX_INITIALIZER;
static struct own_name *own_names;
static size_t own_name_count;
static const uint64_t dead_global_id = UINT64_MAX;
static const uint64_t fileport_global_id = UINT64_MAX - 1;
static const uint64_t memory_entry_global_id = UINT64_MAX - 2;

static void ipc_fork_prepare(void);
static void ipc_fork_parent(void);
static void ipc_fork_child(void);
static mach_msg_return_t remote_send(mach_msg_header_t *header,
		mach_msg_size_t size, ipc_side_t sender,
		const struct ipc_sender *identity, uint64_t dest_global_id);
static void finish_moves(struct moved_port *queued, bool sent);
static void send_queued(struct ipc_kmsg *kmsg, uint64_t global_id);
static void return_ports(uint64_t global_id, uint32_t guest_id);
static void return_port(uint64_t global_id, struct ipc_port *notify);
static bool port_is_gone(uint64_t global_id);
static bool moved_away(struct moved_away *list, uint64_t global_id);
static void forget_moved_away(struct moved_away **list, uint64_t global_id);
static bool forward_frame(uint64_t global_id, const void *blob, uint32_t length,
		const int *fds, size_t fd_count);
static void export_holders(
		struct ipc_entry *entry, uint8_t **data, uint32_t *data_length);
static void import_holders(struct ipc_entry *entry, const uint8_t **data);
static void release_out_of_line(mach_msg_header_t *header);
static void release_ool_ports(mach_msg_header_t *header);
static mach_msg_return_t remote_copyin(
		mach_msg_header_t *header, ipc_side_t sender);
static uint64_t remote_size(const mach_msg_header_t *header,
		mach_msg_size_t size, size_t *fd_count, uint32_t *id_count);
static uint64_t object_size(mach_port_name_t name, size_t *fd_count);
static uint32_t export_body_ports(mach_msg_header_t *header,
		uint64_t *global_ids, uint8_t **data, uint32_t *data_length,
		uint32_t dest_guest_id, struct remote_fds *fds,
		struct moved_port **queued);
static uint64_t export_body_port(mach_port_name_t name,
		mach_msg_type_name_t disposition, uint32_t dest_guest_id,
		struct remote_fds *fds, uint8_t **data, uint32_t *data_length,
		struct moved_port **queued);
static uint64_t export_fileport(
		const struct ipc_port *port, struct remote_fds *fds);
static uint64_t export_memory_entry(const struct ipc_port *port,
		struct remote_fds *fds, uint8_t **data, uint32_t *data_length);
static uint64_t export_kind(struct ipc_port *port, struct remote_fds *fds,
		uint8_t **data, uint32_t *data_length);
static bool export_fd(struct remote_fds *fds, int fd);
static mach_port_name_t import_kind(const struct ipc_kobject_ops *ops,
		const uint8_t **data, const int **fds, const int *all_fds,
		size_t fd_count);
static const struct ipc_kobject_ops *kobject_ops(ipc_kobject_type_t type);
static const struct ipc_kobject_ops *kobject_ops_for_remote_id(uint64_t id);
static void close_fds(const struct remote_fds *fds);
static bool remote_message_fits(const struct remote_header *rh, uint32_t length,
		size_t fd_count, bool lost);
static bool remote_body_fits(const mach_msg_header_t *message,
		mach_msg_size_t size, const uint64_t *global_ids,
		uint32_t id_count, uint32_t room, size_t fd_count, bool lost);
static bool remote_port_fits(uint64_t global_id,
		mach_msg_type_name_t disposition, const uint8_t **data,
		size_t *fd_count, uint32_t *room, bool lost);
static bool remote_right_fits(
		uint64_t global_id, mach_msg_type_name_t disposition);
static void import_body_ports(mach_msg_header_t *header,
		const uint64_t *global_ids, const uint8_t *data, const int *fds,
		size_t fd_count, uint32_t sender_guest_id,
		uint32_t meant_guest_id, mach_msg_return_t *body_error);
static mach_port_name_t import_body_port(uint64_t global_id,
		mach_msg_type_name_t type, const int **fds,
		const uint8_t **data, const int *all_fds, size_t fd_count,
		uint32_t sender_guest_id, uint32_t meant_guest_id);
static mach_port_name_t import_fileport(int fd);
static void turn_dead(struct ipc_entry *entry);
static void remember_gone(uint32_t guest_id);
static bool guest_is_gone(uint32_t guest_id);
static size_t gone_guest_index(uint32_t guest_id);
static void names_fork_prepare(void);
static void names_fork_parent(void);
static void names_fork_child(void);
static kern_return_t look_up(const char *name, uint32_t domain, bool registered,
		bool instance, mach_port_name_t *port, bool *hidden);
static uint32_t register_name(const char *name, uint64_t global_id);
static uint64_t own_name(const char *name);
static void add_own_name(const char *name, uint64_t global_id);
static void ipc_names_release(mach_port_name_t port);
static bool ipc_names_lives(uint64_t global_id);
static mach_port_name_t import_memory_entry(int fd, const uint8_t *record);
static struct ipc_entry *adopt_object(ipc_kobject_type_t kotype, void *kobject);
static void count_rights(const mach_msg_header_t *header, mach_msg_bits_t bits,
		uint64_t reply_global_id, const uint64_t *global_ids,
		uint32_t dest_guest_id, bool sent);
static void count_right(mach_port_name_t name, mach_msg_type_name_t type,
		uint64_t global_id, uint32_t dest_guest_id, bool sent);
static void count_sender_guest(
		struct ipc_port *port, uint32_t guest_id, uint64_t count);
static void release_grants(
		struct ipc_entry *entry, uint32_t guest_id, uint64_t count);
static void give_back_grants(struct ipc_port *port);
static void queue_send_once_gone(uint64_t global_id, uint32_t guest_id);
static void tell_holders_dead(struct ipc_port *port);

static void remember_send_once(mach_port_name_t port, uint32_t guest_id);
static uint32_t forget_send_onces(
		mach_port_name_t port, uint32_t guest_id, uint64_t count);
static void send_onces_gone(uint32_t guest_id);
static void move_send_once(struct ipc_entry *entry, uint32_t from, uint32_t to);
static void receive_notice(
		uint64_t dest_global_id, const struct remote_notice *notice);
static void deliver(uint64_t dest_global_id, const struct broker_sender *sender,
		const void *blob, uint32_t length, const int *fds,
		size_t fd_count, bool lost);
static void send_remote_notice(const struct pending_notice *notice);
static uint64_t export_local_port(mach_port_name_t name);
static uint64_t task_port_global_id(void);
static void remember_guest_pid(uint32_t guest_id, int32_t pid);
static void forget_guest_pid(uint32_t guest_id);
static struct ipc_port *port_for_global_id(uint64_t global_id);
static mach_port_name_t import_remote_send(uint64_t global_id,
		mach_msg_type_name_t type, uint32_t sender_guest_id,
		uint32_t meant_guest_id);

static void kill_kobject_port(struct ipc_entry *entry);
static mach_port_name_t kobject_send_right(ipc_kobject_type_t type);
static struct ipc_port *kobject_port(ipc_kobject_type_t type);
static mach_msg_return_t send(mach_msg_header_t *msg, mach_msg_size_t size,
		ipc_side_t sender, pid_t sender_pid);
static void serve_kernel(
		struct ipc_port *dest, struct ipc_kmsg *kmsg, bool remote);
static struct ipc_sender sender_identity(pid_t pid);
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
static void prepare_move(struct ipc_port *port);
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
		const struct ipc_sender *sender);
static void flush_notices(void);
static void send_returned(struct ipc_kmsg *kmsg, uint64_t global_id);
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
static bool deliver_remote_notification(
		uint64_t global_id, const mach_msg_header_t *msg);
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
static void return_held(struct ipc_port *port, struct ipc_kmsg *queued);
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
	pthread_mutex_lock(&notice_order);
	pthread_mutex_lock(&lock);
}

static void
ipc_fork_parent(void)
{
	pthread_mutex_unlock(&lock);
	pthread_mutex_unlock(&notice_order);
}

static void
ipc_fork_child(void)
{
	arrival_waiters = NULL;
	struct pending_notice **link = &pending_notices;
	while (*link != NULL) {
		struct pending_notice *notice = *link;
		if (notice->id != 0) {
			link = &notice->next;
			continue;
		}
		*link = notice->next;
		free(notice);
	}
	pending_notices_tail = link;
	while (remote_send_onces != NULL) {
		struct remote_send_once *record = remote_send_onces;
		remote_send_onces = record->next;
		free(record);
	}
	while (port_returns != NULL) {
		struct port_return *record = port_returns;
		port_returns = record->next;
		record->notify->kernel_sorights--;
		port_free_if_unheld(record->notify);
		free(record);
	}
	while (moved_aways != NULL) {
		struct moved_away *away = moved_aways;
		moved_aways = away->next;
		free(away);
	}
	for (uint32_t i = 1; i < entry_count; i++) {
		if (entries[i].port != NULL) {
			entries[i].port->sender_guest_count = 0;
			entries[i].port->watcher_count = 0;
			entries[i].port->grants = 0;
		}
		if (entries[i].port != NULL && !entries[i].port->remote) {
			entries[i].port->global_id = 0;
		}
	}
	pthread_mutex_unlock(&lock);
	pthread_mutex_unlock(&notice_order);
}

mach_port_name_t
ipc_task_self(void)
{
	return kobject_send_right(IPC_KOBJECT_TASK);
}

mach_port_name_t
ipc_task_for_pid(int32_t pid)
{
	uint64_t global_id = broker_client_task_for_pid(pid);
	struct process process;
	struct timespec now;
	bool young = process_lookup(pid, &process) == 0
			&& clock_gettime(CLOCK_BOOTTIME, &now) == 0
			&& (uint64_t)now.tv_sec * 1000000000
							+ (uint64_t)now.tv_nsec
							- process_ticks_to_nanoseconds(
									process.start_ticks)
					< 1000000000;
	for (int tries = 0; global_id == 0 && young && tries < 100
			&& (kill(pid, 0) == 0 || errno == EPERM);
			tries++) {
		usleep(20000);
		global_id = broker_client_task_for_pid(pid);
	}
	if (global_id == 0) {
		return MACH_PORT_NULL;
	}
	pthread_mutex_lock(&lock);
	mach_port_name_t name = import_remote_send(global_id,
			MACH_MSG_TYPE_PORT_SEND, BROKER_GUEST_ID,
			broker_client_guest_id());
	remember_guest_pid(broker_guest_of(global_id), pid);
	pthread_mutex_unlock(&lock);
	return name;
}

bool
ipc_task_pid(mach_port_name_t name, int32_t *pid)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	bool found = false;
	if (entry == NULL) {
	} else if (entry->port->kotype == IPC_KOBJECT_TASK) {
		*pid = getpid();
		found = true;
	} else if (entry->port->kotype == IPC_KOBJECT_TASK_NAME) {
		*pid = (int32_t)(intptr_t)entry->port->kobject;
		found = true;
	} else if (entry->port->remote) {
		uint32_t guest_id = broker_guest_of(entry->port->global_id);
		for (size_t i = 0; i != guest_pid_count; i++) {
			if (guest_id != BROKER_GUEST_ID
					&& guest_pids[i].guest_id == guest_id) {
				*pid = guest_pids[i].pid;
				found = true;
			}
		}
	}
	pthread_mutex_unlock(&lock);
	return found;
}

void
ipc_port_release_if_unused(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	release_unused_entry(name);
	pthread_mutex_unlock(&lock);
}

bool
ipc_port_is_remote(mach_port_name_t name)
{
	if (!MACH_PORT_VALID(name)) {
		return false;
	}
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	bool remote = entry != NULL && entry->port != NULL
			&& entry->port->remote;
	pthread_mutex_unlock(&lock);
	return remote;
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

void
ipc_port_adopt_kobject(
		mach_port_name_t name, ipc_kobject_type_t type, void *kobject)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	if (entry != NULL) {
		entry->port->kotype = type;
		entry->port->kobject = kobject;
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
ipc_kobject_alloc_send(ipc_kobject_type_t type, void *kobject)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port = port_alloc(type);
	port->kobject = kobject;
	struct ipc_entry *entry = entry_alloc(port);
	entry->type |= MACH_PORT_TYPE_SEND;
	entry->urefs = 1;
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
	return ipc_kobject_alloc_send(IPC_KOBJECT_FILEPORT, kobject);
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

void *
ipc_kobject_lookup_held(mach_port_name_t name, ipc_kobject_type_t type,
		void (*hold)(void *kobject))
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	void *kobject = (entry != NULL && entry->port->kotype == type)
			? entry->port->kobject
			: NULL;
	if (kobject != NULL) {
		hold(kobject);
	}
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

#define MACH_VM_READ_ID             4804
#define MACH_VM_READ_OVERWRITE_ID 4808
#define MACH_VM_PAGE_RANGE_QUERY_ID 4820
#define MACH_VM_REMAP_ID            4813

mach_msg_return_t
ipc_mach_msg(mach_msg_header_t *msg, mach_msg_option64_t options,
		mach_msg_size_t send_size, mach_msg_size_t rcv_size,
		mach_port_name_t rcv_name, mach_msg_timeout_t timeout)
{
	if (options & MACH64_SEND_MSG) {
		trace_message(TRACE_MESSAGE_SENT, msg, send_size);
		int32_t read_pid;
		if (msg->msgh_id == MACH_VM_READ_ID
				&& ipc_port_is_remote(msg->msgh_remote_port)
				&& ipc_task_pid(msg->msgh_remote_port,
						&read_pid)
				&& mach_vm_read_request_answer(
						msg, send_size, read_pid)) {
			flush_notices();
			if (options & MACH64_RCV_MSG) {
				return receive(msg, options, rcv_size, rcv_name,
						timeout);
			}
			return MACH_MSG_SUCCESS;
		}
		if (msg->msgh_id == MACH_VM_PAGE_RANGE_QUERY_ID
				&& ipc_port_is_remote(msg->msgh_remote_port)
				&& ipc_task_pid(msg->msgh_remote_port,
						&read_pid)
				&& mach_vm_page_range_query_request_answer(
						msg, send_size, read_pid)) {
			flush_notices();
			if (options & MACH64_RCV_MSG) {
				return receive(msg, options, rcv_size, rcv_name,
						timeout);
			}
			return MACH_MSG_SUCCESS;
		}
		if (msg->msgh_id == MACH_VM_READ_OVERWRITE_ID
				&& ipc_port_is_remote(msg->msgh_remote_port)
				&& ipc_task_pid(msg->msgh_remote_port,
						&read_pid)
				&& mach_vm_read_overwrite_request_answer(
						msg, send_size, read_pid)) {
			flush_notices();
			if (options & MACH64_RCV_MSG) {
				return receive(msg, options, rcv_size, rcv_name,
						timeout);
			}
			return MACH_MSG_SUCCESS;
		}
		mach_port_name_t remap_entry = MACH_PORT_NULL;
		if (msg->msgh_id == MACH_VM_REMAP_ID
				&& ipc_port_is_remote(msg->msgh_remote_port)) {
			remap_entry = mach_vm_remap_request_prepare(
					msg, send_size);
		}
		mach_msg_return_t mr = send(msg, send_size, IPC_USER,
				getpid());
		if (remap_entry != MACH_PORT_NULL) {
			ipc_port_release_if_unused(remap_entry);
		}
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

mach_msg_return_t
ipc_mach_msg_kernel(mach_msg_header_t *msg, mach_msg_option64_t options,
		mach_msg_size_t send_size, mach_msg_size_t rcv_size,
		mach_port_name_t rcv_name, mach_msg_timeout_t timeout)
{
	bool outer = kernel_receive;
	kernel_receive = true;
	mach_msg_return_t mr = ipc_mach_msg(
			msg, options, send_size, rcv_size, rcv_name, timeout);
	kernel_receive = outer;
	return mr;
}

static mach_msg_return_t
send(mach_msg_header_t *msg, mach_msg_size_t size, ipc_side_t sender,
		pid_t sender_pid)
{
	struct ipc_kmsg *kmsg = malloc(
			sizeof(*kmsg) + size + sizeof(mach_msg_max_trailer_t));
	kmsg->sender = sender_identity(sender_pid);
	kmsg->body_error = MACH_MSG_SUCCESS;
	memcpy(kmsg->header, msg, size);
	kmsg->header->msgh_size = size;
	if (!has_valid_descriptors(kmsg->header)) {
		free(kmsg);
		return MACH_SEND_INVALID_TYPE;
	}

	pthread_mutex_lock(&lock);
	struct ipc_entry *remote_entry = lookup(kmsg->header->msgh_remote_port);
	if (remote_entry != NULL && remote_entry->port->remote) {
		mach_msg_return_t rr = remote_send(kmsg->header, size, sender,
				&kmsg->sender, remote_entry->port->global_id);
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

	serve_kernel(dest, kmsg, false);
	return MACH_MSG_SUCCESS;
}

bool
ipc_serving_remote(void)
{
	return serving_remote;
}

static void
serve_kernel(struct ipc_port *dest, struct ipc_kmsg *kmsg, bool remote)
{
	write_trailer(kmsg->header, dest, &kmsg->sender);
	bool serve_xpc = dest->kotype == IPC_KOBJECT_BOOTSTRAP
			&& xpc_bootstrap_is_message(kmsg->header->msgh_id);
	void *service = dest->kotype == IPC_KOBJECT_XPC_SERVICE ? dest->kobject
								: NULL;
	const struct ipc_kobject_ops *ops = kobject_ops(dest->kotype);
	void *kobject = dest->kobject;
	pthread_mutex_unlock(&lock);

	bool outer_remote = serving_remote;
	serving_remote = remote;
	if (ops != NULL && ops->serve != NULL) {
		if (!ops->serve(kobject, kmsg->header, remote)) {
			serve_kobject(kmsg->header);
		}
	} else if (service != NULL) {
		xpc_service_serve(service, kmsg->header);
	} else if (!serve_xpc || !xpc_bootstrap_serve(kmsg->header)) {
		serve_kobject(kmsg->header);
	}
	serving_remote = outer_remote;

	pthread_mutex_lock(&lock);
	release_unused_entries(kmsg->header);
	pthread_mutex_unlock(&lock);

	free(kmsg);
}

static struct ipc_sender
sender_identity(pid_t pid)
{
	if (pid == 0) {
		return (struct ipc_sender){0};
	}
	uid_t uid, euid;
	gid_t gid, egid;
	credentials_of_process(&uid, &euid, &gid, &egid);
	return (struct ipc_sender){
			.pid = pid,
			.uid = uid,
			.euid = euid,
			.gid = gid_from_linux(gid),
			.egid = gid_from_linux(egid),
	};
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
		const struct ipc_sender *identity, uint64_t dest_global_id)
{
	mach_msg_bits_t bits = header->msgh_bits;
	size_t fd_count = 0;
	uint32_t id_count = 0;
	if (!broker_client_carries(
			    remote_size(header, size, &fd_count, &id_count),
			    fd_count)) {
		pthread_mutex_unlock(&lock);
		return MACH_SEND_TOO_LARGE;
	}

	mach_msg_return_t mr = remote_copyin(header, sender);
	if (mr == MACH_SEND_INVALID_RIGHT
			&& received_type(MACH_MSGH_BITS_REMOTE(bits))
					== MACH_MSG_TYPE_PORT_SEND_ONCE) {
		queue_send_once_gone(dest_global_id, broker_client_guest_id());
	}
	if (mr != MACH_MSG_SUCCESS) {
		release_unused_entries(header);
		pthread_mutex_unlock(&lock);
		return mr;
	}

	uint64_t *global_ids = malloc(id_count * sizeof(*global_ids));
	uint8_t *data = NULL;
	uint32_t data_length = 0;
	struct remote_fds fds = {
			.fds = malloc((fd_count + 1) * sizeof(*fds.fds)),
	};
	struct moved_port *queued = NULL;
	uint32_t descriptor_count = export_body_ports(header, global_ids, &data,
			&data_length, broker_guest_of(dest_global_id), &fds,
			&queued);

	struct remote_header rh = {
			.message_size = size,
			.dest_disposition = MACH_MSGH_BITS_REMOTE(bits),
			.reply_disposition = MACH_MSGH_BITS_LOCAL(bits),
			.reply_global_id
			= (header->msgh_local_port != MACH_PORT_NULL)
					? export_local_port(
							  header->msgh_local_port)
					: 0,
			.sender = *identity,
			.descriptor_count = descriptor_count,
			.sender_guest_id = broker_client_guest_id(),
	};

	count_rights(header, bits, rh.reply_global_id, global_ids,
			broker_guest_of(dest_global_id), true);

	uint32_t ids_length = descriptor_count * sizeof(global_ids[0]);
	uint32_t blob_length = sizeof(rh) + size + ids_length + data_length;
	char *blob = malloc(blob_length);
	memcpy(blob, &rh, sizeof(rh));
	memcpy(blob + sizeof(rh), header, size);
	memcpy(blob + sizeof(rh) + size, global_ids, ids_length);
	memcpy(blob + sizeof(rh) + size + ids_length, data, data_length);
	free(data);

	pthread_mutex_unlock(&lock);
	flush_notices();
	if (fds.failed) {
		close_fds(&fds);
		mr = MACH_SEND_NO_BUFFER;
	} else {
		uint64_t *moved = malloc((id_count + 1) * sizeof(*moved));
		size_t moved_count = 0;
		for (struct moved_port *move = queued; move != NULL;
				move = move->next) {
			moved[moved_count++] = move->global_id;
		}
		mr = broker_client_send(dest_global_id, blob, blob_length,
				fds.fds, fds.count, moved, moved_count);
		free(moved);
	}
	pthread_mutex_lock(&lock);
	if (mr != MACH_MSG_SUCCESS) {
		count_rights(header, bits, rh.reply_global_id, global_ids,
				broker_guest_of(dest_global_id), false);
	}
	if (mr != MACH_MSG_SUCCESS
			&& received_type(rh.dest_disposition)
					== MACH_MSG_TYPE_PORT_SEND_ONCE) {
		queue_send_once_gone(dest_global_id, broker_client_guest_id());
	}
	release_unused_entries(header);
	release_ool_ports(header);
	finish_moves(queued, mr == MACH_MSG_SUCCESS);
	pthread_mutex_unlock(&lock);
	flush_notices();
	free(global_ids);
	free(fds.fds);
	free(blob);
	return mr;
}

static void
finish_moves(struct moved_port *queued, bool sent)
{
	while (queued != NULL) {
		struct moved_port *move = queued;
		queued = move->next;
		if (move->destroyed_notify != NULL && !sent) {
			return_port(move->global_id, move->destroyed_notify);
		} else if (!sent) {
			forget_moved_away(&moved_aways, move->global_id);
		} else if (move->destroyed_notify != NULL) {
			struct port_return *record = malloc(sizeof(*record));
			*record = (struct port_return){
					.next = port_returns,
					.global_id = move->global_id,
					.notify = move->destroyed_notify,
			};
			port_returns = record;
			queue_notice((struct pending_notice){
					.global_id = move->global_id,
					.notice = {
							.kind = REMOTE_NOTICE_WATCH,
							.guest_id = broker_client_guest_id(),
					},
			});
		}
		while (move->messages != NULL) {
			struct ipc_kmsg *kmsg = move->messages;
			move->messages = kmsg->next;
			if (!sent) {
				destroy_rights(kmsg->header);
				free(kmsg);
				continue;
			}
			send_queued(kmsg, move->global_id);
		}
		if (sent) {
			queue_notice((struct pending_notice){
					.global_id = broker_global_id(
							BROKER_GUEST_ID, 0),
					.notice = {
							.kind = REMOTE_NOTICE_QUEUE_SENT,
							.count = move->global_id,
					},
			});
		}
		free(move);
	}
}

static void
send_queued(struct ipc_kmsg *kmsg, uint64_t global_id)
{
	mach_msg_header_t *header = kmsg->header;
	mach_msg_bits_t bits = header->msgh_bits;
	header->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSGH_BITS_LOCAL(bits),
			MACH_MSGH_BITS_REMOTE(bits), 0,
			bits & MACH_MSGH_BITS_COMPLEX);
	header->msgh_local_port = header->msgh_remote_port;
	header->msgh_remote_port = MACH_PORT_NULL;
	release_out_of_line(header);
	remote_send(header, header->msgh_size, IPC_USER, &kmsg->sender,
			global_id);
	pthread_mutex_lock(&lock);
	free(kmsg);
}

static void
return_ports(uint64_t global_id, uint32_t guest_id)
{
	struct port_return **link = &port_returns;
	while (*link != NULL) {
		struct port_return *record = *link;
		if (global_id != 0 ? record->global_id != global_id
				   : broker_guest_of(record->global_id) != guest_id
								|| moved_away(outliving_ports,
										record->global_id)) {
			link = &record->next;
			continue;
		}
		*link = record->next;
		return_port(record->global_id, record->notify);
		free(record);
	}
}

static void
return_port(uint64_t global_id, struct ipc_port *notify)
{
	struct ipc_entry *entry = NULL;
	for (uint32_t i = 1; i < entry_count && entry == NULL; i++) {
		struct ipc_port *port = entries[i].port;
		if (port != NULL && port->remote
				&& port->global_id == global_id) {
			entry = &entries[i];
		}
	}
	if (entry == NULL) {
		entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	}
	entry->port->remote = false;
	entry->port->global_id = global_id;
	entry->port->grants = 0;
	entry->type |= MACH_PORT_TYPE_RECEIVE;
	forget_moved_away(&moved_aways, global_id);
	queue_notice((struct pending_notice){
			.global_id = broker_global_id(BROKER_GUEST_ID, 0),
			.notice = {
					.kind = REMOTE_NOTICE_RETURNED,
					.count = global_id,
			},
	});
	queue_notice((struct pending_notice){
			.id = MACH_NOTIFY_PORT_DESTROYED,
			.notify = notify,
			.name = entry->port->name,
	});
}

static bool
port_is_gone(uint64_t global_id)
{
	return guest_is_gone(broker_guest_of(global_id))
			&& !moved_away(outliving_ports, global_id);
}

static bool
moved_away(struct moved_away *list, uint64_t global_id)
{
	for (struct moved_away *away = list; away != NULL; away = away->next) {
		if (away->global_id == global_id) {
			return true;
		}
	}
	return false;
}

static void
forget_moved_away(struct moved_away **list, uint64_t global_id)
{
	for (struct moved_away **link = list; *link != NULL;
			link = &(*link)->next) {
		struct moved_away *away = *link;
		if (away->global_id == global_id) {
			*link = away->next;
			free(away);
			return;
		}
	}
}

static void
release_out_of_line(mach_msg_header_t *header)
{
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}

	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_ool_descriptor64_t *d
				= (mach_msg_ool_descriptor64_t *)cursor;
		if (d->type == MACH_MSG_OOL_DESCRIPTOR
				|| d->type == MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
			d->deallocate = true;
		} else if (d->type == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
			((mach_msg_ool_ports_descriptor64_t *)cursor)
					->deallocate = true;
		}
		cursor += d->type == MACH_MSG_PORT_DESCRIPTOR
				? sizeof(mach_msg_port_descriptor_t)
				: sizeof(*d);
	}
}

static void
release_ool_ports(mach_msg_header_t *header)
{
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}

	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_ool_ports_descriptor64_t *d
				= (mach_msg_ool_ports_descriptor64_t *)cursor;
		if (d->type == MACH_MSG_OOL_PORTS_DESCRIPTOR && d->deallocate
				&& d->address != 0 && d->count != 0) {
			_kernelrpc_mach_vm_deallocate(0, d->address,
					d->count * sizeof(mach_port_name_t));
		}
		cursor += d->type == MACH_MSG_PORT_DESCRIPTOR
				? sizeof(mach_msg_port_descriptor_t)
				: sizeof(*d);
	}
}

static uint64_t
remote_size(const mach_msg_header_t *header, mach_msg_size_t size,
		size_t *fd_count, uint32_t *id_count)
{
	uint64_t length = sizeof(struct remote_header) + size;
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return length;
	}

	const mach_msg_body_t *body = (const mach_msg_body_t *)(header + 1);
	const uint8_t *cursor = (const uint8_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		const mach_msg_type_descriptor_t *descriptor
				= (const mach_msg_type_descriptor_t *)cursor;
		if (descriptor->type == MACH_MSG_OOL_DESCRIPTOR
				|| descriptor->type
						== MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
			const mach_msg_ool_descriptor64_t *d
					= (const mach_msg_ool_descriptor64_t *)
							cursor;
			length += d->size;
			cursor += sizeof(*d);
			continue;
		}
		if (descriptor->type == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
			const mach_msg_ool_ports_descriptor64_t *d
					= (const mach_msg_ool_ports_descriptor64_t
									*)
							cursor;
			const mach_port_name_t *names
					= (const mach_port_name_t *)d->address;
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				length += sizeof(uint64_t)
						+ object_size(names[j],
								fd_count);
			}
			*id_count += d->count;
			cursor += sizeof(*d);
			continue;
		}
		mach_port_name_t name
				= descriptor->type == MACH_MSG_PORT_DESCRIPTOR
				? ((const mach_msg_port_descriptor_t *)cursor)
						  ->name
				: ((const mach_msg_guarded_port_descriptor64_t
								   *)cursor)
						  ->name;
		length += sizeof(uint64_t) + object_size(name, fd_count);
		(*id_count)++;
		cursor += descriptor->type == MACH_MSG_PORT_DESCRIPTOR
				? sizeof(mach_msg_port_descriptor_t)
				: sizeof(mach_msg_guarded_port_descriptor64_t);
	}
	return length;
}

static uint64_t
object_size(mach_port_name_t name, size_t *fd_count)
{
	const struct ipc_entry *entry = lookup(name);
	ipc_kobject_type_t kotype = entry != NULL ? entry->port->kotype
						  : IPC_KOBJECT_NONE;
	*fd_count += kotype == IPC_KOBJECT_FILEPORT
			|| kotype == IPC_KOBJECT_MEMORY_ENTRY;
	if (kotype == IPC_KOBJECT_MEMORY_ENTRY) {
		return sizeof(struct remote_memory_entry);
	}
	const struct ipc_kobject_ops *ops = kobject_ops(kotype);
	if (ops == NULL || ops->describe == NULL || entry->port->remote
			|| entry->port->kobject == NULL) {
		return 0;
	}
	*fd_count += ops->fd_count;
	return sizeof(struct remote_object) + ops->record_size;
}

static mach_msg_return_t
remote_copyin(mach_msg_header_t *header, ipc_side_t sender)
{
	mach_msg_bits_t bits = header->msgh_bits;

	struct ipc_entry *dest_entry = lookup(header->msgh_remote_port);
	if (sender == IPC_USER && dest_entry != NULL
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
		uint8_t **data, uint32_t *data_length, uint32_t dest_guest_id,
		struct remote_fds *fds, struct moved_port **queued)
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
					d->disposition, dest_guest_id, fds,
					data, data_length, queued);
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
		} else if (descriptor->type == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
			mach_msg_ool_ports_descriptor64_t *d
					= (mach_msg_ool_ports_descriptor64_t *)
							cursor;
			const mach_port_name_t *names
					= (const mach_port_name_t *)d->address;
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				global_ids[count++] = export_body_port(names[j],
						d->disposition, dest_guest_id,
						fds, data, data_length, queued);
			}
			cursor += sizeof(*d);
		} else {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t *)
							cursor;
			global_ids[count++] = export_body_port(d->name,
					d->disposition, dest_guest_id, fds,
					data, data_length, queued);
			cursor += sizeof(*d);
		}
	}
	return count;
}

static uint64_t
export_body_port(mach_port_name_t name, mach_msg_type_name_t disposition,
		uint32_t dest_guest_id, struct remote_fds *fds, uint8_t **data,
		uint32_t *data_length, struct moved_port **queued)
{
	if (name == MACH_PORT_NULL) {
		return 0;
	}

	struct ipc_entry *held = lookup(name);
	if (held != NULL && held->port->kotype == IPC_KOBJECT_FILEPORT) {
		return export_fileport(held->port, fds);
	}
	if (held != NULL && held->port->kotype == IPC_KOBJECT_MEMORY_ENTRY) {
		return export_memory_entry(held->port, fds, data, data_length);
	}
	uint64_t kind_id = held != NULL
			? export_kind(held->port, fds, data, data_length)
			: 0;
	if (kind_id != 0) {
		return kind_id;
	}

	if (name == MACH_PORT_DEAD
			|| disposition != MACH_MSG_TYPE_MOVE_RECEIVE) {
		return export_local_port(name);
	}

	struct ipc_entry *entry = lookup(name);
	uint64_t global_id = export_local_port(name);
	if (!moved_away(moved_aways, global_id)) {
		struct moved_away *away = malloc(sizeof(*away));
		*away = (struct moved_away){
				.next = moved_aways,
				.global_id = global_id,
		};
		moved_aways = away;
	}
	export_holders(entry, data, data_length);
	entry->port->remote = true;
	entry->port->grants = 1;
	struct moved_port *move = malloc(sizeof(*move));
	*move = (struct moved_port){
			.next = *queued,
			.global_id = global_id,
			.messages = entry->port->messages,
			.destroyed_notify = entry->port->destroyed_notify,
	};
	*queued = move;
	entry->port->messages = NULL;
	entry->port->destroyed_notify = NULL;
	return global_id;
}

static void
export_holders(struct ipc_entry *entry, uint8_t **data, uint32_t *data_length)
{
	struct ipc_port *port = entry->port;
	uint32_t at = *data_length;
	struct remote_holders holders = {0};
	struct remote_notice *notices = malloc(
			(2 + port->sender_guest_count + port->watcher_count)
			* sizeof(*notices));
	notices[holders.count++] = (struct remote_notice){
			.kind = REMOTE_NOTICE_ADD,
			.guest_id = broker_client_guest_id(),
			.count = 1,
	};
	for (uint32_t i = 0; i < port->sender_guest_count; i++) {
		notices[holders.count++] = (struct remote_notice){
				.kind = REMOTE_NOTICE_ADD,
				.guest_id = port->sender_guests[i],
				.count = port->sender_grants[i],
		};
	}
	port->sender_guest_count = 0;
	struct remote_send_once **link = &remote_send_onces;
	while (*link != NULL) {
		struct remote_send_once *record = *link;
		if (record->port != port->name) {
			link = &record->next;
			continue;
		}
		notices = realloc(notices,
				(holders.count + 2 + port->watcher_count)
						* sizeof(*notices));
		notices[holders.count++] = (struct remote_notice){
				.kind = REMOTE_NOTICE_SEND_ONCE_MOVED,
				.guest_id = record->guest_id,
				.count = 1,
		};
		*link = record->next;
		free(record);
	}
	for (uint32_t i = 0; i < port->watcher_count; i++) {
		notices[holders.count++] = (struct remote_notice){
				.kind = REMOTE_NOTICE_WATCH,
				.guest_id = port->watchers[i],
		};
	}
	port->watcher_count = 0;
	uint32_t length = sizeof(holders) + holders.count * sizeof(*notices);
	*data = realloc(*data, at + length);
	memcpy(*data + at, &holders, sizeof(holders));
	memcpy(*data + at + sizeof(holders), notices,
			holders.count * sizeof(*notices));
	*data_length = at + length;
	free(notices);
}

static uint64_t
export_fileport(const struct ipc_port *port, struct remote_fds *fds)
{
	return export_fd(fds, *(int *)port->kobject) ? fileport_global_id : 0;
}

static uint64_t
export_memory_entry(const struct ipc_port *port, struct remote_fds *fds,
		uint8_t **data, uint32_t *data_length)
{
	int fd;
	struct remote_memory_entry record;
	memory_entry_describe(
			port->kobject, &fd, &record.size, &record.data_offset);
	if (!export_fd(fds, fd)) {
		return 0;
	}
	*data = realloc(*data, *data_length + sizeof(record));
	memcpy(*data + *data_length, &record, sizeof(record));
	*data_length += sizeof(record);
	return memory_entry_global_id;
}

static uint64_t
export_kind(struct ipc_port *port, struct remote_fds *fds, uint8_t **data,
		uint32_t *data_length)
{
	const struct ipc_kobject_ops *ops = kobject_ops(port->kotype);
	if (ops == NULL || ops->describe == NULL || port->remote
			|| port->kobject == NULL) {
		return 0;
	}
	struct ipc_export out = {data, data_length, fds};
	uint32_t start = *data_length;
	size_t first_fd = fds->count;
	struct remote_object object = {0};
	ipc_export_record(&out, &object, sizeof(object));
	if (!ops->describe(port->kobject, &out)) {
		while (fds->count > first_fd) {
			close(fds->fds[--fds->count]);
		}
		*data_length = start;
		return 0;
	}
	object.fd_count = (uint32_t)(fds->count - first_fd);
	object.length = *data_length - start - (uint32_t)sizeof(object);
	memcpy(*data + start, &object, sizeof(object));
	return ops->remote_id;
}

int
ipc_export_fd(struct ipc_export *out, int fd, bool closed_after_send)
{
	int index = (int)out->fds->count;
	if (closed_after_send) {
		out->fds->fds[out->fds->count++] = fd;
		return index;
	}
	return export_fd(out->fds, fd) ? index : -1;
}

void
ipc_export_record(struct ipc_export *out, const void *record, size_t size)
{
	*out->data = realloc(*out->data, *out->data_length + size);
	memcpy(*out->data + *out->data_length, record, size);
	*out->data_length += (uint32_t)size;
}

static bool
export_fd(struct remote_fds *fds, int fd)
{
	int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (copy == -1) {
		fds->failed = true;
		return false;
	}
	fds->fds[fds->count++] = copy;
	return true;
}

static void
close_fds(const struct remote_fds *fds)
{
	for (size_t i = 0; i != fds->count; i++) {
		close(fds->fds[i]);
	}
}

static void
count_rights(const mach_msg_header_t *header, mach_msg_bits_t bits,
		uint64_t reply_global_id, const uint64_t *global_ids,
		uint32_t dest_guest_id, bool sent)
{
	count_right(header->msgh_local_port,
			received_type(MACH_MSGH_BITS_LOCAL(bits)),
			reply_global_id, dest_guest_id, sent);
	if (!(bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}

	const mach_msg_body_t *body = (const mach_msg_body_t *)(header + 1);
	const uint8_t *cursor = (const uint8_t *)(body + 1);
	uint32_t count = 0;
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		const mach_msg_type_descriptor_t *descriptor
				= (const mach_msg_type_descriptor_t *)cursor;
		if (descriptor->type == MACH_MSG_PORT_DESCRIPTOR) {
			const mach_msg_port_descriptor_t *d
					= (const mach_msg_port_descriptor_t *)
							cursor;
			count_right(d->name, d->disposition,
					global_ids[count++], dest_guest_id,
					sent);
			cursor += sizeof(*d);
		} else if (descriptor->type == MACH_MSG_OOL_DESCRIPTOR
				|| descriptor->type
						== MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
			cursor += sizeof(mach_msg_ool_descriptor64_t);
		} else if (descriptor->type == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
			const mach_msg_ool_ports_descriptor64_t *d
					= (const mach_msg_ool_ports_descriptor64_t
									*)
							cursor;
			const mach_port_name_t *names
					= (const mach_port_name_t *)d->address;
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				count_right(names[j], d->disposition,
						global_ids[count++],
						dest_guest_id, sent);
			}
			cursor += sizeof(*d);
		} else {
			const mach_msg_guarded_port_descriptor64_t *d
					= (const mach_msg_guarded_port_descriptor64_t
									*)
							cursor;
			count_right(d->name, d->disposition,
					global_ids[count++], dest_guest_id,
					sent);
			cursor += sizeof(*d);
		}
	}
}

static void
count_right(mach_port_name_t name, mach_msg_type_name_t type,
		uint64_t global_id, uint32_t dest_guest_id, bool sent)
{
	struct ipc_entry *entry = lookup(name);
	bool owned = entry != NULL && entry->port->global_id == global_id
			&& (entry->type & MACH_PORT_TYPE_RECEIVE);
	uint64_t owner_id = broker_guest_of(global_id) == BROKER_GUEST_ID
			? 0
			: global_id;
	uint32_t owner = broker_guest_of(owner_id);
	bool elsewhere = !owned && owner_id != 0 && owner != UINT32_MAX
			&& ((entry != NULL && entry->port->remote)
					|| owner != broker_client_guest_id());
	if (owned && type == MACH_MSG_TYPE_PORT_SEND && sent) {
		count_sender_guest(entry->port, dest_guest_id, 1);
	} else if (owned && type == MACH_MSG_TYPE_PORT_SEND) {
		release_grants(entry, dest_guest_id, 1);
	} else if (owned && type == MACH_MSG_TYPE_PORT_SEND_ONCE && sent) {
		remember_send_once(name, dest_guest_id);
	} else if (owned && type == MACH_MSG_TYPE_PORT_SEND_ONCE) {
		queue_send_once_notifications(entry,
				forget_send_onces(name, dest_guest_id, 1));
	} else if (elsewhere && type == MACH_MSG_TYPE_PORT_SEND_ONCE) {
		queue_notice((struct pending_notice){
				.global_id = owner_id,
				.notice = {
						.kind = sent ? REMOTE_NOTICE_SEND_ONCE_MOVED
							     : REMOTE_NOTICE_SEND_ONCE,
						.guest_id = dest_guest_id,
						.count = sent ? broker_client_guest_id()
							      : 1,
				},
		});
	} else if (elsewhere && type == MACH_MSG_TYPE_PORT_SEND) {
		queue_notice((struct pending_notice){
				.global_id = owner_id,
				.notice = {
						.kind = sent ? REMOTE_NOTICE_ADD
							     : REMOTE_NOTICE_RELEASE,
						.guest_id = dest_guest_id,
						.count = 1,
				},
		});
	}
}

static void
count_sender_guest(struct ipc_port *port, uint32_t guest_id, uint64_t count)
{
	for (uint32_t i = 0; i < port->sender_guest_count; i++) {
		if (port->sender_guests[i] == guest_id) {
			port->sender_grants[i] += count;
			return;
		}
	}

	uint32_t index = port->sender_guest_count++;
	port->sender_guests = realloc(port->sender_guests,
			port->sender_guest_count
					* sizeof(*port->sender_guests));
	port->sender_grants = realloc(port->sender_grants,
			port->sender_guest_count
					* sizeof(*port->sender_grants));
	port->sender_guests[index] = guest_id;
	port->sender_grants[index] = count;
}

static void
release_grants(struct ipc_entry *entry, uint32_t guest_id, uint64_t count)
{
	struct ipc_port *port = entry->port;
	for (uint32_t i = 0; i < port->sender_guest_count; i++) {
		if (port->sender_guests[i] != guest_id) {
			continue;
		}
		if (port->sender_grants[i] > count) {
			port->sender_grants[i] -= count;
			return;
		}
		uint32_t last = --port->sender_guest_count;
		port->sender_guests[i] = port->sender_guests[last];
		port->sender_grants[i] = port->sender_grants[last];
		queue_no_senders_notification(entry);
		return;
	}
}

static void
tell_holders_dead(struct ipc_port *port)
{
	for (uint32_t i = 0; i < port->sender_guest_count; i++) {
		uint32_t guest_id = port->sender_guests[i];
		queue_notice((struct pending_notice){
				.global_id = broker_global_id(guest_id, 0),
				.notice = {
						.kind = REMOTE_NOTICE_DEAD,
						.count = port->global_id,
				},
		});
	}
	port->sender_guest_count = 0;
	for (uint32_t i = 0; i < port->watcher_count; i++) {
		queue_notice((struct pending_notice){
				.global_id = broker_global_id(
						port->watchers[i], 0),
				.notice = {
						.kind = REMOTE_NOTICE_DEAD,
						.count = port->global_id,
				},
		});
	}
	port->watcher_count = 0;

	struct remote_send_once **link = &remote_send_onces;
	while (*link != NULL) {
		struct remote_send_once *record = *link;
		if (record->port != port->name) {
			link = &record->next;
			continue;
		}
		*link = record->next;
		free(record);
	}
}

static void
remember_send_once(mach_port_name_t port, uint32_t guest_id)
{
	struct remote_send_once *record = malloc(sizeof(*record));
	*record = (struct remote_send_once){
			.next = remote_send_onces,
			.port = port,
			.guest_id = guest_id,
	};
	remote_send_onces = record;
}

static uint32_t
forget_send_onces(mach_port_name_t port, uint32_t guest_id, uint64_t count)
{
	uint32_t found = 0;
	struct remote_send_once **link = &remote_send_onces;
	while (*link != NULL && found != count) {
		struct remote_send_once *record = *link;
		if (record->port != port || record->guest_id != guest_id) {
			link = &record->next;
			continue;
		}
		*link = record->next;
		free(record);
		found++;
	}
	return found;
}

static void
move_send_once(struct ipc_entry *entry, uint32_t from, uint32_t to)
{
	if (forget_send_onces(entry->port->name, from, 1) == 0) {
		return;
	}
	if (guest_is_gone(to)) {
		queue_send_once_notifications(entry, 1);
	} else {
		remember_send_once(entry->port->name, to);
	}
}

static void
queue_send_once_gone(uint64_t global_id, uint32_t guest_id)
{
	queue_notice((struct pending_notice){
			.global_id = global_id,
			.notice = {
					.kind = REMOTE_NOTICE_SEND_ONCE,
					.guest_id = guest_id,
					.count = 1,
			},
	});
}

static void
give_back_grants(struct ipc_port *port)
{
	if (!port->remote || port->grants == 0) {
		return;
	}

	queue_notice((struct pending_notice){
			.global_id = port->global_id,
			.notice = {
					.kind = REMOTE_NOTICE_RELEASE,
					.guest_id = broker_client_guest_id(),
					.count = port->grants,
			},
	});
	port->grants = 0;
}

static void
receive_notice(uint64_t dest_global_id, const struct remote_notice *notice)
{
	pthread_mutex_lock(&lock);
	if (notice->kind == REMOTE_NOTICE_DEAD) {
		return_ports(notice->count, 0);
		forget_moved_away(&moved_aways, notice->count);
	}
	for (uint32_t i = 1;
			notice->kind == REMOTE_NOTICE_DEAD && i < entry_count;
			i++) {
		struct ipc_port *held = entries[i].port;
		if (held != NULL && held->remote
				&& held->global_id == notice->count) {
			turn_dead(&entries[i]);
		}
	}
	struct ipc_port *port = port_for_global_id(dest_global_id);
	struct ipc_entry *entry = port != NULL ? lookup(port->name) : NULL;
	bool owned = entry != NULL && (entry->type & MACH_PORT_TYPE_RECEIVE);
	if (owned && notice->kind == REMOTE_NOTICE_RELEASE) {
		release_grants(entry, notice->guest_id, notice->count);
	} else if (owned && notice->kind == REMOTE_NOTICE_ADD
			&& !guest_is_gone(notice->guest_id)) {
		count_sender_guest(port, notice->guest_id, 1);
	} else if (owned && notice->kind == REMOTE_NOTICE_SEND_ONCE_MOVED) {
		move_send_once(entry, (uint32_t)notice->count,
				notice->guest_id);
	} else if (owned && notice->kind == REMOTE_NOTICE_SEND_ONCE) {
		queue_send_once_notifications(entry,
				forget_send_onces(port->name, notice->guest_id,
						notice->count));
	} else if (owned && notice->kind == REMOTE_NOTICE_WATCH
			&& !guest_is_gone(notice->guest_id)) {
		port->watchers = realloc(port->watchers,
				(port->watcher_count + 1)
						* sizeof(*port->watchers));
		port->watchers[port->watcher_count++] = notice->guest_id;
	} else if (port == NULL
			&& (notice->kind == REMOTE_NOTICE_ADD
					|| notice->kind == REMOTE_NOTICE_WATCH)
			&& !guest_is_gone(notice->guest_id)) {
		queue_notice((struct pending_notice){
				.global_id = broker_global_id(
						notice->guest_id, 0),
				.notice = {
						.kind = REMOTE_NOTICE_DEAD,
						.count = dest_global_id,
				},
		});
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
}

static void
send_remote_notice(const struct pending_notice *notice)
{
	struct {
		struct remote_header header;
		struct remote_notice notice;
	} blob = {.notice = notice->notice};
	broker_client_send(notice->global_id, &blob, sizeof(blob), NULL, 0,
			NULL, 0);
}

static uint64_t
export_local_port(mach_port_name_t name)
{
	if (name == MACH_PORT_DEAD) {
		return dead_global_id;
	}

	struct ipc_port *port = lookup(name)->port;
	if (port == kobjects[IPC_KOBJECT_TASK] && task_port_global_id() != 0) {
		port->global_id = task_port_global_id();
	}
	if (port->global_id == 0) {
		port->global_id = broker_global_id(
				broker_client_guest_id(), ++export_counter);
	}
	return port->global_id;
}

static uint64_t
task_port_global_id(void)
{
	uint32_t guest = broker_client_guest_id();
	return guest != 0 ? broker_global_id(guest, BROKER_TASK_PORT_LOCAL) : 0;
}

static void
remember_guest_pid(uint32_t guest_id, int32_t pid)
{
	if (guest_id == BROKER_GUEST_ID || pid <= 1) {
		return;
	}
	for (size_t i = 0; i != guest_pid_count; i++) {
		if (guest_pids[i].guest_id == guest_id) {
			guest_pids[i].pid = pid;
			return;
		}
	}
	if (guest_pid_count == guest_pid_capacity) {
		size_t capacity = guest_pid_capacity ? guest_pid_capacity * 2
						     : 64;
		struct guest_pid *grown = realloc(
				guest_pids, capacity * sizeof(*grown));
		if (grown == NULL) {
			return;
		}
		guest_pids = grown;
		guest_pid_capacity = capacity;
	}
	guest_pids[guest_pid_count++] = (struct guest_pid){guest_id, pid};
}

static void
forget_guest_pid(uint32_t guest_id)
{
	for (size_t i = 0; i != guest_pid_count; i++) {
		if (guest_pids[i].guest_id == guest_id) {
			guest_pids[i] = guest_pids[--guest_pid_count];
			return;
		}
	}
}

static struct ipc_port *
port_for_global_id(uint64_t global_id)
{
	if (global_id != 0 && global_id == task_port_global_id()) {
		struct ipc_port *task = kobject_port(IPC_KOBJECT_TASK);
		task->global_id = global_id;
		return task;
	}
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
import_remote_send(uint64_t global_id, mach_msg_type_name_t type,
		uint32_t sender_guest_id, uint32_t meant_guest_id)
{
	bool counted = sender_guest_id != BROKER_GUEST_ID
			&& broker_guest_of(global_id) != BROKER_GUEST_ID;
	if (global_id == dead_global_id) {
		return MACH_PORT_DEAD;
	}

	struct ipc_port *own = port_for_global_id(global_id);
	if (own != NULL) {
		mach_port_name_t name = own->name;
		transfer_right(name, type, IPC_KERNEL, IPC_USER, &type);
		if (counted && type == MACH_MSG_TYPE_PORT_SEND_ONCE) {
			forget_send_onces(name, meant_guest_id, 1);
		} else if (counted && type == MACH_MSG_TYPE_PORT_SEND) {
			release_grants(lookup(name), meant_guest_id, 1);
		}
		return name;
	}
	if (port_is_gone(global_id)
			|| (broker_guest_of(global_id) == broker_client_guest_id()
					&& !moved_away(moved_aways,
							global_id))) {
		return MACH_PORT_DEAD;
	}
	if (counted && meant_guest_id != broker_client_guest_id()) {
		bool send_once = type == MACH_MSG_TYPE_PORT_SEND_ONCE;
		queue_notice((struct pending_notice){
				.global_id = global_id,
				.notice = {
						.kind = send_once ? REMOTE_NOTICE_SEND_ONCE_MOVED
								  : REMOTE_NOTICE_ADD,
						.guest_id = broker_client_guest_id(),
						.count = send_once ? meant_guest_id : 1,
				},
		});
		if (!send_once) {
			queue_notice((struct pending_notice){
					.global_id = global_id,
					.notice = {
							.kind = REMOTE_NOTICE_RELEASE,
							.guest_id = meant_guest_id,
							.count = 1,
					},
			});
		}
	}

	struct ipc_entry *found = NULL;
	for (uint32_t i = 1; i < entry_count && found == NULL; i++) {
		struct ipc_port *port = entries[i].port;
		if (port != NULL && port->remote
				&& port->global_id == global_id) {
			found = &entries[i];
		}
	}
	if (found != NULL && (found->type & MACH_PORT_TYPE_DEAD_NAME)) {
		return MACH_PORT_DEAD;
	}
	if (found != NULL) {
		transfer_right(found->port->name, type, IPC_KERNEL, IPC_USER,
				&type);
		found->port->grants
				+= counted && type == MACH_MSG_TYPE_PORT_SEND;
		return found->port->name;
	}

	struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	entry->port->remote = true;
	entry->port->global_id = global_id;
	entry->port->grants = counted && type == MACH_MSG_TYPE_PORT_SEND;
	transfer_right(entry->port->name, type, IPC_KERNEL, IPC_USER, &type);
	return entry->port->name;
}

void
ipc_remote_deliver(uint64_t dest_global_id, const struct broker_sender *sender,
		const void *blob, uint32_t length, const int *fds,
		size_t fd_count)
{
	deliver(dest_global_id, sender, blob, length, fds, fd_count, false);
}

void
ipc_remote_lost(uint64_t dest_global_id, const void *blob, uint32_t length)
{
	deliver(dest_global_id, NULL, blob, length, NULL, 0, true);
}

static void
deliver(uint64_t dest_global_id, const struct broker_sender *sender,
		const void *blob, uint32_t length, const int *fds,
		size_t fd_count, bool lost)
{
	const struct remote_header *rh = blob;
	if (!remote_message_fits(rh, length, fd_count, lost)) {
		return;
	}
	pthread_mutex_lock(&lock);
	bool gone = !lost && port_for_global_id(dest_global_id) == NULL;
	bool moved = gone && moved_away(moved_aways, dest_global_id);
	bool returned = gone && moved_away(returned_ports, dest_global_id);
	pthread_mutex_unlock(&lock);
	if ((moved || returned)
			&& forward_frame(dest_global_id, blob, length, fds,
					fd_count)) {
		return;
	}
	if (moved) {
		fds = NULL;
		lost = true;
	}
	if (rh->message_size == 0) {
		receive_notice(dest_global_id,
				(const struct remote_notice *)(rh + 1));
		return;
	}
	const mach_msg_header_t *message
			= (const mach_msg_header_t *)((const char *)blob
					+ sizeof(*rh));

	const uint64_t *global_ids = (const uint64_t *)((const char *)message
			+ rh->message_size);

	pthread_mutex_lock(&lock);
	struct ipc_port *dest = port_for_global_id(dest_global_id);
	struct ipc_kmsg *kmsg = malloc(sizeof(*kmsg) + rh->message_size
			+ sizeof(mach_msg_max_trailer_t));
	remember_guest_pid(rh->sender_guest_id, rh->sender.pid);
	kmsg->sender = rh->sender;
	kmsg->body_error = MACH_MSG_SUCCESS;
	if (sender != NULL && sender->pid > 0) {
		kmsg->sender.pid = sender->pid;
		kmsg->sender.uid = kmsg->sender.euid = sender->uid;
		kmsg->sender.gid = kmsg->sender.egid
				= gid_from_linux(sender->gid);
	}
	memcpy(kmsg->header, message, rh->message_size);

	mach_msg_type_name_t reply_type = received_type(rh->reply_disposition);
	mach_port_name_t reply_name = (rh->reply_global_id != 0)
			? import_remote_send(rh->reply_global_id, reply_type,
					  rh->sender_guest_id,
					  broker_guest_of(dest_global_id))
			: MACH_PORT_NULL;
	if (dest != NULL
			&& received_type(rh->dest_disposition)
					== MACH_MSG_TYPE_PORT_SEND_ONCE) {
		uint32_t used = forget_send_onces(
				dest->name, rh->sender_guest_id, 1);
		queue_send_once_notifications(
				lookup(dest->name), lost ? used : 0);
	}
	kmsg->header->msgh_bits = MACH_MSGH_BITS_SET(reply_type,
			received_type(rh->dest_disposition), 0,
			message->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	kmsg->header->msgh_remote_port = reply_name;
	kmsg->header->msgh_local_port
			= dest != NULL ? dest->name : MACH_PORT_NULL;
	kmsg->header->msgh_voucher_port = MACH_PORT_NULL;
	kmsg->header->msgh_size = rh->message_size;

	import_body_ports(kmsg->header, global_ids,
			(const uint8_t *)&global_ids[rh->descriptor_count], fds,
			fd_count, rh->sender_guest_id,
			broker_guest_of(dest_global_id), &kmsg->body_error);

	if (dest == NULL || lost) {
		destroy_rights(kmsg->header);
		free(kmsg);
		pthread_mutex_unlock(&lock);
		flush_notices();
		return;
	}
	if (dest->kotype != IPC_KOBJECT_NONE) {
		mach_msg_type_name_t type;
		transfer_right(kmsg->header->msgh_remote_port, reply_type,
				IPC_USER, IPC_KERNEL, &type);
		serve_kernel(dest, kmsg, true);
		flush_notices();
		return;
	}
	enqueue(dest, kmsg);
	unlock_and_notify_arrival(dest);
}

static bool
forward_frame(uint64_t global_id, const void *blob, uint32_t length,
		const int *fds, size_t fd_count)
{
	int *copies = malloc((fd_count + 1) * sizeof(*copies));
	size_t copied = 0;
	while (copied != fd_count
			&& (copies[copied] = fcntl(
					    fds[copied], F_DUPFD_CLOEXEC, 0))
					!= -1) {
		copied++;
	}
	bool forwarded = copied == fd_count;
	if (forwarded) {
		broker_client_send(global_id, blob, length, copies, fd_count,
				NULL, 0);
	} else {
		while (copied != 0) {
			close(copies[--copied]);
		}
	}
	free(copies);
	return forwarded;
}

static bool
remote_message_fits(const struct remote_header *rh, uint32_t length,
		size_t fd_count, bool lost)
{
	if (length < sizeof(*rh)) {
		return false;
	}
	uint32_t room = length - sizeof(*rh);
	if (rh->message_size == 0) {
		return room == sizeof(struct remote_notice) && fd_count == 0;
	}
	if (rh->message_size < sizeof(mach_msg_header_t)
			|| rh->message_size > room) {
		return false;
	}
	room -= rh->message_size;
	if (rh->descriptor_count > room / sizeof(uint64_t)) {
		return false;
	}
	room -= rh->descriptor_count * sizeof(uint64_t);

	mach_msg_type_name_t dest_type = received_type(rh->dest_disposition);
	mach_msg_type_name_t reply_type = received_type(rh->reply_disposition);
	if (dest_type == MACH_MSG_TYPE_PORT_NONE
			|| dest_type == MACH_MSG_TYPE_PORT_RECEIVE
			|| reply_type == MACH_MSG_TYPE_PORT_RECEIVE
			|| rh->reply_global_id == fileport_global_id
			|| !remote_right_fits(rh->reply_global_id,
					rh->reply_disposition)) {
		return false;
	}

	const mach_msg_header_t *message = (const mach_msg_header_t *)(rh + 1);
	const uint64_t *global_ids = (const uint64_t *)((const char *)message
			+ rh->message_size);
	if (!(message->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return rh->descriptor_count == 0 && (fd_count == 0 || lost);
	}
	return remote_body_fits(message, rh->message_size, global_ids,
			rh->descriptor_count, room, fd_count, lost);
}

static bool
remote_body_fits(const mach_msg_header_t *message, mach_msg_size_t size,
		const uint64_t *global_ids, uint32_t id_count, uint32_t room,
		size_t fd_count, bool lost)
{
	if (size < sizeof(*message) + sizeof(mach_msg_body_t)) {
		return false;
	}

	const mach_msg_body_t *body = (const mach_msg_body_t *)(message + 1);
	const uint8_t *cursor = (const uint8_t *)(body + 1);
	const uint8_t *end = (const uint8_t *)message + size;
	const uint8_t *data = (const uint8_t *)(global_ids + id_count);
	uint32_t count = 0;
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		const mach_msg_type_descriptor_t *descriptor
				= (const mach_msg_type_descriptor_t *)cursor;
		if ((size_t)(end - cursor) < sizeof(*descriptor)) {
			return false;
		}
		if (descriptor->type == MACH_MSG_PORT_DESCRIPTOR) {
			const mach_msg_port_descriptor_t *d
					= (const mach_msg_port_descriptor_t *)
							cursor;
			if (count == id_count
					|| !remote_port_fits(
							global_ids[count++],
							d->disposition, &data,
							&fd_count, &room,
							lost)) {
				return false;
			}
			cursor += sizeof(*d);
			continue;
		}
		if ((size_t)(end - cursor)
				< sizeof(mach_msg_ool_descriptor64_t)) {
			return false;
		}
		if (descriptor->type == MACH_MSG_GUARDED_PORT_DESCRIPTOR) {
			const mach_msg_guarded_port_descriptor64_t *d
					= (const mach_msg_guarded_port_descriptor64_t
									*)
							cursor;
			if (count == id_count
					|| !remote_port_fits(
							global_ids[count++],
							d->disposition, &data,
							&fd_count, &room,
							lost)) {
				return false;
			}
		} else if (descriptor->type == MACH_MSG_OOL_DESCRIPTOR
				|| descriptor->type
						== MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
			const mach_msg_ool_descriptor64_t *d
					= (const mach_msg_ool_descriptor64_t *)
							cursor;
			if (d->size > room) {
				return false;
			}
			room -= d->size;
			data += d->size;
		} else if (descriptor->type == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
			const mach_msg_ool_ports_descriptor64_t *d
					= (const mach_msg_ool_ports_descriptor64_t
									*)
							cursor;
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				if (count == id_count
						|| !remote_port_fits(
								global_ids[count++],
								d->disposition,
								&data,
								&fd_count,
								&room, lost)) {
					return false;
				}
			}
		} else {
			return false;
		}
		cursor += sizeof(mach_msg_ool_descriptor64_t);
	}
	return count == id_count && (fd_count == 0 || lost);
}

static bool
remote_port_fits(uint64_t global_id, mach_msg_type_name_t disposition,
		const uint8_t **data, size_t *fd_count, uint32_t *room,
		bool lost)
{
	const struct ipc_kobject_ops *ops
			= kobject_ops_for_remote_id(global_id);
	if (global_id != fileport_global_id
			&& global_id != memory_entry_global_id && ops == NULL) {
		if (received_type(disposition) == MACH_MSG_TYPE_PORT_RECEIVE
				&& global_id != 0
				&& global_id != dead_global_id) {
			struct remote_holders holders;
			if (*room < sizeof(holders)) {
				return false;
			}
			memcpy(&holders, *data, sizeof(holders));
			uint64_t length = sizeof(holders)
					+ (uint64_t)holders.count
							* sizeof(struct remote_notice);
			if (*room < length) {
				return false;
			}
			*room -= (uint32_t)length;
			*data += length;
		}
		return remote_right_fits(global_id, disposition);
	}
	if (received_type(disposition) != MACH_MSG_TYPE_PORT_SEND) {
		return false;
	}
	if (ops != NULL) {
		struct remote_object object;
		if (*room < sizeof(object)) {
			return false;
		}
		memcpy(&object, *data, sizeof(object));
		if (object.length != ops->record_size
				|| *room - sizeof(object) < object.length
				|| (!lost && object.fd_count > *fd_count)) {
			return false;
		}
		*room -= sizeof(object) + object.length;
		*data += sizeof(object) + object.length;
		*fd_count -= lost ? 0 : object.fd_count;
		return true;
	}
	if (!lost && *fd_count == 0) {
		return false;
	}
	*fd_count -= !lost;
	if (global_id == memory_entry_global_id) {
		if (*room < sizeof(struct remote_memory_entry)) {
			return false;
		}
		*room -= sizeof(struct remote_memory_entry);
		*data += sizeof(struct remote_memory_entry);
	}
	return true;
}

static bool
remote_right_fits(uint64_t global_id, mach_msg_type_name_t disposition)
{
	return global_id == 0 || global_id == dead_global_id
			|| received_type(disposition)
			!= MACH_MSG_TYPE_PORT_NONE;
}

static void
import_body_ports(mach_msg_header_t *header, const uint64_t *global_ids,
		const uint8_t *data, const int *fds, size_t fd_count,
		uint32_t sender_guest_id, uint32_t meant_guest_id,
		mach_msg_return_t *body_error)
{
	const int *all_fds = fds;
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
			d->name = import_body_port(global_ids[count++], type,
					&fds, &data, all_fds, fd_count,
					sender_guest_id, meant_guest_id);
			d->disposition = type;
			cursor += sizeof(*d);
		} else if (descriptor->type == MACH_MSG_OOL_DESCRIPTOR
				|| descriptor->type
						== MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
			mach_msg_ool_descriptor64_t *d
					= (mach_msg_ool_descriptor64_t *)cursor;
			d->address = (uint64_t)copy_ool(data, d->size);
			data += d->size;
			if (d->address == 0 && d->size != 0) {
				d->size = 0;
				*body_error = MACH_MSG_VM_SPACE;
			}
			cursor += sizeof(*d);
		} else if (descriptor->type == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
			mach_msg_ool_ports_descriptor64_t *d
					= (mach_msg_ool_ports_descriptor64_t *)
							cursor;
			mach_msg_type_name_t type
					= received_type(d->disposition);
			mach_vm_address_t address = 0;
			if (d->count != 0
					&& _kernelrpc_mach_vm_allocate(0,
							   &address,
							   d->count * sizeof(mach_port_name_t),
							   VM_FLAGS_ANYWHERE)
							!= KERN_SUCCESS) {
				address = 0;
				*body_error = MACH_MSG_VM_SPACE;
			}
			mach_port_name_t *names = (mach_port_name_t *)address;
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				mach_port_name_t name = import_body_port(
						global_ids[count++], type, &fds,
						&data, all_fds, fd_count,
						sender_guest_id,
						meant_guest_id);
				if (names != NULL) {
					names[j] = name;
				} else {
					destroy_right(name, type);
				}
			}
			if (names == NULL) {
				d->count = 0;
			}
			d->address = address;
			d->disposition = type;
			d->deallocate = false;
			cursor += sizeof(*d);
		} else {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t *)
							cursor;
			mach_msg_type_name_t type = received_type(d->disposition);
			d->name = import_body_port(global_ids[count++], type,
					&fds, &data, all_fds, fd_count,
					sender_guest_id, meant_guest_id);
			d->disposition = type;
			cursor += sizeof(*d);
		}
	}
}

static mach_port_name_t
import_body_port(uint64_t global_id, mach_msg_type_name_t type, const int **fds,
		const uint8_t **data, const int *all_fds, size_t fd_count,
		uint32_t sender_guest_id, uint32_t meant_guest_id)
{
	if (global_id == 0) {
		return MACH_PORT_NULL;
	}
	if (global_id == fileport_global_id) {
		return *fds != NULL ? import_fileport(*(*fds)++)
				    : MACH_PORT_NULL;
	}
	if (global_id == memory_entry_global_id) {
		const uint8_t *record = *data;
		*data += sizeof(struct remote_memory_entry);
		return *fds != NULL ? import_memory_entry(*(*fds)++, record)
				    : MACH_PORT_NULL;
	}
	const struct ipc_kobject_ops *ops
			= kobject_ops_for_remote_id(global_id);
	if (ops != NULL) {
		return import_kind(ops, data, fds, all_fds, fd_count);
	}

	if (type == MACH_MSG_TYPE_PORT_RECEIVE && global_id != dead_global_id) {
		struct ipc_entry *entry = NULL;
		for (uint32_t i = 1; i < entry_count && entry == NULL; i++) {
			struct ipc_port *port = entries[i].port;
			if (port != NULL && port->remote
					&& port->global_id == global_id
					&& !(entries[i].type
							& MACH_PORT_TYPE_DEAD_NAME)) {
				entry = &entries[i];
			}
		}
		if (entry == NULL) {
			entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
			entry->port->global_id = global_id;
		}
		entry->port->remote = false;
		entry->port->grants = 0;
		entry->type |= MACH_PORT_TYPE_RECEIVE;
		import_holders(entry, data);
		forget_moved_away(&moved_aways, global_id);
		return entry->port->name;
	}
	return import_remote_send(
			global_id, type, sender_guest_id, meant_guest_id);
}

static void
import_holders(struct ipc_entry *entry, const uint8_t **data)
{
	struct remote_holders holders;
	memcpy(&holders, *data, sizeof(holders));
	*data += sizeof(holders);
	for (uint32_t i = 0; i < holders.count; i++) {
		struct remote_notice holder;
		memcpy(&holder, *data, sizeof(holder));
		*data += sizeof(holder);
		if (holder.guest_id == broker_client_guest_id()
				|| guest_is_gone(holder.guest_id)) {
			continue;
		}
		if (holder.kind == REMOTE_NOTICE_ADD) {
			count_sender_guest(entry->port, holder.guest_id,
					holder.count);
		} else if (holder.kind == REMOTE_NOTICE_SEND_ONCE_MOVED) {
			remember_send_once(entry->port->name, holder.guest_id);
		} else if (holder.kind == REMOTE_NOTICE_WATCH) {
			struct ipc_port *port = entry->port;
			port->watchers = realloc(port->watchers,
					(port->watcher_count + 1)
							* sizeof(*port->watchers));
			port->watchers[port->watcher_count++] = holder.guest_id;
		}
	}
}

static mach_port_name_t
import_fileport(int fd)
{
	int own = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (own == -1) {
		return MACH_PORT_NULL;
	}

	int *kobject = malloc(sizeof(*kobject));
	*kobject = own;
	return adopt_object(IPC_KOBJECT_FILEPORT, kobject)->port->name;
}

static mach_port_name_t
import_memory_entry(int fd, const uint8_t *record)
{
	int own = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (own == -1) {
		return MACH_PORT_NULL;
	}

	struct remote_memory_entry entry;
	memcpy(&entry, record, sizeof(entry));
	return adopt_object(IPC_KOBJECT_MEMORY_ENTRY,
			memory_entry_adopt(own, entry.size, entry.data_offset))
			->port->name;
}

static mach_port_name_t
import_kind(const struct ipc_kobject_ops *ops, const uint8_t **data,
		const int **fds, const int *all_fds, size_t fd_count)
{
	struct remote_object object;
	memcpy(&object, *data, sizeof(object));
	void *record = malloc(object.length + 1);
	memcpy(record, *data + sizeof(object), object.length);
	*data += sizeof(object) + object.length;
	mach_port_name_t name = MACH_PORT_NULL;
	if (*fds != NULL) {
		void *kobject = ops->adopt(record, all_fds, fd_count);
		*fds += object.fd_count;
		name = kobject != NULL
				? adopt_object(ops->type, kobject)->port->name
				: MACH_PORT_NULL;
	}
	free(record);
	return name;
}

int
ipc_import_fd(const int *fds, size_t fd_count, uint32_t index)
{
	return index < fd_count ? fcntl(fds[index], F_DUPFD_CLOEXEC, 0) : -1;
}

extern const struct ipc_kobject_ops *const __start_limbo_ipc_kobject_ops[]
		__attribute__((weak));
extern const struct ipc_kobject_ops *const __stop_limbo_ipc_kobject_ops[]
		__attribute__((weak));

static const struct ipc_kobject_ops *
kobject_ops(ipc_kobject_type_t type)
{
	for (const struct ipc_kobject_ops *const *ops
			= __start_limbo_ipc_kobject_ops;
			ops != __stop_limbo_ipc_kobject_ops; ops++) {
		if ((*ops)->type == type) {
			return *ops;
		}
	}
	return NULL;
}

static const struct ipc_kobject_ops *
kobject_ops_for_remote_id(uint64_t id)
{
	for (const struct ipc_kobject_ops *const *ops
			= __start_limbo_ipc_kobject_ops;
			ops != __stop_limbo_ipc_kobject_ops; ops++) {
		if ((*ops)->remote_id != 0 && (*ops)->remote_id == id) {
			return *ops;
		}
	}
	return NULL;
}

static struct ipc_entry *
adopt_object(ipc_kobject_type_t kotype, void *kobject)
{
	struct ipc_port *port = port_alloc(kotype);
	port->kobject = kobject;
	struct ipc_entry *entry = entry_alloc(port);
	entry->type = MACH_PORT_TYPE_SEND;
	entry->urefs = 1;
	return entry;
}

void
ipc_remote_guest_gone(uint32_t guest_id)
{
	pthread_mutex_lock(&lock);
	remember_gone(guest_id);
	forget_guest_pid(guest_id);
	send_onces_gone(guest_id);
	return_ports(0, guest_id);
	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *port = entries[i].port;
		if (port != NULL && port->remote
				&& broker_guest_of(port->global_id) == guest_id
				&& !moved_away(outliving_ports,
						port->global_id)) {
			turn_dead(&entries[i]);
		}
		if (port != NULL
				&& (entries[i].type & MACH_PORT_TYPE_RECEIVE)) {
			release_grants(&entries[i], guest_id, UINT64_MAX);
		}
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
}

void
ipc_remote_port_moved(uint64_t global_id, uint32_t guest_id)
{
	pthread_mutex_lock(&lock);
	if (guest_id != 0) {
		if (!moved_away(outliving_ports, global_id)) {
			struct moved_away *outliving
					= malloc(sizeof(*outliving));
			*outliving = (struct moved_away){
					.next = outliving_ports,
					.global_id = global_id,
			};
			outliving_ports = outliving;
		}
		pthread_mutex_unlock(&lock);
		return;
	}
	forget_moved_away(&moved_aways, global_id);
	forget_moved_away(&outliving_ports, global_id);
	return_ports(global_id, 0);
	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *port = entries[i].port;
		if (port != NULL && port->remote
				&& port->global_id == global_id) {
			turn_dead(&entries[i]);
		}
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
}

void
ipc_remote_all_gone(void)
{
	pthread_mutex_lock(&lock);
	while (remote_send_onces != NULL) {
		send_onces_gone(remote_send_onces->guest_id);
	}
	while (port_returns != NULL) {
		struct port_return *record = port_returns;
		port_returns = record->next;
		return_port(record->global_id, record->notify);
		free(record);
	}
	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *port = entries[i].port;
		if (port != NULL && port->remote) {
			turn_dead(&entries[i]);
		}
		if (port != NULL
				&& (entries[i].type & MACH_PORT_TYPE_RECEIVE)) {
			port->sender_guest_count = 0;
			queue_no_senders_notification(&entries[i]);
		}
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
}

static void
send_onces_gone(uint32_t guest_id)
{
	struct remote_send_once **link = &remote_send_onces;
	while (*link != NULL) {
		struct remote_send_once *record = *link;
		if (record->guest_id != guest_id) {
			link = &record->next;
			continue;
		}
		*link = record->next;
		struct ipc_entry *entry = lookup(record->port);
		if (entry != NULL) {
			queue_send_once_notifications(entry, 1);
		}
		free(record);
	}
}

static void
turn_dead(struct ipc_entry *entry)
{
	if (!(entry->type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE))) {
		return;
	}

	entry->type = MACH_PORT_TYPE_DEAD_NAME;
	entry->urefs += entry->sorights;
	entry->sorights = 0;
	entry->port->grants = 0;
	queue_dead_name_notification(entry);
}

static void
remember_gone(uint32_t guest_id)
{
	if (guest_is_gone(guest_id)) {
		return;
	}

	size_t index = gone_guest_index(guest_id);
	gone_guests = realloc(gone_guests,
			(gone_guest_count + 1) * sizeof(*gone_guests));
	memmove(&gone_guests[index + 1], &gone_guests[index],
			(gone_guest_count - index) * sizeof(*gone_guests));
	gone_guests[index] = guest_id;
	gone_guest_count++;
}

static bool
guest_is_gone(uint32_t guest_id)
{
	size_t index = gone_guest_index(guest_id);
	return index != gone_guest_count && gone_guests[index] == guest_id;
}

static size_t
gone_guest_index(uint32_t guest_id)
{
	size_t low = 0;
	size_t high = gone_guest_count;
	while (low != high) {
		size_t middle = low + (high - low) / 2;
		if (gone_guests[middle] < guest_id) {
			low = middle + 1;
		} else {
			high = middle;
		}
	}
	return low;
}

__attribute__((constructor)) static void
names_init(void)
{
	pthread_atfork(names_fork_prepare, names_fork_parent, names_fork_child);
}

static void
names_fork_prepare(void)
{
	pthread_mutex_lock(&own_lock);
}

static void
names_fork_parent(void)
{
	pthread_mutex_unlock(&own_lock);
}

static void
names_fork_child(void)
{
	free(own_names);
	own_names = NULL;
	own_name_count = 0;
	pthread_mutex_unlock(&own_lock);
}

kern_return_t
names_check_in(const char *name, mach_port_name_t *port)
{
	broker_client_ensure();
	ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, port);
	uint32_t holder = register_name(name, ipc_names_hold(*port));
	if (holder == BROKER_NAME_FREE) {
		return KERN_SUCCESS;
	}
	ipc_port_mod_refs(*port, MACH_PORT_RIGHT_RECEIVE, -1);
	*port = MACH_PORT_NULL;
	return holder == BROKER_NAME_ASKERS ? BOOTSTRAP_SERVICE_ACTIVE
					    : BOOTSTRAP_NOT_PRIVILEGED;
}

kern_return_t
names_register(const char *name, mach_port_name_t port)
{
	broker_client_ensure();
	uint32_t holder = register_name(name, ipc_names_hold(port));
	if (holder == BROKER_NAME_FREE) {
		return KERN_SUCCESS;
	}
	ipc_names_release(port);
	return holder == BROKER_NAME_ASKERS ? BOOTSTRAP_NAME_IN_USE
					    : BOOTSTRAP_NOT_PRIVILEGED;
}

kern_return_t
names_look_up(const char *name, mach_port_name_t *port)
{
	return names_look_up_in(name, broker_client_domain(), port, NULL);
}

kern_return_t
names_look_up_in(const char *name, uint32_t domain, mach_port_name_t *port,
		bool *hidden)
{
	return look_up(name, domain, false, false, port, hidden);
}

kern_return_t
names_look_up_registered(
		const char *name, uint32_t domain, mach_port_name_t *port)
{
	return look_up(name, domain, true, false, port, NULL);
}

kern_return_t
names_look_up_instance(
		const char *name, uint32_t domain, mach_port_name_t *port)
{
	return look_up(name, domain, false, true, port, NULL);
}

static kern_return_t
look_up(const char *name, uint32_t domain, bool registered, bool instance,
		mach_port_name_t *port, bool *hidden)
{
	*port = MACH_PORT_NULL;
	if (hidden != NULL) {
		*hidden = false;
	}
	pthread_mutex_lock(&own_lock);
	uint64_t own = own_name(name);
	pthread_mutex_unlock(&own_lock);
	if (own != 0) {
		*port = ipc_names_send_right(own);
		return KERN_SUCCESS;
	}

	broker_client_ensure();
	if (!broker_client_available()) {
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}

	struct broker_lookup request = {
			.domain = domain,
			.registered = registered,
			.instance = instance,
	};
	strncpy(request.name, name, sizeof(request.name) - 1);
	struct broker_lookup_reply reply = {0};
	if (!broker_client_call(BROKER_LOOKUP, &request, sizeof(request),
			    BROKER_LOOKUP_REPLY, &reply, sizeof(reply))
			|| !reply.found) {
		if (hidden != NULL) {
			*hidden = reply.hidden;
		}
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}
	*port = ipc_names_send_right(reply.global_id);
	return KERN_SUCCESS;
}

static uint32_t
register_name(const char *name, uint64_t global_id)
{
	struct broker_register request = {.global_id = global_id};
	strncpy(request.name, name, sizeof(request.name) - 1);
	const char *instance = getenv(BROKER_INSTANCE_VARIABLE);
	if (instance != NULL && instance[0] != '\0') {
		snprintf(request.name, sizeof(request.name), "%s#%s", name,
				instance);
	}
	struct broker_registered reply = {.holder = BROKER_NAME_FREE};
	pthread_mutex_lock(&own_lock);
	if (own_name(name) != 0) {
		reply.holder = BROKER_NAME_ASKERS;
	} else {
		broker_client_call(BROKER_REGISTER, &request, sizeof(request),
				BROKER_REGISTERED, &reply, sizeof(reply));
	}
	if (reply.holder == BROKER_NAME_FREE
			&& broker_guest_of(global_id)
					== broker_client_guest_id()) {
		add_own_name(name, global_id);
	}
	pthread_mutex_unlock(&own_lock);
	return reply.holder;
}

static uint64_t
own_name(const char *name)
{
	for (size_t i = 0; i != own_name_count; i++) {
		if (strncmp(own_names[i].name, name,
				    sizeof(own_names[i].name) - 1)
				!= 0) {
			continue;
		}
		uint64_t global_id = own_names[i].global_id;
		if (ipc_names_lives(global_id)) {
			return global_id;
		}
		own_names[i] = own_names[--own_name_count];
		return 0;
	}
	return 0;
}

static void
add_own_name(const char *name, uint64_t global_id)
{
	own_names = reallocarray(
			own_names, own_name_count + 1, sizeof(*own_names));
	struct own_name *own = &own_names[own_name_count++];
	*own = (struct own_name){.global_id = global_id};
	strncpy(own->name, name, sizeof(own->name) - 1);
}

uint64_t
ipc_names_hold(mach_port_name_t port)
{
	pthread_mutex_lock(&lock);
	uint64_t global_id = export_local_port(port);
	struct ipc_entry *entry = lookup(port);
	if (entry->type & MACH_PORT_TYPE_RECEIVE) {
		count_sender_guest(entry->port, BROKER_GUEST_ID, 1);
	} else if (entry->port->remote) {
		queue_notice((struct pending_notice){
				.global_id = global_id,
				.notice = {
						.kind = REMOTE_NOTICE_ADD,
						.guest_id = BROKER_GUEST_ID,
				},
		});
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
	return global_id;
}

static void
ipc_names_release(mach_port_name_t port)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(port);
	if (entry != NULL && (entry->type & MACH_PORT_TYPE_RECEIVE)) {
		release_grants(entry, BROKER_GUEST_ID, 1);
	} else if (entry != NULL && entry->port->remote) {
		queue_notice((struct pending_notice){
				.global_id = entry->port->global_id,
				.notice = {
						.kind = REMOTE_NOTICE_RELEASE,
						.guest_id = BROKER_GUEST_ID,
						.count = 1,
				},
		});
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
}

static bool
ipc_names_lives(uint64_t global_id)
{
	pthread_mutex_lock(&lock);
	bool lives = port_for_global_id(global_id) != NULL;
	pthread_mutex_unlock(&lock);
	return lives;
}

mach_port_name_t
ipc_names_send_right(uint64_t global_id)
{
	pthread_mutex_lock(&lock);
	bool held = broker_guest_of(global_id) == BROKER_GUEST_ID;
	uint32_t guest_id = broker_client_guest_id();
	mach_port_name_t name = import_remote_send(
			global_id, MACH_MSG_TYPE_PORT_SEND, guest_id, guest_id);
	if (MACH_PORT_VALID(name) && !held && lookup(name)->port->remote) {
		queue_notice((struct pending_notice){
				.global_id = global_id,
				.notice = {
						.kind = REMOTE_NOTICE_ADD,
						.guest_id = guest_id,
						.count = 1,
				},
		});
	}
	pthread_mutex_unlock(&lock);
	flush_notices();
	return name;
}

void
ipc_names_keep(uint64_t global_id, uint64_t held_global_id)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port = port_for_global_id(global_id);
	if (port != NULL) {
		port->global_id = held_global_id;
		port->held = true;
	}
	pthread_mutex_unlock(&lock);
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
		if (disposition == MACH_MSG_TYPE_MOVE_RECEIVE) {
			prepare_move(entry->port);
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

static void
prepare_move(struct ipc_port *port)
{
	port_leave_all_sets(port);
	port->mscount = 0;
	port->seqno = 0;
	port->context = 0;
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
	if (_kernelrpc_mach_vm_allocate(0, &copy, size, VM_FLAGS_ANYWHERE)
			!= KERN_SUCCESS) {
		return NULL;
	}
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
	write_trailer(kmsg->header, port, &kmsg->sender);
	pthread_mutex_unlock(&lock);

	mach_msg_return_t mr = MACH_RCV_TOO_LARGE;
	if (size + trailer_size <= rcv_size) {
		memcpy(msg, kmsg->header, size);
		mach_msg_max_trailer_t *trailer
				= (mach_msg_max_trailer_t *)((uint8_t *)msg
						+ size);
		memcpy(trailer, (uint8_t *)kmsg->header + size, trailer_size);
		trailer->msgh_trailer_size = trailer_size;
		mr = kmsg->body_error != MACH_MSG_SUCCESS
				? MACH_RCV_BODY_ERROR | kmsg->body_error
				: MACH_MSG_SUCCESS;
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
	int error;
	do {
		error = signals_futex_wait(
				&waiter.woken, &lock, timed ? deadline : NULL);
	} while (error == EINTR && kernel_receive);
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
write_trailer(mach_msg_header_t *msg, struct ipc_port *port,
		const struct ipc_sender *sender)
{
	mach_msg_max_trailer_t *trailer
			= (mach_msg_max_trailer_t *)((uint8_t *)msg
					+ msg->msgh_size);
	memset(trailer, 0, sizeof(*trailer));
	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
	trailer->msgh_trailer_size = sizeof(*trailer);
	trailer->msgh_seqno = port->seqno++;
	trailer->msgh_sender.val[0] = sender->euid;
	trailer->msgh_sender.val[1] = sender->egid;
	trailer->msgh_audit.val[1] = sender->euid;
	trailer->msgh_audit.val[2] = sender->egid;
	trailer->msgh_audit.val[3] = sender->uid;
	trailer->msgh_audit.val[4] = sender->gid;
	trailer->msgh_audit.val[5] = sender->pid;
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
	pthread_mutex_lock(&notice_order);
	pthread_mutex_lock(&lock);
	struct pending_notice *notices = pending_notices;
	pending_notices = NULL;
	pending_notices_tail = &pending_notices;
	pthread_mutex_unlock(&lock);
	for (struct pending_notice *notice = notices; notice != NULL;
			notice = notice->next) {
		if (notice->id == 0 && notice->kmsg == NULL) {
			send_remote_notice(notice);
		}
	}
	pthread_mutex_unlock(&notice_order);
	for (struct pending_notice *notice = notices; notice != NULL;
			notice = notice->next) {
		if (notice->kmsg != NULL) {
			send_returned(notice->kmsg, notice->global_id);
		}
	}

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
send_returned(struct ipc_kmsg *kmsg, uint64_t global_id)
{
	pthread_mutex_lock(&lock);
	send_queued(kmsg, global_id);
	pthread_mutex_unlock(&lock);
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
	if (port->remote) {
		uint64_t global_id = port->global_id;
		port_free_if_unheld(port);
		pthread_mutex_unlock(&lock);
		return deliver_remote_notification(global_id, msg);
	}
	if (!port_has_receiver(port)) {
		port_free_if_unheld(port);
		pthread_mutex_unlock(&lock);
		return false;
	}

	struct ipc_kmsg *kmsg = malloc(sizeof(*kmsg) + msg->msgh_size
			+ sizeof(mach_msg_max_trailer_t));
	kmsg->sender = (struct ipc_sender){0};
	kmsg->body_error = MACH_MSG_SUCCESS;
	memcpy(kmsg->header, msg, msg->msgh_size);
	kmsg->header->msgh_bits = MACH_MSGH_BITS_SET(0,
			MACH_MSG_TYPE_PORT_SEND_ONCE, 0,
			msg->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	kmsg->header->msgh_local_port = port->name;
	enqueue(port, kmsg);
	unlock_and_notify_arrival(port);
	return true;
}

static bool
deliver_remote_notification(uint64_t global_id, const mach_msg_header_t *msg)
{
	bool whole = !(msg->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	mach_msg_header_t unused = {
			.msgh_size = sizeof(unused),
			.msgh_id = MACH_NOTIFY_SEND_ONCE,
	};
	const mach_msg_header_t *sent = whole ? msg : &unused;
	struct remote_header rh = {
			.message_size = sent->msgh_size,
			.dest_disposition = MACH_MSG_TYPE_MOVE_SEND_ONCE,
			.sender_guest_id = broker_client_guest_id(),
	};

	uint32_t length = sizeof(rh) + sent->msgh_size;
	char *blob = malloc(length);
	memcpy(blob, &rh, sizeof(rh));
	memcpy(blob + sizeof(rh), sent, sent->msgh_size);
	broker_client_send(global_id, blob, length, NULL, 0, NULL, 0);
	free(blob);
	return whole;
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
		status->mps_srights = (entry->type & MACH_PORT_TYPE_SEND) != 0
				|| port->sender_guest_count != 0;
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
	tell_holders_dead(port);
	if (port->held) {
		return_held(port, queued);
		queued = NULL;
	}

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
return_held(struct ipc_port *port, struct ipc_kmsg *queued)
{
	if (!moved_away(returned_ports, port->global_id)) {
		struct moved_away *returned = malloc(sizeof(*returned));
		*returned = (struct moved_away){
				.next = returned_ports,
				.global_id = port->global_id,
		};
		returned_ports = returned;
	}
	while (queued != NULL) {
		struct ipc_kmsg *kmsg = queued;
		queued = kmsg->next;
		queue_notice((struct pending_notice){
				.global_id = port->global_id,
				.kmsg = kmsg,
		});
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
	give_back_grants(port);
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
	} else if (port->kotype == IPC_KOBJECT_MEMORY_ENTRY) {
		memory_entry_destroy(port->kobject);
		free(port);
	} else if (port->kotype == IPC_KOBJECT_EVENTLINK) {
		eventlink_port_gone(port->kobject);
		free(port);
	} else if (port->kotype == IPC_KOBJECT_TASK_NAME
			|| port->kotype == IPC_KOBJECT_XPC_SERVICE) {
		free(port);
	} else if (kobject_ops(port->kotype) != NULL
			&& kobject_ops(port->kotype)->destroy != NULL) {
		kobject_ops(port->kotype)->destroy(port->kobject);
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
		free(port->sender_guests);
		free(port->sender_grants);
		free(port->watchers);
		free(port);
	}
}

static void
queue_no_senders_notification(struct ipc_entry *entry)
{
	struct ipc_port *port = entry->port;
	if (!(entry->type & MACH_PORT_TYPE_SEND)) {
		give_back_grants(port);
	}
	if (!(entry->type & MACH_PORT_TYPE_RECEIVE)
			|| (entry->type & MACH_PORT_TYPE_SEND)
			|| port->sender_guest_count != 0
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
	if (port->remote) {
		struct ipc_entry *entry = port->name != MACH_PORT_NULL
				? lookup(port->name)
				: entry_alloc(port);
		return (entry->type & MACH_PORT_TYPE_DEAD_NAME) ? MACH_PORT_DEAD
								: port->name;
	}
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
	if (entry->port->remote && count != 0
			&& broker_guest_of(entry->port->global_id)
					!= BROKER_GUEST_ID) {
		queue_notice((struct pending_notice){
				.global_id = entry->port->global_id,
				.notice = {
						.kind = REMOTE_NOTICE_SEND_ONCE,
						.guest_id = broker_client_guest_id(),
						.count = count,
				},
		});
	}
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
