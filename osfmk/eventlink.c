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
#include <mach/mach.h>
#include <mach/mig.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "broker_client.h"
#include "bsd/process.h"
#include "bsd/signals.h"
#include "commpage.h"
#include "eventlink.h"
#include "ipc.h"
#include "thread.h"

#define MELC_OPTION_NO_COPYIN         0x1
#define MELA_OPTION_ASSOCIATE_ON_WAIT 0x1
#define MELD_OPTION_NONE              0x0
#define MELSW_OPTION_NO_WAIT          0x1
#define KERN_CLOCK_MACH_ABSOLUTE_TIME 1
#define EVENTLINK_SIGNAL_COUNT_MASK   0xffffffffffffffull
#define EVENTLINK_SIGNAL_ERROR_SHIFT  56
#define THREAD_ASSOCIATE_WILD         UINT64_MAX
#define NO_WAITER                     UINT64_MAX
#define NO_THREAD                     0
#define PAIR_SIZE                     4096
#define WAITER_COUNT                  8

struct eventlink_waiter {
	_Atomic uint32_t woken;
	kern_return_t result;
	bool waiting;
};

struct eventlink_end {
	uint64_t thread;
	uint64_t sync_count;
	uint64_t wait_count;
	uint32_t waiter;
	uint32_t holders;
};

struct eventlink {
	struct eventlink_pair *pair;
	struct eventlink_end *end;
	int fd;
	_Atomic uint32_t references;
};

struct eventlink_pair {
	pthread_mutex_t lock;
	struct eventlink_end ends[2];
	bool active;
	struct eventlink_waiter waiters[WAITER_COUNT];
};

#pragma pack(push, 4)
struct create_request {
	mach_msg_header_t header;
	NDR_record_t ndr;
	uint32_t option;
};

struct create_reply {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t pair[2];
};

struct associate_request {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t thread;
	NDR_record_t ndr;
	mach_vm_address_t copyin_addr_wait;
	uint64_t copyin_mask_wait;
	mach_vm_address_t copyin_addr_signal;
	uint64_t copyin_mask_signal;
	uint32_t option;
};

struct disassociate_request {
	mach_msg_header_t header;
	NDR_record_t ndr;
	uint32_t option;
};
#pragma pack(pop)

static void create_routine(mach_msg_header_t *in, mach_msg_header_t *out);
static void destroy_routine(mach_msg_header_t *in, mach_msg_header_t *out);
static void associate_routine(mach_msg_header_t *in, mach_msg_header_t *out);
static kern_return_t associate(struct eventlink *end, uint64_t thread,
		const struct associate_request *request);
static void disassociate_routine(mach_msg_header_t *in, mach_msg_header_t *out);
static kern_return_t disassociate(struct eventlink *end, uint32_t option);
static uint64_t signal_wait(mach_port_name_t name, bool signal, uint64_t count,
		uint64_t deadline, uint32_t clock_id, uint32_t option);
static kern_return_t signal_wait_end(struct eventlink *end, bool signal,
		uint64_t *count, uint64_t deadline, uint32_t option);
static kern_return_t held_trap_end(
		mach_port_name_t name, struct eventlink **end);
static struct eventlink *held_end(mach_port_name_t name);
static void hold_end(void *kobject);
static kern_return_t signal_end(
		struct eventlink_pair *pair, struct eventlink_end *end);
static struct eventlink_end *remote_end(struct eventlink *end);
static kern_return_t wait_end(
		struct eventlink *end, uint64_t *count, uint64_t deadline);
static void wake_end(struct eventlink_pair *pair, struct eventlink_end *end,
		kern_return_t result);
static uint64_t encode(uint64_t count, kern_return_t kr);
static bool create_pair(struct eventlink *ends[2]);
static struct eventlink *map_end(int fd, uint64_t side);
static void end_pair(struct eventlink_pair *pair);
static void lock_pair(struct eventlink_pair *pair);
static void release_end(struct eventlink *end);

const struct mach_eventlink_subsystem {
	mig_server_routine_t server;
	mach_msg_id_t start;
	mach_msg_id_t end;
	unsigned int maxsize;
	vm_address_t reserved;
	struct routine_descriptor routine[4];
} mach_eventlink_subsystem = {
	.start = 716200,
	.end = 716204,
	.maxsize = sizeof(struct create_reply),
	.routine = {
		{.stub_routine = create_routine},
		{.stub_routine = destroy_routine},
		{.stub_routine = associate_routine},
		{.stub_routine = disassociate_routine},
	},
};

static void
create_routine(mach_msg_header_t *in, mach_msg_header_t *out)
{
	const struct create_request *request
			= (const struct create_request *)in;
	if (request->option != MELC_OPTION_NO_COPYIN) {
		((mig_reply_error_t *)out)->RetCode = KERN_INVALID_ARGUMENT;
		return;
	}

	struct eventlink *ends[2];
	if (!create_pair(ends)) {
		((mig_reply_error_t *)out)->RetCode = KERN_RESOURCE_SHORTAGE;
		return;
	}
	struct create_reply *reply = (struct create_reply *)out;
	reply->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
	reply->header.msgh_size = sizeof(*reply);
	reply->body.msgh_descriptor_count = 2;
	ipc_kobject_type_t type = IPC_KOBJECT_EVENTLINK;
	for (int i = 0; i < 2; i++) {
		reply->pair[i] = (mach_msg_port_descriptor_t){
				.name = ipc_kobject_alloc(type, ends[i]),
				.disposition = MACH_MSG_TYPE_MOVE_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
}

static bool
create_pair(struct eventlink *ends[2])
{
	int fd = limbo_fd_high(memfd_create("eventlink", MFD_CLOEXEC));
	if (fd == -1 || ftruncate(fd, PAIR_SIZE) == -1) {
		if (fd != -1) {
			close(fd);
		}
		return false;
	}
	ends[0] = map_end(fd, 0);
	if (ends[0] == NULL) {
		return false;
	}
	struct eventlink_pair *pair = ends[0]->pair;
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
	pthread_mutex_init(&pair->lock, &attr);
	pthread_mutexattr_destroy(&attr);
	pair->active = true;
	for (int i = 0; i < 2; i++) {
		pair->ends[i].wait_count = NO_WAITER;
		pair->ends[i].holders = 1;
	}

	int second = limbo_fd_copy(fd);
	ends[1] = second != -1 ? map_end(second, 1) : NULL;
	if (ends[1] == NULL) {
		release_end(ends[0]);
		return false;
	}
	return true;
}

static struct eventlink *
map_end(int fd, uint64_t side)
{
	struct eventlink_pair *pair = mmap(NULL, PAIR_SIZE,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (pair == MAP_FAILED) {
		close(fd);
		return NULL;
	}
	struct eventlink *end = malloc(sizeof(*end));
	*end = (struct eventlink){
			.pair = pair,
			.end = &pair->ends[side & 1],
			.fd = fd,
			.references = 1,
	};
	return end;
}

static void
destroy_routine(mach_msg_header_t *in, mach_msg_header_t *out)
{
	struct eventlink *end = ipc_kobject_detach(
			in->msgh_local_port, IPC_KOBJECT_EVENTLINK);
	if (end != NULL) {
		lock_pair(end->pair);
		end_pair(end->pair);
		pthread_mutex_unlock(&end->pair->lock);
		eventlink_port_gone(end);
	}
}

static void
associate_routine(mach_msg_header_t *in, mach_msg_header_t *out)
{
	const struct associate_request *request
			= (const struct associate_request *)in;
	struct thread *thread = ipc_kobject_lookup(
			request->thread.name, IPC_KOBJECT_THREAD);
	((mig_reply_error_t *)out)->RetCode = associate(
			held_end(in->msgh_local_port),
			thread != NULL ? (uint64_t)thread->tid : NO_THREAD,
			request);
}

static kern_return_t
associate(struct eventlink *end, uint64_t thread,
		const struct associate_request *request)
{
	if (end == NULL) {
		return KERN_TERMINATED;
	}

	bool on_wait = request->option == MELA_OPTION_ASSOCIATE_ON_WAIT;
	lock_pair(end->pair);
	kern_return_t kr = KERN_SUCCESS;
	if (request->copyin_addr_wait != 0 || request->copyin_mask_wait != 0
			|| request->copyin_addr_signal != 0
			|| request->copyin_mask_signal != 0
			|| (thread == NO_THREAD) != on_wait) {
		kr = KERN_INVALID_ARGUMENT;
	} else if (!end->pair->active) {
		kr = KERN_TERMINATED;
	} else if (end->end->thread != NO_THREAD) {
		kr = KERN_NAME_EXISTS;
	} else {
		end->end->thread = on_wait ? THREAD_ASSOCIATE_WILD : thread;
	}
	pthread_mutex_unlock(&end->pair->lock);
	release_end(end);
	return kr;
}

static void
disassociate_routine(mach_msg_header_t *in, mach_msg_header_t *out)
{
	const struct disassociate_request *request
			= (const struct disassociate_request *)in;
	((mig_reply_error_t *)out)->RetCode = disassociate(
			held_end(in->msgh_local_port), request->option);
}

static kern_return_t
disassociate(struct eventlink *end, uint32_t option)
{
	if (end == NULL) {
		return KERN_TERMINATED;
	}

	lock_pair(end->pair);
	kern_return_t kr = KERN_SUCCESS;
	if (option != MELD_OPTION_NONE) {
		kr = KERN_INVALID_ARGUMENT;
	} else if (!end->pair->active) {
		kr = KERN_TERMINATED;
	} else if (end->end->thread == NO_THREAD) {
		kr = KERN_INVALID_ARGUMENT;
	} else {
		end->end->thread = NO_THREAD;
		wake_end(end->pair, end->end, KERN_TERMINATED);
	}
	pthread_mutex_unlock(&end->pair->lock);
	release_end(end);
	return kr;
}

uint64_t
eventlink_signal(mach_port_name_t name)
{
	struct eventlink *end;
	kern_return_t kr = held_trap_end(name, &end);
	if (kr == KERN_SUCCESS) {
		lock_pair(end->pair);
		kr = signal_end(end->pair, remote_end(end));
		pthread_mutex_unlock(&end->pair->lock);
		release_end(end);
	}
	return encode(0, kr);
}

uint64_t
eventlink_wait_until(mach_port_name_t name, uint64_t count, uint64_t deadline,
		uint32_t clock_id, uint32_t option)
{
	return signal_wait(name, false, count, deadline, clock_id, option);
}

uint64_t
eventlink_signal_wait_until(mach_port_name_t name, uint64_t count,
		uint64_t deadline, uint32_t clock_id, uint32_t option)
{
	return signal_wait(name, true, count, deadline, clock_id, option);
}

static uint64_t
signal_wait(mach_port_name_t name, bool signal, uint64_t count,
		uint64_t deadline, uint32_t clock_id, uint32_t option)
{
	if (clock_id != KERN_CLOCK_MACH_ABSOLUTE_TIME) {
		return encode(count, KERN_INVALID_ARGUMENT);
	}
	struct eventlink *end;
	kern_return_t kr = held_trap_end(name, &end);
	if (kr != KERN_SUCCESS) {
		return encode(count, kr);
	}

	lock_pair(end->pair);
	kr = signal_wait_end(end, signal, &count, deadline, option);
	pthread_mutex_unlock(&end->pair->lock);
	release_end(end);
	return encode(count, kr);
}

static kern_return_t
signal_wait_end(struct eventlink *end, bool signal, uint64_t *count,
		uint64_t deadline, uint32_t option)
{
	struct eventlink_end *local = end->end;
	if (!end->pair->active) {
		return KERN_TERMINATED;
	}
	if (local->thread != (uint64_t)thread_current()->tid
			&& (local->thread != THREAD_ASSOCIATE_WILD
					|| local->wait_count != NO_WAITER)) {
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t kr = KERN_ALREADY_WAITING;
	if (*count < local->sync_count) {
		*count = local->sync_count;
		kr = KERN_SUCCESS;
	} else if (option & MELSW_OPTION_NO_WAIT) {
		*count = local->sync_count;
		kr = KERN_OPERATION_TIMED_OUT;
	} else {
		local->wait_count = *count;
	}
	if (signal) {
		signal_end(end->pair, remote_end(end));
	}
	return kr == KERN_ALREADY_WAITING ? wait_end(end, count, deadline) : kr;
}

static kern_return_t
held_trap_end(mach_port_name_t name, struct eventlink **end)
{
	*end = held_end(name);
	if (*end != NULL) {
		return KERN_SUCCESS;
	}
	mach_port_type_t type;
	return ipc_port_type(name, &type) == KERN_SUCCESS
			? KERN_INVALID_CAPABILITY
			: KERN_INVALID_NAME;
}

static struct eventlink *
held_end(mach_port_name_t name)
{
	return ipc_kobject_lookup_held(name, IPC_KOBJECT_EVENTLINK, hold_end);
}

static void
hold_end(void *kobject)
{
	struct eventlink *end = kobject;
	atomic_fetch_add(&end->references, 1);
}

void
eventlink_port_gone(void *kobject)
{
	struct eventlink *end = kobject;
	lock_pair(end->pair);
	if (--end->end->holders == 0) {
		end_pair(end->pair);
	}
	pthread_mutex_unlock(&end->pair->lock);
	release_end(end);
}

void
eventlink_fork_child(void)
{
	ipc_kobject_fork_child(IPC_KOBJECT_EVENTLINK);
}

static kern_return_t
signal_end(struct eventlink_pair *pair, struct eventlink_end *end)
{
	if (!pair->active) {
		return KERN_TERMINATED;
	}

	end->sync_count++;
	if (end->sync_count > end->wait_count) {
		wake_end(pair, end, KERN_SUCCESS);
	}
	return KERN_SUCCESS;
}

static struct eventlink_end *
remote_end(struct eventlink *end)
{
	struct eventlink_pair *pair = end->pair;
	return &pair->ends[end->end == &pair->ends[0]];
}

static kern_return_t
wait_end(struct eventlink *end, uint64_t *count, uint64_t deadline)
{
	struct eventlink_pair *pair = end->pair;
	struct eventlink_end *local = end->end;
	uint64_t old_count = local->sync_count;
	struct timespec until;
	if (deadline != 0) {
		uint64_t now = commpage_absolute_time();
		uint64_t delay = deadline > now
				? commpage_absolute_to_nanoseconds(
						  deadline - now)
				: 0;
		clock_gettime(CLOCK_REALTIME, &until);
		until.tv_sec += delay / 1000000000;
		until.tv_nsec += delay % 1000000000;
		if (until.tv_nsec >= 1000000000) {
			until.tv_sec++;
			until.tv_nsec -= 1000000000;
		}
	}

	uint32_t slot = 0;
	while (slot < WAITER_COUNT && pair->waiters[slot].waiting) {
		slot++;
	}
	if (slot == WAITER_COUNT) {
		local->wait_count = NO_WAITER;
		*count = old_count;
		return KERN_RESOURCE_SHORTAGE;
	}
	struct eventlink_waiter *waiter = &pair->waiters[slot];
	*waiter = (struct eventlink_waiter){.waiting = true};
	local->waiter = slot + 1;
	int error = signals_futex_wait(&waiter->woken, &pair->lock,
			deadline != 0 ? &until : NULL);
	pthread_mutex_consistent(&pair->lock);
	if (local->waiter == slot + 1) {
		local->waiter = 0;
	}
	kern_return_t kr = waiter->result;
	waiter->waiting = false;
	if (error == ETIMEDOUT) {
		kr = KERN_OPERATION_TIMED_OUT;
	} else if (error == EINTR) {
		kr = KERN_ABORTED;
	}
	*count = kr == KERN_SUCCESS ? *count + 1 : old_count;
	return kr;
}

static void
wake_end(struct eventlink_pair *pair, struct eventlink_end *end,
		kern_return_t result)
{
	end->wait_count = NO_WAITER;
	if (end->waiter != 0) {
		struct eventlink_waiter *waiter
				= &pair->waiters[end->waiter - 1];
		waiter->result = result;
		signals_futex_wake(&waiter->woken);
		end->waiter = 0;
	}
}

static void
end_pair(struct eventlink_pair *pair)
{
	pair->active = false;
	for (int i = 0; i < 2; i++) {
		wake_end(pair, &pair->ends[i], KERN_TERMINATED);
	}
}

static void
lock_pair(struct eventlink_pair *pair)
{
	if (pthread_mutex_lock(&pair->lock) == EOWNERDEAD) {
		pthread_mutex_consistent(&pair->lock);
	}
}

static void
release_end(struct eventlink *end)
{
	if (atomic_fetch_sub(&end->references, 1) == 1) {
		munmap(end->pair, PAIR_SIZE);
		close(end->fd);
		free(end);
	}
}

static uint64_t
encode(uint64_t count, kern_return_t kr)
{
	return (count & EVENTLINK_SIGNAL_COUNT_MASK)
			| (uint64_t)kr << EVENTLINK_SIGNAL_ERROR_SHIFT;
}

static bool
describe_end(void *kobject, struct ipc_export *out)
{
	struct eventlink *end = kobject;
	lock_pair(end->pair);
	end->end->holders++;
	pthread_mutex_unlock(&end->pair->lock);
	struct ipc_memory_record record = {
			.size = end->end == &end->pair->ends[1],
	};
	record.fd_index = (uint32_t)ipc_export_fd(out, end->fd, false);
	ipc_export_record(out, &record, sizeof(record));
	return true;
}

static void *
adopt_end(const void *record, const int *fds, size_t fd_count)
{
	const struct ipc_memory_record *memory = record;
	int fd = ipc_import_fd(fds, fd_count, memory->fd_index);
	struct eventlink *end = fd != -1 ? map_end(fd, memory->size) : NULL;
	if (end == NULL) {
		fprintf(stderr, "ipc: eventlink without its memfd\n");
		return NULL;
	}
	return end;
}

static const struct ipc_kobject_ops eventlink_ops = {
		.type = IPC_KOBJECT_EVENTLINK,
		.remote_id = IPC_REMOTE_EVENTLINK,
		.record_size = sizeof(struct ipc_memory_record),
		.fd_count = 1,
		.describe = describe_end,
		.adopt = adopt_end,
		.destroy = eventlink_port_gone,
};

IPC_KOBJECT_OPS(eventlink_ops);
