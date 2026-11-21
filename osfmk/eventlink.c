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

#include <errno.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

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
#define THREAD_ASSOCIATE_WILD         ((struct thread *)-1)
#define NO_WAITER                     UINT64_MAX

struct eventlink_waiter {
	_Atomic uint32_t woken;
	kern_return_t result;
};

struct eventlink {
	struct eventlink_pair *pair;
	struct thread *thread;
	uint64_t sync_count;
	uint64_t wait_count;
	struct eventlink_waiter *waiter;
};

struct eventlink_pair {
	struct eventlink ends[2];
	bool active;
	uint32_t references;
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
static kern_return_t associate(struct eventlink *end, struct thread *thread,
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
static kern_return_t signal_end(struct eventlink *end);
static struct eventlink *remote_end(struct eventlink *end);
static kern_return_t wait_end(
		struct eventlink *end, uint64_t *count, uint64_t deadline);
static void wake_end(struct eventlink *end, kern_return_t result);
static void release_pair(struct eventlink_pair *pair);
static uint64_t encode(uint64_t count, kern_return_t kr);

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

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void
create_routine(mach_msg_header_t *in, mach_msg_header_t *out)
{
	const struct create_request *request
			= (const struct create_request *)in;
	if (request->option != MELC_OPTION_NO_COPYIN) {
		((mig_reply_error_t *)out)->RetCode = KERN_INVALID_ARGUMENT;
		return;
	}

	struct eventlink_pair *pair = calloc(1, sizeof(*pair));
	pair->active = true;
	pair->references = 2;
	struct create_reply *reply = (struct create_reply *)out;
	reply->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
	reply->header.msgh_size = sizeof(*reply);
	reply->body.msgh_descriptor_count = 2;
	ipc_kobject_type_t type = IPC_KOBJECT_EVENTLINK;
	for (int i = 0; i < 2; i++) {
		struct eventlink *end = &pair->ends[i];
		end->pair = pair;
		end->wait_count = NO_WAITER;
		reply->pair[i] = (mach_msg_port_descriptor_t){
				.name = ipc_kobject_alloc(type, end),
				.disposition = MACH_MSG_TYPE_MOVE_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
}

static void
destroy_routine(mach_msg_header_t *in, mach_msg_header_t *out)
{
	struct eventlink *end = ipc_kobject_detach(
			in->msgh_local_port, IPC_KOBJECT_EVENTLINK);
	if (end != NULL) {
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
			held_end(in->msgh_local_port), thread, request);
}

static kern_return_t
associate(struct eventlink *end, struct thread *thread,
		const struct associate_request *request)
{
	if (end == NULL) {
		return KERN_TERMINATED;
	}

	bool on_wait = request->option == MELA_OPTION_ASSOCIATE_ON_WAIT;
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	if (request->copyin_addr_wait != 0 || request->copyin_mask_wait != 0
			|| request->copyin_addr_signal != 0
			|| request->copyin_mask_signal != 0
			|| (thread == NULL) != on_wait) {
		kr = KERN_INVALID_ARGUMENT;
	} else if (!end->pair->active) {
		kr = KERN_TERMINATED;
	} else if (end->thread != NULL) {
		kr = KERN_NAME_EXISTS;
	} else {
		end->thread = on_wait ? THREAD_ASSOCIATE_WILD : thread;
	}
	release_pair(end->pair);
	pthread_mutex_unlock(&lock);
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

	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	if (option != MELD_OPTION_NONE) {
		kr = KERN_INVALID_ARGUMENT;
	} else if (!end->pair->active) {
		kr = KERN_TERMINATED;
	} else if (end->thread == NULL) {
		kr = KERN_INVALID_ARGUMENT;
	} else {
		end->thread = NULL;
		wake_end(end, KERN_TERMINATED);
	}
	release_pair(end->pair);
	pthread_mutex_unlock(&lock);
	return kr;
}

uint64_t
eventlink_signal(mach_port_name_t name)
{
	struct eventlink *end;
	kern_return_t kr = held_trap_end(name, &end);
	if (kr == KERN_SUCCESS) {
		pthread_mutex_lock(&lock);
		kr = signal_end(remote_end(end));
		release_pair(end->pair);
		pthread_mutex_unlock(&lock);
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

	pthread_mutex_lock(&lock);
	struct eventlink_pair *pair = end->pair;
	kr = signal_wait_end(end, signal, &count, deadline, option);
	release_pair(pair);
	pthread_mutex_unlock(&lock);
	return encode(count, kr);
}

static kern_return_t
signal_wait_end(struct eventlink *end, bool signal, uint64_t *count,
		uint64_t deadline, uint32_t option)
{
	if (!end->pair->active) {
		return KERN_TERMINATED;
	}
	if (end->thread != thread_current()
			&& (end->thread != THREAD_ASSOCIATE_WILD
					|| end->wait_count != NO_WAITER)) {
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t kr = KERN_ALREADY_WAITING;
	if (*count < end->sync_count) {
		*count = end->sync_count;
		kr = KERN_SUCCESS;
	} else if (option & MELSW_OPTION_NO_WAIT) {
		*count = end->sync_count;
		kr = KERN_OPERATION_TIMED_OUT;
	} else {
		end->wait_count = *count;
	}
	if (signal) {
		signal_end(remote_end(end));
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
	pthread_mutex_lock(&lock);
	end->pair->references++;
	pthread_mutex_unlock(&lock);
}

void
eventlink_port_gone(void *kobject)
{
	struct eventlink *end = kobject;
	struct eventlink_pair *pair = end->pair;
	pthread_mutex_lock(&lock);
	pair->active = false;
	for (int i = 0; i < 2; i++) {
		wake_end(&pair->ends[i], KERN_TERMINATED);
	}
	release_pair(pair);
	pthread_mutex_unlock(&lock);
}

static kern_return_t
signal_end(struct eventlink *end)
{
	if (!end->pair->active) {
		return KERN_TERMINATED;
	}

	end->sync_count++;
	if (end->sync_count > end->wait_count) {
		wake_end(end, KERN_SUCCESS);
	}
	return KERN_SUCCESS;
}

static struct eventlink *
remote_end(struct eventlink *end)
{
	struct eventlink_pair *pair = end->pair;
	return &pair->ends[end == &pair->ends[0]];
}

static kern_return_t
wait_end(struct eventlink *end, uint64_t *count, uint64_t deadline)
{
	uint64_t old_count = end->sync_count;
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

	struct eventlink_waiter waiter = {0};
	end->waiter = &waiter;
	int error = signals_futex_wait(
			&waiter.woken, &lock, deadline != 0 ? &until : NULL);
	if (end->waiter == &waiter) {
		end->waiter = NULL;
	}
	kern_return_t kr = waiter.result;
	if (error == ETIMEDOUT) {
		kr = KERN_OPERATION_TIMED_OUT;
	} else if (error == EINTR) {
		kr = KERN_ABORTED;
	}
	*count = kr == KERN_SUCCESS ? *count + 1 : old_count;
	return kr;
}

static void
wake_end(struct eventlink *end, kern_return_t result)
{
	end->wait_count = NO_WAITER;
	if (end->waiter != NULL) {
		end->waiter->result = result;
		signals_futex_wake(&end->waiter->woken);
		end->waiter = NULL;
	}
}

static void
release_pair(struct eventlink_pair *pair)
{
	if (--pair->references == 0) {
		free(pair);
	}
}

static uint64_t
encode(uint64_t count, kern_return_t kr)
{
	return (count & EVENTLINK_SIGNAL_COUNT_MASK)
			| (uint64_t)kr << EVENTLINK_SIGNAL_ERROR_SHIFT;
}
