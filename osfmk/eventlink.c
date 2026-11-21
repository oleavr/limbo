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

#include <mach/mach.h>
#include <mach/mig.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include "eventlink.h"
#include "ipc.h"
#include "thread.h"

#define MELC_OPTION_NO_COPYIN         0x1
#define MELA_OPTION_ASSOCIATE_ON_WAIT 0x1
#define MELD_OPTION_NONE              0x0
#define THREAD_ASSOCIATE_WILD         ((struct thread *)-1)

struct eventlink {
	struct eventlink_pair *pair;
	struct thread *thread;
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
static struct eventlink *held_end(mach_port_name_t name);
static void hold_end(void *kobject);
static void release_pair(struct eventlink_pair *pair);

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
	}
	release_pair(end->pair);
	pthread_mutex_unlock(&lock);
	return kr;
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
	pthread_mutex_lock(&lock);
	end->pair->active = false;
	release_pair(end->pair);
	pthread_mutex_unlock(&lock);
}

static void
release_pair(struct eventlink_pair *pair)
{
	if (--pair->references == 0) {
		free(pair);
	}
}
