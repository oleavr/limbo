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
#include <stdlib.h>

#include "eventlink.h"
#include "ipc.h"

#define MELC_OPTION_NO_COPYIN 0x1

struct eventlink {
	struct eventlink_pair *pair;
};

struct eventlink_pair {
	struct eventlink ends[2];
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
#pragma pack(pop)

static void create_routine(mach_msg_header_t *in, mach_msg_header_t *out);
static void destroy_routine(mach_msg_header_t *in, mach_msg_header_t *out);

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

void
eventlink_port_gone(void *kobject)
{
	struct eventlink *end = kobject;
	struct eventlink_pair *pair = end->pair;
	pthread_mutex_lock(&lock);
	if (--pair->references == 0) {
		free(pair);
	}
	pthread_mutex_unlock(&lock);
}
