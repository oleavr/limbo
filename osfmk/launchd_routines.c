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

#include <stdint.h>

#include "launchd.h"
#include "osfmk/ipc.h"
#include "osfmk/mach_vm.h"
#include "xpc_service.h"

#define XPC_ENOTSUP 45

static void reply_with_errno(mach_msg_header_t *request, int64_t error);
static void reply_with_int64(
		mach_msg_header_t *request, const char *key, int64_t value);
static void release_request(mach_msg_header_t *request);
static void release_right(
		mach_port_name_t name, mach_msg_type_name_t disposition);

void
launchd_answer(mach_msg_header_t *request)
{
	reply_with_errno(request, XPC_ENOTSUP);
	release_request(request);
}

static void
reply_with_errno(mach_msg_header_t *request, int64_t error)
{
	reply_with_int64(request, "error", error);
}

static void
reply_with_int64(mach_msg_header_t *request, const char *key, int64_t value)
{
	uint8_t storage[128];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, storage, sizeof(storage));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_int64(&encoder, key, value);
	xpc_encoder_end(&encoder);

	xpc_launchd_reply(request, &encoder);
}

static void
release_request(mach_msg_header_t *request)
{
	if (!(request->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}
	mach_msg_body_t *body = (mach_msg_body_t *)(request + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);
	const uint8_t *end = (const uint8_t *)request + request->msgh_size;
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_type_descriptor_t *descriptor = (void *)cursor;
		if (descriptor->type == MACH_MSG_PORT_DESCRIPTOR) {
			mach_msg_port_descriptor_t *d = (void *)cursor;
			if (cursor + sizeof(*d) > end) {
				return;
			}
			release_right(d->name, d->disposition);
			cursor += sizeof(*d);
			continue;
		}
		mach_msg_ool_descriptor64_t *d = (void *)cursor;
		if (cursor + sizeof(*d) > end) {
			return;
		}
		if ((d->type == MACH_MSG_OOL_DESCRIPTOR
				    || d->type == MACH_MSG_OOL_VOLATILE_DESCRIPTOR)
				&& d->address != 0 && d->size != 0) {
			_kernelrpc_mach_vm_deallocate(0, d->address, d->size);
		} else if (d->type == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
			mach_msg_ool_ports_descriptor64_t *ports
					= (void *)cursor;
			mach_port_name_t *names = (void *)ports->address;
			for (mach_msg_size_t j = 0;
					names != NULL && j < ports->count;
					j++) {
				release_right(names[j], ports->disposition);
			}
			if (names != NULL && ports->count != 0) {
				_kernelrpc_mach_vm_deallocate(0, ports->address,
						ports->count * sizeof(*names));
			}
		} else if (d->type == MACH_MSG_GUARDED_PORT_DESCRIPTOR) {
			mach_msg_guarded_port_descriptor64_t *guarded
					= (void *)cursor;
			release_right(guarded->name, guarded->disposition);
		}
		cursor += sizeof(*d);
	}
}

static void
release_right(mach_port_name_t name, mach_msg_type_name_t disposition)
{
	if (!MACH_PORT_VALID(name)) {
		return;
	}
	if (disposition == MACH_MSG_TYPE_PORT_SEND) {
		ipc_port_mod_refs(name, MACH_PORT_RIGHT_SEND, -1);
	} else if (disposition == MACH_MSG_TYPE_PORT_SEND_ONCE) {
		ipc_port_mod_refs(name, MACH_PORT_RIGHT_SEND_ONCE, -1);
	} else if (disposition == MACH_MSG_TYPE_PORT_RECEIVE) {
		ipc_port_mod_refs(name, MACH_PORT_RIGHT_RECEIVE, -1);
	}
}
