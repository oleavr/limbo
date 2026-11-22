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

#include "libinfo.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipc.h"
#include "sysroot.h"
#include "xpc_serial.h"

#define LIBINFO_HANDSHAKE_ID 0x77303074
#define REPLY_MAX            4096

struct passwd_entry {
	char name[256];
	char passwd[256];
	uint64_t uid;
	uint64_t gid;
	char gecos[256];
	char dir[256];
	char shell[256];
};

static void adopt_request_port(mach_msg_header_t *request);
static bool passwd_lookup(uint64_t uid, struct passwd_entry *out);
static void reply_with_passwd(
		mach_msg_header_t *request, const struct passwd_entry *entry);
static void reply_empty(mach_msg_header_t *request);

bool
libinfo_is_handshake(mach_msg_id_t id)
{
	return id == LIBINFO_HANDSHAKE_ID;
}

void
libinfo_serve(mach_msg_header_t *request)
{
	if (libinfo_is_handshake(request->msgh_id)) {
		adopt_request_port(request);
		return;
	}

	struct xpc_object message;
	const char *rpc_name = xpc_serial_payload(request, &message)
			? xpc_serial_get_string(&message, "rpc_name")
			: NULL;
	uint64_t uid = 0;
	struct passwd_entry entry;
	if (rpc_name != NULL && strcmp(rpc_name, "getpwuid") == 0
			&& xpc_serial_get_int(&message, "uid", &uid)
			&& passwd_lookup(uid, &entry)) {
		reply_with_passwd(request, &entry);
	} else {
		reply_empty(request);
	}
}

static void
adopt_request_port(mach_msg_header_t *request)
{
	mach_msg_body_t *body = (mach_msg_body_t *)(request + 1);
	mach_msg_port_descriptor_t *descriptor
			= (mach_msg_port_descriptor_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		if (descriptor->disposition == MACH_MSG_TYPE_PORT_RECEIVE) {
			ipc_port_adopt_kotype(
					descriptor->name, IPC_KOBJECT_LIBINFO);
		}
		descriptor++;
	}
}

static bool
passwd_lookup(uint64_t uid, struct passwd_entry *out)
{
	char host_path[PATH_MAX];
	FILE *file = fopen(sysroot_host_path("/etc/passwd", 0, host_path), "r");
	if (file == NULL) {
		return false;
	}

	bool found = false;
	char line[1024];
	while (fgets(line, sizeof(line), file) != NULL) {
		if (line[0] == '#' || line[0] == '\n') {
			continue;
		}
		struct passwd_entry entry = {0};
		char *change = NULL;
		char *expire = NULL;
		if (sscanf(line,
				    "%255[^:]:%255[^:]:%llu:%llu:%255[^:]:%255["
				    "^:]:%255[^:\n]",
				    entry.name, entry.passwd,
				    (unsigned long long *)&entry.uid,
				    (unsigned long long *)&entry.gid,
				    entry.gecos, entry.dir, entry.shell)
				< 7) {
			continue;
		}
		(void)change;
		(void)expire;
		if (entry.uid == uid) {
			*out = entry;
			found = true;
			break;
		}
	}

	fclose(file);
	return found;
}

static void
reply_with_passwd(mach_msg_header_t *request, const struct passwd_entry *entry)
{
	uint8_t uuid[16] = {0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc,
			0xbb, 0xbb, 0xaa, 0xaa, entry->uid >> 24,
			entry->uid >> 16, entry->uid >> 8, entry->uid};

	uint8_t buffer[REPLY_MAX];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_string(&encoder, "pw_name", entry->name);
	xpc_encoder_string(&encoder, "pw_passwd", entry->passwd);
	xpc_encoder_int64(&encoder, "pw_uid", entry->uid);
	xpc_encoder_int64(&encoder, "pw_gid", entry->gid);
	xpc_encoder_string(&encoder, "pw_gecos", entry->gecos);
	xpc_encoder_string(&encoder, "pw_dir", entry->dir);
	xpc_encoder_string(&encoder, "pw_shell", entry->shell);
	xpc_encoder_uuid(&encoder, "pw_uuid", uuid);
	xpc_encoder_int64(&encoder, "rpc_version", 2);
	xpc_encoder_end(&encoder);
	xpc_serial_reply(request, &encoder, ipc_kernel_send);
}

static void
reply_empty(mach_msg_header_t *request)
{
	uint8_t buffer[64];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_end(&encoder);
	xpc_serial_reply(request, &encoder, ipc_kernel_send);
}
