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

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "broker.h"
#include "bsd/codesign.h"
#include "bsd/handler.h"
#include "bsd/process.h"
#include "launchd.h"
#include "launchd_engine.h"
#include "osfmk/bootstrap/bootstrap_defs.h"
#include "osfmk/broker_client.h"
#include "osfmk/ipc.h"
#include "osfmk/mach_vm.h"
#include "osfmk/xpc_bootstrap.h"
#include "sysroot.h"
#include "xpc_service.h"
#include "xpc_services.h"

enum xpc_routine {
	XPC_ROUTINE_LOOK_UP = 0x324,
	XPC_ROUTINE_CHECK_IN = 0x325,
	XPC_ROUTINE_LOOK_UP_LEGACY = 0xcf,
	XPC_ROUTINE_CHECK_IN_LEGACY = 0xce,
	XPC_ROUTINE_REGISTER = 0xcc,
	XPC_ROUTINE_BOOTSTRAP_PARENT = 0xcb,
	XPC_ROUTINE_UNCORK_PID_DOMAIN = 0x323,
	XPC_ROUTINE_COPY_BOOTSTRAP = 0x2c7,
	XPC_ROUTINE_SET_BOOTSTRAP = 0x2c6,
	XPC_ROUTINE_SERVICE_ENABLED = 0x32b,
	XPC_ROUTINE_LEGACY_LIST = 0x32f,
	XPC_ROUTINE_LOOK_UP_PER_USER = 0xd1,
	XPC_ROUTINE_SWITCH_TO_SESSION = 0x338,
	XPC_ROUTINE_SWAP = 0x12d,
	XPC_ROUTINE_KILL_SERVICE = 0x32c,
	XPC_ROUTINE_ADD_SERVICE_PATHS = 0x320,
	XPC_ROUTINE_REGISTER_SERVICE_PATHS = 0x322,
	XPC_ROUTINE_CREATE_SESSION = 0x337,
	XPC_ROUTINE_SPAWN = 0x331,
	XPC_ROUTINE_USER_SESSIONS_INFO = 0x388,
	XPC_ROUTINE_REBOOT = 0x335,
};

#define RB_HALT 0x8

#define XPC_ESRCH   3
#define XPC_EINVAL  22
#define XPC_ENOTSUP 45

#define CHECK_IN_SOCKETS 0x20

#define XPC_DOMAIN_SYSTEM 1
#define XPC_DOMAIN_USER   2

#define VPROC_GSK_MGR_UID         3
#define VPROC_GSK_MGR_PID         4
#define VPROC_GSK_IS_MANAGED      5
#define VPROC_GSK_MGR_NAME        6
#define VPROC_GSK_BASIC_KEEPALIVE 7
#define VPROC_GSK_PERUSER_SUSPEND 0x16
#define VPROC_GSK_PERUSER_RESUME  0x17
#define XPC_EPERM                 1

struct xpc_request {
	uint64_t type;
	char name[256];
	char stream[256];
	uint64_t outgsk;
	uint64_t ingsk;
	int64_t in;
	int64_t pid;
	uint64_t flags;
	bool has_uid;
	uint64_t uid;
	int64_t targetpid;
	int64_t signal;
	uint64_t token;
	int64_t subscriber_pid;
	uint64_t lookup_handle;
	bool has_handle;
	uint64_t handle;
	uint64_t cid;
	char label[256];
	bool has_instance;
	uint8_t instance[16];
	const uint8_t *descriptor;
	size_t descriptor_size;
};

struct xpc_cursor {
	const uint8_t *position;
	const uint8_t *end;
};

struct caller {
	pid_t pid;
	uid_t euid;
};

#define REGISTER_PER_PID 0x1

#define ANSWER_MAX (16 * 1024)

static void parse_request(
		const void *body, uint32_t length, struct xpc_request *out);
static uint32_t read_u32(struct xpc_cursor *cursor);
static const char *read_key(struct xpc_cursor *cursor);
static void cursor_align(struct xpc_cursor *cursor);
static bool read_member(struct xpc_cursor *cursor, const char *name,
		struct xpc_request *out);
static uint64_t read_u64(struct xpc_cursor *cursor);
static bool reply_swap(mach_msg_header_t *request, uint64_t outgsk,
		uint64_t ingsk, int64_t in);
static bool forward_to_launchd(mach_msg_header_t *request);
static void reply_empty(mach_msg_header_t *request);
static void reply_with_errno(mach_msg_header_t *request, int64_t error);
static void reply_with_int64(
		mach_msg_header_t *request, const char *key, int64_t value);
static bool job_of_pid(int64_t pid, char *label, size_t label_size, char *plist,
		size_t plist_size);
static char *launchd_control(
		const char *const *words, size_t count, uint32_t *status);
static pid_t caller_pid(void);
static bool reply_service_enabled(mach_msg_header_t *request, const char *name);
static bool reply_legacy_list(mach_msg_header_t *request, const char *name);
static uid_t caller_euid(void);
static bool reboot_system(mach_msg_header_t *request, uint64_t flags);
static bool spawn(mach_msg_header_t *request, const char *label);
static bool check_in_sockets(mach_msg_header_t *request, const char *name);
static void reply_with_port(mach_msg_header_t *request, mach_port_name_t port,
		mach_msg_type_name_t disposition, bool with_metadata);
static void reply_with_named_port(mach_msg_header_t *request, const char *key,
		mach_port_name_t port, mach_msg_type_name_t disposition,
		bool with_metadata);
static bool create_session(mach_msg_header_t *request, bool login_window);
static mach_msg_header_t *ask_launchd(const mach_msg_header_t *request);
static void release_request(mach_msg_header_t *request);
static void release_right(
		mach_port_name_t name, mach_msg_type_name_t disposition);
static bool is_message(mach_msg_id_t id);
static bool xpc_bootstrap_serve_port(mach_msg_header_t *request, void *kobject);
static bool serve_port(void *kobject, mach_msg_header_t *request, bool remote);
static uint32_t user_domain(int64_t uid);
static bool reply_per_user_bootstrap(mach_msg_header_t *request, int64_t uid);
static bool serve(mach_msg_header_t *request);
static bool look_up(mach_msg_header_t *request, const char *name,
		const uint8_t *instance, uint64_t domain_type,
		int64_t targetpid, int64_t target_uid);
static mach_port_name_t xpc_service_look_up_or_start(
		const char *name, const uint8_t *instance);
static bool register_name(
		mach_msg_header_t *request, const char *name, uint64_t flags);
static bool check_in(
		mach_msg_header_t *request, const char *name, uint64_t flags);
static bool reply_bootstrap(mach_msg_header_t *request);
static bool set_bootstrap(mach_msg_header_t *request, const char *name);
static void reply_user_sessions_info(mach_msg_header_t *request);

static __thread const struct caller *answering;

static __thread int64_t port_domain = -1;

static const struct ipc_kobject_ops bootstrap_port_ops = {
		.type = IPC_KOBJECT_BOOTSTRAP,
		.serve = serve_port,
};

IPC_KOBJECT_OPS(bootstrap_port_ops);

static const struct xpc_bootstrap_routines launchd_routines = {
		.is_message = is_message,
		.serve = serve,
};

XPC_BOOTSTRAP_ROUTINES(launchd_routines);

void
launchd_answer(mach_msg_header_t *request)
{
	const mach_msg_audit_trailer_t *trailer = (const mach_msg_audit_trailer_t
					*)((const uint8_t *)request
			+ request->msgh_size);
	const struct caller caller = {
			.pid = (pid_t)trailer->msgh_audit.val[5],
			.euid = (uid_t)trailer->msgh_audit.val[1],
	};
	struct xpc_request parsed = {0};
	parse_request(request + 1, request->msgh_size - sizeof(*request),
			&parsed);
	answering = &caller;
	bool answered = false;
	switch (request->msgh_id & 0xffff) {
	case XPC_ROUTINE_SWAP:
		answered = reply_swap(request, parsed.outgsk, parsed.ingsk,
				parsed.in);
		break;
	case XPC_ROUTINE_SERVICE_ENABLED:
		answered = reply_service_enabled(request, parsed.name);
		break;
	case XPC_ROUTINE_LEGACY_LIST:
		answered = reply_legacy_list(request, parsed.name);
		break;
	case XPC_ROUTINE_REBOOT:
		answered = reboot_system(request, parsed.flags);
		break;
	case XPC_ROUTINE_SPAWN:
		answered = spawn(request, parsed.label);
		break;
	case XPC_ROUTINE_CHECK_IN:
	case XPC_ROUTINE_CHECK_IN_LEGACY:
		if (parsed.flags & CHECK_IN_SOCKETS) {
			answered = check_in_sockets(request, parsed.name);
		}
		break;
	case XPC_ROUTINE_CREATE_SESSION:
		answered = create_session(request,
				parsed.has_uid
						&& (uid_t)parsed.uid
								== (uid_t)-1);
		break;
	}
	answering = NULL;
	if (!answered) {
		reply_with_errno(request, XPC_ENOTSUP);
	}
	release_request(request);
}

static void
parse_request(const void *body, uint32_t length, struct xpc_request *out)
{
	const uint8_t *scan = body;
	const uint8_t *limit = (const uint8_t *)body + length;
	while (scan + sizeof(uint32_t) <= limit) {
		uint32_t word;
		memcpy(&word, scan, sizeof(word));
		if (word == XPC_SERIAL_MAGIC) {
			break;
		}
		scan += sizeof(uint32_t);
	}

	struct xpc_cursor cursor = {
			.position = scan,
			.end = limit,
	};
	if (read_u32(&cursor) != XPC_SERIAL_MAGIC) {
		return;
	}
	read_u32(&cursor);
	if (read_u32(&cursor) != XPC_SERIAL_DICTIONARY) {
		return;
	}
	read_u32(&cursor);
	uint32_t count = read_u32(&cursor);
	for (uint32_t i = 0; i != count; i++) {
		const char *key = read_key(&cursor);
		if (!read_member(&cursor, key, out)) {
			return;
		}
	}
}

static uint32_t
read_u32(struct xpc_cursor *cursor)
{
	uint32_t value;
	memcpy(&value, cursor->position, sizeof(value));
	cursor->position += sizeof(value);
	return value;
}

static const char *
read_key(struct xpc_cursor *cursor)
{
	const char *key = (const char *)cursor->position;
	cursor->position += strlen(key) + 1;
	cursor_align(cursor);
	return key;
}

static void
cursor_align(struct xpc_cursor *cursor)
{
	while (((uintptr_t)cursor->position & 3) != 0) {
		cursor->position++;
	}
}

static bool
read_member(struct xpc_cursor *cursor, const char *name,
		struct xpc_request *out)
{
	const uint8_t *start = cursor->position;
	uint32_t type = read_u32(cursor);
	switch (type) {
	case XPC_SERIAL_UINT64:
	case XPC_SERIAL_INT64: {
		uint64_t value = read_u64(cursor);
		if (strcmp(name, "type") == 0) {
			out->type = value;
		} else if (strcmp(name, "outgsk") == 0) {
			out->outgsk = value + 1;
		} else if (strcmp(name, "ingsk") == 0) {
			out->ingsk = value + 1;
		} else if (strcmp(name, "in") == 0) {
			out->in = (int64_t)value;
		} else if (strcmp(name, "pid") == 0) {
			out->pid = (int64_t)value;
		} else if (strcmp(name, "flags") == 0) {
			out->flags = value;
		} else if (strcmp(name, "uid") == 0) {
			out->has_uid = true;
			out->uid = value;
		} else if (strcmp(name, "targetpid") == 0) {
			out->targetpid = (int64_t)value;
		} else if (strcmp(name, "token") == 0) {
			out->token = value;
		} else if (strcmp(name, "subscriber-pid") == 0) {
			out->subscriber_pid = (int64_t)value;
		} else if (strcmp(name, "lookup-handle") == 0) {
			out->lookup_handle = value;
		} else if (strcmp(name, "handle") == 0) {
			out->has_handle = true;
			out->handle = value;
		} else if (strcmp(name, "cid") == 0) {
			out->cid = value;
		} else if (strcmp(name, "signal") == 0) {
			out->signal = (int64_t)value;
		}
		return true;
	}
	case XPC_SERIAL_STRING:
	case XPC_SERIAL_DATA: {
		uint32_t length = read_u32(cursor);
		if (type == XPC_SERIAL_STRING && strcmp(name, "name") == 0) {
			strncpy(out->name, (const char *)cursor->position,
					sizeof(out->name) - 1);
		} else if (type == XPC_SERIAL_STRING
				&& strcmp(name, "stream") == 0) {
			strncpy(out->stream, (const char *)cursor->position,
					sizeof(out->stream) - 1);
		} else if (type == XPC_SERIAL_STRING
				&& strcmp(name, "label") == 0) {
			strncpy(out->label, (const char *)cursor->position,
					sizeof(out->label) - 1);
		}
		cursor->position += length;
		cursor_align(cursor);
		return true;
	}
	case XPC_SERIAL_BOOL:
		read_u32(cursor);
		return true;
	case XPC_SERIAL_DOUBLE:
		read_u64(cursor);
		return true;
	case XPC_SERIAL_UUID:
		if (strcmp(name, "instance") == 0) {
			static const uint8_t none[16];
			memcpy(out->instance, cursor->position, 16);
			out->has_instance
					= memcmp(out->instance, none, 16) != 0;
		}
		cursor->position += 16;
		return true;
	case XPC_SERIAL_NULL:
	case XPC_SERIAL_MACH_SEND:
	case XPC_SERIAL_MACH_RECV:
	case XPC_SERIAL_MACH_SEND_ONCE:
		return true;
	case XPC_SERIAL_DICTIONARY:
	case XPC_SERIAL_ARRAY: {
		uint32_t size = read_u32(cursor);
		const uint8_t *end = cursor->position + size;
		if (type == XPC_SERIAL_DICTIONARY
				&& strcmp(name, "paths") == 0) {
			uint32_t count = read_u32(cursor);
			struct xpc_request ignored = {0};
			for (uint32_t i = 0; i != count; i++) {
				const char *key = read_key(cursor);
				xpc_services_add_binary(key);
				if (!read_member(cursor, key, &ignored)) {
					break;
				}
			}
		}
		if (type == XPC_SERIAL_DICTIONARY
				&& strcmp(name, "descriptor") == 0) {
			out->descriptor = start;
			out->descriptor_size = end - start;
		}
		cursor->position = end;
		return true;
	}
	default:
		return false;
	}
}

static uint64_t
read_u64(struct xpc_cursor *cursor)
{
	uint64_t value;
	memcpy(&value, cursor->position, sizeof(value));
	cursor->position += sizeof(value);
	return value;
}

static bool
reply_swap(mach_msg_header_t *request, uint64_t outgsk, uint64_t ingsk,
		int64_t in)
{
	if (outgsk == 0 && ingsk == VPROC_GSK_BASIC_KEEPALIVE + 1) {
		if (answering != NULL) {
			jobs_set_keepalive(answering->pid, in != 0);
		} else if (forward_to_launchd(request)) {
			return true;
		}
		reply_empty(request);
		return true;
	}
	if (outgsk == 0
			&& (ingsk == VPROC_GSK_PERUSER_SUSPEND + 1
					|| ingsk
							== VPROC_GSK_PERUSER_RESUME
									+ 1)) {
		if (geteuid() != 0) {
			reply_with_errno(request, XPC_EPERM);
		} else {
			reply_empty(request);
		}
		return true;
	}
	if (outgsk != VPROC_GSK_MGR_NAME + 1 && outgsk != VPROC_GSK_MGR_UID + 1
			&& outgsk != VPROC_GSK_MGR_PID + 1
			&& outgsk != VPROC_GSK_IS_MANAGED + 1) {
		return false;
	}
	if (outgsk == VPROC_GSK_IS_MANAGED + 1 && forward_to_launchd(request)) {
		return true;
	}
	bool system = broker_client_domain() == BROKER_DOMAIN_SYSTEM;
	uint8_t storage[128];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, storage, sizeof(storage));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	switch (outgsk - 1) {
	case VPROC_GSK_MGR_NAME: {
		const char *type = getenv(LIMBO_LAUNCHD_SESSION_TYPE_ENV);
		xpc_encoder_string(&encoder, "out",
				type != NULL ? type
						: system ? "System"
							 : "Aqua");
		break;
	}
	case VPROC_GSK_MGR_UID:
		xpc_encoder_int64(&encoder, "out", system ? 0 : geteuid());
		break;
	case VPROC_GSK_MGR_PID:
		xpc_encoder_int64(&encoder, "out", 1);
		break;
	case VPROC_GSK_IS_MANAGED: {
		char label[256], plist[PATH_MAX];
		xpc_encoder_int64(&encoder, "out",
				job_of_pid(caller_pid(), label, sizeof(label),
						plist, sizeof(plist)));
		break;
	}
	}
	xpc_encoder_end(&encoder);

	xpc_launchd_reply(request, &encoder);
	return true;
}

static bool
forward_to_launchd(mach_msg_header_t *request)
{
	if (answering != NULL) {
		return false;
	}
	uint64_t port = broker_client_launchd_port();
	if (port == 0) {
		return false;
	}
	mach_port_name_t launchd = ipc_names_send_right(port);
	if (!MACH_PORT_VALID(launchd)) {
		return false;
	}
	mach_msg_header_t *message = malloc(request->msgh_size);
	memcpy(message, request, request->msgh_size);
	message->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND,
			MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0,
			request->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	message->msgh_remote_port = launchd;
	message->msgh_local_port = request->msgh_remote_port;
	message->msgh_voucher_port = MACH_PORT_NULL;
	mach_msg_return_t mr = ipc_kernel_send(message);
	free(message);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_port_deallocate(launchd);
	}
	return mr == MACH_MSG_SUCCESS;
}

static void
reply_empty(mach_msg_header_t *request)
{
	uint8_t storage[64];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, storage, sizeof(storage));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_end(&encoder);

	xpc_launchd_reply(request, &encoder);
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

static bool
job_of_pid(int64_t pid, char *label, size_t label_size, char *plist,
		size_t plist_size)
{
	char number[24];
	snprintf(number, sizeof(number), "%lld", (long long)pid);
	const char *const words[] = {"pid", number};
	uint32_t status = 0;
	char *text = launchd_control(words, 2, &status);
	char *tab = text != NULL && status == 0 ? strchr(text, '\t') : NULL;
	if (tab != NULL) {
		*tab++ = '\0';
		tab[strcspn(tab, "\n")] = '\0';
		snprintf(label, label_size, "%s", text);
		snprintf(plist, plist_size, "%s", tab);
	}
	free(text);
	return tab != NULL;
}

static char *
launchd_control(const char *const *words, size_t count, uint32_t *status)
{
	if (answering == NULL) {
		*status = 1;
		return NULL;
	}
	char *argv[8];
	size_t argc = 0;
	for (; argc != count && argc != 8; argc++) {
		argv[argc] = strdup(words[argc]);
	}
	char *text = launchd_command(argv, argc, answering->euid, status);
	for (size_t i = 0; i != argc; i++) {
		free(argv[i]);
	}
	return text;
}

static pid_t
caller_pid(void)
{
	return answering != NULL ? answering->pid : getpid();
}

static bool
reply_service_enabled(mach_msg_header_t *request, const char *name)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	const char *const words[] = {"print", name};
	uint32_t status = 1;
	free(name[0] != '\0' ? launchd_control(words, 2, &status) : NULL);
	bool loaded = status == 0;
	uint8_t buffer[256];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_bool(&encoder, "loaded", loaded);
	xpc_encoder_bool(&encoder, "enabled", true);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	return true;
}

static bool
reply_legacy_list(mach_msg_header_t *request, const char *name)
{
	if (name[0] != '\0') {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	if (forward_to_launchd(request)) {
		return true;
	}
	const char *const words[] = {"list"};
	uint32_t status = 1;
	char *list = launchd_control(words, 1, &status);
	uint32_t capacity = 65536;
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, capacity);
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_begin_dictionary(&encoder, "services");
	bool root = caller_euid() == 0;
	for (char *line = list, *next; line != NULL && *line != '\0';
			line = next) {
		next = strchr(line, '\n');
		if (next != NULL) {
			*next++ = '\0';
		}
		char pid[16], exit_status[16], state[32], job[256];
		if (sscanf(line, "%15s\t%15s\t%31s\t%255s", pid, exit_status,
				    state, job) != 4
				|| strcmp(pid, "PID") == 0) {
			continue;
		}
		char *label = strchr(job, '/');
		if (label == NULL || strchr(label, '#') != NULL) {
			continue;
		}
		*label++ = '\0';
		bool mine = root ? strcmp(job, "system") == 0
				 : strcmp(job, "gui") == 0
						|| strcmp(job, "user") == 0;
		if (!mine || encoder.offset + 512 > capacity) {
			continue;
		}
		int64_t wait_status = 0;
		if (strcmp(exit_status, "-") != 0) {
			int shell = atoi(exit_status);
			wait_status = shell > 128 ? shell - 128
						  : (int64_t)shell << 8;
		}
		xpc_encoder_begin_dictionary(&encoder, label);
		xpc_encoder_int64(&encoder, "pid",
				strcmp(pid, "-") == 0 ? 0 : atoi(pid));
		xpc_encoder_int64(&encoder, "status", wait_status);
		xpc_encoder_end_dictionary(&encoder);
	}
	xpc_encoder_end_dictionary(&encoder);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	free(buffer);
	free(list);
	return true;
}

static uid_t
caller_euid(void)
{
	return answering != NULL ? answering->euid : geteuid();
}

static bool
reboot_system(mach_msg_header_t *request, uint64_t flags)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	if (caller_euid() != 0) {
		reply_with_errno(request, XPC_EPERM);
		return true;
	}
	reply_empty(request);
	const char *const words[]
			= {(flags & RB_HALT) != 0 ? "halt" : "reboot"};
	uint32_t status = 0;
	free(launchd_control(words, 1, &status));
	return true;
}

static bool
spawn(mach_msg_header_t *request, const char *label)
{
	static const char *const system_domains[] = {"system", "gui", "user"};
	static const char *const user_domains[] = {"gui", "user"};
	if (forward_to_launchd(request)) {
		return true;
	}
	bool system = caller_euid() < 500;
	const char *const *domains = system ? system_domains : user_domains;
	size_t domain_count = system ? 3 : 2;

	long pid = 0;
	for (size_t i = 0; i != domain_count && pid <= 0; i++) {
		char name[300];
		snprintf(name, sizeof(name), "%s/%s", domains[i], label);
		const char *const words[] = {"start", name};
		uint32_t status = 0;
		char *text = launchd_control(words, 2, &status);
		if (text != NULL && status == 0) {
			pid = strtol(text, NULL, 10);
		}
		free(text);
	}
	if (pid <= 0) {
		reply_with_errno(request, XPC_ESRCH);
	} else {
		reply_with_int64(request, "pid", pid);
	}
	return true;
}

static bool
check_in_sockets(mach_msg_header_t *request, const char *name)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	int fds[8];
	size_t count = answering != NULL
			? jobs_sockets(answering->pid, name, fds, 8)
			: 0;
	if (count == 0) {
		reply_with_errno(request, ENOENT);
		return true;
	}

	uint8_t storage[256];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, storage, sizeof(storage));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_begin_array(&encoder, "port");
	for (size_t i = 0; i != count; i++) {
		xpc_encoder_fd(&encoder, NULL, ipc_fileport_alloc(fds[i]));
	}
	xpc_encoder_end(&encoder);
	xpc_encoder_end(&encoder);
	xpc_launchd_reply(request, &encoder);
	return true;
}

static void
reply_with_port(mach_msg_header_t *request, mach_port_name_t port,
		mach_msg_type_name_t disposition, bool with_metadata)
{
	reply_with_named_port(
			request, "port", port, disposition, with_metadata);
}

static void
reply_with_named_port(mach_msg_header_t *request, const char *key,
		mach_port_name_t port, mach_msg_type_name_t disposition,
		bool with_metadata)
{
	uint8_t storage[256];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, storage, sizeof(storage));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	if (with_metadata) {
		xpc_encoder_uint64(&encoder, "rec_execcnt", 10);
		xpc_encoder_uint64(&encoder, "req_pid", getpid());
	}
	xpc_encoder_port(&encoder, key, port, disposition);
	xpc_encoder_end(&encoder);
	xpc_launchd_reply(request, &encoder);
}

static bool
create_session(mach_msg_header_t *request, bool login_window)
{
	if (login_window && answering != NULL) {
		static const char *const words[] = {"loginwindow"};
		uint32_t status = 0;
		free(launchd_control(words, 1, &status));
		reply_empty(request);
		return true;
	}
	if (login_window) {
		free(ask_launchd(request));
		reply_with_port(request, ipc_bootstrap_self(),
				MACH_MSG_TYPE_MOVE_SEND, false);
		return true;
	}

	if (forward_to_launchd(request)) {
		return true;
	}
	static const char *const words[] = {"login"};
	uint32_t status = 0;
	char *text = launchd_control(words, 1, &status);
	if (text == NULL || status != 0) {
		reply_with_errno(request, XPC_ENOTSUP);
	} else {
		reply_empty(request);
	}
	free(text);
	return true;
}

static mach_msg_header_t *
ask_launchd(const mach_msg_header_t *request)
{
	if (answering != NULL) {
		return NULL;
	}
	uint64_t port = broker_client_launchd_port();
	if (port == 0) {
		return NULL;
	}
	mach_port_name_t launchd = ipc_names_send_right(port);
	mach_port_name_t reply;
	if (!MACH_PORT_VALID(launchd)) {
		return NULL;
	}
	if (ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, &reply)
			!= KERN_SUCCESS) {
		ipc_port_deallocate(launchd);
		return NULL;
	}
	mach_msg_size_t size = request->msgh_size > ANSWER_MAX
			? request->msgh_size
			: ANSWER_MAX;
	mach_msg_header_t *message = malloc(size);
	memcpy(message, request, request->msgh_size);
	message->msgh_bits = MACH_MSGH_BITS(
			MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	message->msgh_remote_port = launchd;
	message->msgh_local_port = reply;
	message->msgh_voucher_port = MACH_PORT_NULL;
	mach_msg_return_t mr = ipc_mach_msg_kernel(message,
			MACH64_SEND_MSG | MACH64_RCV_MSG, request->msgh_size,
			size, reply, 0);
	ipc_port_mod_refs(reply, MACH_PORT_RIGHT_RECEIVE, -1);
	if (mr >= MACH_SEND_IN_PROGRESS && mr < MACH_RCV_IN_PROGRESS) {
		ipc_port_deallocate(launchd);
	}
	if (mr != MACH_MSG_SUCCESS) {
		free(message);
		return NULL;
	}
	return message;
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

static bool
is_message(mach_msg_id_t id)
{
	return (id & 0x50000000) != 0;
}

static bool
xpc_bootstrap_serve_port(mach_msg_header_t *request, void *kobject)
{
	int64_t outer = port_domain;
	port_domain = kobject != NULL ? (int64_t)(uintptr_t)kobject - 1 : -1;
	bool served = xpc_bootstrap_serve(request);
	port_domain = outer;
	return served;
}

static bool
serve_port(void *kobject, mach_msg_header_t *request, bool remote)
{
	return xpc_bootstrap_is_message(request->msgh_id)
			&& xpc_bootstrap_serve_port(request, kobject);
}

static uint32_t
user_domain(int64_t uid)
{
	return uid == 0 ? BROKER_DOMAIN_SYSTEM
			: uid >= 500 ? BROKER_DOMAIN_USER
				     : broker_domain_account((uint32_t)uid);
}

static bool
reply_per_user_bootstrap(mach_msg_header_t *request, int64_t uid)
{
	if (uid < 0 || (geteuid() != 0 && (uid_t)uid != geteuid())) {
		reply_with_errno(request, XPC_EPERM);
		return true;
	}
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	static struct {
		uint32_t domain;
		mach_port_name_t port;
	} ports[16];
	static size_t count;
	uint32_t domain = user_domain(uid);
	pthread_mutex_lock(&lock);
	mach_port_name_t port = MACH_PORT_NULL;
	for (size_t i = 0; i < count; i++) {
		if (ports[i].domain == domain) {
			port = ports[i].port;
		}
	}
	if (port == MACH_PORT_NULL && count < 16) {
		port = ipc_kobject_alloc(IPC_KOBJECT_BOOTSTRAP,
				(void *)(uintptr_t)(domain + 1));
		ports[count].domain = domain;
		ports[count++].port = port;
	}
	pthread_mutex_unlock(&lock);
	if (port == MACH_PORT_NULL) {
		reply_with_errno(request, XPC_EINVAL);
		return true;
	}
	reply_with_port(request, port, MACH_MSG_TYPE_MAKE_SEND, true);
	return true;
}

static bool
serve(mach_msg_header_t *request)
{
	struct xpc_request parsed = {0};
	parse_request(request + 1, request->msgh_size - sizeof(*request),
			&parsed);

	switch (request->msgh_id & 0xffff) {
	case XPC_ROUTINE_LOOK_UP:
	case XPC_ROUTINE_LOOK_UP_LEGACY:
		return look_up(request, parsed.name,
				parsed.has_instance ? parsed.instance : NULL,
				parsed.type, parsed.targetpid,
				parsed.has_handle ? (int64_t)parsed.handle
						  : -1);
	case XPC_ROUTINE_LOOK_UP_PER_USER:
		if (!parsed.has_uid) {
			reply_with_errno(request, XPC_EINVAL);
			return true;
		}
		if (parsed.name[0] == '\0') {
			return reply_per_user_bootstrap(
					request, (int64_t)parsed.uid);
		}
		return look_up(request, parsed.name, NULL, XPC_DOMAIN_USER, 0,
				(int64_t)parsed.uid);
	case XPC_ROUTINE_REGISTER:
		return register_name(request, parsed.name, parsed.flags);
	case XPC_ROUTINE_CHECK_IN:
	case XPC_ROUTINE_CHECK_IN_LEGACY:
		if (parsed.flags & CHECK_IN_SOCKETS) {
			return check_in_sockets(request, parsed.name);
		}
		return check_in(request, parsed.name, parsed.flags);
	case XPC_ROUTINE_KILL_SERVICE: {
		if (xpc_services_kill(parsed.name, (int)parsed.signal) != 0) {
			reply_with_errno(request, XPC_ESRCH);
		} else {
			reply_empty(request);
		}
		return true;
	}
	case XPC_ROUTINE_ADD_SERVICE_PATHS:
	case XPC_ROUTINE_REGISTER_SERVICE_PATHS:
		reply_empty(request);
		return true;
	case XPC_ROUTINE_BOOTSTRAP_PARENT:
		reply_with_named_port(request, "parent", ipc_bootstrap_self(),
				MACH_MSG_TYPE_MOVE_SEND, false);
		return true;
	case XPC_ROUTINE_COPY_BOOTSTRAP:
		return reply_bootstrap(request);
	case XPC_ROUTINE_SET_BOOTSTRAP:
		return set_bootstrap(request, parsed.name);
	case XPC_ROUTINE_SERVICE_ENABLED:
		return reply_service_enabled(request, parsed.name);
	case XPC_ROUTINE_SWITCH_TO_SESSION:
		reply_empty(request);
		return true;
	case XPC_ROUTINE_LEGACY_LIST:
		return reply_legacy_list(request, parsed.name);
	case XPC_ROUTINE_UNCORK_PID_DOMAIN:
		reply_empty(request);
		return true;
	case XPC_ROUTINE_CREATE_SESSION:
		return create_session(request,
				parsed.has_uid
						&& (uid_t)parsed.uid
								== (uid_t)-1);
	case XPC_ROUTINE_SPAWN:
		return spawn(request, parsed.label);
	case XPC_ROUTINE_USER_SESSIONS_INFO:
		if (!codesign_embedded()) {
			break;
		}
		reply_user_sessions_info(request);
		return true;
	case XPC_ROUTINE_REBOOT:
		return reboot_system(request, parsed.flags);
	case XPC_ROUTINE_SWAP:
		if (reply_swap(request, parsed.outgsk, parsed.ingsk,
				    parsed.in)) {
			return true;
		}
	default:
		break;
	}
	return false;
}

static bool
look_up(mach_msg_header_t *request, const char *name, const uint8_t *instance,
		uint64_t domain_type, int64_t targetpid, int64_t target_uid)
{
	char per_pid[300];
	if (targetpid > 0 && targetpid != getpid()) {
		xpc_services_host_name(name, (pid_t)targetpid, per_pid,
				sizeof(per_pid));
		name = per_pid;
	}
	uint32_t domain = port_domain >= 0 ? (uint32_t)port_domain
			: (domain_type == XPC_DOMAIN_SYSTEM)
			? BROKER_DOMAIN_SYSTEM
			: broker_client_domain();
	if (domain_type == XPC_DOMAIN_USER && target_uid >= 0
			&& (geteuid() == 0 || (uid_t)target_uid == geteuid())) {
		domain = user_domain(target_uid);
	}
	if (strcmp(name, "com.apple.system.opendirectoryd.libinfo") == 0) {
		mach_port_name_t real;
		names_look_up_registered(name, BROKER_DOMAIN_SYSTEM, &real);
		reply_with_port(request,
				real != MACH_PORT_NULL
						? real
						: xpc_service_stand_in(name),
				MACH_MSG_TYPE_MOVE_SEND, true);
		return true;
	}
	if (instance != NULL && name != per_pid
			&& !xpc_services_multiple_instances(name)) {
		static const char digits[] = "0123456789ABCDEF";
		char named[300];
		int at = snprintf(named, sizeof(named), "%s#", name);
		for (int i = 0; i != 16 && at < (int)sizeof(named) - 3; i++) {
			if (i == 4 || i == 6 || i == 8 || i == 10) {
				named[at++] = '-';
			}
			named[at++] = digits[instance[i] >> 4];
			named[at++] = digits[instance[i] & 0xf];
		}
		named[at] = '\0';
		mach_port_name_t own;
		names_look_up_instance(named, domain, &own);
		if (own != MACH_PORT_NULL) {
			reply_with_port(request, own, MACH_MSG_TYPE_MOVE_SEND,
					true);
			return true;
		}
	}
	mach_port_name_t service;
	xpc_service_look_up_in(name, domain, &service);
	if (service == MACH_PORT_NULL && targetpid <= 0) {
		xpc_services_host_name(
				name, getpid(), per_pid, sizeof(per_pid));
		xpc_service_look_up_in(per_pid, domain, &service);
	}
	if (service == MACH_PORT_NULL && name != per_pid) {
		service = xpc_service_look_up_or_start(name, instance);
	}
	if (service == MACH_PORT_NULL) {
		reply_with_errno(request, BOOTSTRAP_UNKNOWN_SERVICE);
	} else {
		reply_with_port(request, service, MACH_MSG_TYPE_MOVE_SEND,
				true);
	}
	return true;
}

static mach_port_name_t
xpc_service_look_up_or_start(const char *name, const uint8_t *instance)
{
	if (instance != NULL && !xpc_services_multiple_instances(name)) {
		instance = NULL;
	}
	char host_name[300];
	xpc_services_instance_name(
			name, getpid(), instance, host_name, sizeof(host_name));
	mach_port_name_t service;
	xpc_service_look_up(host_name, &service);
	bool shared = false;
	pid_t pid = 0;
	if (service != MACH_PORT_NULL
			|| !xpc_services_start(name, instance, &shared, &pid)) {
		return service;
	}
	int process = (pid > 0) ? (int)syscall(SYS_pidfd_open, pid, 0) : -1;
	bool gone = pid > 0 && process == -1 && errno == ESRCH;
	for (int i = 0; i < 300 && service == MACH_PORT_NULL; i++) {
		bool exited = gone;
		if (gone) {
		} else if (process != -1) {
			struct pollfd fd = {.fd = process, .events = POLLIN};
			exited = poll(&fd, 1, 50) == 1;
		} else {
			usleep(50000);
		}
		xpc_service_look_up(shared ? name : host_name, &service);
		if (exited && service == MACH_PORT_NULL) {
			fprintf(stderr,
					"launchd: XPC service %s exited before "
					"it checked in\n",
					name);
			break;
		}
	}
	if (process != -1) {
		close(process);
	}
	return service;
}

static bool
register_name(mach_msg_header_t *request, const char *name, uint64_t flags)
{
	mach_port_name_t port = MACH_PORT_NULL;
	if (request->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_body_t *body = (mach_msg_body_t *)(request + 1);
		mach_msg_port_descriptor_t *descriptors = (void *)(body + 1);
		for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count;
				i++) {
			if (descriptors[i].type == MACH_MSG_PORT_DESCRIPTOR
					&& descriptors[i].name
							!= ipc_bootstrap_self()) {
				port = descriptors[i].name;
			}
		}
	}
	if (port == MACH_PORT_NULL || name[0] == '\0') {
		reply_with_errno(request, EINVAL);
		return true;
	}
	char per_pid[300];
	if (flags & REGISTER_PER_PID) {
		xpc_services_host_name(
				name, getpid(), per_pid, sizeof(per_pid));
		name = per_pid;
	}
	kern_return_t kr = names_register(name, port);
	if (kr != KERN_SUCCESS) {
		reply_with_errno(request, kr);
	} else {
		reply_empty(request);
	}
	return true;
}

static bool
check_in(mach_msg_header_t *request, const char *name, uint64_t flags)
{
	char host_name[300];
	const char *service_name = xpc_services_check_in_name(
			name, host_name, sizeof(host_name));
	mach_port_name_t service;
	kern_return_t kr = names_check_in(service_name, &service);
	if (kr == BOOTSTRAP_NOT_PRIVILEGED && xpc_services_is_service(name)) {
		_exit(0);
	}
	if (kr != KERN_SUCCESS) {
		reply_with_errno(request, kr);
		return true;
	}
	reply_with_port(request, service, MACH_MSG_TYPE_MOVE_RECEIVE, false);
	return true;
}

static bool
reply_bootstrap(mach_msg_header_t *request)
{
	size_t capacity = 0;
	if (!xpc_services_copy_bootstrap(NULL, &capacity)) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	xpc_services_copy_bootstrap(&encoder, &capacity);
	xpc_launchd_reply(request, &encoder);
	free(buffer);
	return true;
}

static bool
set_bootstrap(mach_msg_header_t *request, const char *name)
{
	struct xpc_object message, bootstrap;
	if (name[0] == '\0' || !xpc_message_payload(request, &message)
			|| !xpc_dictionary_get_dictionary(
					&message, "bootstrap", &bootstrap)) {
		reply_with_errno(request, XPC_EINVAL);
		return true;
	}
	xpc_services_set_bootstrap(
			name, bootstrap.data, xpc_object_size(&bootstrap));
	reply_empty(request);
	return true;
}

static void
reply_user_sessions_info(mach_msg_header_t *request)
{
	char buffer[PATH_MAX];
	struct stat st;
	const char *root = sysroot_host_path("/", 0, buffer);
	uint64_t user = (root != NULL && stat(root, &st) == 0) ? st.st_uid : 0;
	const char *type = getenv(LIMBO_LAUNCHD_SESSION_TYPE_ENV);
	uint64_t session = (type != NULL && strcmp(type, "System") == 0) ? 0
									 : user;

	uint8_t storage[256];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, storage, sizeof(storage));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_bool(&encoder, "enabled", true);
	xpc_encoder_uint64(&encoder, "foreground_uid", user);
	xpc_encoder_uint64(&encoder, "session_uid", session);
	xpc_encoder_end(&encoder);

	xpc_launchd_reply(request, &encoder);
}
