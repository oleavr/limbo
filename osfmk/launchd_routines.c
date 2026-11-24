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
#include "launchd_jobs.h"
#include "osfmk/bootstrap/bootstrap_defs.h"
#include "osfmk/broker_client.h"
#include "osfmk/ipc.h"
#include "osfmk/mach_vm.h"
#include "osfmk/xpc_bootstrap.h"
#include "plist.h"
#include "sysroot.h"
#include "xpc_service.h"
#include "xpc_services.h"

enum xpc_routine {
	XPC_ROUTINE_LOOK_UP = 0x324,
	XPC_ROUTINE_CHECK_IN = 0x325,
	XPC_ROUTINE_LOOK_UP_LEGACY = 0xcf,
	XPC_ROUTINE_CHECK_IN_LEGACY = 0xce,
	XPC_ROUTINE_REGISTER = 0xcc,
	XPC_ROUTINE_PUBLISHER_SUBSCRIPTIONS = 0x193,
	XPC_ROUTINE_PUBLISHER_ARM_POLL = 0x196,
	XPC_ROUTINE_PUBLISHER_CREATE_SUBSCRIPTION = 0x19c,
	XPC_ROUTINE_PUBLISHER_SET_EVENT = 0x198,
	XPC_ROUTINE_PUBLISHER_COPY_EVENT = 0x199,
	XPC_ROUTINE_PUBLISHER_EVENT_NAME = 0x192,
	XPC_ROUTINE_PUBLISHER_SUBSCRIBER = 0x19a,
	XPC_ROUTINE_PUBLISHER_SUBSCRIBER_UID = 0x19b,
	XPC_ROUTINE_PUBLISHER_SUBSCRIBER_ASID = 0x197,
	XPC_ROUTINE_COPY_EVENT = 0x191,
	XPC_ROUTINE_SET_EVENT = 0x190,
	XPC_ROUTINE_BOOTSTRAP_PARENT = 0xcb,
	XPC_ROUTINE_UNCORK_PID_DOMAIN = 0x323,
	XPC_ROUTINE_COPY_BOOTSTRAP = 0x2c7,
	XPC_ROUTINE_SET_BOOTSTRAP = 0x2c6,
	XPC_ROUTINE_SERVICE_ENABLED = 0x32b,
	XPC_ROUTINE_LEGACY_LIST = 0x32f,
	XPC_ROUTINE_LOOK_UP_PER_USER = 0xd1,
	XPC_ROUTINE_SWITCH_TO_SESSION = 0x338,
	XPC_ROUTINE_COALITION_INFO = 0x33d,
	XPC_ROUTINE_JOBS_LOADED_BY_COALITION = 0x3f8,
	XPC_ROUTINE_EXTENSION_LIVE = 0x2cc,
	XPC_ROUTINE_SWAP = 0x12d,
	XPC_ROUTINE_PROPERTIES_FOR_PID = 0x2c8,
	XPC_ROUTINE_JOB_FOR_PID = 0x3f0,
	XPC_ROUTINE_JOB_FOR_ENDPOINT = 0x3f4,
	XPC_ROUTINE_JOB_SUBMIT_AND_START = 0x3e8,
	XPC_ROUTINE_JOB_REMOVE = 0x3eb,
	XPC_ROUTINE_JOB_FOR_LABEL = 0x3ed,
	XPC_ROUTINE_JOB_INFO = 0x3f7,
	XPC_ROUTINE_JOB_PROPERTIES = 0x3f1,
	XPC_ROUTINE_JOB_MONITOR = 0x3e9,
	XPC_ROUTINE_JOB_MONITOR_POLL = 0x3ea,
	XPC_ROUTINE_JOBS_MANAGED_BY = 0x3ec,
	XPC_ROUTINE_JOB_SUBMIT_EXTENSION = 0x3ef,
	XPC_ROUTINE_JOB_CREATE_INSTANCE = 0x3f2,
	XPC_ROUTINE_JOB_START = 0x3ee,
	XPC_ROUTINE_SERVICE_INFO = 0x2ce,
	XPC_ROUTINE_KILL_SERVICE = 0x32c,
	XPC_ROUTINE_ADD_SERVICE_PATHS = 0x320,
	XPC_ROUTINE_REGISTER_SERVICE_PATHS = 0x322,
	XPC_ROUTINE_CREATE_SESSION = 0x337,
	XPC_ROUTINE_SPAWN = 0x331,
	XPC_ROUTINE_USER_SESSIONS_INFO = 0x388,
	XPC_ROUTINE_REBOOT = 0x335,
};

#define RB_HALT 0x8

#define SERVICE_TYPE_DAEMON      1
#define SERVICE_TYPE_APP         4
#define SERVICE_TYPE_XPC_SERVICE 5
#define RBS_IDENTITY_MAC_APP     1
#define XPC_ESRCH                3
#define XPC_EINVAL               22
#define XPC_ENOTSUP              45

#define GETAUDIT_ADDR_ASID 10

#define CHECK_IN_SOCKETS      0x20
#define LOOK_UP_EVENT_CHANNEL 7
#define CHECK_IN_EVENT_STREAM 0x10

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

struct event_channel {
	struct event_channel *next;
	char *name;
	mach_port_name_t port;
};

struct subscription {
	struct subscription *next;
	char *stream;
	uint32_t domain;
	char *name;
	uint64_t token;
	int64_t subscriber_pid;
	char *job;
	uint32_t job_uid;
	uint32_t job_domain;
	uint8_t *descriptor;
	size_t size;
};

struct loaded_stream {
	struct loaded_stream *next;
	char *stream;
	uint32_t domain;
	uint64_t generation;
};

struct publisher_poll {
	struct publisher_poll *next;
	char *stream;
	uint32_t domain;
	mach_port_name_t reply;
};

struct silent_listener {
	struct silent_listener *next;
	char *name;
};

#define LISTENER_WAIT_STEPS       100
#define LISTENER_WAIT_STEP_US     50000
#define LISTENER_RUNNING_GRACE_MS 1000

struct job_subscriptions {
	const char *stream;
	const char *label;
	uint32_t uid;
	int64_t pid;
	uint32_t domain;
	struct job_event **events;
};

struct job_event {
	struct job_event *next;
	char *label;
	char *name;
	uint32_t uid;
	int64_t pid;
	uint32_t domain;
	uint8_t *descriptor;
	size_t size;
};

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
static bool reply_event_channel(mach_msg_header_t *request, const char *name);
static mach_port_name_t event_channel(const char *name);
static void reply_with_port(mach_msg_header_t *request, mach_port_name_t port,
		mach_msg_type_name_t disposition, bool with_metadata);
static void reply_with_named_port(mach_msg_header_t *request, const char *key,
		mach_port_name_t port, mach_msg_type_name_t disposition,
		bool with_metadata);
static bool set_event(mach_msg_header_t *request, const char *stream,
		const char *name, const uint8_t *descriptor, size_t size);
static void answer_polls(void);
static uint64_t events_generation(void);
static bool reply_subscriber_listener(
		mach_msg_header_t *request, const char *stream, uint64_t token);
static bool subscriber_name(const char *stream, uint64_t token, char *name,
		size_t size, char *job, size_t job_size, uint32_t *job_domain);
static struct subscription *subscription_of(const char *stream, uint64_t token);
static int64_t job_running_or_start(const char *job);
static int64_t job_running_ms(const char *job);
static void reply_subscriptions(
		mach_msg_header_t *request, const char *stream, uint64_t token);
static void load_job_subscriptions(const char *stream);
static uint32_t publisher_domain(void);
static size_t split_fields(char *line, char **fields, size_t max);
static void add_job_subscription(void *context, const char *name,
		const uint8_t *descriptor, size_t size);
static void put_job_event(struct job_event **events,
		const struct job_subscriptions *job, const char *name,
		const uint8_t *descriptor, size_t size);
static struct job_event **job_event_link(
		struct job_event **events, const char *label, const char *name);
static bool arm_poll(mach_msg_header_t *request, const char *stream);
static bool create_subscription(
		mach_msg_header_t *request, const struct xpc_request *parsed);
static bool set_subscription_event(
		mach_msg_header_t *request, const struct xpc_request *parsed);
static bool reply_subscription_event(
		mach_msg_header_t *request, const char *stream, uint64_t token);
static bool reply_subscription_name(
		mach_msg_header_t *request, const char *stream, uint64_t token);
static bool reply_subscriber(
		mach_msg_header_t *request, uint64_t token, bool uid);
static bool reply_subscriber_session(
		mach_msg_header_t *request, const char *stream, uint64_t token);
static bool reply_event(mach_msg_header_t *request, const char *stream,
		const char *name);
static bool create_session(mach_msg_header_t *request, bool login_window);
static mach_msg_header_t *ask_launchd(const mach_msg_header_t *request);
static bool reply_coalition_info(mach_msg_header_t *request, uint64_t cid);
static bool app_identifier(const char *path, char *identifier, size_t size);
static bool reply_properties_for_pid(mach_msg_header_t *request, int64_t pid);
static void release_request(mach_msg_header_t *request);
static void release_right(
		mach_port_name_t name, mach_msg_type_name_t disposition);
static bool is_message(mach_msg_id_t id);
static bool xpc_bootstrap_serve_port(mach_msg_header_t *request, void *kobject);
static bool serve_port(void *kobject, mach_msg_header_t *request, bool remote);
static uint32_t user_domain(int64_t uid);
static bool reply_per_user_bootstrap(mach_msg_header_t *request, int64_t uid);
static bool serve(mach_msg_header_t *request);
static bool look_up_subscriber(
		mach_msg_header_t *request, const struct xpc_request *parsed);
static bool look_up_job_listener(mach_msg_header_t *request, const char *name,
		const char *job, uint32_t domain, int64_t ran_ms);
static bool look_up(mach_msg_header_t *request, const char *name,
		const uint8_t *instance, uint64_t domain_type,
		int64_t targetpid, int64_t target_uid);
static mach_port_name_t xpc_service_look_up_or_start(
		const char *name, const uint8_t *instance);
static bool register_name(
		mach_msg_header_t *request, const char *name, uint64_t flags);
static bool check_in(
		mach_msg_header_t *request, const char *name, uint64_t flags);
static mach_port_name_t job_event_channel(const mach_msg_header_t *request);
static bool reply_service_info(mach_msg_header_t *request);
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
static struct event_channel *event_channels;
static struct loaded_stream *loaded_streams;

static struct subscription *subscriptions;
static struct publisher_poll *publisher_polls;
static uint64_t last_token;
static pthread_mutex_t subscriptions_lock = PTHREAD_MUTEX_INITIALIZER;
static struct silent_listener *silent_listeners;

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
		} else if (parsed.flags & CHECK_IN_EVENT_STREAM) {
			answered = reply_event_channel(request, parsed.name);
		}
		break;
	case XPC_ROUTINE_SET_EVENT:
		answered = set_event(request, parsed.stream, parsed.name,
				parsed.descriptor, parsed.descriptor_size);
		break;
	case XPC_ROUTINE_LOOK_UP:
	case XPC_ROUTINE_LOOK_UP_LEGACY:
		answered = parsed.type == LOOK_UP_EVENT_CHANNEL
				&& parsed.lookup_handle != 0
				&& reply_subscriber_listener(request,
						parsed.name,
						parsed.lookup_handle);
		break;
	case XPC_ROUTINE_PUBLISHER_SUBSCRIPTIONS:
		reply_subscriptions(request, parsed.stream, 0);
		answered = true;
		break;
	case XPC_ROUTINE_PUBLISHER_ARM_POLL:
		answered = arm_poll(request, parsed.stream);
		break;
	case XPC_ROUTINE_PUBLISHER_CREATE_SUBSCRIPTION:
		answered = create_subscription(request, &parsed);
		break;
	case XPC_ROUTINE_PUBLISHER_SET_EVENT:
		answered = set_subscription_event(request, &parsed);
		break;
	case XPC_ROUTINE_PUBLISHER_COPY_EVENT:
		answered = reply_subscription_event(
				request, parsed.stream, parsed.token);
		break;
	case XPC_ROUTINE_PUBLISHER_EVENT_NAME:
		answered = reply_subscription_name(
				request, parsed.stream, parsed.token);
		break;
	case XPC_ROUTINE_PUBLISHER_SUBSCRIBER:
		answered = reply_subscriber(request, parsed.token, false);
		break;
	case XPC_ROUTINE_PUBLISHER_SUBSCRIBER_UID:
		answered = reply_subscriber(request, parsed.token, true);
		break;
	case XPC_ROUTINE_PUBLISHER_SUBSCRIBER_ASID:
		answered = reply_subscriber_session(
				request, parsed.stream, parsed.token);
		break;
	case XPC_ROUTINE_COPY_EVENT:
		answered = reply_event(request, parsed.stream, parsed.name);
		break;
	case XPC_ROUTINE_CREATE_SESSION:
		answered = create_session(request,
				parsed.has_uid
						&& (uid_t)parsed.uid
								== (uid_t)-1);
		break;
	case XPC_ROUTINE_COALITION_INFO:
		answered = reply_coalition_info(request, parsed.cid);
		break;
	case XPC_ROUTINE_PROPERTIES_FOR_PID:
		answered = reply_properties_for_pid(request, parsed.pid);
		break;
	case XPC_ROUTINE_JOB_FOR_ENDPOINT:
		answered = launchd_jobs_handle_for_endpoint(request);
		break;
	case XPC_ROUTINE_JOB_FOR_PID:
		if (!launchd_jobs_handle_for_pid(request, (pid_t)parsed.pid)) {
			reply_with_errno(request, XPC_ESRCH);
		}
		answered = true;
		break;
	case XPC_ROUTINE_JOB_SUBMIT_AND_START:
		answered = launchd_jobs_submit_and_start(request);
		break;
	case XPC_ROUTINE_JOB_REMOVE:
		answered = launchd_jobs_remove(request);
		break;
	case XPC_ROUTINE_JOB_FOR_LABEL:
		answered = launchd_jobs_copy_with_label(request);
		break;
	case XPC_ROUTINE_JOB_INFO:
		answered = launchd_jobs_info(request);
		break;
	case XPC_ROUTINE_JOB_PROPERTIES:
		answered = launchd_jobs_properties(request);
		break;
	case XPC_ROUTINE_JOB_MONITOR:
		answered = launchd_jobs_monitor(request);
		break;
	case XPC_ROUTINE_JOB_MONITOR_POLL:
		answered = launchd_jobs_monitor_poll(request);
		break;
	case XPC_ROUTINE_JOBS_MANAGED_BY:
		answered = launchd_jobs_managed(request);
		break;
	case XPC_ROUTINE_JOB_SUBMIT_EXTENSION:
		answered = launchd_jobs_submit_extension(request);
		break;
	case XPC_ROUTINE_JOB_CREATE_INSTANCE:
		answered = launchd_jobs_create_instance(request);
		break;
	case XPC_ROUTINE_JOB_START:
		answered = launchd_jobs_start(request);
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

static bool
reply_event_channel(mach_msg_header_t *request, const char *name)
{
	char label[256], plist[PATH_MAX];
	if (!job_of_pid(caller_pid(), label, sizeof(label), plist,
			    sizeof(plist))) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	char buffer[300], per_job[600];
	snprintf(per_job, sizeof(per_job), "%s#%s",
			xpc_services_check_in_name(
					name, buffer, sizeof(buffer)),
			label);
	mach_port_name_t port = event_channel(per_job);
	if (port == MACH_PORT_NULL) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	reply_with_port(request, port, MACH_MSG_TYPE_MOVE_RECEIVE, false);
	return true;
}

static mach_port_name_t
event_channel(const char *name)
{
	struct event_channel *channel = event_channels;
	while (channel != NULL && strcmp(channel->name, name) != 0) {
		channel = channel->next;
	}
	mach_port_type_t type = 0;
	if (channel != NULL
			&& ipc_port_type(channel->port, &type) == KERN_SUCCESS
			&& (type & MACH_PORT_TYPE_RECEIVE)) {
		return channel->port;
	}
	if (channel != NULL && (type & MACH_PORT_TYPE_SEND)) {
		return MACH_PORT_NULL;
	}
	if (channel != NULL && (type & MACH_PORT_TYPE_DEAD_NAME)) {
		ipc_port_mod_refs(channel->port, MACH_PORT_RIGHT_DEAD_NAME, -1);
	}
	mach_port_name_t port;
	if (ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) {
		return MACH_PORT_NULL;
	}
	ipc_port_insert_right(port, port, MACH_MSG_TYPE_MAKE_SEND);
	if (names_register(name, port) != KERN_SUCCESS) {
		ipc_port_mod_refs(port, MACH_PORT_RIGHT_RECEIVE, -1);
		ipc_port_deallocate(port);
		return MACH_PORT_NULL;
	}
	if (channel == NULL) {
		channel = calloc(1, sizeof(*channel));
		channel->name = strdup(name);
		channel->next = event_channels;
		event_channels = channel;
	}
	channel->port = port;
	return port;
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
set_event(mach_msg_header_t *request, const char *stream, const char *name,
		const uint8_t *descriptor, size_t size)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	char label[256], plist[PATH_MAX];
	if (!job_of_pid(caller_pid(), label, sizeof(label), plist,
			    sizeof(plist))) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	char *hex = malloc(descriptor != NULL ? size * 2 + 1 : 2);
	if (descriptor == NULL) {
		strcpy(hex, "-");
	}
	for (size_t i = 0; descriptor != NULL && i != size; i++) {
		snprintf(hex + i * 2, 3, "%02x", descriptor[i]);
	}
	const char *const words[] = {"setevent", label, stream, name, hex};
	uint32_t status = 0;
	free(launchd_control(words, 5, &status));
	free(hex);
	reply_empty(request);
	if (answering != NULL) {
		answer_polls();
	}
	return true;
}

static void
answer_polls(void)
{
	uint64_t generation = events_generation();
	mach_port_name_t replies[16];
	size_t count = 0;
	pthread_mutex_lock(&subscriptions_lock);
	for (struct publisher_poll *poll = publisher_polls;
			poll != NULL && count != 16; poll = poll->next) {
		const struct loaded_stream *loaded = loaded_streams;
		while (loaded != NULL
				&& (strcmp(loaded->stream, poll->stream) != 0
						|| loaded->domain
								!= poll->domain)) {
			loaded = loaded->next;
		}
		if (poll->reply != MACH_PORT_NULL && loaded != NULL
				&& loaded->generation != generation) {
			replies[count++] = poll->reply;
			poll->reply = MACH_PORT_NULL;
		}
	}
	pthread_mutex_unlock(&subscriptions_lock);
	for (size_t i = 0; i != count; i++) {
		uint8_t buffer[128];
		struct xpc_encoder encoder;
		xpc_encoder_init(&encoder, buffer, sizeof(buffer));
		xpc_encoder_begin_dictionary(&encoder, NULL);
		xpc_encoder_int64(&encoder, "error", 0);
		xpc_encoder_end_dictionary(&encoder);
		xpc_launchd_send(replies[i], MACH_MSG_TYPE_MOVE_SEND_ONCE,
				&encoder);
	}
}

static uint64_t
events_generation(void)
{
	const char *const words[] = {"generation"};
	uint32_t status = 0;
	char *text = broker_client_available()
			? launchd_control(words, 1, &status)
			: NULL;
	uint64_t generation = text != NULL && status == 0
			? strtoull(text, NULL, 10)
			: 0;
	free(text);
	return generation;
}

static bool
reply_subscriber_listener(
		mach_msg_header_t *request, const char *stream, uint64_t token)
{
	char subscriber[300], job[256];
	uint32_t job_domain = 0;
	if (!subscriber_name(stream, token, subscriber, sizeof(subscriber), job,
			    sizeof(job), &job_domain)) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	if (job[0] != '\0') {
		event_channel(subscriber);
	}
	int64_t ran_ms = job[0] != '\0' ? job_running_or_start(job) : -1;
	uint8_t buffer[1024];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_string(&encoder, "name", subscriber);
	xpc_encoder_string(&encoder, "job", job);
	xpc_encoder_uint64(&encoder, "domain", job_domain);
	xpc_encoder_int64(&encoder, "ran", ran_ms);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	return true;
}

static bool
subscriber_name(const char *stream, uint64_t token, char *name, size_t size,
		char *job, size_t job_size, uint32_t *job_domain)
{
	pthread_mutex_lock(&subscriptions_lock);
	const struct subscription *subscription
			= subscription_of(stream, token);
	bool found = subscription != NULL
			&& (subscription->job != NULL
					|| subscription->subscriber_pid > 0);
	job[0] = '\0';
	if (found && subscription->job != NULL) {
		snprintf(name, size, "%s#%s", stream, subscription->job);
		snprintf(job, job_size, "%s", subscription->job);
		*job_domain = subscription->job_domain;
	} else if (found) {
		xpc_services_host_name(stream,
				(pid_t)subscription->subscriber_pid, name,
				size);
	}
	pthread_mutex_unlock(&subscriptions_lock);
	return found;
}

static struct subscription *
subscription_of(const char *stream, uint64_t token)
{
	struct subscription *subscription = subscriptions;
	while (subscription != NULL
			&& (subscription->token != token
					|| (stream != NULL
							&& strcmp(subscription->stream,
									   stream)
									!= 0))) {
		subscription = subscription->next;
	}
	return subscription;
}

static int64_t
job_running_or_start(const char *job)
{
	int64_t ran_ms = job_running_ms(job);
	if (ran_ms < 0) {
		const char *const words[] = {"start", job};
		uint32_t status = 0;
		free(launchd_control(words, 2, &status));
	}
	return ran_ms;
}

static int64_t
job_running_ms(const char *job)
{
	const char *const words[] = {"print", job};
	uint32_t status = 0;
	char *text = launchd_control(words, 2, &status);
	long pid = text != NULL && status == 0 ? strtol(text, NULL, 10) : 0;
	free(text);
	if (pid <= 0) {
		return -1;
	}
	char path[64], line[1024];
	snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
	FILE *file = fopen(path, "re");
	if (file == NULL) {
		return -1;
	}
	bool read = fgets(line, sizeof(line), file) != NULL;
	fclose(file);
	const char *field = read ? strrchr(line, ')') : NULL;
	unsigned long long start = 0;
	for (int i = 2; field != NULL && i != 22; i++) {
		field = strchr(field + 1, ' ');
	}
	if (field == NULL || sscanf(field, " %llu", &start) != 1) {
		return 0;
	}
	struct timespec now;
	clock_gettime(CLOCK_BOOTTIME, &now);
	long ticks = sysconf(_SC_CLK_TCK);
	int64_t started_ms
			= (int64_t)(start * 1000 / (ticks > 0 ? ticks : 100));
	int64_t now_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
	return now_ms > started_ms ? now_ms - started_ms : 0;
}

static void
reply_subscriptions(
		mach_msg_header_t *request, const char *stream, uint64_t token)
{
	load_job_subscriptions(stream);
	uint32_t domain = publisher_domain();
	pthread_mutex_lock(&subscriptions_lock);
	size_t capacity = 256;
	for (const struct subscription *subscription = subscriptions;
			subscription != NULL;
			subscription = subscription->next) {
		capacity += 16 + subscription->size;
	}
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	xpc_encoder_begin_dictionary(&encoder, NULL);
	if (token != 0) {
		xpc_encoder_uint64(&encoder, "token", token);
	}
	xpc_encoder_begin_array(&encoder, "events");
	for (const struct subscription *subscription = subscriptions;
			subscription != NULL;
			subscription = subscription->next) {
		if (strcmp(subscription->stream, stream) == 0
				&& subscription->domain == domain) {
			xpc_encoder_uint64(&encoder, NULL, subscription->token);
			xpc_encoder_object(&encoder, NULL,
					subscription->descriptor,
					subscription->size);
		}
	}
	xpc_encoder_end_array(&encoder);
	xpc_encoder_bool(&encoder, "initial-load-completed", true);
	xpc_encoder_end_dictionary(&encoder);
	pthread_mutex_unlock(&subscriptions_lock);
	xpc_launchd_reply(request, &encoder);
	free(buffer);
}

static void
load_job_subscriptions(const char *stream)
{
	if (!broker_client_available()) {
		return;
	}
	uint64_t generation = events_generation();
	uint32_t publisher = publisher_domain();
	pthread_mutex_lock(&subscriptions_lock);
	struct loaded_stream *loaded = loaded_streams;
	while (loaded != NULL
			&& (strcmp(loaded->stream, stream) != 0
					|| loaded->domain != publisher)) {
		loaded = loaded->next;
	}
	bool current = loaded != NULL && loaded->generation == generation;
	pthread_mutex_unlock(&subscriptions_lock);
	if (current) {
		return;
	}
	char domain[16];
	snprintf(domain, sizeof(domain), "%u", (unsigned)publisher);
	const char *const plist_words[] = {"events", stream, domain};
	const char *const set_words[] = {"setevents", stream, domain};
	uint32_t plist_status = 0, set_status = 0;
	char *plists = launchd_control(plist_words, 3, &plist_status);
	char *set = launchd_control(set_words, 3, &set_status);
	if (plists == NULL || plist_status != 0) {
		free(plists);
		free(set);
		return;
	}

	struct job_event *events = NULL;
	char *save = NULL;
	for (char *line = strtok_r(plists, "\n", &save); line != NULL;
			line = strtok_r(NULL, "\n", &save)) {
		char *fields[5];
		if (split_fields(line, fields, 5) != 5) {
			continue;
		}
		struct job_subscriptions job = {
				.stream = stream,
				.label = fields[0],
				.uid = (uint32_t)strtoul(fields[2], NULL, 10),
				.pid = strtoll(fields[3], NULL, 10),
				.domain
				= (uint32_t)strtoul(fields[4], NULL, 10),
				.events = &events,
		};
		xpc_services_job_events(
				fields[1], stream, add_job_subscription, &job);
	}
	save = NULL;
	for (char *line = set != NULL && set_status == 0
					? strtok_r(set, "\n", &save)
					: NULL;
			line != NULL; line = strtok_r(NULL, "\n", &save)) {
		char *fields[6];
		if (split_fields(line, fields, 6) != 6) {
			continue;
		}
		if (strcmp(fields[5], "-") == 0) {
			struct job_event **link = job_event_link(
					&events, fields[0], fields[4]);
			struct job_event *removed = *link;
			if (removed != NULL) {
				*link = removed->next;
				free(removed->label);
				free(removed->name);
				free(removed->descriptor);
				free(removed);
			}
			continue;
		}
		size_t size = strlen(fields[5]) / 2;
		uint8_t *descriptor = malloc(size + 1);
		for (size_t i = 0; i != size; i++) {
			char byte[3] = {fields[5][2 * i], fields[5][2 * i + 1],
					0};
			descriptor[i] = (uint8_t)strtoul(byte, NULL, 16);
		}
		struct job_subscriptions job = {
				.stream = stream,
				.label = fields[0],
				.uid = (uint32_t)strtoul(fields[1], NULL, 10),
				.pid = strtoll(fields[2], NULL, 10),
				.domain
				= (uint32_t)strtoul(fields[3], NULL, 10),
		};
		put_job_event(&events, &job, fields[4], descriptor, size);
		free(descriptor);
	}
	free(plists);
	free(set);

	pthread_mutex_lock(&subscriptions_lock);
	struct subscription **link = &subscriptions;
	while (*link != NULL) {
		struct subscription *subscription = *link;
		struct job_event **event_link = subscription->job != NULL
						&& strcmp(subscription->stream,
								   stream)
								== 0
						&& subscription->domain
								== publisher
				? job_event_link(&events, subscription->job,
						  subscription->name)
				: NULL;
		if (event_link == NULL) {
			link = &subscription->next;
			continue;
		}
		struct job_event *event = *event_link;
		if (event == NULL) {
			*link = subscription->next;
			free(subscription->stream);
			free(subscription->name);
			free(subscription->job);
			free(subscription->descriptor);
			free(subscription);
			continue;
		}
		*event_link = event->next;
		free(subscription->descriptor);
		subscription->descriptor = event->descriptor;
		subscription->size = event->size;
		subscription->subscriber_pid = event->pid;
		subscription->job_uid = event->uid;
		subscription->job_domain = event->domain;
		free(event->label);
		free(event->name);
		free(event);
		link = &subscription->next;
	}
	while (events != NULL) {
		struct job_event *event = events;
		events = event->next;
		struct subscription *subscription
				= calloc(1, sizeof(*subscription));
		subscription->stream = strdup(stream);
		subscription->domain = publisher;
		subscription->name = event->name;
		subscription->subscriber_pid = event->pid;
		subscription->job = event->label;
		subscription->job_uid = event->uid;
		subscription->job_domain = event->domain;
		subscription->descriptor = event->descriptor;
		subscription->size = event->size;
		subscription->token = ++last_token;
		subscription->next = subscriptions;
		subscriptions = subscription;
		free(event);
	}
	loaded = loaded_streams;
	while (loaded != NULL
			&& (strcmp(loaded->stream, stream) != 0
					|| loaded->domain != publisher)) {
		loaded = loaded->next;
	}
	if (loaded == NULL) {
		loaded = calloc(1, sizeof(*loaded));
		loaded->stream = strdup(stream);
		loaded->domain = publisher;
		loaded->next = loaded_streams;
		loaded_streams = loaded;
	}
	loaded->generation = generation;
	pthread_mutex_unlock(&subscriptions_lock);
}

static uint32_t
publisher_domain(void)
{
	if (answering == NULL) {
		return broker_client_domain();
	}
	return caller_euid() < 500 ? BROKER_DOMAIN_SYSTEM : BROKER_DOMAIN_USER;
}

static size_t
split_fields(char *line, char **fields, size_t max)
{
	size_t count = 0;
	char *save = NULL;
	for (char *field = strtok_r(line, "\t", &save);
			field != NULL && count != max;
			field = strtok_r(NULL, "\t", &save)) {
		fields[count++] = field;
	}
	return count;
}

static void
add_job_subscription(void *context, const char *name, const uint8_t *descriptor,
		size_t size)
{
	const struct job_subscriptions *job = context;
	put_job_event(job->events, job, name, descriptor, size);
}

static void
put_job_event(struct job_event **events, const struct job_subscriptions *job,
		const char *name, const uint8_t *descriptor, size_t size)
{
	struct job_event **link = job_event_link(events, job->label, name);
	struct job_event *event = *link;
	if (event == NULL) {
		event = calloc(1, sizeof(*event));
		event->label = strdup(job->label);
		event->name = strdup(name);
		*link = event;
	}
	free(event->descriptor);
	event->uid = job->uid;
	event->pid = job->pid;
	event->domain = job->domain;
	event->descriptor = malloc(size);
	memcpy(event->descriptor, descriptor, size);
	event->size = size;
}

static struct job_event **
job_event_link(struct job_event **events, const char *label, const char *name)
{
	while (*events != NULL
			&& (strcmp((*events)->label, label) != 0
					|| strcmp((*events)->name, name)
							!= 0)) {
		events = &(*events)->next;
	}
	return events;
}

static bool
arm_poll(mach_msg_header_t *request, const char *stream)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	mach_port_name_t reply = request->msgh_remote_port;
	if (reply == MACH_PORT_NULL
			|| MACH_MSGH_BITS_REMOTE(request->msgh_bits)
					!= MACH_MSG_TYPE_PORT_SEND_ONCE) {
		return false;
	}
	uint32_t domain = publisher_domain();
	pthread_mutex_lock(&subscriptions_lock);
	struct publisher_poll *poll = publisher_polls;
	while (poll != NULL
			&& (strcmp(poll->stream, stream) != 0
					|| poll->domain != domain)) {
		poll = poll->next;
	}
	if (poll == NULL) {
		poll = calloc(1, sizeof(*poll));
		poll->stream = strdup(stream);
		poll->domain = domain;
		poll->next = publisher_polls;
		publisher_polls = poll;
	} else if (poll->reply != MACH_PORT_NULL) {
		ipc_port_deallocate(poll->reply);
	}
	poll->reply = reply;
	pthread_mutex_unlock(&subscriptions_lock);
	return true;
}

static bool
create_subscription(
		mach_msg_header_t *request, const struct xpc_request *parsed)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	if (parsed->descriptor == NULL) {
		reply_with_errno(request, XPC_EINVAL);
		return true;
	}
	struct subscription *subscription = calloc(1, sizeof(*subscription));
	subscription->stream = strdup(parsed->stream);
	subscription->domain = publisher_domain();
	subscription->name = strdup(parsed->name);
	subscription->subscriber_pid = parsed->subscriber_pid;
	subscription->descriptor = malloc(parsed->descriptor_size);
	memcpy(subscription->descriptor, parsed->descriptor,
			parsed->descriptor_size);
	subscription->size = parsed->descriptor_size;
	pthread_mutex_lock(&subscriptions_lock);
	subscription->token = ++last_token;
	subscription->next = subscriptions;
	subscriptions = subscription;
	pthread_mutex_unlock(&subscriptions_lock);
	reply_subscriptions(request, parsed->stream, subscription->token);
	return true;
}

static bool
set_subscription_event(
		mach_msg_header_t *request, const struct xpc_request *parsed)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	pthread_mutex_lock(&subscriptions_lock);
	struct subscription **link = &subscriptions;
	while (*link != NULL
			&& ((*link)->token != parsed->token
					|| strcmp((*link)->stream,
							   parsed->stream)
							!= 0)) {
		link = &(*link)->next;
	}
	struct subscription *subscription = *link;
	if (subscription == NULL) {
		pthread_mutex_unlock(&subscriptions_lock);
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	free(subscription->descriptor);
	if (parsed->descriptor == NULL) {
		*link = subscription->next;
		free(subscription->stream);
		free(subscription->name);
		free(subscription->job);
		free(subscription);
	} else {
		subscription->descriptor = malloc(parsed->descriptor_size);
		memcpy(subscription->descriptor, parsed->descriptor,
				parsed->descriptor_size);
		subscription->size = parsed->descriptor_size;
	}
	pthread_mutex_unlock(&subscriptions_lock);
	reply_subscriptions(request, parsed->stream, parsed->token);
	return true;
}

static bool
reply_subscription_event(
		mach_msg_header_t *request, const char *stream, uint64_t token)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	pthread_mutex_lock(&subscriptions_lock);
	const struct subscription *subscription
			= subscription_of(stream, token);
	if (subscription == NULL) {
		pthread_mutex_unlock(&subscriptions_lock);
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	size_t capacity = 128 + subscription->size;
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_object(&encoder, "event", subscription->descriptor,
			subscription->size);
	xpc_encoder_end_dictionary(&encoder);
	pthread_mutex_unlock(&subscriptions_lock);
	xpc_launchd_reply(request, &encoder);
	free(buffer);
	return true;
}

static bool
reply_subscription_name(
		mach_msg_header_t *request, const char *stream, uint64_t token)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	pthread_mutex_lock(&subscriptions_lock);
	const struct subscription *subscription
			= subscription_of(stream, token);
	char name[256];
	bool found = subscription != NULL;
	if (found) {
		snprintf(name, sizeof(name), "%s", subscription->name);
	}
	pthread_mutex_unlock(&subscriptions_lock);
	if (!found) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	uint8_t buffer[512];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_string(&encoder, "name", name);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	return true;
}

static bool
reply_subscriber(mach_msg_header_t *request, uint64_t token, bool uid)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	pthread_mutex_lock(&subscriptions_lock);
	const struct subscription *subscription = subscription_of(NULL, token);
	int64_t pid = subscription != NULL ? subscription->subscriber_pid : 0;
	char label[256], plist[PATH_MAX];
	struct process process;
	bool job = subscription != NULL && subscription->job != NULL;
	if (job) {
		snprintf(label, sizeof(label), "%s", subscription->job);
		process.uid[1] = subscription->job_uid;
	}
	pthread_mutex_unlock(&subscriptions_lock);
	if (!job
			&& (pid <= 0
					|| (uid ? process_lookup((int32_t)pid,
								  &process) != 0
						: !job_of_pid(pid, label,
								  sizeof(label),
								  plist,
								  sizeof(plist))))) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	uint8_t buffer[512];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	if (uid) {
		xpc_encoder_uint64(&encoder, "uid", process.uid[1]);
	} else {
		xpc_encoder_string(&encoder, "identifier", label);
	}
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	return true;
}

static bool
reply_subscriber_session(
		mach_msg_header_t *request, const char *stream, uint64_t token)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	pthread_mutex_lock(&subscriptions_lock);
	const struct subscription *subscription
			= subscription_of(stream, token);
	bool found = subscription != NULL;
	pthread_mutex_unlock(&subscriptions_lock);
	if (!found) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	uint8_t buffer[256];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_int64(&encoder, "asid", GETAUDIT_ADDR_ASID);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	return true;
}

static bool
reply_event(mach_msg_header_t *request, const char *stream, const char *name)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	char label[256], plist[PATH_MAX];
	bool job = job_of_pid(caller_pid(), label, sizeof(label), plist,
			sizeof(plist));
	char domain[16];
	snprintf(domain, sizeof(domain), "%u", (unsigned)BROKER_DOMAIN_SYSTEM);
	const char *const words[] = {"setevents", stream, domain};
	uint32_t status = 0;
	char *set = job ? launchd_control(words, 3, &status) : NULL;
	const char *description = NULL;
	char *save = NULL;
	for (char *line = set != NULL && status == 0
					? strtok_r(set, "\n", &save)
					: NULL;
			line != NULL && description == NULL;
			line = strtok_r(NULL, "\n", &save)) {
		char *fields[6];
		if (split_fields(line, fields, 6) == 6
				&& strcmp(fields[0], label) == 0
				&& strcmp(fields[4], name) == 0) {
			description = fields[5];
		}
	}
	size_t capacity = 64 * 1024;
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	size_t size = description != NULL ? strlen(description) / 2 : 0;
	if (description != NULL && strcmp(description, "-") != 0
			&& size + 256 <= capacity) {
		uint8_t *descriptor = malloc(size + 1);
		for (size_t i = 0; i != size; i++) {
			char byte[3] = {description[2 * i],
					description[2 * i + 1], 0};
			descriptor[i] = (uint8_t)strtoul(byte, NULL, 16);
		}
		xpc_encoder_begin_dictionary(&encoder, NULL);
		xpc_encoder_object(&encoder, "event", descriptor, size);
		xpc_encoder_end_dictionary(&encoder);
		free(descriptor);
		xpc_launchd_reply(request, &encoder);
	} else if (job && description == NULL
			&& xpc_services_job_event(
					plist, stream, name, &encoder)) {
		xpc_launchd_reply(request, &encoder);
	} else {
		reply_with_errno(request, XPC_ESRCH);
	}
	free(set);
	free(buffer);
	return true;
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

static bool
reply_coalition_info(mach_msg_header_t *request, uint64_t cid)
{
	if (forward_to_launchd(request)) {
		return true;
	}
	int32_t leader;
	if (proc_coalition_leader(cid, &leader) != 0 || leader == 0) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	char label[256] = "", plist[PATH_MAX], path[PATH_MAX];
	char identifier[256] = "";
	struct xpc_service_of_pid service;
	struct process process;
	if (job_of_pid(leader, label, sizeof(label), plist, sizeof(plist))) {
		if (strncmp(label, "application.", strlen("application."))
				== 0) {
			if (!process_executable_path(leader, path)
					|| !app_identifier(path, identifier,
							sizeof(identifier))) {
				identifier[0] = '\0';
			}
		} else if (plist[0] != '\0' && strcmp(plist, "-") != 0) {
			char guest[PATH_MAX], buffer[PATH_MAX];
			snprintf(guest, sizeof(guest), "%s%s",
					plist[0] == '/' ? "" : "/", plist);
			char *text = plist_read(
					sysroot_host_path(guest, 0, buffer));
			if (text == NULL
					|| !plist_string(text,
							text + strlen(text),
							"CFBundleIdentifier",
							identifier,
							sizeof(identifier))) {
				identifier[0] = '\0';
			}
			free(text);
		}
	} else if (process_executable_path(leader, path)
			&& app_identifier(
					path, identifier, sizeof(identifier))) {
		snprintf(label, sizeof(label), "application.%s.%d.%d",
				identifier, leader, leader);
	} else if (xpc_services_of_pid(leader, &service)) {
		snprintf(label, sizeof(label), "%s", service.name);
	} else if (process_lookup(leader, &process) == 0) {
		snprintf(label, sizeof(label), "%s", process.name);
	}
	uint8_t buffer[2048];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_uint64(&encoder, "cid", cid);
	xpc_encoder_string(&encoder, "name", label);
	if (identifier[0] != '\0') {
		xpc_encoder_string(&encoder, "bundle_identifier", identifier);
	}
	xpc_encoder_int64(&encoder, "leader-pid", leader);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	return true;
}

static bool
app_identifier(const char *path, char *identifier, size_t size)
{
	char bundle[PATH_MAX];
	snprintf(bundle, sizeof(bundle), "%s", sysroot_guest_path(path));
	char *contents = strstr(bundle, ".app/Contents/MacOS/");
	if (contents == NULL
			|| strchr(contents + strlen(".app/Contents/MacOS/"),
					   '/')
					!= NULL) {
		return false;
	}
	contents[strlen(".app")] = '\0';
	return xpc_services_bundle_identifier(bundle, identifier, size);
}

static bool
reply_properties_for_pid(mach_msg_header_t *request, int64_t pid)
{
	if (launchd_jobs_reply_properties(request, (pid_t)pid)) {
		return true;
	}
	if (forward_to_launchd(request)) {
		return true;
	}

	char label[256];
	char plist[PATH_MAX];
	char path[PATH_MAX];
	bool known = job_of_pid(pid, label, sizeof(label), plist, sizeof(plist))
			&& process_executable_path((int32_t)pid, path);
	char identifier[256];
	bool app = !known && process_executable_path((int32_t)pid, path)
			&& app_identifier(path, identifier, sizeof(identifier));
	if (app) {
		snprintf(label, sizeof(label), "application.%s.%lld.%lld",
				identifier, (long long)pid, (long long)pid);
	}
	struct xpc_service_of_pid service_of_pid;
	bool service = !known && !app
			&& process_executable_path((int32_t)pid, path)
			&& xpc_services_of_pid((pid_t)pid, &service_of_pid);
	if (service) {
		snprintf(label, sizeof(label), "%s", service_of_pid.name);
	}

	uint8_t storage[1024 + 3 * PATH_MAX];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, storage, sizeof(storage));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_uint64(&encoder, "rec_execcnt", 10);
	xpc_encoder_uint64(&encoder, "req_pid", getpid());
	if (known) {
		xpc_encoder_begin_dictionary(&encoder, "attrs");
		xpc_encoder_string(&encoder, "label", label);
		xpc_encoder_string(
				&encoder, "program", sysroot_guest_path(path));
		xpc_encoder_string(&encoder, "path", plist);
		xpc_encoder_uint64(
				&encoder, "service-type", SERVICE_TYPE_DAEMON);
		xpc_encoder_end(&encoder);
	} else if (app) {
		struct process process;
		uint32_t auid = process_lookup((int32_t)pid, &process) == 0
				? process.uid[0]
				: getuid();
		xpc_encoder_begin_dictionary(&encoder, "attrs");
		xpc_encoder_string(&encoder, "label", label);
		xpc_encoder_string(
				&encoder, "program", sysroot_guest_path(path));
		xpc_encoder_uint64(&encoder, "service-type", SERVICE_TYPE_APP);
		xpc_encoder_begin_dictionary(&encoder, "additional-properties");
		xpc_encoder_begin_dictionary(&encoder, "RunningBoard");
		xpc_encoder_begin_dictionary(
				&encoder, "RunningBoardLaunchedIdentity");
		xpc_encoder_int64(&encoder, "TYPE", RBS_IDENTITY_MAC_APP);
		xpc_encoder_string(&encoder, "AJL", label);
		xpc_encoder_string(&encoder, "EAI", identifier);
		xpc_encoder_uint64(&encoder, "AUID", auid);
		xpc_encoder_uint64(&encoder, "PLAT",
				codesign_platform((int32_t)pid));
		xpc_encoder_end(&encoder);
		xpc_encoder_end(&encoder);
		xpc_encoder_end(&encoder);
		xpc_encoder_end(&encoder);
	} else if (service) {
		xpc_encoder_begin_dictionary(&encoder, "attrs");
		xpc_encoder_string(&encoder, "label", label);
		xpc_encoder_string(
				&encoder, "program", sysroot_guest_path(path));
		xpc_encoder_string(&encoder, "path", service_of_pid.bundle);
		xpc_encoder_uint64(&encoder, "service-type",
				SERVICE_TYPE_XPC_SERVICE);
		xpc_encoder_int64(&encoder, "XPCExtensionHostPID",
				service_of_pid.host);
		if (service_of_pid.has_instance) {
			xpc_encoder_uuid(&encoder, "instance",
					service_of_pid.instance);
		}
		xpc_encoder_end(&encoder);
	} else {
		xpc_encoder_int64(&encoder, "error", XPC_ESRCH);
	}
	xpc_encoder_end(&encoder);

	xpc_launchd_reply(request, &encoder);
	return true;
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
		if (parsed.type == LOOK_UP_EVENT_CHANNEL
				&& parsed.lookup_handle != 0) {
			return look_up_subscriber(request, &parsed);
		}
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
	case XPC_ROUTINE_PUBLISHER_SUBSCRIPTIONS:
		if (!forward_to_launchd(request)) {
			reply_subscriptions(request, parsed.stream, 0);
		}
		return true;
	case XPC_ROUTINE_PUBLISHER_ARM_POLL:
		return arm_poll(request, parsed.stream);
	case XPC_ROUTINE_PUBLISHER_CREATE_SUBSCRIPTION:
		return create_subscription(request, &parsed);
	case XPC_ROUTINE_PUBLISHER_SET_EVENT:
		return set_subscription_event(request, &parsed);
	case XPC_ROUTINE_PUBLISHER_COPY_EVENT:
		return reply_subscription_event(
				request, parsed.stream, parsed.token);
	case XPC_ROUTINE_PUBLISHER_EVENT_NAME:
		return reply_subscription_name(
				request, parsed.stream, parsed.token);
	case XPC_ROUTINE_PUBLISHER_SUBSCRIBER:
		return reply_subscriber(request, parsed.token, false);
	case XPC_ROUTINE_PUBLISHER_SUBSCRIBER_UID:
		return reply_subscriber(request, parsed.token, true);
	case XPC_ROUTINE_PUBLISHER_SUBSCRIBER_ASID:
		return reply_subscriber_session(
				request, parsed.stream, parsed.token);
	case XPC_ROUTINE_PROPERTIES_FOR_PID:
		if (parsed.pid != getpid() && forward_to_launchd(request)) {
			return true;
		}
		return reply_properties_for_pid(request, parsed.pid);
	case XPC_ROUTINE_SERVICE_INFO:
		return reply_service_info(request);
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
	case XPC_ROUTINE_JOB_FOR_ENDPOINT:
	case XPC_ROUTINE_JOB_FOR_PID:
	case XPC_ROUTINE_JOB_SUBMIT_AND_START:
	case XPC_ROUTINE_JOB_REMOVE:
	case XPC_ROUTINE_JOB_FOR_LABEL:
	case XPC_ROUTINE_JOB_INFO:
	case XPC_ROUTINE_JOB_PROPERTIES:
	case XPC_ROUTINE_JOB_MONITOR:
	case XPC_ROUTINE_JOB_MONITOR_POLL:
	case XPC_ROUTINE_JOBS_MANAGED_BY:
	case XPC_ROUTINE_JOB_SUBMIT_EXTENSION:
	case XPC_ROUTINE_JOB_CREATE_INSTANCE:
	case XPC_ROUTINE_JOB_START:
		if (forward_to_launchd(request)) {
			return true;
		}
		break;
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
	case XPC_ROUTINE_COALITION_INFO:
		return reply_coalition_info(request, parsed.cid);
	case XPC_ROUTINE_JOBS_LOADED_BY_COALITION: {
		uint8_t buffer[256];
		struct xpc_encoder encoder;
		xpc_encoder_init(&encoder, buffer, sizeof(buffer));
		xpc_encoder_begin_dictionary(&encoder, NULL);
		xpc_encoder_begin_array(&encoder, "handles");
		xpc_encoder_end_array(&encoder);
		xpc_encoder_end_dictionary(&encoder);
		xpc_launchd_reply(request, &encoder);
		return true;
	}
	case XPC_ROUTINE_UNCORK_PID_DOMAIN:
		reply_empty(request);
		return true;
	case XPC_ROUTINE_EXTENSION_LIVE:
		reply_empty(request);
		return true;
	case XPC_ROUTINE_SET_EVENT:
		return set_event(request, parsed.stream, parsed.name,
				parsed.descriptor, parsed.descriptor_size);
	case XPC_ROUTINE_COPY_EVENT:
		return reply_event(request, parsed.stream, parsed.name);
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
look_up_subscriber(mach_msg_header_t *request, const struct xpc_request *parsed)
{
	char subscriber[300], job[256];
	uint32_t job_domain = 0;
	int64_t ran_ms = -1;
	bool found;
	mach_msg_header_t *answer = ask_launchd(request);
	if (answer != NULL) {
		struct xpc_object payload;
		const char *name = NULL, *label = NULL;
		uint64_t domain = 0, ran = 0;
		found = xpc_message_payload(answer, &payload)
				&& (name = xpc_dictionary_get_string(
						    &payload, "name"))
						!= NULL
				&& (label = xpc_dictionary_get_string(
						    &payload, "job"))
						!= NULL
				&& xpc_dictionary_get_uint64(
						&payload, "domain", &domain)
				&& xpc_dictionary_get_uint64(
						&payload, "ran", &ran);
		if (found) {
			snprintf(subscriber, sizeof(subscriber), "%s", name);
			snprintf(job, sizeof(job), "%s", label);
			job_domain = (uint32_t)domain;
			ran_ms = (int64_t)ran;
		}
		free(answer);
	} else {
		found = subscriber_name(parsed->name, parsed->lookup_handle,
				subscriber, sizeof(subscriber), job,
				sizeof(job), &job_domain);
		if (found && job[0] != '\0') {
			ran_ms = job_running_or_start(job);
		}
	}
	if (!found) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	if (job[0] != '\0') {
		return look_up_job_listener(
				request, subscriber, job, job_domain, ran_ms);
	}
	return look_up(request, subscriber, NULL, parsed->type, 0, -1);
}

static bool
look_up_job_listener(mach_msg_header_t *request, const char *name,
		const char *job, uint32_t domain, int64_t ran_ms)
{
	mach_port_name_t listener;
	names_look_up_registered(name, domain, &listener);
	pthread_mutex_lock(&subscriptions_lock);
	struct silent_listener *silent = silent_listeners;
	while (silent != NULL && strcmp(silent->name, name) != 0) {
		silent = silent->next;
	}
	pthread_mutex_unlock(&subscriptions_lock);
	if (listener == MACH_PORT_NULL && silent == NULL) {
		int steps = LISTENER_WAIT_STEPS;
		if (ran_ms >= 0) {
			int64_t left_ms = LISTENER_RUNNING_GRACE_MS - ran_ms;
			steps = left_ms > 0
					? (int)(left_ms * 1000
							  / LISTENER_WAIT_STEP_US)
							+ 1
					: 0;
		}
		for (int i = 0; i != steps && listener == MACH_PORT_NULL; i++) {
			usleep(LISTENER_WAIT_STEP_US);
			names_look_up_registered(name, domain, &listener);
		}
		if (listener == MACH_PORT_NULL) {
			silent = calloc(1, sizeof(*silent));
			silent->name = strdup(name);
			pthread_mutex_lock(&subscriptions_lock);
			silent->next = silent_listeners;
			silent_listeners = silent;
			pthread_mutex_unlock(&subscriptions_lock);
		}
	}
	if (listener == MACH_PORT_NULL) {
		reply_with_errno(request, XPC_ESRCH);
		return true;
	}
	reply_with_port(request, listener, MACH_MSG_TYPE_MOVE_SEND, true);
	return true;
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
	bool stream = (flags & CHECK_IN_EVENT_STREAM) != 0;
	char per_pid[300];
	if (stream) {
		xpc_services_host_name(service_name, getpid(), per_pid,
				sizeof(per_pid));
		mach_port_name_t channel = job_event_channel(request);
		if (channel != MACH_PORT_NULL) {
			names_register(per_pid, channel);
			reply_with_port(request, channel,
					MACH_MSG_TYPE_MOVE_RECEIVE, false);
			return true;
		}
	}
	mach_port_name_t service;
	kern_return_t kr = names_check_in(
			stream ? per_pid : service_name, &service);
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

static mach_port_name_t
job_event_channel(const mach_msg_header_t *request)
{
	mach_msg_header_t *answer = ask_launchd(request);
	mach_port_name_t port = MACH_PORT_NULL;
	if (answer != NULL && (answer->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		const mach_msg_body_t *body
				= (const mach_msg_body_t *)(answer + 1);
		const mach_msg_port_descriptor_t *descriptors
				= (const void *)(body + 1);
		for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count;
				i++) {
			if (descriptors[i].type == MACH_MSG_PORT_DESCRIPTOR
					&& descriptors[i].disposition
							== MACH_MSG_TYPE_PORT_RECEIVE) {
				port = descriptors[i].name;
			}
		}
	}
	free(answer);
	return port;
}

static bool
reply_service_info(mach_msg_header_t *request)
{
	size_t capacity = xpc_services_service_info_size();
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	if (xpc_services_service_info(&encoder)) {
		xpc_launchd_reply(request, &encoder);
	} else if (!launchd_jobs_reply_service_info(request)) {
		reply_with_errno(request, XPC_ESRCH);
	}
	free(buffer);
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
