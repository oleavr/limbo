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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define XPC_SERVICES_HOST_PID_VARIABLE "LIMBO_XPC_HOST_PID"
#define XPC_SERVICES_INSTANCE_VARIABLE "LIMBO_XPC_INSTANCE"

void xpc_services_init(const char *executable);
void xpc_services_add_binary(const char *path);
void xpc_services_host_name(
		const char *name, pid_t host, char *out, size_t size);
const char *xpc_services_check_in_name(
		const char *name, char *buffer, size_t size);
void xpc_services_uuid_text(const uint8_t *uuid, char *out);
void xpc_services_instance_name(const char *name, pid_t host,
		const uint8_t *instance, char *out, size_t size);
bool xpc_services_is_service(const char *name);
bool xpc_services_multiple_instances(const char *name);
bool xpc_services_start(const char *name, const uint8_t *instance, bool *shared,
		pid_t *pid);
int xpc_services_kill(const char *name, int signo);
struct xpc_service_of_pid {
	char name[256];
	char bundle[1024];
	pid_t host;
	bool has_instance;
	uint8_t instance[16];
};
bool xpc_services_of_pid(pid_t pid, struct xpc_service_of_pid *out);
bool xpc_services_bundle_identifier(
		const char *bundle, char *identifier, size_t size);
struct xpc_encoder;
void xpc_services_set_bootstrap(
		const char *name, const void *dictionary, size_t size);
bool xpc_services_copy_bootstrap(struct xpc_encoder *encoder, size_t *size);

bool xpc_services_job_event(const char *plist_path, const char *stream,
		const char *name, struct xpc_encoder *encoder);
void xpc_services_job_events(const char *plist_path, const char *stream,
		void (*each)(void *context, const char *name,
				const uint8_t *descriptor, size_t size),
		void *context);
