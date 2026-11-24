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

#include <mach/mach.h>
#include <stdbool.h>
#include <sys/types.h>

void launchd_jobs_init(void);
bool launchd_jobs_submit_and_start(mach_msg_header_t *request);
bool launchd_jobs_submit_extension(mach_msg_header_t *request);
bool launchd_jobs_copy_with_label(mach_msg_header_t *request);
bool launchd_jobs_create_instance(mach_msg_header_t *request);
bool launchd_jobs_start(mach_msg_header_t *request);
bool launchd_jobs_info(mach_msg_header_t *request);
bool launchd_jobs_remove(mach_msg_header_t *request);
bool launchd_jobs_monitor(mach_msg_header_t *request);
bool launchd_jobs_managed(mach_msg_header_t *request);
bool launchd_jobs_monitor_poll(mach_msg_header_t *request);
bool launchd_jobs_handle_for_pid(mach_msg_header_t *request, pid_t pid);
bool launchd_jobs_handle_for_endpoint(mach_msg_header_t *request);
bool launchd_jobs_reply_properties(mach_msg_header_t *request, pid_t pid);
bool launchd_jobs_properties(mach_msg_header_t *request);
bool launchd_jobs_reply_service_info(mach_msg_header_t *request);
bool launchd_jobs_own_variable(const char *variable);
void launchd_jobs_exited(pid_t pid, int status);
