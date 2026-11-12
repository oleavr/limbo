/*
 * Copyright © 2026 Ole André Vadla Ravnås
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
#include <stdio.h>
#include <time.h>

#include "ipc.h"

kern_return_t
clock_get_time(clock_serv_t clock_serv, mach_timespec_t *cur_time)
{
	clockid_t id = (clock_serv == ipc_kobject_name(IPC_KOBJECT_CLOCK))
			? CLOCK_MONOTONIC
			: CLOCK_REALTIME;
	struct timespec now;
	clock_gettime(id, &now);
	cur_time->tv_sec = now.tv_sec;
	cur_time->tv_nsec = now.tv_nsec;
	return KERN_SUCCESS;
}

kern_return_t
clock_get_attributes(clock_serv_t clock_serv, clock_flavor_t flavor,
		clock_attr_t clock_attr, mach_msg_type_number_t *clock_attrCnt)
{
	unimplemented();
}

kern_return_t
clock_alarm(clock_serv_t clock_serv, alarm_type_t alarm_type,
		mach_timespec_t alarm_time, clock_reply_t alarm_port,
		mach_msg_type_name_t alarm_portPoly)
{
	unimplemented();
}
