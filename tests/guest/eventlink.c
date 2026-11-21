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

#include "check.h"

#define MELC_OPTION_NO_COPYIN 0x1

kern_return_t mach_eventlink_create(
		task_t task, uint32_t option, mach_port_t eventlink_pair[2]);
kern_return_t mach_eventlink_destroy(mach_port_t eventlink);

static mach_port_t ends[2];

static void check_pairs(void);
static void create_pair(void);

int
main(void)
{
	check_pairs();
	return 0;
}

static void
check_pairs(void)
{
	mach_port_t task = mach_task_self();
	CHECK(mach_eventlink_create(task, 0, ends) == KERN_INVALID_ARGUMENT);
	create_pair();
	CHECK(MACH_PORT_VALID(ends[0]) && MACH_PORT_VALID(ends[1])
			&& ends[0] != ends[1]);
	for (int i = 0; i < 2; i++) {
		mach_port_type_t type;
		CHECK(mach_port_type(task, ends[i], &type) == KERN_SUCCESS);
		CHECK(type == MACH_PORT_TYPE_SEND);
		mach_port_urefs_t refs;
		CHECK(mach_port_get_refs(task, ends[i], MACH_PORT_RIGHT_SEND,
				      &refs)
				== KERN_SUCCESS);
		CHECK(refs == 1);
	}

	mach_port_type_t type;
	CHECK(mach_eventlink_destroy(ends[0]) == KERN_SUCCESS);
	CHECK(mach_port_type(task, ends[0], &type) == KERN_INVALID_NAME);
	CHECK(mach_port_type(task, ends[1], &type) == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_SEND);
	CHECK(mach_eventlink_destroy(ends[1]) == KERN_SUCCESS);
	CHECK(mach_port_type(task, ends[1], &type) == KERN_INVALID_NAME);
}

static void
create_pair(void)
{
	CHECK(mach_eventlink_create(
			      mach_task_self(), MELC_OPTION_NO_COPYIN, ends)
			== KERN_SUCCESS);
}
