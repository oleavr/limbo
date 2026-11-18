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
#include <pthread.h>
#include <unistd.h>

#include "check.h"

static volatile unsigned long counter;
static int fds[2];
static volatile int got;

static void *
spin(void *arg)
{
	for (;;) {
		counter++;
	}
	return NULL;
}

static void *
block(void *arg)
{
	char c;
	read(fds[0], &c, 1);
	got = 1;
	return NULL;
}

static void
stopped_at(mach_port_t port, uintptr_t *pc, uintptr_t *sp)
{
#ifdef __x86_64__
	x86_thread_state64_t state;
	mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
	CHECK(thread_get_state(port, x86_THREAD_STATE64, (thread_state_t)&state,
			      &count)
			== KERN_SUCCESS);
	*pc = state.__rip;
	*sp = state.__rsp;
#else
	arm_thread_state64_t state;
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
	CHECK(thread_get_state(port, ARM_THREAD_STATE64, (thread_state_t)&state,
			      &count)
			== KERN_SUCCESS);
	*pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(state);
	*sp = (uintptr_t)__darwin_arm_thread_state64_get_sp(state);
#endif
}

static void
check_running_thread(void)
{
	pthread_t thread;
	pthread_create(&thread, NULL, spin, NULL);
	usleep(100000);
	mach_port_t port = pthread_mach_thread_np(thread);
	uintptr_t pc, sp;
	stopped_at(port, &pc, &sp);
	CHECK(pc >= (uintptr_t)spin && pc < (uintptr_t)spin + 64);
	unsigned long before = counter;
	usleep(100000);
	CHECK(counter > before);

	CHECK(thread_suspend(port) == KERN_SUCCESS);
	before = counter;
	usleep(100000);
	CHECK(counter == before);

	stopped_at(port, &pc, &sp);
	CHECK(pc >= (uintptr_t)spin && pc < (uintptr_t)spin + 64);

	CHECK(thread_resume(port) == KERN_SUCCESS);
	before = counter;
	usleep(100000);
	CHECK(counter > before);
}

static void
check_blocked_thread(void)
{
	pipe(fds);
	pthread_t thread;
	pthread_create(&thread, NULL, block, NULL);
	usleep(100000);
	mach_port_t port = pthread_mach_thread_np(thread);
	CHECK(thread_suspend(port) == KERN_SUCCESS);
	uintptr_t pc, sp;
	stopped_at(port, &pc, &sp);
	CHECK(sp != 0);
	write(fds[1], "x", 1);
	usleep(100000);
	CHECK(got == 0);
	CHECK(thread_resume(port) == KERN_SUCCESS);
	pthread_join(thread, NULL);
	CHECK(got == 1);
}

static void
check_own_thread(void)
{
	uintptr_t pc, sp;
	stopped_at(pthread_mach_thread_np(pthread_self()), &pc, &sp);
	uintptr_t frame = (uintptr_t)__builtin_frame_address(0);
	CHECK(sp <= frame && frame - sp < 65536);
}

int
main(void)
{
	check_running_thread();
	check_blocked_thread();
	check_own_thread();
	return 0;
}
