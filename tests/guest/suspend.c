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
#include <string.h>
#include <unistd.h>

#include "check.h"

static volatile unsigned long counter;
static int fds[2];
static volatile int got;

#ifndef __x86_64__
void spin_in_place(void);
__asm__(".text\n"
	".p2align 2\n"
	"_spin_in_place:\n"
	"	b _spin_in_place\n");

void count_in_place(void);
__asm__(".text\n"
	".p2align 2\n"
	"_count_in_place:\n"
	"	add x19, x19, #1\n"
	"	b _count_in_place\n");
#endif

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
check_unified_state(mach_port_t port, uintptr_t pc, uintptr_t sp)
{
#ifndef __x86_64__
	arm_unified_thread_state_t state;
	mach_msg_type_number_t count = ARM_UNIFIED_THREAD_STATE_COUNT;
	CHECK(thread_get_state(port, ARM_THREAD_STATE, (thread_state_t)&state,
			      &count)
			== KERN_SUCCESS);
	CHECK(count == ARM_UNIFIED_THREAD_STATE_COUNT);
	CHECK(state.ash.flavor == ARM_THREAD_STATE64);
	CHECK(state.ash.count == ARM_THREAD_STATE64_COUNT);
	CHECK((uintptr_t)__darwin_arm_thread_state64_get_pc(state.ts_64) == pc);
	CHECK((uintptr_t)__darwin_arm_thread_state64_get_sp(state.ts_64) == sp);
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
	check_unified_state(port, pc, sp);

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

static void
check_converted_state(void)
{
#ifdef __x86_64__
	thread_state_flavor_t flavor = x86_THREAD_STATE64;
	x86_thread_state64_t state, converted;
	mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
#else
	thread_state_flavor_t flavor = ARM_THREAD_STATE64;
	arm_thread_state64_t state, converted;
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
#endif
	mach_port_t self = pthread_mach_thread_np(pthread_self());
	CHECK(thread_get_state(self, flavor, (thread_state_t)&state, &count)
			== KERN_SUCCESS);
	int directions[] = {THREAD_CONVERT_THREAD_STATE_TO_SELF,
			THREAD_CONVERT_THREAD_STATE_FROM_SELF};
	for (int i = 0; i < 2; i++) {
		mach_msg_type_number_t converted_count = count;
		CHECK(thread_convert_thread_state(self, directions[i], flavor,
				      (thread_state_t)&state, count,
				      (thread_state_t)&converted,
				      &converted_count)
				== KERN_SUCCESS);
		CHECK(converted_count == count);
		CHECK(memcmp(&converted, &state, sizeof(state)) == 0);
	}
	mach_msg_type_number_t short_count = count - 1;
	CHECK(thread_convert_thread_state(self,
			      THREAD_CONVERT_THREAD_STATE_TO_SELF, flavor,
			      (thread_state_t)&state, count,
			      (thread_state_t)&converted, &short_count)
			== KERN_INSUFFICIENT_BUFFER_SIZE);
	CHECK(thread_convert_thread_state(self, 0, flavor,
			      (thread_state_t)&state, count,
			      (thread_state_t)&converted, &count)
			== KERN_INVALID_ARGUMENT);
}

#ifndef __x86_64__
static void
check_vector_registers(mach_port_t port)
{
	arm_neon_state64_t given = {0}, found;
	for (int i = 0; i < 32; i++) {
		given.__v[i] = ((__uint128_t)i << 64) | (0x2000 + i);
	}
	CHECK(thread_set_state(port, ARM_NEON_STATE64, (thread_state_t)&given,
			      ARM_NEON_STATE64_COUNT)
			== KERN_SUCCESS);
	usleep(100000);
	mach_msg_type_number_t count = ARM_NEON_STATE64_COUNT;
	CHECK(thread_get_state(port, ARM_NEON_STATE64, (thread_state_t)&found,
			      &count)
			== KERN_SUCCESS);
	CHECK(count == ARM_NEON_STATE64_COUNT);
	CHECK(memcmp(found.__v, given.__v, sizeof(given.__v)) == 0);
}
#endif

static void
check_created_thread(void)
{
#ifndef __x86_64__
	static _Alignas(16) char stack[16384];
	arm_thread_state64_t given = {0}, found;
	for (int i = 0; i < 29; i++) {
		given.__x[i] = 0x1000 + i;
	}
	arm_thread_state64_set_pc_fptr(given, spin_in_place);
	arm_thread_state64_set_sp(given, stack + sizeof(stack));
	arm_thread_state64_set_fp(given, stack);
	mach_port_t port;
	CHECK(thread_create_running(mach_task_self(), ARM_THREAD_STATE64,
			      (thread_state_t)&given, ARM_THREAD_STATE64_COUNT,
			      &port)
			== KERN_SUCCESS);
	usleep(100000);
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
	CHECK(thread_get_state(port, ARM_THREAD_STATE64, (thread_state_t)&found,
			      &count)
			== KERN_SUCCESS);
	for (int i = 0; i < 29; i++) {
		CHECK(found.__x[i] == given.__x[i] || (i >= 16 && i <= 18));
	}
	CHECK(arm_thread_state64_get_pc(found) == (uintptr_t)spin_in_place);
	CHECK(arm_thread_state64_get_sp(found)
			== (uintptr_t)stack + sizeof(stack));
	CHECK(arm_thread_state64_get_fp(found) == (uintptr_t)stack);

	arm_thread_state64_set_pc_fptr(found, count_in_place);
	found.__x[19] = 0;
	CHECK(thread_set_state(port, ARM_THREAD_STATE64, (thread_state_t)&found,
			      ARM_THREAD_STATE64_COUNT)
			== KERN_SUCCESS);
	usleep(100000);
	CHECK(thread_get_state(port, ARM_THREAD_STATE64, (thread_state_t)&found,
			      &count)
			== KERN_SUCCESS);
	CHECK(found.__x[19] != 0);
	CHECK(found.__x[20] == given.__x[20]);
	check_vector_registers(port);

	CHECK(thread_terminate(port) == KERN_SUCCESS);
	usleep(100000);
	count = ARM_THREAD_STATE64_COUNT;
	CHECK(thread_get_state(port, ARM_THREAD_STATE64, (thread_state_t)&found,
			      &count)
			!= KERN_SUCCESS);
#endif
}

int
main(void)
{
	check_running_thread();
	check_blocked_thread();
	check_own_thread();
	check_converted_state();
	check_created_thread();
	return 0;
}
