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
#include <objc/message.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "check.h"

typedef struct {
	mach_vm_address_t location;
	unsigned short length;
	unsigned short recovery_offs;
	unsigned int flags;
} range_t;

kern_return_t task_restartable_ranges_register(
		task_t task, range_t *ranges, mach_msg_type_number_t count);
kern_return_t task_restartable_ranges_synchronize(task_t task);

#define SELECTORS 512
#define SENDERS   4
#define SECOND    1000000000ull

static int blocked_pipe[2];
static Class class;
static id object;
static SEL selectors[SELECTORS];
static atomic_bool stop;
static atomic_long sent;

static void check_registration(void);
static void check_blocked_thread(void);
static void *block(void *arg);
static void check_replaced_caches(void);
static void *send_messages(void *arg);
static uintptr_t answer(id self, SEL _cmd);

int
main(void)
{
	check_registration();
	check_blocked_thread();
	check_replaced_caches();
	return 0;
}

static void
check_registration(void)
{
	mach_port_t task = mach_task_self();
	range_t range = {.location = 0x1000, .length = 4};
	CHECK(task_restartable_ranges_register(task, &range, 1)
			== KERN_NOT_SUPPORTED);
	CHECK(task_restartable_ranges_register(task, &range, 0)
			== KERN_INVALID_ARGUMENT);
	range.flags = 1;
	CHECK(task_restartable_ranges_register(task, &range, 1)
			== KERN_INVALID_ARGUMENT);
	range_t overlapping[] = {
			{.location = 0x1000, .length = 8},
			{.location = 0x1004, .length = 8},
	};
	CHECK(task_restartable_ranges_register(task, overlapping, 2)
			== KERN_INVALID_ARGUMENT);
}

static void
check_blocked_thread(void)
{
	CHECK(pipe(blocked_pipe) == 0);
	pthread_t blocked;
	CHECK(pthread_create(&blocked, NULL, block, NULL) == 0);
	usleep(20000);
	uint64_t start = clock_gettime_nsec_np(CLOCK_MONOTONIC);
	CHECK(task_restartable_ranges_synchronize(mach_task_self())
			== KERN_SUCCESS);
	CHECK(clock_gettime_nsec_np(CLOCK_MONOTONIC) - start < SECOND / 2);

	CHECK(write(blocked_pipe[1], "x", 1) == 1);
	void *result;
	CHECK(pthread_join(blocked, &result) == 0);
	CHECK(result == (void *)1);
}

static void *
block(void *arg)
{
	char byte;
	return (void *)(intptr_t)read(blocked_pipe[0], &byte, 1);
}

static void
check_replaced_caches(void)
{
	class = objc_allocateClassPair(
			objc_getClass("NSObject"), "Restartable", 0);
	CHECK(class != Nil);
	for (int i = 0; i < SELECTORS; i++) {
		char name[32];
		snprintf(name, sizeof(name), "answer%d", i);
		selectors[i] = sel_registerName(name);
		CHECK(class_addMethod(class, selectors[i], (IMP)answer, "Q@:"));
	}
	objc_registerClassPair(class);
	object = ((id (*)(Class, SEL))objc_msgSend)(
			class, sel_registerName("new"));

	pthread_t senders[SENDERS];
	for (int i = 0; i < SENDERS; i++) {
		CHECK(pthread_create(&senders[i], NULL, send_messages,
				      (void *)(uintptr_t)(i * 97))
				== 0);
	}
	uint64_t start = clock_gettime_nsec_np(CLOCK_MONOTONIC);
	for (int i = 0; clock_gettime_nsec_np(CLOCK_MONOTONIC) - start < SECOND;
			i++) {
		char name[32];
		snprintf(name, sizeof(name), "flush%d", i);
		CHECK(class_addMethod(class, sel_registerName(name),
				(IMP)answer, "Q@:"));
	}
	atomic_store(&stop, true);
	for (int i = 0; i < SENDERS; i++) {
		CHECK(pthread_join(senders[i], NULL) == 0);
	}
	CHECK(atomic_load(&sent) > 0);
}

static void *
send_messages(void *arg)
{
	uintptr_t (*send)(id, SEL) = (uintptr_t (*)(id, SEL))objc_msgSend;
	unsigned int i = (unsigned int)(uintptr_t)arg;
	while (!atomic_load(&stop)) {
		SEL selector = selectors[i++ % SELECTORS];
		CHECK(send(object, selector) == (uintptr_t)selector);
		atomic_fetch_add(&sent, 1);
	}
	return NULL;
}

static uintptr_t
answer(id self, SEL _cmd)
{
	return (uintptr_t)_cmd;
}
