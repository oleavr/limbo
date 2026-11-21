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

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#include "check.h"

#ifdef __arm64__
#define CPU_NUMBER_MASK 7

static uintptr_t read_thread_pointer(void);
static void check_names_the_thread(uintptr_t thread_pointer);
static void *check_on_thread(void *arg);

int
main(void)
{
	check_names_the_thread(read_thread_pointer());
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, check_on_thread, NULL) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	printf("thread_pointer: ok\n");
	return 0;
}

__attribute__((noinline)) static uintptr_t
read_thread_pointer(void)
{
	uintptr_t value;
	__asm__("mrs %0, tpidrro_el0" : "=r"(value));
	return value;
}

static void
check_names_the_thread(uintptr_t thread_pointer)
{
	pthread_t *self = (pthread_t *)(thread_pointer
			& ~(uintptr_t)CPU_NUMBER_MASK);
	CHECK(*self == pthread_self());
}

static void *
check_on_thread(void *arg)
{
	(void)arg;
	check_names_the_thread(read_thread_pointer());
	return NULL;
}
#else
int
main(void)
{
	printf("thread_pointer: skipped (arm64's register)\n");
	return 77;
}
#endif
