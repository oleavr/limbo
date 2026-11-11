/*
 * Copyright © 2021 Keegan Saunders
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "handler.h"
#include "thread.h"
#include "xnu-errno.h"

#define UL_OPCODE_MASK               0xff
#define UL_COMPARE_AND_WAIT64        5
#define UL_COMPARE_AND_WAIT64_SHARED 6
#define UL_UNFAIR_LOCK64_SHARED      4

#define ULF_WAKE_ALL    0x00000100
#define ULF_WAKE_THREAD 0x00000200

struct ulock_waiter {
	struct ulock_waiter *next;
	void *address;
	mach_port_name_t thread;
	pthread_cond_t wakeup;
	bool woken;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct ulock_waiter *waiters;

static int ulock_wait(uint32_t operation, void *addr, uint64_t value,
		uint64_t timeout_ns);
static uint64_t load_value(uint32_t operation, const void *addr);
static int wait_for_wakeup(struct ulock_waiter *waiter, uint64_t timeout_ns);
static void remove_waiter(struct ulock_waiter *waiter);
static int count_waiters(const void *addr);

int
sys_ulock_wait(uint32_t operation, void *addr, uint64_t value, uint32_t timeout)
{
	return ulock_wait(operation, addr, value, timeout * 1000ULL);
}

int
sys_ulock_wait2(uint32_t operation, void *addr, uint64_t value,
		uint64_t timeout, uint64_t value2)
{
	return ulock_wait(operation, addr, value, timeout);
}

static int
ulock_wait(uint32_t operation, void *addr, uint64_t value, uint64_t timeout_ns)
{
	struct ulock_waiter waiter = {
			.address = addr,
			.thread = thread_current()->port,
	};
	pthread_cond_init(&waiter.wakeup, NULL);

	pthread_mutex_lock(&lock);
	int result;
	if (load_value(operation, addr) != value) {
		result = count_waiters(addr);
	} else {
		waiter.next = waiters;
		waiters = &waiter;
		result = wait_for_wakeup(&waiter, timeout_ns);
	}
	pthread_mutex_unlock(&lock);

	pthread_cond_destroy(&waiter.wakeup);
	return result;
}

static uint64_t
load_value(uint32_t operation, const void *addr)
{
	switch (operation & UL_OPCODE_MASK) {
	case UL_UNFAIR_LOCK64_SHARED:
	case UL_COMPARE_AND_WAIT64:
	case UL_COMPARE_AND_WAIT64_SHARED:
		return __atomic_load_n(
				(const uint64_t *)addr, __ATOMIC_RELAXED);
	default:
		return __atomic_load_n(
				(const uint32_t *)addr, __ATOMIC_RELAXED);
	}
}

static int
wait_for_wakeup(struct ulock_waiter *waiter, uint64_t timeout_ns)
{
	struct timespec deadline;
	if (timeout_ns != 0) {
		clock_gettime(CLOCK_REALTIME, &deadline);
		deadline.tv_sec += timeout_ns / 1000000000ULL;
		deadline.tv_nsec += timeout_ns % 1000000000ULL;
		if (deadline.tv_nsec >= 1000000000) {
			deadline.tv_sec++;
			deadline.tv_nsec -= 1000000000;
		}
	}

	while (!waiter->woken) {
		int error = (timeout_ns != 0)
				? pthread_cond_timedwait(&waiter->wakeup, &lock,
						  &deadline)
				: pthread_cond_wait(&waiter->wakeup, &lock);
		if (error == ETIMEDOUT && !waiter->woken) {
			remove_waiter(waiter);
			return _ETIMEDOUT;
		}
	}
	return count_waiters(waiter->address);
}

static void
remove_waiter(struct ulock_waiter *waiter)
{
	for (struct ulock_waiter **p = &waiters; *p != NULL; p = &(*p)->next) {
		if (*p == waiter) {
			*p = waiter->next;
			return;
		}
	}
}

static int
count_waiters(const void *addr)
{
	int count = 0;
	for (struct ulock_waiter *w = waiters; w != NULL; w = w->next) {
		if (w->address == addr) {
			count++;
		}
	}
	return count;
}

int
sys_ulock_wake(uint32_t operation, void *addr, uint64_t wake_value)
{
	bool all = operation & ULF_WAKE_ALL;
	bool specific = operation & ULF_WAKE_THREAD;
	int woken = 0;

	pthread_mutex_lock(&lock);
	struct ulock_waiter **p = &waiters;
	while (*p != NULL) {
		struct ulock_waiter *w = *p;
		if (w->address != addr
				|| (specific && w->thread != wake_value)) {
			p = &w->next;
			continue;
		}

		*p = w->next;
		w->woken = true;
		pthread_cond_signal(&w->wakeup);
		woken++;
		if (!all) {
			break;
		}
	}
	pthread_mutex_unlock(&lock);

	if (woken == 0) {
		return specific ? _EALREADY : _ENOENT;
	}
	return 0;
}
