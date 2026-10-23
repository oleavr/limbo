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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include "commpage.h"
#include "ipc.h"
#include "mk_timer.h"

struct mk_timer {
	struct mk_timer *next;
	mach_port_name_t port;
	uint64_t expire_time;
};

typedef struct {
	mach_msg_header_t header;
	uint64_t unused[3];
} mk_timer_expire_msg_t;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wakeup;
static struct mk_timer *timers;
static bool thread_started;

static struct mk_timer *timer_lookup(mach_port_name_t port);
static void thread_start(void);
static void *timer_main(void *arg);
static struct mk_timer *timer_earliest(void);
static void timer_fire(struct mk_timer *timer);
static void timer_wait(uint64_t expire_time);

mach_port_name_t
mk_timer_create(void)
{
	mach_port_name_t port;
	ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, &port);

	struct mk_timer *timer = calloc(1, sizeof(*timer));
	timer->port = port;
	pthread_mutex_lock(&lock);
	timer->next = timers;
	timers = timer;
	pthread_mutex_unlock(&lock);
	return port;
}

kern_return_t
mk_timer_destroy(mach_port_name_t port)
{
	pthread_mutex_lock(&lock);
	for (struct mk_timer **p = &timers; *p != NULL; p = &(*p)->next) {
		struct mk_timer *timer = *p;
		if (timer->port == port) {
			*p = timer->next;
			free(timer);
			pthread_mutex_unlock(&lock);
			return ipc_port_mod_refs(
					port, MACH_PORT_RIGHT_RECEIVE, -1);
		}
	}
	pthread_mutex_unlock(&lock);
	return KERN_INVALID_ARGUMENT;
}

kern_return_t
mk_timer_arm(mach_port_name_t port, uint64_t expire_time)
{
	pthread_mutex_lock(&lock);
	struct mk_timer *timer = timer_lookup(port);
	if (timer != NULL) {
		timer->expire_time = (expire_time != 0) ? expire_time : 1;
		thread_start();
		pthread_cond_signal(&wakeup);
	}
	pthread_mutex_unlock(&lock);
	return (timer != NULL) ? KERN_SUCCESS : KERN_INVALID_ARGUMENT;
}

kern_return_t
mk_timer_cancel(mach_port_name_t port, uint64_t *result_time)
{
	pthread_mutex_lock(&lock);
	struct mk_timer *timer = timer_lookup(port);
	if (timer != NULL) {
		if (result_time != NULL) {
			*result_time = timer->expire_time;
		}
		timer->expire_time = 0;
	}
	pthread_mutex_unlock(&lock);
	return (timer != NULL) ? KERN_SUCCESS : KERN_INVALID_ARGUMENT;
}

static struct mk_timer *
timer_lookup(mach_port_name_t port)
{
	for (struct mk_timer *timer = timers; timer != NULL;
			timer = timer->next) {
		if (timer->port == port) {
			return timer;
		}
	}
	return NULL;
}

static void
thread_start(void)
{
	if (thread_started) {
		return;
	}
	thread_started = true;

	pthread_condattr_t attr;
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&wakeup, &attr);
	pthread_condattr_destroy(&attr);

	sigset_t all, previous;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &previous);
	pthread_t handle;
	pthread_create(&handle, NULL, timer_main, NULL);
	pthread_detach(handle);
	pthread_sigmask(SIG_SETMASK, &previous, NULL);
}

static void *
timer_main(void *arg)
{
	pthread_mutex_lock(&lock);
	while (true) {
		struct mk_timer *timer = timer_earliest();
		if (timer == NULL) {
			pthread_cond_wait(&wakeup, &lock);
		} else if (commpage_absolute_time() >= timer->expire_time) {
			timer_fire(timer);
		} else {
			timer_wait(timer->expire_time);
		}
	}
	return NULL;
}

static struct mk_timer *
timer_earliest(void)
{
	struct mk_timer *earliest = NULL;
	for (struct mk_timer *timer = timers; timer != NULL;
			timer = timer->next) {
		if (timer->expire_time != 0
				&& (earliest == NULL
						|| timer->expire_time
								< earliest->expire_time)) {
			earliest = timer;
		}
	}
	return earliest;
}

static void
timer_fire(struct mk_timer *timer)
{
	timer->expire_time = 0;
	mk_timer_expire_msg_t msg = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS(
							MACH_MSG_TYPE_COPY_SEND,
							0),
					.msgh_size = sizeof(msg),
					.msgh_remote_port = timer->port,
			},
	};
	pthread_mutex_unlock(&lock);
	ipc_kernel_send(&msg.header);
	pthread_mutex_lock(&lock);
}

static void
timer_wait(uint64_t expire_time)
{
	struct timespec deadline;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	uint64_t delay = commpage_absolute_to_nanoseconds(
			expire_time - commpage_absolute_time());
	deadline.tv_sec += delay / 1000000000;
	deadline.tv_nsec += delay % 1000000000;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}
	pthread_cond_timedwait(&wakeup, &lock, &deadline);
}
