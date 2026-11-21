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
#include <mach/mach_time.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

#include "check.h"

#define MELC_OPTION_NO_COPYIN         0x1
#define MELA_OPTION_NONE              0x0
#define MELA_OPTION_ASSOCIATE_ON_WAIT 0x1
#define MELD_OPTION_NONE              0x0
#define MELSW_OPTION_NONE             0x0
#define MELSW_OPTION_NO_WAIT          0x1
#define KERN_CLOCK_MACH_ABSOLUTE_TIME 1

kern_return_t mach_eventlink_create(
		task_t task, uint32_t option, mach_port_t eventlink_pair[2]);
kern_return_t mach_eventlink_destroy(mach_port_t eventlink);
kern_return_t mach_eventlink_associate(mach_port_t eventlink, thread_t thread,
		mach_vm_address_t copyin_addr_wait, uint64_t copyin_mask_wait,
		mach_vm_address_t copyin_addr_signal,
		uint64_t copyin_mask_signal, uint32_t option);
kern_return_t mach_eventlink_disassociate(
		mach_port_t eventlink, uint32_t option);
kern_return_t mach_eventlink_signal(
		mach_port_t eventlink, uint64_t signal_count);
kern_return_t mach_eventlink_wait_until(mach_port_t eventlink, uint64_t *count,
		uint32_t option, uint32_t clock_id, uint64_t deadline);
kern_return_t mach_eventlink_signal_wait_until(mach_port_t eventlink,
		uint64_t *count, uint64_t signal_count, uint32_t option,
		uint32_t clock_id, uint64_t deadline);

static mach_port_t ends[2];

static void check_pairs(void);
static void check_association(void);
static void check_counts(void);
static void check_waits(void);
static void *wait_for_count(void *arg);
static void ignore_signal(int sig);
static void check_abandoned_waits(void);
static void check_destroyed(void);
static void *wait_until_destroyed(void *arg);
static void create_pair(void);
static uint64_t deadline_after(uint64_t milliseconds);

int
main(void)
{
	check_pairs();
	check_association();
	check_counts();
	check_waits();
	check_abandoned_waits();
	check_destroyed();
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
check_association(void)
{
	create_pair();
	mach_port_t thread = mach_thread_self();
	CHECK(mach_eventlink_associate(ends[1], MACH_PORT_NULL, 0, 0, 0, 0,
			      MELA_OPTION_NONE)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_eventlink_associate(ends[1], thread, 0, 0, 0, 0,
			      MELA_OPTION_ASSOCIATE_ON_WAIT)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_eventlink_associate(
			      ends[1], thread, 0, 0, 0, 0, MELA_OPTION_NONE)
			== KERN_SUCCESS);
	CHECK(mach_eventlink_associate(
			      ends[1], thread, 0, 0, 0, 0, MELA_OPTION_NONE)
			== KERN_NAME_EXISTS);
	CHECK(mach_eventlink_disassociate(ends[1], MELD_OPTION_NONE)
			== KERN_SUCCESS);
	CHECK(mach_eventlink_disassociate(ends[1], MELD_OPTION_NONE)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_eventlink_associate(ends[1], MACH_PORT_NULL, 0, 0, 0, 0,
			      MELA_OPTION_ASSOCIATE_ON_WAIT)
			== KERN_SUCCESS);

	CHECK(mach_eventlink_destroy(ends[0]) == KERN_SUCCESS);
	CHECK(mach_eventlink_associate(
			      ends[1], thread, 0, 0, 0, 0, MELA_OPTION_NONE)
			== KERN_TERMINATED);
	CHECK(mach_eventlink_destroy(ends[1]) == KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), thread) == KERN_SUCCESS);
}

static void
check_counts(void)
{
	create_pair();
	mach_port_t thread = mach_thread_self();
	uint64_t count = 0;
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_eventlink_signal(ends[0], 0) == KERN_SUCCESS);
	CHECK(mach_eventlink_associate(
			      ends[1], thread, 0, 0, 0, 0, MELA_OPTION_NONE)
			== KERN_SUCCESS);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_SUCCESS);
	CHECK(count == 1);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_OPERATION_TIMED_OUT);
	CHECK(count == 1);
	CHECK(mach_eventlink_wait_until(
			      ends[1], &count, MELSW_OPTION_NO_WAIT, 0, 0)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NONE,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, deadline_after(20))
			== KERN_OPERATION_TIMED_OUT);
	CHECK(count == 1);

	CHECK(mach_eventlink_signal(ends[0], 0) == KERN_SUCCESS);
	CHECK(mach_eventlink_signal(ends[0], 0) == KERN_SUCCESS);
	count = 0;
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NONE,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_SUCCESS);
	CHECK(count == 3);
	count = 7;
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_OPERATION_TIMED_OUT);
	CHECK(count == 3);

	CHECK(mach_eventlink_associate(
			      ends[0], thread, 0, 0, 0, 0, MELA_OPTION_NONE)
			== KERN_SUCCESS);
	CHECK(mach_eventlink_signal(ends[1], 0) == KERN_SUCCESS);
	uint64_t other = 0;
	CHECK(mach_eventlink_signal_wait_until(ends[0], &other, 0,
			      MELSW_OPTION_NONE, KERN_CLOCK_MACH_ABSOLUTE_TIME,
			      0)
			== KERN_SUCCESS);
	CHECK(other == 1);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_SUCCESS);
	CHECK(count == 4);

	CHECK(mach_eventlink_destroy(ends[0]) == KERN_SUCCESS);
	CHECK(mach_eventlink_destroy(ends[1]) == KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), thread) == KERN_SUCCESS);
}

static void
check_waits(void)
{
	create_pair();
	mach_port_t thread = mach_thread_self();
	CHECK(mach_eventlink_associate(
			      ends[1], thread, 0, 0, 0, 0, MELA_OPTION_NONE)
			== KERN_SUCCESS);
	uint64_t waited = 0;
	pthread_t waiter;
	void *result;
	CHECK(pthread_create(&waiter, NULL, wait_for_count, &waited) == 0);
	CHECK(pthread_join(waiter, &result) == 0);
	CHECK((kern_return_t)(intptr_t)result == KERN_INVALID_ARGUMENT);

	struct sigaction action = {.sa_handler = ignore_signal};
	CHECK(sigaction(SIGALRM, &action, NULL) == 0);
	uint64_t count = 0;
	kern_return_t aborted = KERN_OPERATION_TIMED_OUT;
	for (int tries = 0; tries < 5 && aborted == KERN_OPERATION_TIMED_OUT;
			tries++) {
		ualarm(100000, 0);
		aborted = mach_eventlink_wait_until(ends[1], &count,
				MELSW_OPTION_NONE,
				KERN_CLOCK_MACH_ABSOLUTE_TIME,
				deadline_after(1000));
	}
	CHECK(aborted == KERN_ABORTED);
	CHECK(count == 0);
	signal(SIGALRM, SIG_DFL);

	CHECK(mach_eventlink_disassociate(ends[1], MELD_OPTION_NONE)
			== KERN_SUCCESS);
	CHECK(mach_eventlink_associate(ends[1], MACH_PORT_NULL, 0, 0, 0, 0,
			      MELA_OPTION_ASSOCIATE_ON_WAIT)
			== KERN_SUCCESS);
	CHECK(pthread_create(&waiter, NULL, wait_for_count, &waited) == 0);
	usleep(100000);
	CHECK(mach_eventlink_signal(ends[0], 0) == KERN_SUCCESS);
	CHECK(pthread_join(waiter, &result) == 0);
	CHECK((kern_return_t)(intptr_t)result == KERN_SUCCESS);
	CHECK(waited == 1);

	CHECK(mach_eventlink_destroy(ends[0]) == KERN_SUCCESS);
	CHECK(mach_eventlink_destroy(ends[1]) == KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), thread) == KERN_SUCCESS);
}

static void *
wait_for_count(void *arg)
{
	return (void *)(intptr_t)mach_eventlink_wait_until(ends[1], arg,
			MELSW_OPTION_NONE, KERN_CLOCK_MACH_ABSOLUTE_TIME,
			deadline_after(2000));
}

static void
ignore_signal(int sig)
{
}

static void
check_abandoned_waits(void)
{
	create_pair();
	CHECK(mach_eventlink_associate(ends[1], MACH_PORT_NULL, 0, 0, 0, 0,
			      MELA_OPTION_ASSOCIATE_ON_WAIT)
			== KERN_SUCCESS);
	uint64_t count = 0;
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NONE,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, deadline_after(20))
			== KERN_OPERATION_TIMED_OUT);
	CHECK(count == 0);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NONE,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, deadline_after(20))
			== KERN_INVALID_ARGUMENT);
	CHECK(count == 0);
	CHECK(mach_eventlink_signal(ends[0], 0) == KERN_SUCCESS);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_SUCCESS);
	CHECK(count == 1);

	struct sigaction action = {.sa_handler = ignore_signal};
	CHECK(sigaction(SIGALRM, &action, NULL) == 0);
	kern_return_t aborted = KERN_OPERATION_TIMED_OUT;
	ualarm(100000, 100000);
	aborted = mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NONE,
			KERN_CLOCK_MACH_ABSOLUTE_TIME, deadline_after(1000));
	ualarm(0, 0);
	CHECK(aborted == KERN_ABORTED);
	CHECK(count == 1);
	signal(SIGALRM, SIG_DFL);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_eventlink_signal(ends[0], 0) == KERN_SUCCESS);
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_SUCCESS);
	CHECK(count == 2);

	CHECK(mach_eventlink_destroy(ends[0]) == KERN_SUCCESS);
	CHECK(mach_eventlink_destroy(ends[1]) == KERN_SUCCESS);
}

static void
check_destroyed(void)
{
	create_pair();
	CHECK(mach_eventlink_associate(ends[1], MACH_PORT_NULL, 0, 0, 0, 0,
			      MELA_OPTION_ASSOCIATE_ON_WAIT)
			== KERN_SUCCESS);
	pthread_t waiter;
	void *result;
	CHECK(pthread_create(&waiter, NULL, wait_until_destroyed, NULL) == 0);
	usleep(100000);
	CHECK(mach_eventlink_destroy(ends[0]) == KERN_SUCCESS);
	CHECK(pthread_join(waiter, &result) == 0);
	CHECK((kern_return_t)(intptr_t)result == KERN_TERMINATED);

	uint64_t count = 0;
	CHECK(mach_eventlink_wait_until(ends[1], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_TERMINATED);
	CHECK(mach_eventlink_signal(ends[1], 0) == KERN_TERMINATED);
	CHECK(mach_eventlink_wait_until(ends[0], &count, MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_INVALID_NAME);
	CHECK(mach_eventlink_wait_until(mach_task_self(), &count,
			      MELSW_OPTION_NO_WAIT,
			      KERN_CLOCK_MACH_ABSOLUTE_TIME, 0)
			== KERN_INVALID_CAPABILITY);
	CHECK(mach_eventlink_destroy(ends[1]) == KERN_SUCCESS);

	create_pair();
	CHECK(mach_eventlink_associate(ends[1], MACH_PORT_NULL, 0, 0, 0, 0,
			      MELA_OPTION_ASSOCIATE_ON_WAIT)
			== KERN_SUCCESS);
	CHECK(pthread_create(&waiter, NULL, wait_until_destroyed, NULL) == 0);
	usleep(100000);
	CHECK(mach_port_deallocate(mach_task_self(), ends[0]) == KERN_SUCCESS);
	CHECK(pthread_join(waiter, &result) == 0);
	CHECK((kern_return_t)(intptr_t)result == KERN_TERMINATED);
	CHECK(mach_eventlink_destroy(ends[1]) == KERN_SUCCESS);
}

static void *
wait_until_destroyed(void *arg)
{
	uint64_t count = 0;
	return (void *)(intptr_t)mach_eventlink_wait_until(ends[1], &count,
			MELSW_OPTION_NONE, KERN_CLOCK_MACH_ABSOLUTE_TIME,
			deadline_after(2000));
}

static void
create_pair(void)
{
	CHECK(mach_eventlink_create(
			      mach_task_self(), MELC_OPTION_NO_COPYIN, ends)
			== KERN_SUCCESS);
}

static uint64_t
deadline_after(uint64_t milliseconds)
{
	mach_timebase_info_data_t timebase;
	mach_timebase_info(&timebase);
	return mach_absolute_time()
			+ milliseconds * 1000000 * timebase.denom
			/ timebase.numer;
}
