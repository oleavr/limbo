/*
 * Copyright © 2026 Ole André Vadla Ravnås
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

#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "check.h"

#define THREADS    8
#define ITERATIONS 10000

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_key_t key;
static int counter;
static int initializations;

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static atomic_int holders;
static int written;

static pthread_cond_t handoff = PTHREAD_COND_INITIALIZER;
static pthread_t main_thread;
static int turn;
static bool by_name;

static atomic_bool spun;
static atomic_bool times_read;
static atomic_bool waiting;
static atomic_bool listed;

static void *increment(void *arg);
static void initialize(void);
static void *produce(void *arg);
static void *read_and_write(void *arg);
static void *change_directory(void *arg);
static void *take_turns(void *arg);
static void hand_over(pthread_t to);
static void check_identifiers(void);
static void *wait_for_lock(void *arg);
static void check_dispatch_queue(void *queue);
static thread_identifier_info_data_t identifier_info(pthread_t thread);
static void check_thread_times(void);
static void *spin_then_wait(void *arg);
static uint64_t cpu_microseconds(pthread_t thread);
static uint64_t microseconds(time_value_t time);
static void check_thread_name(void);
static thread_extended_info_data_t extended_info(void);
static void check_task_threads(void);
static void *wait_until_listed(void *arg);

extern int __pthread_fchdir(int fd);
extern int __proc_info(int callnum, int pid, int flavor, uint64_t arg,
		void *buffer, int buffersize);

int
main(void)
{
	CHECK(pthread_key_create(&key, NULL) == 0);

	pthread_t threads[THREADS];
	for (intptr_t i = 0; i < THREADS; i++) {
		CHECK(pthread_create(&threads[i], NULL, increment, (void *)i)
				== 0);
	}
	for (intptr_t i = 0; i < THREADS; i++) {
		void *result;
		CHECK(pthread_join(threads[i], &result) == 0);
		CHECK(result == (void *)(i + 1));
	}
	CHECK(counter == THREADS * ITERATIONS);
	CHECK(initializations == 1);

	pthread_t producer;
	CHECK(pthread_create(&producer, NULL, produce, NULL) == 0);
	pthread_mutex_lock(&lock);
	while (counter != 0) {
		pthread_cond_wait(&changed, &lock);
	}
	pthread_mutex_unlock(&lock);
	CHECK(pthread_join(producer, NULL) == 0);

	for (intptr_t i = 0; i < THREADS; i++) {
		CHECK(pthread_create(&threads[i], NULL, read_and_write,
				      (void *)i)
				== 0);
	}
	for (intptr_t i = 0; i < THREADS; i++) {
		CHECK(pthread_join(threads[i], NULL) == 0);
	}
	CHECK(written == THREADS / 2 * ITERATIONS / 10);

	main_thread = pthread_self();
	for (int round = 0; round < 2; round++) {
		by_name = round == 0;
		pthread_t partner;
		CHECK(pthread_create(&partner, NULL, take_turns, NULL) == 0);
		pthread_mutex_lock(&lock);
		for (int i = 0; i < ITERATIONS; i++) {
			turn = 1;
			hand_over(partner);
			while (turn != 0) {
				pthread_cond_wait(&handoff, &lock);
			}
		}
		pthread_mutex_unlock(&lock);
		CHECK(pthread_join(partner, NULL) == 0);
	}

	char before[PATH_MAX], after[PATH_MAX];
	CHECK(getcwd(before, sizeof(before)) != NULL);
	pthread_t changer;
	CHECK(pthread_create(&changer, NULL, change_directory, NULL) == 0);
	CHECK(pthread_join(changer, NULL) == 0);
	CHECK(getcwd(after, sizeof(after)) != NULL);
	CHECK(strcmp(before, after) == 0);

	uint64_t wall_start = clock_gettime_nsec_np(CLOCK_MONOTONIC);
	uint64_t start = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID);
	CHECK(start != 0);
	volatile uint64_t sum = 0;
	for (int i = 0; i != 10000000; i++) {
		sum += i;
	}
	uint64_t spent = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - start;
	CHECK(spent > 0);
	CHECK(spent <= clock_gettime_nsec_np(CLOCK_MONOTONIC) - wall_start);

	CHECK(qos_class_main() != QOS_CLASS_UNSPECIFIED);

	char name[32];
	CHECK(pthread_setname_np("limbo-main") == 0);
	CHECK(pthread_getname_np(pthread_self(), name, sizeof(name)) == 0);
	CHECK(strcmp(name, "limbo-main") == 0);

	check_identifiers();
	check_thread_times();
	check_thread_name();
	check_task_threads();
	return 0;
}

static void *
increment(void *arg)
{
	pthread_once(&once, initialize);
	CHECK(pthread_setspecific(key, arg) == 0);
	for (int i = 0; i < ITERATIONS; i++) {
		pthread_mutex_lock(&lock);
		counter++;
		pthread_mutex_unlock(&lock);
	}
	CHECK(pthread_getspecific(key) == arg);
	return (void *)((intptr_t)arg + 1);
}

static void
initialize(void)
{
	initializations++;
}

static void *
produce(void *arg)
{
	while (true) {
		pthread_mutex_lock(&lock);
		int remaining = counter = (counter > 1000) ? counter - 1000 : 0;
		pthread_cond_signal(&changed);
		pthread_mutex_unlock(&lock);
		if (remaining == 0) {
			return NULL;
		}
	}
}

static void *
read_and_write(void *arg)
{
	bool writer = (intptr_t)arg % 2 == 0;
	int iterations = writer ? ITERATIONS / 10 : ITERATIONS;
	for (int i = 0; i < iterations; i++) {
		if (writer) {
			CHECK(pthread_rwlock_wrlock(&rwlock) == 0);
			int expected = 0;
			CHECK(atomic_compare_exchange_strong(
					&holders, &expected, -1));
			written++;
			atomic_store(&holders, 0);
		} else {
			CHECK(pthread_rwlock_rdlock(&rwlock) == 0);
			CHECK(atomic_fetch_add(&holders, 1) >= 0);
			atomic_fetch_sub(&holders, 1);
		}
		CHECK(pthread_rwlock_unlock(&rwlock) == 0);
	}
	return NULL;
}

static void *
take_turns(void *arg)
{
	(void)arg;
	pthread_mutex_lock(&lock);
	for (int i = 0; i < ITERATIONS; i++) {
		while (turn != 1) {
			pthread_cond_wait(&handoff, &lock);
		}
		turn = 0;
		hand_over(main_thread);
	}
	pthread_mutex_unlock(&lock);
	return NULL;
}

static void
hand_over(pthread_t to)
{
	if (by_name) {
		CHECK(pthread_cond_signal_thread_np(&handoff, to) == 0);
	} else {
		CHECK(pthread_cond_broadcast(&handoff) == 0);
	}
}

static void *
change_directory(void *arg)
{
	(void)arg;
	char process[PATH_MAX], own[PATH_MAX];
	CHECK(getcwd(process, sizeof(process)) != NULL);
	int fd = open("/private/var", O_RDONLY | O_DIRECTORY);
	CHECK(fd != -1);
	CHECK(__pthread_fchdir(fd) == 0);
	CHECK(close(fd) == 0);
	CHECK(getcwd(own, sizeof(own)) != NULL);
	CHECK(strcmp(own, "/private/var") == 0);
	CHECK(__pthread_fchdir(-1) == 0);
	CHECK(getcwd(own, sizeof(own)) != NULL);
	CHECK(strcmp(own, process) == 0);
	return NULL;
}

static void
check_identifiers(void)
{
	thread_identifier_info_data_t info = identifier_info(pthread_self());
	uint64_t id;
	CHECK(pthread_threadid_np(NULL, &id) == 0);
	CHECK(info.thread_id == id);
	CHECK(*(pthread_t *)info.thread_handle == pthread_self());

	pthread_t waiter;
	pthread_mutex_lock(&lock);
	CHECK(pthread_create(&waiter, NULL, wait_for_lock, NULL) == 0);
	info = identifier_info(waiter);
	CHECK(*(pthread_t *)info.thread_handle == waiter);
	pthread_mutex_unlock(&lock);
	void *waiter_id;
	CHECK(pthread_join(waiter, &waiter_id) == 0);
	CHECK(info.thread_id == (uint64_t)waiter_id);

	dispatch_queue_t queue = dispatch_queue_create("limbo.threads", NULL);
	dispatch_sync_f(queue, queue, check_dispatch_queue);
	dispatch_release(queue);

	pid_t child = fork();
	if (child == 0) {
		CHECK(pthread_threadid_np(NULL, &id) == 0);
		CHECK(identifier_info(pthread_self()).thread_id == id);
		_exit(0);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void *
wait_for_lock(void *arg)
{
	uint64_t id;
	CHECK(pthread_threadid_np(NULL, &id) == 0);
	pthread_mutex_lock(&lock);
	pthread_mutex_unlock(&lock);
	return (void *)id;
}

static void
check_dispatch_queue(void *queue)
{
	thread_identifier_info_data_t info = identifier_info(pthread_self());
	CHECK(*(void **)info.dispatch_qaddr == queue);
}

static thread_identifier_info_data_t
identifier_info(pthread_t thread)
{
	thread_identifier_info_data_t info;
	mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
	CHECK(thread_info(pthread_mach_thread_np(thread),
			      THREAD_IDENTIFIER_INFO, (thread_info_t)&info,
			      &count)
			== KERN_SUCCESS);
	return info;
}

static void
check_thread_times(void)
{
	pthread_t spinner;
	CHECK(pthread_create(&spinner, NULL, spin_then_wait, NULL) == 0);
	while (!spun) {
		usleep(1000);
	}
	CHECK(cpu_microseconds(spinner) >= 200000);

	thread_basic_info_data_t info;
	for (int tries = 0; tries < 1000; tries++) {
		mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
		CHECK(thread_info(pthread_mach_thread_np(spinner),
				      THREAD_BASIC_INFO, (thread_info_t)&info,
				      &count)
				== KERN_SUCCESS);
		if (info.run_state == TH_STATE_WAITING) {
			break;
		}
		usleep(1000);
	}
	CHECK(info.run_state == TH_STATE_WAITING);

	task_thread_times_info_data_t live;
	mach_msg_type_number_t count = TASK_THREAD_TIMES_INFO_COUNT;
	CHECK(task_info(mach_task_self(), TASK_THREAD_TIMES_INFO,
			      (task_info_t)&live, &count)
			== KERN_SUCCESS);
	CHECK(microseconds(live.user_time) + microseconds(live.system_time)
			>= 200000);

	task_absolutetime_info_data_t absolute;
	count = TASK_ABSOLUTETIME_INFO_COUNT;
	CHECK(task_info(mach_task_self(), TASK_ABSOLUTETIME_INFO,
			      (task_info_t)&absolute, &count)
			== KERN_SUCCESS);
	mach_timebase_info_data_t timebase;
	mach_timebase_info(&timebase);
	uint64_t live_absolute
			= absolute.threads_user + absolute.threads_system;
	CHECK(live_absolute * timebase.numer / timebase.denom >= 200000000);

	times_read = true;
	CHECK(pthread_join(spinner, NULL) == 0);
}

static void *
spin_then_wait(void *arg)
{
	uint64_t start = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID);
	volatile uint64_t sum = 0;
	while (clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - start
			< 300000000) {
		for (int i = 0; i != 100000; i++) {
			sum += i;
		}
	}
	CHECK(cpu_microseconds(pthread_self()) >= 200000);
	spun = true;
	while (!times_read) {
		usleep(1000);
	}
	return NULL;
}

static uint64_t
cpu_microseconds(pthread_t thread)
{
	thread_basic_info_data_t info;
	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	CHECK(thread_info(pthread_mach_thread_np(thread), THREAD_BASIC_INFO,
			      (thread_info_t)&info, &count)
			== KERN_SUCCESS);
	return microseconds(info.user_time) + microseconds(info.system_time);
}

static uint64_t
microseconds(time_value_t time)
{
	return (uint64_t)time.seconds * 1000000 + time.microseconds;
}

static void
check_thread_name(void)
{
	enum { PROC_INFO_CALL_SETCONTROL = 5 };
	char name[MAXTHREADNAMESIZE + 1];
	memset(name, 'n', sizeof(name));
	CHECK(__proc_info(PROC_INFO_CALL_SETCONTROL, getpid(),
			      PROC_SELFSET_THREADNAME, 0, name,
			      MAXTHREADNAMESIZE)
			== -1);
	CHECK(errno == ENAMETOOLONG);
	CHECK(__proc_info(PROC_INFO_CALL_SETCONTROL, getpid(),
			      PROC_SELFSET_THREADNAME, 0, name,
			      MAXTHREADNAMESIZE - 1)
			== 0);
	CHECK(strlen(extended_info().pth_name) == MAXTHREADNAMESIZE - 1);

	const char *longer_than_comm = "a name longer than fifteen bytes";
	CHECK(pthread_setname_np(longer_than_comm) == 0);
	CHECK(strcmp(extended_info().pth_name, longer_than_comm) == 0);
	CHECK(pthread_setname_np("") == 0);
	CHECK(extended_info().pth_name[0] == '\0');
}

static thread_extended_info_data_t
extended_info(void)
{
	thread_extended_info_data_t info;
	mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
	CHECK(thread_info(mach_thread_self(), THREAD_EXTENDED_INFO,
			      (thread_info_t)&info, &count)
			== KERN_SUCCESS);
	return info;
}

static void
check_task_threads(void)
{
	pthread_t waiter;
	CHECK(pthread_create(&waiter, NULL, wait_until_listed, NULL) == 0);
	while (!waiting) {
		usleep(1000);
	}
	mach_port_t waiter_port = pthread_mach_thread_np(waiter);
	mach_port_urefs_t held, holds;
	CHECK(mach_port_get_refs(mach_task_self(), waiter_port,
			      MACH_PORT_RIGHT_SEND, &held)
			== KERN_SUCCESS);

	thread_act_array_t threads;
	mach_msg_type_number_t count;
	CHECK(task_threads(mach_task_self(), &threads, &count) == KERN_SUCCESS);
	CHECK(count >= 2);
	CHECK(threads[0] == pthread_mach_thread_np(pthread_self()));
	bool found = false;
	for (mach_msg_type_number_t i = 0; i < count; i++) {
		found |= threads[i] == waiter_port;
	}
	CHECK(found);
	CHECK(mach_port_get_refs(mach_task_self(), waiter_port,
			      MACH_PORT_RIGHT_SEND, &holds)
			== KERN_SUCCESS);
	CHECK(holds == held + 1);
	for (mach_msg_type_number_t i = 0; i < count; i++) {
		CHECK(mach_port_deallocate(mach_task_self(), threads[i])
				== KERN_SUCCESS);
	}
	CHECK(vm_deallocate(mach_task_self(), (vm_address_t)threads,
			      count * sizeof(*threads))
			== KERN_SUCCESS);

	listed = true;
	CHECK(pthread_join(waiter, NULL) == 0);
	CHECK(task_threads(mach_host_self(), &threads, &count)
			== KERN_INVALID_ARGUMENT);
}

static void *
wait_until_listed(void *arg)
{
	waiting = true;
	while (!listed) {
		usleep(1000);
	}
	return NULL;
}
