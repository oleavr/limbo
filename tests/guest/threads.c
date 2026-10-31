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

#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
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

static void *increment(void *arg);
static void initialize(void);
static void *produce(void *arg);
static void *read_and_write(void *arg);
static void *change_directory(void *arg);
static void *take_turns(void *arg);
static void hand_over(pthread_t to);

extern int __pthread_fchdir(int fd);

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

	uint64_t start = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID);
	CHECK(start != 0);
	volatile uint64_t sum = 0;
	for (int i = 0; i != 10000000; i++) {
		sum += i;
	}
	CHECK(clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) > start);

	CHECK(qos_class_main() != QOS_CLASS_UNSPECIFIED);

	char name[32];
	CHECK(pthread_setname_np("limbo-main") == 0);
	CHECK(pthread_getname_np(pthread_self(), name, sizeof(name)) == 0);
	CHECK(strcmp(name, "limbo-main") == 0);
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
