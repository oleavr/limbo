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
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "check.h"

#define READERS    12
#define WRITERS    3
#define ITERATIONS 20000

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static atomic_int holders;
static atomic_long taken;
static atomic_bool done;
static long written;

static void
hold(unsigned *seed)
{
	unsigned r = rand_r(seed) % 16;
	if (r == 0) {
		sched_yield();
	} else if (r == 1) {
		usleep(50);
	}
}

static void
read_once(unsigned *seed)
{
	CHECK(pthread_rwlock_rdlock(&rwlock) == 0);
	CHECK(atomic_fetch_add(&holders, 1) >= 0);
	hold(seed);
	atomic_fetch_sub(&holders, 1);
	CHECK(pthread_rwlock_unlock(&rwlock) == 0);
	atomic_fetch_add(&taken, 1);
}

static void
write_once(unsigned *seed)
{
	CHECK(pthread_rwlock_wrlock(&rwlock) == 0);
	int expected = 0;
	CHECK(atomic_compare_exchange_strong(&holders, &expected, -1));
	written++;
	hold(seed);
	atomic_store(&holders, 0);
	CHECK(pthread_rwlock_unlock(&rwlock) == 0);
	atomic_fetch_add(&taken, 1);
}

static void *
reader(void *arg)
{
	unsigned seed = (unsigned)(uintptr_t)arg;
	for (int i = 0; i < ITERATIONS; i++) {
		read_once(&seed);
	}
	return NULL;
}

static void *
writer(void *arg)
{
	unsigned seed = (unsigned)(uintptr_t)arg;
	for (int i = 0; i < ITERATIONS / 10; i++) {
		read_once(&seed);
		if (rand_r(&seed) % 4 == 0) {
			write_once(&seed);
		}
		write_once(&seed);
	}
	return NULL;
}

static void *
watchdog(void *arg)
{
	(void)arg;
	long last = -1;
	int still = 0;
	while (!atomic_load(&done)) {
		sleep(1);
		long now = atomic_load(&taken);
		if (now == last && ++still >= 10) {
			fprintf(stderr,
					"rwlock: no lock taken for 10 s after "
					"%ld; "
					"holders %d\n",
					now, atomic_load(&holders));
			abort();
		}
		if (now != last) {
			still = 0;
		}
		last = now;
	}
	return NULL;
}

int
main(void)
{
	pthread_t threads[READERS + WRITERS], dog;
	CHECK(pthread_create(&dog, NULL, watchdog, NULL) == 0);
	for (uintptr_t i = 0; i < READERS + WRITERS; i++) {
		CHECK(pthread_create(&threads[i], NULL,
				      i < READERS ? reader : writer,
				      (void *)(i + 1))
				== 0);
	}
	for (int i = 0; i < READERS + WRITERS; i++) {
		CHECK(pthread_join(threads[i], NULL) == 0);
	}
	atomic_store(&done, true);
	CHECK(pthread_join(dog, NULL) == 0);
	CHECK(atomic_load(&holders) == 0);
	CHECK(written >= (long)WRITERS * (ITERATIONS / 10));
	return 0;
}
