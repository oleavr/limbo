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

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "handler.h"
#include "thread.h"
#include "xnu-errno.h"

#define PTHRW_INC        0x100
#define PTHRW_COUNT_MASK 0xffffff00

struct psynch_waiter {
	struct psynch_waiter *next;
	user_addr_t object;
	mach_port_name_t thread;
	pthread_cond_t wakeup;
	bool woken;
};

struct psynch_prepost {
	struct psynch_prepost *next;
	user_addr_t object;
	uint32_t count;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct psynch_waiter *waiters;
static struct psynch_prepost *preposts;

static int psynch_wait(user_addr_t object, int64_t sec, uint32_t nsec);
static bool consume_prepost(user_addr_t object);
static int wait_for_signal(
		struct psynch_waiter *waiter, int64_t sec, uint32_t nsec);
static void remove_waiter(struct psynch_waiter *waiter);
static void psynch_wake_one(user_addr_t object);
static uint32_t wake_waiters(
		user_addr_t object, mach_port_name_t thread, uint32_t count);
static void add_prepost(user_addr_t object, uint32_t count);
static uint32_t pending_waiters(uint64_t cvlsgen);

int
sys_psynch_mutexwait(user_addr_t mutex, uint32_t mgen, uint32_t ugen,
		uint64_t tid, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "psynch_mutexwait(%p, %#x, %#x, %#lx, %#x)\n", mutex,
			mgen, ugen, tid, flags);
#endif
	return psynch_wait(mutex, 0, 0);
}

int
sys_psynch_mutexdrop(user_addr_t mutex, uint32_t mgen, uint32_t ugen,
		uint64_t tid, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "psynch_mutexdrop(%p, %#x, %#x, %#lx, %#x)\n", mutex,
			mgen, ugen, tid, flags);
#endif
	psynch_wake_one(mutex);
	return 0;
}

int
sys_psynch_cvwait(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen,
		user_addr_t mutex, uint64_t mugen, uint32_t flags, int64_t sec,
		uint32_t nsec)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"psynch_cvwait(%p, %#lx, %#x, %p, %#lx, %#x, %ld, "
			"%u)\n",
			cv, cvlsgen, cvugen, mutex, mugen, flags, sec, nsec);
#endif
	if (mutex != NULL) {
		psynch_wake_one(mutex);
	}
	return psynch_wait(cv, sec, nsec);
}

static int
psynch_wait(user_addr_t object, int64_t sec, uint32_t nsec)
{
	struct psynch_waiter waiter = {
			.object = object,
			.thread = thread_current()->port,
	};
	pthread_cond_init(&waiter.wakeup, NULL);

	pthread_mutex_lock(&lock);
	int result = 0;
	if (!consume_prepost(object)) {
		waiter.next = waiters;
		waiters = &waiter;
		result = wait_for_signal(&waiter, sec, nsec);
	}
	pthread_mutex_unlock(&lock);

	pthread_cond_destroy(&waiter.wakeup);
	return result;
}

static bool
consume_prepost(user_addr_t object)
{
	for (struct psynch_prepost **p = &preposts; *p != NULL;
			p = &(*p)->next) {
		struct psynch_prepost *prepost = *p;
		if (prepost->object != object) {
			continue;
		}
		if (--prepost->count == 0) {
			*p = prepost->next;
			free(prepost);
		}
		return true;
	}
	return false;
}

static int
wait_for_signal(struct psynch_waiter *waiter, int64_t sec, uint32_t nsec)
{
	bool timed = sec != 0 || nsec != 0;
	struct timespec deadline;
	if (timed) {
		clock_gettime(CLOCK_REALTIME, &deadline);
		deadline.tv_sec += sec;
		deadline.tv_nsec += nsec;
		if (deadline.tv_nsec >= 1000000000) {
			deadline.tv_sec++;
			deadline.tv_nsec -= 1000000000;
		}
	}

	while (!waiter->woken) {
		int error = timed ? pthread_cond_timedwait(&waiter->wakeup,
						    &lock, &deadline)
				  : pthread_cond_wait(&waiter->wakeup, &lock);
		if (error == ETIMEDOUT && !waiter->woken) {
			remove_waiter(waiter);
			return _ETIMEDOUT;
		}
	}
	return 0;
}

static void
remove_waiter(struct psynch_waiter *waiter)
{
	for (struct psynch_waiter **p = &waiters; *p != NULL; p = &(*p)->next) {
		if (*p == waiter) {
			*p = waiter->next;
			return;
		}
	}
}

int
sys_psynch_cvsignal(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen,
		int thread_port, user_addr_t mutex, uint64_t mugen,
		uint64_t tid, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"psynch_cvsignal(%p, %#lx, %#x, %#x, %p, %#lx, %#lx, "
			"%#x)\n",
			cv, cvlsgen, cvugen, thread_port, mutex, mugen, tid,
			flags);
#endif
	pthread_mutex_lock(&lock);
	uint32_t woken = wake_waiters(cv, thread_port, 1);
	if (woken == 0 && thread_port == 0 && pending_waiters(cvlsgen) != 0) {
		add_prepost(cv, 1);
		woken = 1;
	}
	pthread_mutex_unlock(&lock);
	return woken * PTHRW_INC;
}

int
sys_psynch_cvbroad(user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen,
		uint32_t flags, user_addr_t mutex, uint64_t mugen, uint64_t tid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "psynch_cvbroad(%p, %#lx, %#lx, %#x, %p, %#lx, %#lx)\n",
			cv, cvlsgen, cvudgen, flags, mutex, mugen, tid);
#endif
	uint32_t pending = pending_waiters(cvlsgen);

	pthread_mutex_lock(&lock);
	uint32_t woken = wake_waiters(cv, MACH_PORT_NULL, pending);
	if (woken < pending) {
		add_prepost(cv, pending - woken);
	}
	pthread_mutex_unlock(&lock);
	return pending * PTHRW_INC;
}

static void
psynch_wake_one(user_addr_t object)
{
	pthread_mutex_lock(&lock);
	if (wake_waiters(object, MACH_PORT_NULL, 1) == 0) {
		add_prepost(object, 1);
	}
	pthread_mutex_unlock(&lock);
}

static uint32_t
wake_waiters(user_addr_t object, mach_port_name_t thread, uint32_t count)
{
	uint32_t woken = 0;
	struct psynch_waiter **p = &waiters;
	while (*p != NULL && woken < count) {
		struct psynch_waiter *w = *p;
		if (w->object != object
				|| (thread != MACH_PORT_NULL
						&& w->thread != thread)) {
			p = &w->next;
			continue;
		}

		*p = w->next;
		w->woken = true;
		pthread_cond_signal(&w->wakeup);
		woken++;
	}
	return woken;
}

static void
add_prepost(user_addr_t object, uint32_t count)
{
	for (struct psynch_prepost *p = preposts; p != NULL; p = p->next) {
		if (p->object == object) {
			p->count += count;
			return;
		}
	}

	struct psynch_prepost *prepost = calloc(1, sizeof(*prepost));
	prepost->object = object;
	prepost->count = count;
	prepost->next = preposts;
	preposts = prepost;
}

static uint32_t
pending_waiters(uint64_t cvlsgen)
{
	uint32_t lseq = (uint32_t)cvlsgen & PTHRW_COUNT_MASK;
	uint32_t sseq = (uint32_t)(cvlsgen >> 32) & PTHRW_COUNT_MASK;
	return (lseq - sseq) / PTHRW_INC;
}

int
sys_psynch_cvclrprepost(user_addr_t cv, uint32_t cvgen, uint32_t cvugen,
		uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq,
		uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"psynch_cvclrprepost(%p, %#x, %#x, %#x, %#x, %#x, "
			"%#x)\n",
			cv, cvgen, cvugen, cvsgen, prepocnt, preposeq, flags);
#endif
	pthread_mutex_lock(&lock);
	for (struct psynch_prepost **p = &preposts; *p != NULL;
			p = &(*p)->next) {
		struct psynch_prepost *prepost = *p;
		if (prepost->object == cv) {
			*p = prepost->next;
			free(prepost);
			break;
		}
	}
	pthread_mutex_unlock(&lock);
	return 0;
}

#define PTHRW_COUNT_SHIFT 8
#define PTH_RWL_KBIT      0x01
#define PTH_RWL_EBIT      0x02
#define PTH_RWL_WBIT      0x04
#define PTH_RWL_MBIT      0x40
#define PTH_RWS_WSVBIT    0x04

struct rw_waiter {
	struct rw_waiter *next;
	user_addr_t rwlock;
	uint32_t seq;
	bool write;
	bool granted;
	uint32_t update;
	pthread_cond_t wakeup;
};

struct rw_prepost {
	struct rw_prepost *next;
	user_addr_t rwlock;
	bool pending;
	uint32_t lseq;
	uint32_t sseq;
	bool overlap;
	uint32_t overlap_sseq;
	uint32_t granted_sseq;
};

static struct rw_waiter *rw_waiters;
static struct rw_prepost *rw_preposts;

static int rw_lock(user_addr_t rwlock, uint32_t lgenval, bool write);
static bool rw_all_arrived(user_addr_t rwlock, uint32_t sseq, uint32_t lseq);
static void rw_grant(user_addr_t rwlock, uint32_t sseq);
static struct rw_waiter *rw_waiter_at(user_addr_t rwlock, uint32_t seq);
static void rw_wake(struct rw_waiter *waiter, uint32_t update);
static struct rw_prepost **rw_prepost_find(user_addr_t rwlock);
static struct rw_prepost *rw_state(user_addr_t rwlock);

int
sys_psynch_rw_rdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval,
		uint32_t rw_wc, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "psynch_rw_rdlock(%p, %#x, %#x, %#x, %#x)\n", rwlock,
			lgenval, ugenval, rw_wc, flags);
#endif
	pthread_mutex_lock(&lock);
	struct rw_prepost *state = *rw_prepost_find(rwlock);
	uint32_t sseq = rw_wc & PTHRW_COUNT_MASK;
	if (state != NULL && state->overlap && !(rw_wc & PTH_RWS_WSVBIT)
			&& !(lgenval & PTH_RWL_WBIT)
			&& ((int32_t)(state->granted_sseq - sseq) >= 0
					|| (int32_t)(sseq - state->overlap_sseq)
							<= 0)) {
		state->granted_sseq += PTHRW_INC;
		pthread_mutex_unlock(&lock);
		return PTHRW_INC | PTH_RWL_MBIT;
	}
	pthread_mutex_unlock(&lock);
	return rw_lock(rwlock, lgenval, false);
}

int
sys_psynch_rw_wrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval,
		uint32_t rw_wc, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "psynch_rw_wrlock(%p, %#x, %#x, %#x, %#x)\n", rwlock,
			lgenval, ugenval, rw_wc, flags);
#endif
	return rw_lock(rwlock, lgenval, true);
}

int
sys_psynch_rw_unlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval,
		uint32_t rw_wc, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "psynch_rw_unlock(%p, %#x, %#x, %#x, %#x)\n", rwlock,
			lgenval, ugenval, rw_wc, flags);
#endif
	uint32_t lseq = lgenval & PTHRW_COUNT_MASK;
	uint32_t sseq = rw_wc & PTHRW_COUNT_MASK;

	pthread_mutex_lock(&lock);
	struct rw_prepost *state = rw_state(rwlock);
	state->overlap = false;
	state->overlap_sseq = sseq;
	if (rw_all_arrived(rwlock, sseq, lseq)) {
		rw_grant(rwlock, sseq);
	} else {
		state->pending = true;
		state->lseq = lseq;
		state->sseq = sseq;
	}
	pthread_mutex_unlock(&lock);
	return 0;
}

static int
rw_lock(user_addr_t rwlock, uint32_t lgenval, bool write)
{
	struct rw_waiter waiter = {
			.rwlock = rwlock,
			.seq = lgenval & PTHRW_COUNT_MASK,
			.write = write,
	};
	pthread_cond_init(&waiter.wakeup, NULL);

	pthread_mutex_lock(&lock);
	waiter.next = rw_waiters;
	rw_waiters = &waiter;

	struct rw_prepost *prepost = *rw_prepost_find(rwlock);
	if (prepost != NULL && prepost->pending
			&& rw_all_arrived(
					rwlock, prepost->sseq, prepost->lseq)) {
		prepost->pending = false;
		rw_grant(rwlock, prepost->sseq);
	}

	while (!waiter.granted) {
		pthread_cond_wait(&waiter.wakeup, &lock);
	}
	pthread_mutex_unlock(&lock);

	pthread_cond_destroy(&waiter.wakeup);
	return (int)waiter.update;
}

static bool
rw_all_arrived(user_addr_t rwlock, uint32_t sseq, uint32_t lseq)
{
	for (uint32_t seq = sseq + PTHRW_INC; (int32_t)(lseq - seq) >= 0;
			seq += PTHRW_INC) {
		if (rw_waiter_at(rwlock, seq) == NULL) {
			return false;
		}
	}
	return true;
}

static void
rw_grant(user_addr_t rwlock, uint32_t sseq)
{
	uint32_t next = sseq + PTHRW_INC;
	struct rw_waiter *first = rw_waiter_at(rwlock, next);
	if (first == NULL) {
		return;
	}

	bool writers = false;
	for (struct rw_waiter *w = rw_waiters; w != NULL; w = w->next) {
		if (w->rwlock == rwlock && w->write && w != first) {
			writers = true;
		}
	}

	if (first->write) {
		uint32_t update = PTHRW_INC | PTH_RWL_KBIT | PTH_RWL_EBIT;
		rw_wake(first, writers ? update | PTH_RWL_WBIT : update);
		return;
	}

	uint32_t count = 0;
	for (uint32_t seq = next;; seq += PTHRW_INC) {
		struct rw_waiter *w = rw_waiter_at(rwlock, seq);
		if (w == NULL || w->write) {
			break;
		}
		count++;
	}
	uint32_t update = count << PTHRW_COUNT_SHIFT;
	if (writers) {
		update |= PTH_RWL_WBIT | PTH_RWL_KBIT;
	} else {
		struct rw_prepost *state = rw_state(rwlock);
		state->overlap = true;
		state->granted_sseq = sseq + count * PTHRW_INC;
	}
	for (uint32_t i = 0; i < count; i++) {
		rw_wake(rw_waiter_at(rwlock, next + i * PTHRW_INC), update);
	}
}

static struct rw_waiter *
rw_waiter_at(user_addr_t rwlock, uint32_t seq)
{
	for (struct rw_waiter *w = rw_waiters; w != NULL; w = w->next) {
		if (w->rwlock == rwlock && w->seq == seq) {
			return w;
		}
	}
	return NULL;
}

static void
rw_wake(struct rw_waiter *waiter, uint32_t update)
{
	for (struct rw_waiter **p = &rw_waiters; *p != NULL; p = &(*p)->next) {
		if (*p == waiter) {
			*p = waiter->next;
			break;
		}
	}
	waiter->granted = true;
	waiter->update = update;
	pthread_cond_signal(&waiter->wakeup);
}

static struct rw_prepost *
rw_state(user_addr_t rwlock)
{
	struct rw_prepost *state = *rw_prepost_find(rwlock);
	if (state == NULL) {
		state = calloc(1, sizeof(*state));
		state->rwlock = rwlock;
		state->next = rw_preposts;
		rw_preposts = state;
	}
	return state;
}

static struct rw_prepost **
rw_prepost_find(user_addr_t rwlock)
{
	struct rw_prepost **link = &rw_preposts;
	while (*link != NULL && (*link)->rwlock != rwlock) {
		link = &(*link)->next;
	}
	return link;
}
