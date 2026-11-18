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
#include "signals.h"
#include "thread.h"
#include "xnu-errno.h"

#define PTHRW_INC        0x100
#define PTHRW_COUNT_MASK 0xffffff00

struct psynch_waiter {
	struct psynch_waiter *next;
	user_addr_t object;
	mach_port_name_t thread;
	_Atomic uint32_t woken;
};

struct psynch_prepost {
	struct psynch_prepost *next;
	user_addr_t object;
	mach_port_name_t thread;
	bool sequenced;
	uint32_t upto;
	uint32_t count;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct psynch_waiter *waiters;
static struct psynch_prepost *preposts;

static int psynch_wait(user_addr_t object, bool sequenced, uint32_t seq,
		int64_t sec, uint32_t nsec);
static bool consume_prepost(user_addr_t object, mach_port_name_t thread,
		bool sequenced, uint32_t seq);
static int wait_for_signal(
		struct psynch_waiter *waiter, int64_t sec, uint32_t nsec);
static void remove_waiter(struct psynch_waiter *waiter);
static void psynch_wake_one(user_addr_t object);
static uint32_t wake_waiters(
		user_addr_t object, mach_port_name_t thread, uint32_t count);
static void add_prepost(user_addr_t object, mach_port_name_t thread,
		bool sequenced, uint32_t upto, uint32_t count);
static uint32_t pending_waiters(uint64_t cvlsgen);

int
sys_psynch_mutexwait(user_addr_t mutex, uint32_t mgen, uint32_t ugen,
		uint64_t tid, uint32_t flags)
{
	return psynch_wait(mutex, false, 0, 0, 0);
}

int
sys_psynch_mutexdrop(user_addr_t mutex, uint32_t mgen, uint32_t ugen,
		uint64_t tid, uint32_t flags)
{
	psynch_wake_one(mutex);
	return 0;
}

int
sys_psynch_cvwait(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen,
		user_addr_t mutex, uint64_t mugen, uint32_t flags, int64_t sec,
		uint32_t nsec)
{
	if (mutex != NULL) {
		psynch_wake_one(mutex);
	}
	return psynch_wait(cv, true, (uint32_t)cvlsgen & PTHRW_COUNT_MASK, sec,
			nsec);
}

static int
psynch_wait(user_addr_t object, bool sequenced, uint32_t seq, int64_t sec,
		uint32_t nsec)
{
	struct psynch_waiter waiter = {
			.object = object,
			.thread = thread_current()->port,
	};

	pthread_mutex_lock(&lock);
	int result = 0;
	if (!consume_prepost(object, waiter.thread, sequenced, seq)) {
		waiter.next = waiters;
		waiters = &waiter;
		result = wait_for_signal(&waiter, sec, nsec);
	}
	pthread_mutex_unlock(&lock);
	return result;
}

static bool
consume_prepost(user_addr_t object, mach_port_name_t thread, bool sequenced,
		uint32_t seq)
{
	for (struct psynch_prepost **p = &preposts; *p != NULL;
			p = &(*p)->next) {
		struct psynch_prepost *prepost = *p;
		if (prepost->object != object
				|| (prepost->thread != MACH_PORT_NULL
						&& prepost->thread != thread)
				|| (prepost->sequenced && sequenced
						&& (int32_t)(seq - prepost->upto)
								> 0)) {
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
		int error = signals_futex_wait(&waiter->woken, &lock,
				timed ? &deadline : NULL);
		if (error == ETIMEDOUT && !waiter->woken) {
			remove_waiter(waiter);
			return _ETIMEDOUT;
		}
		if (error == EINTR && !waiter->woken) {
			remove_waiter(waiter);
			return _EINTR;
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
	pthread_mutex_lock(&lock);
	uint32_t woken = wake_waiters(cv, thread_port, 1);
	if (woken == 0 && pending_waiters(cvlsgen) != 0) {
		add_prepost(cv, thread_port, true,
				(uint32_t)cvlsgen & PTHRW_COUNT_MASK, 1);
		woken = 1;
	}
	pthread_mutex_unlock(&lock);
	return woken * PTHRW_INC;
}

int
sys_psynch_cvbroad(user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen,
		uint32_t flags, user_addr_t mutex, uint64_t mugen, uint64_t tid)
{
	uint32_t pending = pending_waiters(cvlsgen);

	pthread_mutex_lock(&lock);
	uint32_t woken = wake_waiters(cv, MACH_PORT_NULL, pending);
	if (woken < pending) {
		add_prepost(cv, MACH_PORT_NULL, true,
				(uint32_t)cvlsgen & PTHRW_COUNT_MASK,
				pending - woken);
	}
	pthread_mutex_unlock(&lock);
	return pending * PTHRW_INC;
}

static void
psynch_wake_one(user_addr_t object)
{
	pthread_mutex_lock(&lock);
	if (wake_waiters(object, MACH_PORT_NULL, 1) == 0) {
		add_prepost(object, MACH_PORT_NULL, false, 0, 1);
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
		signals_futex_wake(&w->woken);
		woken++;
	}
	return woken;
}

static void
add_prepost(user_addr_t object, mach_port_name_t thread, bool sequenced,
		uint32_t upto, uint32_t count)
{
	for (struct psynch_prepost *p = preposts; p != NULL; p = p->next) {
		if (p->object == object && p->thread == thread
				&& p->sequenced == sequenced) {
			p->count += count;
			if ((int32_t)(upto - p->upto) > 0) {
				p->upto = upto;
			}
			return;
		}
	}

	struct psynch_prepost *prepost = calloc(1, sizeof(*prepost));
	prepost->object = object;
	prepost->thread = thread;
	prepost->sequenced = sequenced;
	prepost->upto = upto;
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
#define PTHRW_BIT_MASK    0xffu
#define PTHRW_MAX_READERS PTHRW_COUNT_MASK
#define PTH_RWL_KBIT      0x01
#define PTH_RWL_EBIT      0x02
#define PTH_RWL_WBIT      0x04
#define PTH_RWL_MBIT      0x40
#define PTH_RWL_IBIT      0x80
#define PTHRW_RWL_INIT    PTH_RWL_IBIT
#define PTH_RWS_SBIT      0x01
#define PTH_RWS_WSVBIT    0x04
#define PTHRW_RWS_INIT    PTH_RWS_SBIT

struct rw_waiter {
	struct rw_waiter *next;
	user_addr_t rwlock;
	uint32_t seq;
	bool write;
	bool granted;
	uint32_t update;
	pthread_cond_t wakeup;
};

struct rw_state {
	struct rw_state *next;
	user_addr_t rwlock;
	uint32_t pp_count;
	uint32_t pp_lseq;
	uint32_t pp_sseq;
	bool overlap;
	bool init_cleared;
	uint32_t nextseqword;
	uint32_t lastseqword;
	uint32_t lastunlockseq;
};

enum rw_prepost_type { RW_PREPOST_NONE, RW_PREPOST_READ, RW_PREPOST_WRITE };

static struct rw_waiter *rw_waiters;
static struct rw_state *rw_states;

static int rw_lock(user_addr_t rwlock, uint32_t lgenval, uint32_t rw_wc,
		bool write);
static struct rw_state *rw_state(user_addr_t rwlock);
static bool rw_check_init(struct rw_state *state, uint32_t lgenval);
static void rw_reset(struct rw_state *state);
static uint32_t seq_diff(uint32_t upto, uint32_t lowest);
static bool seq_higher_eq(uint32_t x, uint32_t y);
static void rw_clear_prepost(struct rw_state *state);
static uint32_t rw_handle_unlock(struct rw_state *state, uint32_t rw_wc,
		enum rw_prepost_type prepost, uint32_t premgen, bool *block);
static struct rw_waiter *rw_lowest(user_addr_t rwlock, bool write);
static uint32_t rw_count(
		user_addr_t rwlock, bool write, bool all, uint32_t upto);
static bool seq_lower_eq(uint32_t x, uint32_t y);
static bool seq_lower(uint32_t x, uint32_t y);
static void rw_wake(struct rw_waiter *waiter, uint32_t update);

int
sys_psynch_rw_rdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval,
		uint32_t rw_wc, int flags)
{
	return rw_lock(rwlock, lgenval, rw_wc, false);
}

int
sys_psynch_rw_wrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval,
		uint32_t rw_wc, int flags)
{
	return rw_lock(rwlock, lgenval, rw_wc, true);
}

int
sys_psynch_rw_unlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval,
		uint32_t rw_wc, int flags)
{
	uint32_t curgen = lgenval & PTHRW_COUNT_MASK;
	pthread_mutex_lock(&lock);
	struct rw_state *state = rw_state(rwlock);
	bool init = rw_check_init(state, lgenval);

	if (state->lastunlockseq != PTHRW_RWL_INIT
			&& seq_lower(ugenval, state->lastunlockseq)) {
		pthread_mutex_unlock(&lock);
		return 0;
	}

	uint32_t diff = seq_diff(lgenval, ugenval);
	uint32_t count = rw_count(rwlock, false, false, curgen)
			+ rw_count(rwlock, true, false, curgen);
	if (count == 0 || count < diff) {
		if ((state->pp_sseq & PTH_RWS_SBIT)
				|| seq_higher_eq(rw_wc, state->pp_sseq)) {
			state->pp_count = diff - count;
			state->pp_lseq = curgen;
			state->pp_sseq = rw_wc;
		}
		pthread_mutex_unlock(&lock);
		return 0;
	}

	if (init && state->init_cleared) {
		state->init_cleared = false;
	}
	rw_clear_prepost(state);
	bool block;
	rw_handle_unlock(state, rw_wc, RW_PREPOST_NONE, 0, &block);
	pthread_mutex_unlock(&lock);
	return 0;
}

static int
rw_lock(user_addr_t rwlock, uint32_t lgenval, uint32_t rw_wc, bool write)
{
	uint32_t lseq = lgenval & PTHRW_COUNT_MASK;
	pthread_mutex_lock(&lock);
	struct rw_state *state = rw_state(rwlock);
	rw_check_init(state, lgenval);

	if (!write && state->overlap && !(rw_wc & PTH_RWS_WSVBIT)
			&& !(lgenval & PTH_RWL_WBIT)
			&& (seq_lower_eq(rw_wc, state->nextseqword)
					|| seq_higher_eq(state->lastseqword,
							rw_wc))) {
		state->nextseqword += PTHRW_INC;
		uint32_t update = PTHRW_INC
				| (state->nextseqword & PTHRW_BIT_MASK)
				| PTH_RWL_MBIT;
		pthread_mutex_unlock(&lock);
		return (int)update;
	}

	if (state->pp_count != 0 && seq_lower_eq(lseq, state->pp_lseq)) {
		state->pp_count--;
		if (state->pp_count == 0) {
			uint32_t sseq = state->pp_sseq;
			rw_clear_prepost(state);
			state->init_cleared = false;
			bool block;
			uint32_t update = rw_handle_unlock(state, sseq,
					write ? RW_PREPOST_WRITE
					      : RW_PREPOST_READ,
					lseq, &block);
			if (!block) {
				pthread_mutex_unlock(&lock);
				return (int)update;
			}
		}
	}

	struct rw_waiter waiter = {
			.rwlock = rwlock,
			.seq = lseq,
			.write = write,
	};
	pthread_cond_init(&waiter.wakeup, NULL);
	waiter.next = rw_waiters;
	rw_waiters = &waiter;
	while (!waiter.granted) {
		pthread_cond_wait(&waiter.wakeup, &lock);
	}
	pthread_mutex_unlock(&lock);
	pthread_cond_destroy(&waiter.wakeup);
	return (int)waiter.update;
}

static struct rw_state *
rw_state(user_addr_t rwlock)
{
	for (struct rw_state *state = rw_states; state != NULL;
			state = state->next) {
		if (state->rwlock == rwlock) {
			return state;
		}
	}
	struct rw_state *state = calloc(1, sizeof(*state));
	state->rwlock = rwlock;
	rw_reset(state);
	state->next = rw_states;
	rw_states = state;
	return state;
}

static bool
rw_check_init(struct rw_state *state, uint32_t lgenval)
{
	if (!(lgenval & PTHRW_RWL_INIT)) {
		return false;
	}
	if (!state->init_cleared) {
		rw_reset(state);
		state->init_cleared = true;
	}
	return true;
}

static void
rw_reset(struct rw_state *state)
{
	state->nextseqword = PTHRW_RWS_INIT;
	state->overlap = false;
	rw_clear_prepost(state);
	state->lastunlockseq = PTHRW_RWL_INIT;
	state->lastseqword = PTHRW_RWS_INIT;
}

static uint32_t
seq_diff(uint32_t upto, uint32_t lowest)
{
	uint32_t x = upto & PTHRW_COUNT_MASK, y = lowest & PTHRW_COUNT_MASK;
	if (x == y) {
		return 0;
	}
	if (seq_lower(x, y)) {
		uint32_t swap = x;
		x = y;
		y = swap;
	}
	uint32_t diff = x > y ? x - y : (PTHRW_MAX_READERS - y) + x + PTHRW_INC;
	return diff >> PTHRW_COUNT_SHIFT;
}

static bool
seq_higher_eq(uint32_t x, uint32_t y)
{
	return (x & PTHRW_COUNT_MASK) == (y & PTHRW_COUNT_MASK)
			|| seq_lower(y, x);
}

static void
rw_clear_prepost(struct rw_state *state)
{
	state->pp_count = 0;
	state->pp_lseq = 0;
	state->pp_sseq = PTHRW_RWS_INIT;
}

static uint32_t
rw_handle_unlock(struct rw_state *state, uint32_t rw_wc,
		enum rw_prepost_type prepost, uint32_t premgen, bool *block)
{
	user_addr_t rwlock = state->rwlock;
	*block = true;
	state->lastseqword = rw_wc;
	state->lastunlockseq = rw_wc & PTHRW_COUNT_MASK;
	state->overlap = false;

	struct rw_waiter *first_reader = rw_lowest(rwlock, false);
	struct rw_waiter *first_writer = rw_lowest(rwlock, true);
	bool readers = first_reader != NULL || prepost == RW_PREPOST_READ;
	bool writers = first_writer != NULL || prepost == RW_PREPOST_WRITE;
	uint32_t low_reader
			= first_reader != NULL ? first_reader->seq : premgen;
	if (prepost == RW_PREPOST_READ && first_reader != NULL
			&& seq_lower(premgen, low_reader)) {
		low_reader = premgen;
	}
	uint32_t low_writer
			= first_writer != NULL ? first_writer->seq : premgen;
	if (prepost == RW_PREPOST_WRITE && first_writer != NULL
			&& seq_lower(premgen, low_writer)) {
		low_writer = premgen;
	}
	if (!readers && !writers) {
		return 0;
	}

	uint32_t update = 0;
	if (readers && (!writers || seq_lower(low_reader, low_writer))) {
		bool current = false;
		uint32_t needed;
		if (writers) {
			update |= PTH_RWL_WBIT | PTH_RWL_KBIT;
			needed = rw_count(rwlock, false, false, low_writer);
			if (prepost == RW_PREPOST_READ
					&& seq_lower(premgen, low_writer)) {
				current = true;
				needed++;
			}
		} else {
			state->overlap = true;
			needed = rw_count(rwlock, false, true, 0);
			if (prepost == RW_PREPOST_READ) {
				current = true;
				needed++;
			}
		}
		update += needed << PTHRW_COUNT_SHIFT;
		state->nextseqword = (rw_wc & PTHRW_COUNT_MASK) + update;
		if (current) {
			*block = false;
		}
		struct rw_waiter *w;
		while ((w = rw_lowest(rwlock, false)) != NULL
				&& (!writers
						|| seq_lower(w->seq,
								low_writer))) {
			rw_wake(w, update);
		}
		return update;
	}

	update = PTHRW_INC | PTH_RWL_KBIT | PTH_RWL_EBIT;
	if (prepost == RW_PREPOST_WRITE && low_writer == premgen) {
		*block = false;
		if (first_writer != NULL) {
			update |= PTH_RWL_WBIT;
		}
	} else {
		if (rw_count(rwlock, true, true, 0) > 1
				|| prepost == RW_PREPOST_WRITE) {
			update |= PTH_RWL_WBIT;
		}
		rw_wake(first_writer, update);
	}
	state->nextseqword = (rw_wc & PTHRW_COUNT_MASK) + update;
	return update;
}

static struct rw_waiter *
rw_lowest(user_addr_t rwlock, bool write)
{
	struct rw_waiter *lowest = NULL;
	for (struct rw_waiter *w = rw_waiters; w != NULL; w = w->next) {
		if (w->rwlock == rwlock && !w->granted && w->write == write
				&& (lowest == NULL
						|| seq_lower(w->seq,
								lowest->seq))) {
			lowest = w;
		}
	}
	return lowest;
}

static uint32_t
rw_count(user_addr_t rwlock, bool write, bool all, uint32_t upto)
{
	uint32_t count = 0;
	for (struct rw_waiter *w = rw_waiters; w != NULL; w = w->next) {
		if (w->rwlock == rwlock && !w->granted && w->write == write
				&& (all || seq_lower_eq(w->seq, upto))) {
			count++;
		}
	}
	return count;
}

static bool
seq_lower_eq(uint32_t x, uint32_t y)
{
	return (x & PTHRW_COUNT_MASK) == (y & PTHRW_COUNT_MASK)
			|| seq_lower(x, y);
}

static bool
seq_lower(uint32_t x, uint32_t y)
{
	x &= PTHRW_COUNT_MASK;
	y &= PTHRW_COUNT_MASK;
	return x < y ? y - x < PTHRW_MAX_READERS / 2
		     : x - y > PTHRW_MAX_READERS / 2;
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
