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

#include <mach/mach.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>

#include "handler.h"
#include "kevent.h"
#include "osfmk/ipc.h"
#include "osfmk/semaphore.h"
#include "thread.h"
#include "workq.h"
#include "xnu-errno.h"

#define PTHREAD_FEATURE_DISPATCHFUNC    0x01
#define PTHREAD_FEATURE_FINEPRIO        0x02
#define PTHREAD_FEATURE_BSDTHREADCTL    0x04
#define PTHREAD_FEATURE_SETSELF         0x08
#define PTHREAD_FEATURE_QOS_MAINTENANCE 0x10
#define PTHREAD_FEATURE_QOS_DEFAULT     0x40000000

#define WORKQ_FEATURE_KEVENT   0x40
#define WORKQ_FEATURE_WORKLOOP 0x80

#define PTHREAD_START_TSD_BASE_SET 0x10000000

#define MAIN_THREAD_PRIORITY 0x8ff
#define PTHREAD_START_SUSPENDED    0x20000000

#define BSDTHREAD_CTL_SET_QOS                         0x10
#define BSDTHREAD_CTL_QOS_OVERRIDE_START              0x40
#define BSDTHREAD_CTL_QOS_OVERRIDE_END                0x80
#define BSDTHREAD_CTL_SET_SELF                        0x100
#define BSDTHREAD_CTL_QOS_OVERRIDE_RESET              0x200
#define BSDTHREAD_CTL_QOS_OVERRIDE_DISPATCH           0x400
#define BSDTHREAD_CTL_QOS_DISPATCH_ASYNC_OVERRIDE_ADD 0x401
#define BSDTHREAD_CTL_QOS_DISPATCH_ASYNC_OVERRIDE_RST 0x402
#define BSDTHREAD_CTL_QOS_MAX_PARALLELISM             0x800
#define BSDTHREAD_CTL_WORKQ_ALLOW_KILL                0x1000

#define WQOPS_THREAD_RETURN              0x004
#define WQOPS_QUEUE_REQTHREADS           0x020
#define WQOPS_QUEUE_REQTHREADS2          0x030
#define WQOPS_THREAD_KEVENT_RETURN       0x040
#define WQOPS_SET_EVENT_MANAGER_PRIORITY 0x080
#define WQOPS_THREAD_WORKLOOP_RETURN     0x100
#define WQOPS_SHOULD_NARROW              0x200
#define WQOPS_SETUP_DISPATCH             0x400

#define WQ_FLAG_THREAD_PRIO_QOS      0x00004000
#define WQ_FLAG_THREAD_OVERCOMMIT    0x00010000
#define WQ_FLAG_THREAD_REUSE         0x00020000
#define WQ_FLAG_THREAD_NEWSPI        0x00040000
#define WQ_FLAG_THREAD_KEVENT        0x00080000
#define WQ_FLAG_THREAD_EVENT_MANAGER 0x00100000
#define WQ_FLAG_THREAD_TSD_BASE_SET  0x00200000
#define WQ_FLAG_THREAD_WORKLOOP      0x00400000
#define WQ_FLAG_THREAD_COOPERATIVE   0x01000000

#define PTHREAD_PRIORITY_OVERCOMMIT_FLAG  0x80000000
#define PTHREAD_PRIORITY_COOPERATIVE_FLAG 0x08000000
#define PTHREAD_PRIORITY_QOS_CLASS_MASK  0x003fff00
#define PTHREAD_PRIORITY_QOS_CLASS_SHIFT 8

#define WORKQ_QOS_COUNT        7

enum {
	WORKQ_CONSTRAINED,
	WORKQ_OVERCOMMIT,
	WORKQ_COOPERATIVE,
};
#define WORKQ_STACK_SIZE       (512 * 1024)
#define WORKQ_KEVENT_LIST_LEN  16
#define WORKQ_KEVENT_DATA_SIZE (32 * 1024)

struct pthread_registration_data {
	uint64_t version;
	uint64_t dispatch_queue_offset;
	uint64_t main_qos;
	uint32_t tsd_offset;
	uint32_t return_to_kernel_offset;
	uint32_t mach_thread_self_offset;
	uint64_t stack_addr_hint;
} __attribute__((packed));

struct workq_request {
	uint32_t qos;
	bool overcommit;
	bool cooperative;
	struct kqueue *kq;
	bool manager;
};

struct workq_kqueue_request {
	struct workq_kqueue_request *next;
	struct workq_request request;
};

struct workq_thread {
	uint8_t *allocation;
	size_t allocation_size;
	uint64_t self;
	uint64_t stack_bottom;
	uint64_t stack_top;
	struct workq_request request;
	bool started;
};

static struct {
	uint64_t threadstart;
	uint64_t wqthread;
	uint32_t pthread_size;
	uint32_t tsd_offset;
	uint32_t mach_thread_self_offset;
} registration;

static struct {
	pthread_mutex_t lock;
	pthread_cond_t wakeup;
	uint32_t requests[WORKQ_QOS_COUNT][WORKQ_COOPERATIVE + 1];
	struct workq_kqueue_request *kqueue_requests;
	struct workq_kqueue_request **kqueue_requests_tail;
	uint32_t idle;
	uint32_t constrained;
} workq = {
		.lock = PTHREAD_MUTEX_INITIALIZER,
		.wakeup = PTHREAD_COND_INITIALIZER,
		.kqueue_requests_tail = &workq.kqueue_requests,
};

static void workq_schedule(void);
static uint32_t workq_pending(void);
static bool workq_claim(struct workq_request *request);
static void workq_spawn(const struct workq_request *request);
static bool workq_continue(struct thread *thread, struct thread_state *state);
static void workq_thread_state(struct workq_thread *wt, uint32_t flags,
		mach_port_name_t kport, struct thread_state *state);
static uint32_t workq_flags(const struct workq_request *request);

int
sys_bsdthread_register(user_addr_t threadstart, user_addr_t wqthread,
		uint32_t pthread_size, user_addr_t data, uint32_t data_size,
		uint32_t dispatch_queue_offset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "bsdthread_register(%p, %p, %p, %p, %p, %p)\n",
			threadstart, wqthread, (void *)(uintptr_t)pthread_size,
			data, (void *)(uintptr_t)data_size,
			(void *)(uintptr_t)dispatch_queue_offset);
#endif
	struct pthread_registration_data *d = data;
#ifndef __x86_64__
	asm("xpaci %0" : "+r"(threadstart));
	asm("xpaci %0" : "+r"(wqthread));
#endif
	registration.threadstart = (uint64_t)threadstart;
	registration.wqthread = (uint64_t)wqthread;
	registration.pthread_size = pthread_size;
	registration.tsd_offset = d->tsd_offset;
	registration.mach_thread_self_offset = d->mach_thread_self_offset;
	if (data_size >= offsetof(struct pthread_registration_data, main_qos)
					+ sizeof(d->main_qos)) {
		d->main_qos = MAIN_THREAD_PRIORITY;
	}

	return PTHREAD_FEATURE_DISPATCHFUNC | PTHREAD_FEATURE_FINEPRIO
			| PTHREAD_FEATURE_BSDTHREADCTL | PTHREAD_FEATURE_SETSELF
			| PTHREAD_FEATURE_QOS_MAINTENANCE
			| PTHREAD_FEATURE_QOS_DEFAULT | WORKQ_FEATURE_KEVENT
			| WORKQ_FEATURE_WORKLOOP;
}

user_addr_t
sys_bsdthread_create(user_addr_t func, user_addr_t func_arg, user_addr_t stack,
		user_addr_t pthread, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "bsdthread_create(%p, %p, %p, %p, %p)\n", func,
			func_arg, stack, pthread, (void *)(uintptr_t)flags);
#endif
	struct thread *thread = thread_new(NULL, NULL);
	mach_port_name_t kport = ipc_kobject_copy_send(thread->port);
	uint64_t tsd_base = (uint64_t)pthread + registration.tsd_offset;
	*(mach_port_name_t *)(tsd_base + registration.mach_thread_self_offset)
			= kport;

#ifdef __x86_64__
	struct thread_state state = {
			.rip = registration.threadstart,
			.rsp = (uint64_t)stack,
			.rdi = (uint64_t)pthread,
			.rsi = kport,
			.rdx = (uint64_t)func,
			.rcx = (uint64_t)func_arg,
			.r8 = (uint64_t)stack,
			.r9 = (flags & ~PTHREAD_START_SUSPENDED)
					| PTHREAD_START_TSD_BASE_SET,
			.gs_base = tsd_base,
	};
#else
	struct thread_state state = {
			.pc = registration.threadstart,
			.sp = (uint64_t)stack,
			.x = { (uint64_t)pthread, kport, (uint64_t)func,
					(uint64_t)func_arg, (uint64_t)stack,
					(flags & ~PTHREAD_START_SUSPENDED)
							| PTHREAD_START_TSD_BASE_SET },
			.tpidr = tsd_base,
	};
#endif

	int error = thread_start(thread, &state);
	if (error != 0) {
		return (user_addr_t)(intptr_t)err_map(error);
	}
	return pthread;
}

int
sys_bsdthread_terminate(user_addr_t stackaddr, size_t freesize, uint32_t port,
		uint32_t sem)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "bsdthread_terminate(%p, %p, %p, %p)\n", stackaddr,
			(void *)freesize, (void *)(uintptr_t)port,
			(void *)(uintptr_t)sem);
#endif
	ipc_port_deallocate(port);
	if (sem != MACH_PORT_NULL) {
		semaphore_signal(sem);
	}
	thread_exit(stackaddr, freesize);
}

int
sys_workq_open(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "workq_open()\n");
#endif
	return 0;
}

int
sys_workq_kernreturn(int options, user_addr_t item, int affinity, int prio)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "workq_kernreturn(%p, %p, %p, %p)\n",
			(void *)(intptr_t)options, item,
			(void *)(intptr_t)affinity, (void *)(intptr_t)prio);
#endif
	switch (options) {
	case WQOPS_QUEUE_REQTHREADS:
	case WQOPS_QUEUE_REQTHREADS2: {
		uint32_t classes
				= ((uint32_t)prio & PTHREAD_PRIORITY_QOS_CLASS_MASK)
				>> PTHREAD_PRIORITY_QOS_CLASS_SHIFT;
		uint32_t kind = WORKQ_CONSTRAINED;
		if ((uint32_t)prio & PTHREAD_PRIORITY_OVERCOMMIT_FLAG) {
			kind = WORKQ_OVERCOMMIT;
		} else if ((uint32_t)prio & PTHREAD_PRIORITY_COOPERATIVE_FLAG) {
			kind = WORKQ_COOPERATIVE;
		}
		pthread_mutex_lock(&workq.lock);
		workq.requests[ffs(classes)][kind] += affinity;
		workq_schedule();
		pthread_mutex_unlock(&workq.lock);
		return 0;
	}
	case WQOPS_THREAD_RETURN:
		thread_block();
	case WQOPS_THREAD_KEVENT_RETURN:
	case WQOPS_THREAD_WORKLOOP_RETURN: {
		struct workq_thread *wt = thread_current()->context;
		kevent_unbind(wt->request.kq, wt->request.manager, item,
				affinity);
		thread_block();
	}
	case WQOPS_SET_EVENT_MANAGER_PRIORITY:
	case WQOPS_SHOULD_NARROW:
	case WQOPS_SETUP_DISPATCH:
		return 0;
	default:
		unimplemented();
	}
}

static void
workq_schedule(void)
{
	uint32_t pending = workq_pending();
	if (workq.idle > 0) {
		pthread_cond_broadcast(&workq.wakeup);
	}

	struct workq_request request;
	while (pending > workq.idle && workq_claim(&request)) {
		workq_spawn(&request);
		pending--;
	}
}

static uint32_t
workq_pending(void)
{
	uint32_t pending = 0;
	for (struct workq_kqueue_request *kr = workq.kqueue_requests;
			kr != NULL; kr = kr->next) {
		pending++;
	}
	for (uint32_t qos = 0; qos < WORKQ_QOS_COUNT; qos++) {
		pending += workq.requests[qos][WORKQ_CONSTRAINED]
				+ workq.requests[qos][WORKQ_OVERCOMMIT]
				+ workq.requests[qos][WORKQ_COOPERATIVE];
	}
	return pending;
}

static bool
workq_claim(struct workq_request *request)
{
	struct workq_kqueue_request *kr = workq.kqueue_requests;
	if (kr != NULL) {
		workq.kqueue_requests = kr->next;
		if (workq.kqueue_requests == NULL) {
			workq.kqueue_requests_tail = &workq.kqueue_requests;
		}
		*request = kr->request;
		free(kr);
		return true;
	}

	bool constrained_allowed
			= workq.constrained < sysconf(_SC_NPROCESSORS_ONLN);
	for (int32_t qos = WORKQ_QOS_COUNT - 1; qos >= 0; qos--) {
		if (workq.requests[qos][WORKQ_OVERCOMMIT] > 0) {
			workq.requests[qos][WORKQ_OVERCOMMIT]--;
			*request = (struct workq_request){
					.qos = qos,
					.overcommit = true,
			};
			return true;
		}
		if (constrained_allowed
				&& workq.requests[qos][WORKQ_CONSTRAINED] > 0) {
			workq.requests[qos][WORKQ_CONSTRAINED]--;
			workq.constrained++;
			*request = (struct workq_request){.qos = qos};
			return true;
		}
		if (constrained_allowed
				&& workq.requests[qos][WORKQ_COOPERATIVE] > 0) {
			workq.requests[qos][WORKQ_COOPERATIVE]--;
			workq.constrained++;
			*request = (struct workq_request){
					.qos = qos,
					.cooperative = true,
			};
			return true;
		}
	}
	return false;
}

static void
workq_spawn(const struct workq_request *request)
{
	struct workq_thread *wt = calloc(1, sizeof(*wt));
	wt->allocation_size = PAGE_SIZE + WORKQ_STACK_SIZE
			+ registration.pthread_size;
	wt->allocation = mmap(NULL, wt->allocation_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	mprotect(wt->allocation, PAGE_SIZE, PROT_NONE);
	wt->stack_bottom = (uint64_t)wt->allocation + PAGE_SIZE;
	wt->stack_top = wt->stack_bottom + WORKQ_STACK_SIZE;
	wt->self = wt->stack_top;
	wt->request = *request;

	thread_start(thread_new(workq_continue, wt), NULL);
}

static bool
workq_continue(struct thread *thread, struct thread_state *state)
{
	struct workq_thread *wt = thread->context;

	if (!wt->started) {
		wt->started = true;
		workq_thread_state(wt,
				workq_flags(&wt->request)
						| WQ_FLAG_THREAD_TSD_BASE_SET,
				ipc_kobject_copy_send(thread->port), state);
		return true;
	}

	pthread_mutex_lock(&workq.lock);
	if (!wt->request.overcommit) {
		workq.constrained--;
	}
	while (!workq_claim(&wt->request)) {
		workq.idle++;
		pthread_cond_wait(&workq.wakeup, &workq.lock);
		workq.idle--;
	}
	pthread_mutex_unlock(&workq.lock);

	workq_thread_state(wt, workq_flags(&wt->request) | WQ_FLAG_THREAD_REUSE,
			thread->port, state);
	return true;
}

static void
workq_thread_state(struct workq_thread *wt, uint32_t flags,
		mach_port_name_t kport, struct thread_state *state)
{
#ifdef __x86_64__
	*state = (struct thread_state){
			.rip = registration.wqthread,
			.rsp = wt->stack_top,
			.rdi = wt->self,
			.rsi = kport,
			.rdx = wt->stack_bottom,
			.r8 = flags,
			.gs_base = wt->self + registration.tsd_offset,
	};
#else
	*state = (struct thread_state){
			.pc = registration.wqthread,
			.sp = wt->stack_top,
			.x = { wt->self, kport, wt->stack_bottom, 0, flags },
			.tpidr = wt->self + registration.tsd_offset,
	};
#endif

	struct kqueue *kq = wt->request.kq;
	if (kq == NULL) {
		return;
	}

	struct kevent_qos_s *events = (struct kevent_qos_s *)(wt->self
			- WORKQ_KEVENT_LIST_LEN * sizeof(struct kevent_qos_s));
	uint64_t *kqid = (uint64_t *)events - 1;
	*kqid = kevent_kqid(kq);
	uint64_t nevents = kevent_bind(kq, wt->request.manager, events,
			WORKQ_KEVENT_LIST_LEN,
			(uint8_t *)kqid - WORKQ_KEVENT_DATA_SIZE,
			WORKQ_KEVENT_DATA_SIZE);
	uint64_t new_sp = ((uint64_t)kqid - WORKQ_KEVENT_DATA_SIZE) & ~15ULL;
#ifdef __x86_64__
	state->rcx = (uint64_t)events;
	state->r9 = nevents;
	state->rsp = new_sp;
#else
	state->x[3] = (uint64_t)events;
	state->x[5] = nevents;
	state->sp = new_sp;
#endif
}

static uint32_t
workq_flags(const struct workq_request *request)
{
	uint32_t flags = WQ_FLAG_THREAD_NEWSPI;
	if (request->manager) {
		flags |= WQ_FLAG_THREAD_EVENT_MANAGER;
	} else {
		flags |= WQ_FLAG_THREAD_PRIO_QOS | request->qos;
	}
	if (request->overcommit) {
		flags |= WQ_FLAG_THREAD_OVERCOMMIT;
	}
	if (request->cooperative) {
		flags |= WQ_FLAG_THREAD_COOPERATIVE;
	}
	if (request->kq != NULL) {
		flags |= WQ_FLAG_THREAD_KEVENT;
		if (kevent_kqid(request->kq) != 0) {
			flags |= WQ_FLAG_THREAD_WORKLOOP;
		}
	}
	return flags;
}

void
workq_request_kqueue(struct kqueue *kq, uint32_t qos, bool manager)
{
	struct workq_kqueue_request *kr = calloc(1, sizeof(*kr));
	kr->request = (struct workq_request){
			.qos = qos,
			.overcommit = true,
			.kq = kq,
			.manager = manager,
	};

	pthread_mutex_lock(&workq.lock);
	*workq.kqueue_requests_tail = kr;
	workq.kqueue_requests_tail = &kr->next;
	workq_schedule();
	pthread_mutex_unlock(&workq.lock);
}

uint64_t
sys_thread_selfid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_selfid()\n");
#endif
	return gettid();
}

int
sys_bsdthread_ctl(user_addr_t cmd, user_addr_t arg1, user_addr_t arg2,
		user_addr_t arg3)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "bsdthread_ctl(%p, %p, %p, %p)\n", cmd, arg1, arg2,
			arg3);
#endif
	switch ((uintptr_t)cmd) {
	case BSDTHREAD_CTL_QOS_MAX_PARALLELISM:
		return sysconf(_SC_NPROCESSORS_ONLN);
	case BSDTHREAD_CTL_SET_QOS:
	case BSDTHREAD_CTL_QOS_OVERRIDE_START:
	case BSDTHREAD_CTL_QOS_OVERRIDE_END:
	case BSDTHREAD_CTL_SET_SELF:
	case BSDTHREAD_CTL_QOS_OVERRIDE_RESET:
	case BSDTHREAD_CTL_QOS_OVERRIDE_DISPATCH:
	case BSDTHREAD_CTL_QOS_DISPATCH_ASYNC_OVERRIDE_ADD:
	case BSDTHREAD_CTL_QOS_DISPATCH_ASYNC_OVERRIDE_RST:
	case BSDTHREAD_CTL_WORKQ_ALLOW_KILL:
		return 0;
	default:
		unimplemented();
	}
}
