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
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "commpage.h"
#include "handler.h"
#include "kevent.h"
#include "osfmk/ipc.h"
#include "signals.h"
#include "thread.h"
#include "workq.h"
#include "xnu-errno.h"

#define EVFILT_READ     -1
#define EVFILT_WRITE    -2
#define EVFILT_PROC     -5
#define EVFILT_SIGNAL   -6
#define EVFILT_MACHPORT -8
#define EVFILT_TIMER    -7
#define EVFILT_USER     -10
#define EVFILT_SOCK     -13
#define EVFILT_WORKLOOP -17

#define EV_ADD            0x0001
#define EV_DELETE         0x0002
#define EV_ENABLE         0x0004
#define EV_DISABLE        0x0008
#define EV_ONESHOT        0x0010
#define EV_CLEAR          0x0020
#define EV_RECEIPT        0x0040
#define EV_DISPATCH       0x0080
#define EV_UDATA_SPECIFIC 0x0100
#define EV_VANISHED       0x0200
#define EV_ERROR          0x4000
#define EV_EOF            0x8000

#define KEVENT_FLAG_IMMEDIATE                 0x000001
#define KEVENT_FLAG_ERROR_EVENTS              0x000002
#define KEVENT_FLAG_WORKQ                     0x000020
#define KEVENT_FLAG_WORKQ_MANAGER             0x000200
#define KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST     0x020000
#define KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST 0x040000

#define NOTE_TRIGGER    0x01000000
#define NOTE_FFAND      0x40000000
#define NOTE_FFOR       0x80000000
#define NOTE_FFCOPY     0xc0000000
#define NOTE_FFCTRLMASK 0xc0000000
#define NOTE_FFLAGSMASK 0x00ffffff

#define NOTE_SECONDS  0x00000001
#define NOTE_USECONDS 0x00000002
#define NOTE_NSECONDS 0x00000004
#define NOTE_ABSOLUTE 0x00000008
#define NOTE_MACHTIME 0x00000100

#define NOTE_EXIT 0x80000000

#define NOTE_WL_THREAD_REQUEST 0x00000001
#define NOTE_WL_SYNC_WAIT      0x00000004
#define NOTE_WL_SYNC_WAKE      0x00000008
#define NOTE_WL_SYNC_IPC       0x80000000
#define NOTE_WL_COMMANDS_MASK  0x8000000f
#define NOTE_WL_END_OWNERSHIP  0x00000020
#define NOTE_WL_DISCOVER_OWNER 0x00000080
#define NOTE_WL_IGNORE_ESTALE  0x00000100

#define EV_EXTIDX_WL_ADDR  1
#define EV_EXTIDX_WL_MASK  2
#define EV_EXTIDX_WL_VALUE 3

#define PTHREAD_PRIORITY_EVENT_MANAGER_FLAG 0x02000000
#define PTHREAD_PRIORITY_QOS_CLASS_MASK     0x003fff00
#define PTHREAD_PRIORITY_QOS_CLASS_SHIFT    8

#define THREAD_QOS_LEGACY 4

typedef enum {
	KQUEUE_WORKQ,
	KQUEUE_WORKLOOP,
	KQUEUE_FD,
} kqueue_kind_t;

struct knote {
	struct knote *next;
	struct kqueue *kq;
	struct kevent_qos_s kev;
	bool active;
	bool disabled;
	bool manager;
	bool woken;
	bool waiting;
	bool deleted;
	bool in_flight;
	bool defer_delete;
	uint64_t deadline;
	uint64_t interval;

	uint32_t proc_fflags;
	struct proc_watch *watch;
	uint32_t sock_interest;
	uint32_t sock_reported;
};

#define NOTE_CONNRESET    0x00000001
#define NOTE_READCLOSED   0x00000002
#define NOTE_WRITECLOSED  0x00000004
#define NOTE_CONNECTED    0x00000800
#define NOTE_DISCONNECTED 0x00001000
#define SOCKEV_CONNECTED    0x00000001
#define SOCKEV_DISCONNECTED 0x00000002

struct proc_watch {
	struct knote *kn;
	int pidfd;
	struct proc_watch *next;
};

static struct proc_watch *proc_watches;

struct __darwin_kevent {
	uint64_t ident;
	int16_t filter;
	uint16_t flags;
	uint32_t fflags;
	int64_t data;
	uint64_t udata;
};

struct __darwin_kevent64_s {
	uint64_t ident;
	int16_t filter;
	uint16_t flags;
	uint32_t fflags;
	int64_t data;
	uint64_t udata;
	uint64_t ext[2];
};

struct __darwin_timespec {
	int64_t tv_sec;
	int64_t tv_nsec;
};

struct kqueue {
	struct kqueue *next;
	kqueue_kind_t kind;
	uint64_t id;
	int fd;
	struct knote *knotes;
	bool bound[2];
	bool requested[2];

	struct thread *owner;
	struct thread *servicer;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct kqueue workq_kqueue = {.kind = KQUEUE_WORKQ};
static struct kqueue *workloops;
static struct kqueue *fd_kqueues;

static pthread_cond_t sync_wakeup = PTHREAD_COND_INITIALIZER;
static pthread_cond_t timer_wakeup;
static bool timer_thread_started;

static int64_t timeout_nanoseconds(const struct __darwin_timespec *timeout);
static int kevent_fd(int fd, const struct kevent_qos_s *changes, int nchanges,
		struct kevent_qos_s *events, int nevents, int64_t timeout);
static struct kqueue *fd_kqueue_lookup(int fd);
static struct kqueue *workloop_lookup(uint64_t id, unsigned int flags);
static int kevent_internal(struct kqueue *kq,
		const struct kevent_qos_s *changes, int nchanges,
		struct kevent_qos_s *events, int nevents, uint8_t *data_out,
		size_t *data_available, unsigned int flags, int64_t timeout);
static int kevent_register(
		struct kqueue *kq, const struct kevent_qos_s *change);
static struct knote *knote_find(
		struct kqueue *kq, const struct kevent_qos_s *change);
static struct knote *knote_attach(
		struct kqueue *kq, const struct kevent_qos_s *change);
static void knote_detach(struct knote *kn);
static int knote_touch(struct knote *kn, const struct kevent_qos_s *change);
static void user_touch(struct knote *kn, const struct kevent_qos_s *change);
static void timer_arm(struct knote *kn);
static void proc_watch_start(struct knote *kn);
static void proc_exited(struct knote *kn);
static uint64_t timer_nanoseconds(uint32_t fflags, int64_t data);
static uint64_t now_monotonic(void);
static uint64_t now_realtime(void);
static void timer_thread_start(void);
static void *timer_main(void *arg);
static struct knote *timer_earliest(void);
static struct kqueue *kqueue_next(struct kqueue *kq);
static void timer_fire(struct knote *kn);
static int workloop_touch(struct knote *kn, const struct kevent_qos_s *change);
static bool workloop_state_matches(
		const struct kevent_qos_s *change, uint64_t *state);
static int workloop_update_owner(struct kqueue *kq,
		const struct kevent_qos_s *change, bool stale, uint64_t state);
static void workloop_sync_wait(struct knote *kn);
static void kqueue_request(struct kqueue *kq, bool manager);
static bool kqueue_deliverable(struct kqueue *kq, bool manager, uint32_t *qos);
static bool knote_deliverable(struct knote *kn, bool manager);
static bool knote_active(struct knote *kn);
static bool fd_ready(struct knote *kn);
static uint32_t thread_qos(int32_t priority);
static int kqueue_wait(struct kqueue *kq, struct kevent_qos_s *events,
		int nevents, int64_t timeout);
static void kqueue_poll(struct kqueue *kq, int timeout);
static bool sock_ready(struct knote *kn);
static void fd_watch_wake(void);
static void fd_watch_start(void);
static int kqueue_collect(struct kqueue *kq, bool manager,
		struct kevent_qos_s *events, int max_events, uint8_t **data,
		size_t *data_size);
static bool machport_receive(
		struct kevent_qos_s *event, uint8_t **data, size_t *data_size);
static void knote_delivered(struct knote *kn);

int
sys_kqueue(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kqueue()\n");
#endif
	int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fd == -1) {
		return err_map(errno);
	}

	struct kqueue *kq = calloc(1, sizeof(*kq));
	kq->kind = KQUEUE_FD;
	kq->fd = fd;
	pthread_mutex_lock(&lock);
	kq->next = fd_kqueues;
	fd_kqueues = kq;
	pthread_mutex_unlock(&lock);
	return fd;
}

int
sys_kevent(int fd, void *changelist, int nchanges, void *eventlist, int nevents,
		void *timeout)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kevent(%d, %p, %d, %p, %d, %p)\n", fd, changelist,
			nchanges, eventlist, nevents, timeout);
#endif
	const struct __darwin_kevent *darwin_changes = changelist;
	struct __darwin_kevent *darwin_events = eventlist;
	struct kevent_qos_s *changes
			= calloc(nchanges + nevents, sizeof(*changes));
	struct kevent_qos_s *events = changes + nchanges;
	for (int i = 0; i < nchanges; i++) {
		const struct __darwin_kevent *change = &darwin_changes[i];
		changes[i] = (struct kevent_qos_s){
				.ident = change->ident,
				.filter = change->filter,
				.flags = change->flags,
				.fflags = change->fflags,
				.data = change->data,
				.udata = change->udata,
		};
	}

	int result = kevent_fd(fd, changes, nchanges, events, nevents,
			timeout_nanoseconds(timeout));
	for (int i = 0; i < result; i++) {
		darwin_events[i] = (struct __darwin_kevent){
				.ident = events[i].ident,
				.filter = events[i].filter,
				.flags = events[i].flags,
				.fflags = events[i].fflags,
				.data = events[i].data,
				.udata = events[i].udata,
		};
	}
	free(changes);
	return result;
}

static int64_t
timeout_nanoseconds(const struct __darwin_timespec *timeout)
{
	if (timeout == NULL) {
		return -1;
	}
	return timeout->tv_sec * 1000000000LL + timeout->tv_nsec;
}

static int
kevent_fd(int fd, const struct kevent_qos_s *changes, int nchanges,
		struct kevent_qos_s *events, int nevents, int64_t timeout)
{
	pthread_mutex_lock(&lock);
	int result = _EBADF;
	struct kqueue *kq = fd_kqueue_lookup(fd);
	if (kq != NULL) {
		result = kevent_internal(kq, changes, nchanges, events, nevents,
				NULL, NULL, 0, timeout);
	}
	pthread_mutex_unlock(&lock);
	return result;
}

static struct kqueue *
fd_kqueue_lookup(int fd)
{
	for (struct kqueue *kq = fd_kqueues; kq != NULL; kq = kq->next) {
		if (kq->fd == fd) {
			return kq;
		}
	}
	return NULL;
}

int
sys_kevent64(int fd, void *changelist, int nchanges, void *eventlist,
		int nevents, unsigned int flags, void *timeout)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kevent64(%d, %p, %d, %p, %d, %#x, %p)\n", fd,
			changelist, nchanges, eventlist, nevents, flags,
			timeout);
#endif
	const struct __darwin_kevent64_s *darwin_changes = changelist;
	struct __darwin_kevent64_s *darwin_events = eventlist;
	struct kevent_qos_s *changes
			= calloc(nchanges + nevents, sizeof(*changes));
	struct kevent_qos_s *events = changes + nchanges;
	for (int i = 0; i < nchanges; i++) {
		const struct __darwin_kevent64_s *change = &darwin_changes[i];
		changes[i] = (struct kevent_qos_s){
				.ident = change->ident,
				.filter = change->filter,
				.flags = change->flags,
				.fflags = change->fflags,
				.data = change->data,
				.udata = change->udata,
				.ext = {change->ext[0], change->ext[1]},
		};
	}

	int result = kevent_fd(fd, changes, nchanges, events, nevents,
			(flags & KEVENT_FLAG_IMMEDIATE)
					? 0
					: timeout_nanoseconds(timeout));
	for (int i = 0; i < result; i++) {
		darwin_events[i] = (struct __darwin_kevent64_s){
				.ident = events[i].ident,
				.filter = events[i].filter,
				.flags = events[i].flags,
				.fflags = events[i].fflags,
				.data = events[i].data,
				.udata = events[i].udata,
				.ext = {events[i].ext[0], events[i].ext[1]},
		};
	}
	free(changes);
	return result;
}

int
sys_kevent_qos(int fd, void *changelist, int nchanges, void *eventlist,
		int nevents, void *data_out, size_t *data_available,
		unsigned int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kevent_qos(%d, %p, %d, %p, %d, %p, %p, %#x)\n", fd,
			changelist, nchanges, eventlist, nevents, data_out,
			(void *)data_available, flags);
#endif
	int64_t timeout = (flags & KEVENT_FLAG_IMMEDIATE) ? 0 : -1;
	if (!(flags & KEVENT_FLAG_WORKQ)) {
		return kevent_fd(fd, changelist, nchanges, eventlist, nevents,
				timeout);
	}

	pthread_mutex_lock(&lock);
	int result = kevent_internal(&workq_kqueue, changelist, nchanges,
			eventlist, nevents, data_out, data_available, flags,
			timeout);
	pthread_mutex_unlock(&lock);
	return result;
}

int
sys_kevent_id(uint64_t id, void *changelist, int nchanges, void *eventlist,
		int nevents, void *data_out, size_t *data_available,
		unsigned int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kevent_id(%#lx, %p, %d, %p, %d, %p, %p, %#x)\n", id,
			changelist, nchanges, eventlist, nevents, data_out,
			(void *)data_available, flags);
#endif
	pthread_mutex_lock(&lock);
	int result;
	struct kqueue *kq = workloop_lookup(id, flags);
	if (kq == NULL) {
		result = (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST) ? _ENOENT
								     : _EEXIST;
	} else {
		result = kevent_internal(kq, changelist, nchanges, eventlist,
				nevents, data_out, data_available, flags,
				(flags & KEVENT_FLAG_IMMEDIATE) ? 0 : -1);
	}
	pthread_mutex_unlock(&lock);
	return result;
}

size_t
kevent_dynamic_ids(uint64_t *ids, size_t capacity)
{
	size_t count = 0;
	pthread_mutex_lock(&lock);
	for (struct kqueue *kq = workloops; kq != NULL; kq = kq->next) {
		if (count < capacity) {
			ids[count] = kq->id;
		}
		count++;
	}
	pthread_mutex_unlock(&lock);
	return count;
}

static struct kqueue *
workloop_lookup(uint64_t id, unsigned int flags)
{
	for (struct kqueue *kq = workloops; kq != NULL; kq = kq->next) {
		if (kq->id == id) {
			return (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST)
					? NULL
					: kq;
		}
	}

	if (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST) {
		return NULL;
	}

	struct kqueue *kq = calloc(1, sizeof(*kq));
	kq->kind = KQUEUE_WORKLOOP;
	kq->id = id;
	kq->next = workloops;
	workloops = kq;
	return kq;
}

static int
kevent_internal(struct kqueue *kq, const struct kevent_qos_s *changes,
		int nchanges, struct kevent_qos_s *events, int nevents,
		uint8_t *data_out, size_t *data_available, unsigned int flags,
		int64_t timeout)
{
	int nerrors = 0;
	for (int i = 0; i < nchanges; i++) {
		int error = kevent_register(kq, &changes[i]);
		if (error == 0 && !(changes[i].flags & EV_RECEIPT)) {
			continue;
		}

		if (nerrors >= nevents) {
			if (error != 0) {
				return error;
			}
			continue;
		}
		events[nerrors] = changes[i];
		events[nerrors].flags |= EV_ERROR;
		events[nerrors].data = -error;
		nerrors++;
	}

	kqueue_request(kq, false);
	kqueue_request(kq, true);

	if (nerrors != 0 || (flags & KEVENT_FLAG_ERROR_EVENTS)
			|| nevents == 0) {
		return nerrors;
	}
	if (kq->kind == KQUEUE_FD) {
		return kqueue_wait(kq, events, nevents, timeout);
	}
	if (timeout != 0) {
		unimplemented();
	}

	size_t data_size = (data_available != NULL) ? *data_available : 0;
	int count = kqueue_collect(kq, flags & KEVENT_FLAG_WORKQ_MANAGER,
			events, nevents, &data_out, &data_size);
	if (data_available != NULL) {
		*data_available = data_size;
	}
	return count;
}

static int
kevent_register(struct kqueue *kq, const struct kevent_qos_s *change)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"  kevent(ident=%#lx, filter=%d, flags=%#x, qos=%#x, "
			"udata=%#lx, fflags=%#x, data=%#lx, ext=[%#lx, %#lx, "
			"%#lx, %#lx])\n",
			change->ident, change->filter, change->flags,
			change->qos, change->udata, change->fflags,
			change->data, change->ext[0], change->ext[1],
			change->ext[2], change->ext[3]);
#endif
	struct knote *kn = knote_find(kq, change);

	if (change->filter == EVFILT_WORKLOOP) {
		uint64_t state = 0;
		bool stale = !workloop_state_matches(change, &state);
		int error = workloop_update_owner(kq, change, stale, state);
		if (error != 0) {
			return error;
		}
		if (stale) {
			return (change->fflags & NOTE_WL_IGNORE_ESTALE)
					? 0
					: _ESTALE;
		}
	}

	if (change->flags & EV_DELETE) {
		if (kn == NULL) {

			return change->filter == EVFILT_WORKLOOP
							&& (change->flags & EV_ADD)
					? 0
					: _ENOENT;
		}
		if (kn->in_flight && !(change->flags & EV_ENABLE)) {
#ifdef ENABLE_STRACE
			fprintf(stderr, "  kevent: the delete of %#lx waits for "
					"its event in flight\n",
					(unsigned long)kn->kev.ident);
#endif
			kn->defer_delete = true;
			kn->disabled = true;
			return _EINPROGRESS;
		}
		if (change->filter == EVFILT_WORKLOOP
				&& (change->fflags & NOTE_WL_COMMANDS_MASK)
						== NOTE_WL_SYNC_WAKE) {
			kn->woken = true;
			pthread_cond_broadcast(&sync_wakeup);
		}
		knote_detach(kn);
		return 0;
	}

	int error = 0;
	if (kn == NULL) {
		if (!(change->flags & EV_ADD)) {
			return _ENOENT;
		}
		kn = knote_attach(kq, change);
	} else {
		error = knote_touch(kn, change);
	}

	if (change->flags & EV_DISABLE) {
		kn->disabled = true;
	}
	if (change->flags & EV_ENABLE) {
		kn->in_flight = false;
		if (kn->defer_delete) {
			knote_detach(kn);
			return 0;
		}
		kn->disabled = false;
	}

	if (error == 0 && change->filter == EVFILT_WORKLOOP
			&& (change->fflags & NOTE_WL_COMMANDS_MASK)
					== NOTE_WL_SYNC_WAIT) {
		workloop_sync_wait(kn);
	}
	return error;
}

static struct knote *
knote_find(struct kqueue *kq, const struct kevent_qos_s *change)
{
	for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
		if (kn->kev.ident != change->ident
				|| kn->kev.filter != change->filter) {
			continue;
		}
		if ((change->flags & EV_UDATA_SPECIFIC)
				&& kn->kev.udata != change->udata) {
			continue;
		}
		return kn;
	}
	return NULL;
}

static struct knote *
knote_attach(struct kqueue *kq, const struct kevent_qos_s *change)
{
	struct knote *kn = calloc(1, sizeof(*kn));
	kn->kq = kq;
	kn->kev = *change;
	kn->kev.flags &= ~(EV_ADD | EV_ENABLE | EV_DISABLE | EV_RECEIPT
			| EV_VANISHED);
	kn->kev.fflags = 0;
	kn->kev.data = 0;
	kn->manager = kq->kind == KQUEUE_WORKQ
			&& (change->qos & PTHREAD_PRIORITY_EVENT_MANAGER_FLAG);
	kn->next = kq->knotes;
	kq->knotes = kn;

	knote_touch(kn, change);
	if (kn->kev.filter == EVFILT_SIGNAL) {
		signals_watch((int)kn->kev.ident, true);
	}
	if (kq->kind != KQUEUE_FD
			&& (kn->kev.filter == EVFILT_READ
					|| kn->kev.filter == EVFILT_WRITE
					|| kn->kev.filter == EVFILT_SOCK)) {
		fd_watch_start();
	}
	return kn;
}

static void
knote_detach(struct knote *kn)
{
	struct kqueue *kq = kn->kq;
	for (struct knote **p = &kq->knotes; *p != NULL; p = &(*p)->next) {
		if (*p == kn) {
			*p = kn->next;
			break;
		}
	}
	if (kn->watch != NULL) {
		kn->watch->kn = NULL;
		fd_watch_wake();
	}
	if (kn->kev.filter == EVFILT_SIGNAL) {
		signals_watch((int)kn->kev.ident, false);
	}
	if (kn->waiting) {
		kn->deleted = true;
		return;
	}
	free(kn);
}

static int
knote_touch(struct knote *kn, const struct kevent_qos_s *change)
{
	if (!(change->flags & EV_UDATA_SPECIFIC)) {
		kn->kev.udata = change->udata;
	}
	kn->kev.qos = change->qos;

	switch (change->filter) {
	case EVFILT_USER:
		user_touch(kn, change);
		return 0;
	case EVFILT_TIMER:
		kn->kev.fflags = change->fflags;
		kn->kev.data = change->data;
		kn->kev.ext[1] = change->ext[1];
		timer_arm(kn);
		return 0;
	case EVFILT_WORKLOOP:
		return workloop_touch(kn, change);
	case EVFILT_PROC:
		kn->proc_fflags = change->fflags;
		if (kn->watch == NULL) {
			proc_watch_start(kn);
		}
		return 0;
	case EVFILT_SOCK:
		kn->sock_interest = change->fflags;
		memcpy(kn->kev.ext, change->ext, sizeof(kn->kev.ext));
		return 0;
	default:
		kn->kev.fflags = change->fflags;
		memcpy(kn->kev.ext, change->ext, sizeof(kn->kev.ext));
		return 0;
	}
}

static void
user_touch(struct knote *kn, const struct kevent_qos_s *change)
{
	uint32_t fflags = change->fflags & NOTE_FFLAGSMASK;
	switch (change->fflags & NOTE_FFCTRLMASK) {
	case NOTE_FFAND:
		kn->kev.fflags &= fflags;
		break;
	case NOTE_FFOR:
		kn->kev.fflags |= fflags;
		break;
	case NOTE_FFCOPY:
		kn->kev.fflags = fflags;
		break;
	}

	if (change->fflags & NOTE_TRIGGER) {
		kn->active = true;
	}
}

/* Watch the process the knote names, which comes from another task */
static void
proc_watch_start(struct knote *kn)
{
	int pidfd = syscall(SYS_pidfd_open, (pid_t)kn->kev.ident, 0);
	if (pidfd == -1) {
		proc_exited(kn);
		return;
	}
	struct proc_watch *watch = calloc(1, sizeof(*watch));
	if (watch == NULL) {
		close(pidfd);
		return;
	}
	watch->kn = kn;
	watch->pidfd = pidfd;
	watch->next = proc_watches;
	proc_watches = watch;
	kn->watch = watch;
	fd_watch_start();
	fd_watch_wake();
}

/*
 * The process exited: the knote fires with NOTE_EXIT, if it asked for it.
 * Its status is the parent's to know, so it reads as 0
 */
static void
proc_exited(struct knote *kn)
{
	if (!(kn->proc_fflags & NOTE_EXIT)) {
		return;
	}
	kn->kev.fflags = NOTE_EXIT;
	kn->kev.data = 0;
	kn->kev.flags |= EV_EOF | EV_ONESHOT;
	kn->active = true;
	kqueue_request(kn->kq, kn->manager);
}

static void
timer_arm(struct knote *kn)
{
	uint32_t fflags = kn->kev.fflags;
	uint64_t nanoseconds = timer_nanoseconds(fflags, kn->kev.data);

	if (fflags & NOTE_ABSOLUTE) {
		kn->interval = 0;
		uint64_t delay;
		if (fflags & NOTE_MACHTIME) {
			uint64_t now = commpage_absolute_time();
			delay = commpage_absolute_to_nanoseconds(
					kn->kev.data > (int64_t)now
							? kn->kev.data - now
							: 0);
		} else {
			uint64_t now = now_realtime();
			delay = nanoseconds > now ? nanoseconds - now : 0;
		}
		kn->deadline = now_monotonic() + delay;
	} else {
		kn->interval = (kn->kev.flags & (EV_ONESHOT | EV_DISPATCH))
				? 0
				: nanoseconds;
		kn->deadline = now_monotonic() + nanoseconds;
	}
	kn->kev.data = 0;
	kn->active = false;

	timer_thread_start();
	pthread_cond_signal(&timer_wakeup);
}

static uint64_t
timer_nanoseconds(uint32_t fflags, int64_t data)
{
	if (fflags & NOTE_SECONDS) {
		return data * 1000000000ULL;
	}
	if (fflags & NOTE_USECONDS) {
		return data * 1000ULL;
	}
	if (fflags & NOTE_MACHTIME) {
		return commpage_absolute_to_nanoseconds(data);
	}
	if (fflags & NOTE_NSECONDS) {
		return data;
	}
	return data * 1000000ULL;
}

static uint64_t
now_monotonic(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static uint64_t
now_realtime(void)
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	return now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static void
timer_thread_start(void)
{
	if (timer_thread_started) {
		return;
	}
	timer_thread_started = true;

	pthread_condattr_t attr;
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&timer_wakeup, &attr);
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
		struct knote *kn = timer_earliest();
		if (kn == NULL) {
			pthread_cond_wait(&timer_wakeup, &lock);
		} else if (now_monotonic() >= kn->deadline) {
			timer_fire(kn);
		} else {
			struct timespec deadline = {
					.tv_sec = kn->deadline / 1000000000ULL,
					.tv_nsec = kn->deadline % 1000000000ULL,
			};
			pthread_cond_timedwait(&timer_wakeup, &lock, &deadline);
		}
	}
	return NULL;
}

static struct knote *
timer_earliest(void)
{
	struct knote *earliest = NULL;
	struct kqueue *kq = &workq_kqueue;
	while (kq != NULL) {
		for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
			if (kn->kev.filter == EVFILT_TIMER && kn->deadline != 0
					&& (earliest == NULL
							|| kn->deadline < earliest->deadline)) {
				earliest = kn;
			}
		}
		kq = kqueue_next(kq);
	}
	return earliest;
}

static struct kqueue *
kqueue_next(struct kqueue *kq)
{
	if (kq == &workq_kqueue) {
		return (workloops != NULL) ? workloops : fd_kqueues;
	}
	if (kq->next != NULL) {
		return kq->next;
	}
	return (kq->kind == KQUEUE_WORKLOOP) ? fd_kqueues : NULL;
}

static void
timer_fire(struct knote *kn)
{
	kn->kev.data++;
	kn->active = true;
	if (kn->interval != 0) {
		kn->deadline += kn->interval;
	} else {
		kn->deadline = 0;
	}
	kqueue_request(kn->kq, kn->manager);
}

static int
workloop_touch(struct knote *kn, const struct kevent_qos_s *change)
{
	kn->kev.fflags = change->fflags;
	memcpy(kn->kev.ext, change->ext, sizeof(kn->kev.ext));

	switch (change->fflags & NOTE_WL_COMMANDS_MASK) {
	case NOTE_WL_THREAD_REQUEST:
		kn->active = true;
		return 0;
	case NOTE_WL_SYNC_WAIT:
		return 0;
	case NOTE_WL_SYNC_WAKE:
		kn->woken = true;
		pthread_cond_broadcast(&sync_wakeup);
		return 0;
	case NOTE_WL_SYNC_IPC:
		return 0;
	default:
		unimplemented();
	}
}

static bool
workloop_state_matches(const struct kevent_qos_s *change, uint64_t *state)
{
	if (change->ext[EV_EXTIDX_WL_ADDR] == 0) {
		return true;
	}
	*state = __atomic_load_n((uint64_t *)change->ext[EV_EXTIDX_WL_ADDR],
			__ATOMIC_ACQUIRE);
	uint64_t mask = change->ext[EV_EXTIDX_WL_MASK];
	return (*state & mask) == (change->ext[EV_EXTIDX_WL_VALUE] & mask);
}

static int
workloop_update_owner(struct kqueue *kq, const struct kevent_qos_s *change,
		bool stale, uint64_t state)
{
	if ((change->fflags & NOTE_WL_COMMANDS_MASK) == NOTE_WL_SYNC_IPC) {
		return 0;
	}
	struct thread *owner = kq->owner;
	if (!stale && (change->fflags & NOTE_WL_DISCOVER_OWNER)) {

		mach_port_name_t name = (mach_port_name_t)state & ~0x3u;
		if (name != MACH_PORT_NULL) {
			owner = ipc_kobject_lookup(
					name | 0x3, IPC_KOBJECT_THREAD);
			if (owner == NULL) {
				return _EOWNERDEAD;
			}
		}
	}
	if ((change->fflags & NOTE_WL_END_OWNERSHIP)
			&& owner == thread_current()) {
		owner = NULL;
	}
	if (owner != NULL && owner == kq->servicer) {
		owner = NULL;
	}
	kq->owner = owner;
	return 0;
}

static void
workloop_sync_wait(struct knote *kn)
{
	kn->waiting = true;
	kqueue_request(kn->kq, false);
	while (!kn->woken) {
		pthread_cond_wait(&sync_wakeup, &lock);
	}
	kn->waiting = false;
	if (kn->deleted) {
		free(kn);
	}
}

static void
kqueue_request(struct kqueue *kq, bool manager)
{
	if (kq->kind == KQUEUE_FD) {
		eventfd_write(kq->fd, 1);
		return;
	}

	uint32_t qos;
	fd_watch_wake();
	if (kq->bound[manager] || kq->requested[manager] || kq->owner != NULL
			|| !kqueue_deliverable(kq, manager, &qos)) {
		return;
	}

	kq->requested[manager] = true;
	workq_request_kqueue(kq, qos, manager);
}

/*
 * The descriptors of the knotes of the workqueue and the workloops, which
 * no thread waits on as a kqueue's own do: a thread of limbo's polls them,
 * and requests a thread for a kqueue as one of them becomes ready. Only the
 * kqueues that no thread is requested or bound for, which look again
 * themselves as they go back to the kernel. It polls the process knotes'
 * pidfds too, of every kqueue, and closes those let go of: one thread for
 * all, where a daemon watches each of its clients' exits
 */
static int fd_watch_event = -1;

static void
fd_watch_wake(void)
{
	if (fd_watch_event != -1) {
		eventfd_write(fd_watch_event, 1);
	}
}

struct fd_watched {
	struct kqueue *kq;
	bool manager;
	struct proc_watch *watch;
};

static void *
fd_watch_main(void *arg)
{
	size_t capacity = 64;
	struct pollfd *fds = malloc(capacity * sizeof(*fds));
	struct fd_watched *watched = malloc(capacity * sizeof(*watched));
	pthread_mutex_lock(&lock);
	while (true) {
		nfds_t count = 1;
		fds[0] = (struct pollfd){.fd = fd_watch_event, .events = POLLIN};
		for (struct proc_watch **p = &proc_watches; *p != NULL;) {
			struct proc_watch *watch = *p;
			if (watch->kn == NULL) {
				*p = watch->next;
				close(watch->pidfd);
				free(watch);
				continue;
			}
			if (count == capacity) {
				capacity *= 2;
				fds = realloc(fds, capacity * sizeof(*fds));
				watched = realloc(watched,
						capacity * sizeof(*watched));
			}
			watched[count] = (struct fd_watched){.watch = watch};
			fds[count++] = (struct pollfd){
					.fd = watch->pidfd, .events = POLLIN};
			p = &watch->next;
		}
		for (struct kqueue *kq = &workq_kqueue; kq != NULL;
				kq = kqueue_next(kq)) {
			if (kq->kind == KQUEUE_FD) {
				break;
			}
			for (struct knote *kn = kq->knotes; kn != NULL;
					kn = kn->next) {
				short events = 0;
				if (kn->kev.filter == EVFILT_READ) {
					events = POLLIN;
				} else if (kn->kev.filter == EVFILT_WRITE) {
					events = POLLOUT;
				} else if (kn->kev.filter == EVFILT_SOCK) {
					events = POLLRDHUP;
					if ((kn->sock_interest & NOTE_CONNECTED)
							&& !(kn->sock_reported
									& NOTE_CONNECTED)) {
						events |= POLLOUT;
					}
				}
				if (events == 0 || kn->disabled
						|| kq->requested[kn->manager]
						|| kq->bound[kn->manager]
						|| kq->owner != NULL) {
					continue;
				}
				if (count == capacity) {
					capacity *= 2;
					fds = realloc(fds, capacity * sizeof(*fds));
					watched = realloc(watched,
							capacity * sizeof(*watched));
				}
				watched[count] = (struct fd_watched){
						kq, kn->manager, NULL};
				fds[count++] = (struct pollfd){
						.fd = (int)kn->kev.ident,
						.events = events};
			}
		}
		pthread_mutex_unlock(&lock);
		poll(fds, count, 100);
		if (fds[0].revents & POLLIN) {
			eventfd_t value;
			eventfd_read(fd_watch_event, &value);
		}
		pthread_mutex_lock(&lock);
		for (nfds_t i = 1; i < count; i++) {
			struct proc_watch *watch = watched[i].watch;
			if (watch != NULL) {
				if (fds[i].revents != 0 && watch->kn != NULL) {
					watch->kn->watch = NULL;
					proc_exited(watch->kn);
					watch->kn = NULL;
				}
				continue;
			}
			if (fds[i].revents != 0) {
#ifdef ENABLE_STRACE
				fprintf(stderr, "  fd watch: %d ready, %#x, kq %#lx\n",
						fds[i].fd, fds[i].revents,
						watched[i].kq->id);
#endif
				kqueue_request(watched[i].kq, watched[i].manager);
			}
		}
	}
	return NULL;
}

static void
fd_watch_fork_prepare(void)
{
	pthread_mutex_lock(&lock);
}

static void
fd_watch_fork_parent(void)
{
	pthread_mutex_unlock(&lock);
}

static void
fd_watch_fork_child(void)
{
	if (fd_watch_event != -1) {
		close(fd_watch_event);
		fd_watch_event = -1;
	}
	while (proc_watches != NULL) {
		struct proc_watch *watch = proc_watches;
		proc_watches = watch->next;
		if (watch->kn != NULL) {
			watch->kn->watch = NULL;
		}
		close(watch->pidfd);
		free(watch);
	}
	pthread_mutex_unlock(&lock);
}

static void
fd_watch_init(void)
{
	pthread_atfork(fd_watch_fork_prepare, fd_watch_fork_parent,
			fd_watch_fork_child);
}

static void
fd_watch_start(void)
{
	if (fd_watch_event != -1) {
		return;
	}
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	pthread_once(&once, fd_watch_init);
	fd_watch_event = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	sigset_t all, previous;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &previous);
	pthread_t handle;
	pthread_create(&handle, NULL, fd_watch_main, NULL);
	pthread_detach(handle);
	pthread_sigmask(SIG_SETMASK, &previous, NULL);
}

static bool
kqueue_deliverable(struct kqueue *kq, bool manager, uint32_t *qos)
{
	bool deliverable = false;
	*qos = 0;
	for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
		if (knote_deliverable(kn, manager)) {
			deliverable = true;
			uint32_t kn_qos = thread_qos(kn->kev.qos);
			if (kn_qos > *qos) {
				*qos = kn_qos;
			}
		}
	}
	if (*qos == 0) {
		*qos = THREAD_QOS_LEGACY;
	}
	return deliverable;
}

static bool
knote_deliverable(struct knote *kn, bool manager)
{

	if (kn->kev.filter == EVFILT_WORKLOOP && kn->kq->owner != NULL) {
		return false;
	}
	return !kn->disabled && kn->manager == manager && knote_active(kn);
}

static bool
knote_active(struct knote *kn)
{
	switch (kn->kev.filter) {
	case EVFILT_READ:
	case EVFILT_WRITE:
		return fd_ready(kn);
	case EVFILT_MACHPORT:
		return ipc_port_peek(kn->kev.ident);
	case EVFILT_SOCK:
		return sock_ready(kn);
	default:
		return kn->active;
	}
}

/*
 * A socket's events since they were last told, of those the knote watches
 * for: connected, its connection lost or refused, its reading side closed.
 * The error of a failed connection stays for SO_ERROR to read
 */
static uint32_t
sock_events(int fd, uint32_t *state)
{
	struct pollfd pfd = {.fd = fd, .events = POLLOUT | POLLRDHUP};
	*state = 0;
	if (poll(&pfd, 1, 0) != 1 || (pfd.revents & POLLNVAL)) {
		return 0;
	}
	uint32_t events = 0;
	struct sockaddr_storage peer;
	socklen_t length = sizeof(peer);
	bool connected = (pfd.revents & POLLOUT)
			&& getpeername(fd, (struct sockaddr *)&peer, &length) == 0;
	if (connected) {
		events |= NOTE_CONNECTED;
		*state |= SOCKEV_CONNECTED;
	}
	if (pfd.revents & (POLLERR | POLLHUP)) {
		events |= NOTE_DISCONNECTED | NOTE_WRITECLOSED;
		if (!connected) {
			events |= NOTE_CONNRESET;
		}
		*state |= SOCKEV_DISCONNECTED;
	}
	if (pfd.revents & (POLLRDHUP | POLLHUP)) {
		events |= NOTE_READCLOSED;
	}
	return events;
}

static bool
sock_ready(struct knote *kn)
{
	uint32_t state;
	uint32_t events = sock_events((int)kn->kev.ident, &state)
			& kn->sock_interest & ~kn->sock_reported;
	if (events == 0) {
		return false;
	}
	kn->kev.fflags = events;
	kn->kev.data = state;
	return true;
}

static bool
fd_ready(struct knote *kn)
{
	struct pollfd pfd = {
			.fd = kn->kev.ident,
			.events
			= (kn->kev.filter == EVFILT_READ) ? POLLIN : POLLOUT,
	};
	if (poll(&pfd, 1, 0) != 1 || (pfd.revents & POLLNVAL)) {
		return false;
	}

	if (pfd.revents & (POLLHUP | POLLERR)) {
		kn->kev.flags |= EV_EOF;
	}
	int available = 1;
	if (kn->kev.filter == EVFILT_READ) {
		ioctl(kn->kev.ident, FIONREAD, &available);
	}
	kn->kev.data = available;
	return true;
}

static uint32_t
thread_qos(int32_t priority)
{
	return ffs(((uint32_t)priority & PTHREAD_PRIORITY_QOS_CLASS_MASK)
			>> PTHREAD_PRIORITY_QOS_CLASS_SHIFT);
}

static int
kqueue_wait(struct kqueue *kq, struct kevent_qos_s *events, int nevents,
		int64_t timeout)
{
	uint64_t deadline = (timeout > 0) ? now_monotonic() + timeout : 0;
	while (true) {

		eventfd_t value;
		eventfd_read(kq->fd, &value);
		uint8_t *data = NULL;
		size_t data_size = 0;
		int count = kqueue_collect(
				kq, false, events, nevents, &data, &data_size);
		if (count == nevents) {
			eventfd_write(kq->fd, 1);
		}
		if (count != 0 || timeout == 0) {
			return count;
		}

		int poll_timeout = -1;
		if (timeout > 0) {
			uint64_t now = now_monotonic();
			if (now >= deadline) {
				return 0;
			}
			poll_timeout = (deadline - now + 999999) / 1000000;
		}
		kqueue_poll(kq, poll_timeout);
	}
}

static void
kqueue_poll(struct kqueue *kq, int timeout)
{
	nfds_t count = 1;
	for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
		count++;
	}

	struct pollfd *fds = calloc(count, sizeof(*fds));
	fds[0] = (struct pollfd){.fd = kq->fd, .events = POLLIN};
	nfds_t used = 1;
	for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
		if (kn->disabled) {
			continue;
		}
		if (kn->kev.filter == EVFILT_READ) {
			fds[used++] = (struct pollfd){
					.fd = kn->kev.ident, .events = POLLIN};
		} else if (kn->kev.filter == EVFILT_WRITE) {
			fds[used++] = (struct pollfd){
					.fd = kn->kev.ident, .events = POLLOUT};
		}
	}

	pthread_mutex_unlock(&lock);
	poll(fds, used, timeout);
	eventfd_t value;
	eventfd_read(kq->fd, &value);
	pthread_mutex_lock(&lock);
	free(fds);
}

static int
kqueue_collect(struct kqueue *kq, bool manager, struct kevent_qos_s *events,
		int max_events, uint8_t **data, size_t *data_size)
{
	int count = 0;
	struct knote *kn = kq->knotes;
	while (kn != NULL && count < max_events) {
		struct knote *next = kn->next;
		if (knote_deliverable(kn, manager)) {
			events[count] = kn->kev;
			if (kn->kev.filter != EVFILT_MACHPORT
					|| machport_receive(&events[count],
							data, data_size)) {
#ifdef ENABLE_STRACE
				fprintf(stderr,
						"  deliver(kq=%#lx, "
						"ident=%#lx, "
						"filter=%d, fflags=%#x)\n",
						kq->id, kn->kev.ident,
						kn->kev.filter,
						events[count].fflags);
#endif
				count++;
				knote_delivered(kn);
			}
		}
		kn = next;
	}
	return count;
}

int
kevent_bind(struct kqueue *kq, bool manager, struct kevent_qos_s *events,
		int max_events, uint8_t *data, size_t data_size)
{
	pthread_mutex_lock(&lock);
#ifdef ENABLE_STRACE
	fprintf(stderr, "  bind(kq=%#lx, manager=%d, tid=%d)\n", kq->id,
			manager, gettid());
#endif
	kq->requested[manager] = false;
	kq->bound[manager] = true;
	if (kq->kind == KQUEUE_WORKLOOP && !manager) {
		kq->servicer = thread_current();
		if (kq->owner == kq->servicer) {
			kq->owner = NULL;
		}
	}
	int count = kqueue_collect(
			kq, manager, events, max_events, &data, &data_size);
	pthread_mutex_unlock(&lock);
	return count;
}

static bool
machport_receive(struct kevent_qos_s *event, uint8_t **data, size_t *data_size)
{
	uint32_t options = event->fflags;
	if (!(options & MACH_RCV_MSG)) {
		event->fflags = 0;
		event->data = event->ident;
		return true;
	}

	bool use_data = event->ext[1] == 0;
	mach_msg_header_t *msg = use_data ? (mach_msg_header_t *)*data
					  : (mach_msg_header_t *)event->ext[0];
	mach_msg_size_t size = use_data ? *data_size : event->ext[1];
	mach_msg_return_t mr = ipc_mach_msg(msg,
			MACH64_RCV_MSG | MACH_RCV_TIMEOUT
					| (options & (MACH_RCV_LARGE | MACH_RCV_TRAILER_MASK)),
			0, size, event->ident, 0);
	if (mr == MACH_RCV_TIMED_OUT) {
		return false;
	}

	size = msg->msgh_size;
	if (mr == MACH_MSG_SUCCESS) {
		size += ((mach_msg_trailer_t *)((uint8_t *)msg + size))
					->msgh_trailer_size;
		if (use_data) {
			size_t used = (size + 7) & ~7;
			*data += used;
			*data_size -= used;
		}
	}

	event->fflags = mr;
	event->data = event->ident;
	event->ext[0] = (uint64_t)msg;
	event->ext[1] = size;
	event->ext[2] = 0;
	return true;
}

static void
knote_delivered(struct knote *kn)
{

	if (kn->kev.filter == EVFILT_WORKLOOP) {
		kn->active = false;
		return;
	}

	if (kn->kev.filter == EVFILT_SOCK) {
		kn->sock_reported |= kn->kev.fflags;
	}

	if ((kn->kev.flags & (EV_DISPATCH | EV_UDATA_SPECIFIC))
			== (EV_DISPATCH | EV_UDATA_SPECIFIC)) {
		kn->in_flight = true;
	}

	if (kn->kev.flags & EV_ONESHOT) {

		if ((kn->kev.flags & (EV_DISPATCH | EV_UDATA_SPECIFIC))
				== (EV_DISPATCH | EV_UDATA_SPECIFIC)) {
			kn->disabled = true;
			kn->active = false;
			return;
		}
		knote_detach(kn);
		return;
	}

	if (kn->kev.flags & EV_DISPATCH) {
		kn->disabled = true;
	}

	if (kn->kev.flags & (EV_CLEAR | EV_DISPATCH)) {
		kn->active = false;
		if (kn->kev.filter == EVFILT_TIMER
				|| kn->kev.filter == EVFILT_SIGNAL) {
			kn->kev.data = 0;
		}
	}
}

void
kevent_unbind(struct kqueue *kq, bool manager,
		const struct kevent_qos_s *changes, int nchanges)
{
	pthread_mutex_lock(&lock);
#ifdef ENABLE_STRACE
	fprintf(stderr, "  unbind(kq=%#lx, manager=%d, tid=%d)\n", kq->id,
			manager, gettid());
#endif
	for (int i = 0; i < nchanges; i++) {
		kevent_register(kq, &changes[i]);
	}
	kq->bound[manager] = false;
	if (!manager && kq->servicer == thread_current()) {
		kq->servicer = NULL;
	}
	kqueue_request(kq, false);
	kqueue_request(kq, true);
	pthread_mutex_unlock(&lock);
}

uint64_t
kevent_kqid(struct kqueue *kq)
{
	return kq->id;
}

void
kevent_close(int fd)
{
	pthread_mutex_lock(&lock);
	for (struct kqueue **p = &fd_kqueues; *p != NULL; p = &(*p)->next) {
		struct kqueue *kq = *p;
		if (kq->fd == fd) {
			*p = kq->next;
			while (kq->knotes != NULL) {
				knote_detach(kq->knotes);
			}
			free(kq);
			break;
		}
	}

	for (struct kqueue *kq = &workq_kqueue; kq != NULL;
			kq = kqueue_next(kq)) {
		struct knote *kn = kq->knotes;
		while (kn != NULL) {
			struct knote *next = kn->next;
			if ((kn->kev.filter == EVFILT_READ
					    || kn->kev.filter == EVFILT_WRITE
					    || kn->kev.filter == EVFILT_SOCK)
					&& kn->kev.ident == (uint64_t)fd) {
				knote_detach(kn);
			}
			kn = next;
		}
	}
	pthread_mutex_unlock(&lock);
}

void
kevent_signal(int sig, int64_t count)
{
	pthread_mutex_lock(&lock);
	for (struct kqueue *kq = &workq_kqueue; kq != NULL;
			kq = kqueue_next(kq)) {
		for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
			if (kn->kev.filter == EVFILT_SIGNAL
					&& kn->kev.ident == (uint64_t)sig) {
				kn->kev.data += count;
				kn->active = true;
				kqueue_request(kq, kn->manager);
			}
		}
	}
	pthread_mutex_unlock(&lock);
}

void
kevent_machport_arrival(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	struct kqueue *kq = &workq_kqueue;
	while (kq != NULL) {
		for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
			if (kn->kev.filter == EVFILT_MACHPORT
					&& kn->kev.ident == name) {
				kqueue_request(kq, kn->manager);
			}
		}
		kq = kqueue_next(kq);
	}
	pthread_mutex_unlock(&lock);
}

int
sys_kqueue_workloop_ctl(
		user_addr_t cmd, uint64_t options, user_addr_t addr, size_t sz)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kqueue_workloop_ctl(%p, %p, %p, %p)\n", (void *)cmd,
			(void *)options, (void *)addr, (void *)sz);
#endif
	struct kqueue_workloop_params {
		int kqwlp_version;
		int kqwlp_flags;
		uint64_t kqwlp_id;
		int kqwlp_sched_pri;
		int kqwlp_sched_pol;
		int kqwlp_cpu_percent;
		int kqwlp_cpu_refillms;
	};
	enum { KQ_WORKLOOP_CREATE = 1, KQ_WORKLOOP_DESTROY = 2 };

	const struct kqueue_workloop_params *params = addr;
	if (params == NULL || sz < sizeof(*params)) {
		return _EINVAL;
	}

	int result = 0;
	pthread_mutex_lock(&lock);
	switch ((uintptr_t)cmd) {
	case KQ_WORKLOOP_CREATE:
		if (workloop_lookup(params->kqwlp_id,
				    KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST)
				== NULL) {
			result = _EEXIST;
		}
		break;
	case KQ_WORKLOOP_DESTROY:
		if (workloop_lookup(params->kqwlp_id,
				    KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST)
				== NULL) {
			result = _ENOENT;
		}
		break;
	default:
		result = _EINVAL;
		break;
	}
	pthread_mutex_unlock(&lock);
	return result;
}
