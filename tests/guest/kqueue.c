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

#include <pthread.h>
#include <signal.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

static int kq;

static void *trigger(void *arg);

int
main(void)
{
	int fds[2];
	CHECK(pipe(fds) == 0);
	kq = kqueue();
	CHECK(kq != -1);

	struct kevent changes[3], events[4];
	EV_SET(&changes[0], fds[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&changes[1], 1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 20, NULL);
	EV_SET(&changes[2], 42, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
	CHECK(kevent(kq, changes, 3, NULL, 0, NULL) == 0);

	struct timespec zero = {0, 0};
	CHECK(kevent(kq, NULL, 0, events, 4, &zero) == 0);

	CHECK(write(fds[1], "hello", 5) == 5);
	CHECK(kevent(kq, NULL, 0, events, 4, &zero) == 1);
	CHECK(events[0].ident == (uintptr_t)fds[0]);
	CHECK(events[0].filter == EVFILT_READ && events[0].data == 5);
	char buffer[8];
	CHECK(read(fds[0], buffer, sizeof(buffer)) == 5);

	CHECK(kevent(kq, NULL, 0, events, 4, NULL) == 1);
	CHECK(events[0].filter == EVFILT_TIMER);

	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, trigger, NULL) == 0);
	CHECK(kevent(kq, NULL, 0, events, 4, NULL) == 1);
	CHECK(events[0].filter == EVFILT_USER && events[0].ident == 42);
	CHECK(pthread_join(thread, NULL) == 0);

	struct timespec timeout = {0, 30000000};
	CHECK(kevent(kq, NULL, 0, events, 4, &timeout) == 0);

	close(fds[1]);
	CHECK(kevent(kq, NULL, 0, events, 4, &zero) == 1);
	CHECK(events[0].flags & EV_EOF);
	CHECK(close(kq) == 0);

	int inner = kqueue(), outer = kqueue();
	CHECK(inner != -1 && outer != -1);
	EV_SET(&changes[0], 7, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
	CHECK(kevent(inner, changes, 1, NULL, 0, NULL) == 0);
	EV_SET(&changes[0], inner, EVFILT_READ, EV_ADD, 0, 0, NULL);
	CHECK(kevent(outer, changes, 1, NULL, 0, NULL) == 0);
	CHECK(kevent(inner, NULL, 0, events, 4, &zero) == 0);
	CHECK(kevent(outer, NULL, 0, events, 4, &zero) == 0);
	EV_SET(&changes[0], 7, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	CHECK(kevent(inner, changes, 1, NULL, 0, NULL) == 0);
	CHECK(kevent(outer, NULL, 0, events, 4, &zero) == 1);
	CHECK(events[0].ident == (uintptr_t)inner);
	CHECK(kevent(inner, NULL, 0, events, 4, &zero) == 1);
	CHECK(events[0].filter == EVFILT_USER);
	CHECK(kevent(outer, NULL, 0, events, 4, &zero) == 0);
	CHECK(close(outer) == 0 && close(inner) == 0);

	enum { CHILDREN = 8 };
	pid_t children[CHILDREN];
	kq = kqueue();
	CHECK(kq != -1);
	for (int i = 0; i < CHILDREN; i++) {
		children[i] = fork();
		CHECK(children[i] != -1);
		if (children[i] == 0) {
			pause();
			_exit(0);
		}
		EV_SET(&changes[0], children[i], EVFILT_PROC, EV_ADD, NOTE_EXIT,
				0, NULL);
		CHECK(kevent(kq, changes, 1, NULL, 0, NULL) == 0);
	}
	EV_SET(&changes[0], children[0], EVFILT_PROC, EV_DELETE, 0, 0, NULL);
	CHECK(kevent(kq, changes, 1, NULL, 0, NULL) == 0);
	CHECK(kevent(kq, NULL, 0, events, 4, &zero) == 0);
	for (int i = 0; i < CHILDREN; i++) {
		CHECK(kill(children[i], SIGKILL) == 0);
	}
	struct timespec second = {1, 0};
	int told = 0;
	while (told < CHILDREN - 1) {
		int count = kevent(kq, NULL, 0, events, 4, &second);
		CHECK(count > 0);
		for (int i = 0; i < count; i++) {
			CHECK(events[i].filter == EVFILT_PROC);
			CHECK(events[i].fflags & NOTE_EXIT);
			CHECK(events[i].ident != (uintptr_t)children[0]);
		}
		told += count;
	}
	CHECK(kevent(kq, NULL, 0, events, 4, &timeout) == 0);
	for (int i = 0; i < CHILDREN; i++) {
		CHECK(waitpid(children[i], NULL, 0) == children[i]);
	}
	CHECK(close(kq) == 0);
	return 0;
}

static void *
trigger(void *arg)
{
	usleep(20000);
	struct kevent change;
	EV_SET(&change, 42, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	CHECK(kevent(kq, &change, 1, NULL, 0, NULL) == 0);
	return NULL;
}
