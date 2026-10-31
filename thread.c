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

#ifdef __x86_64__
#include <asm/prctl.h>
#endif
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include "bsd/credentials.h"
#include "osfmk/ipc.h"
#include "syscall.h"
#include "thread.h"

#ifdef __x86_64__
int arch_prctl(int, unsigned long);
#endif

static __thread struct thread *current;

static void *thread_main(void *arg);
static void thread_destroy(struct thread *thread);

struct thread *
thread_current(void)
{
	if (current == NULL) {
		current = thread_new(NULL, NULL);
		current->tid = gettid();
	}
	return current;
}

struct thread *
thread_new(thread_continuation_t continuation, void *context)
{
	struct thread *thread = calloc(1, sizeof(*thread));
	thread->port = ipc_kobject_copy_send(
			ipc_kobject_alloc(IPC_KOBJECT_THREAD, thread));
	thread->continuation = continuation;
	thread->context = context;
	pthread_mutex_init(&thread->suspend_lock, NULL);
	pthread_cond_init(&thread->resumed, NULL);
	return thread;
}

int
thread_start(struct thread *thread, const struct thread_state *state)
{
	thread->spawned = true;
	thread->continuation_pending = state == NULL;
	if (state != NULL) {
		thread->state = *state;
	}

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_t handle;
	int error = pthread_create(&handle, &attr, thread_main, thread);
	pthread_attr_destroy(&attr);
	return error;
}

int
thread_create_own(pthread_t *handle, const pthread_attr_t *attr,
		void *(*start)(void *), void *arg)
{
	sigset_t all, previous;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &previous);
	int error = pthread_create(handle, attr, start, arg);
	pthread_sigmask(SIG_SETMASK, &previous, NULL);
	return error;
}

static void *
thread_main(void *arg)
{
	struct thread *thread = arg;
	current = thread;

	sigset_t needed;
	sigemptyset(&needed);
	sigaddset(&needed, SIGSYS);
	sigaddset(&needed, SIGILL);
	sigaddset(&needed, SIGSEGV);
	sigaddset(&needed, SIGBUS);
	sigaddset(&needed, SIGTRAP);
	sigaddset(&needed, SIGFPE);
	pthread_sigmask(SIG_UNBLOCK, &needed, NULL);

	if (thread->continuation != NULL) {
		sigset_t others;
		sigfillset(&others);
		sigdelset(&others, SIGSYS);
		sigdelset(&others, SIGILL);
		sigdelset(&others, SIGSEGV);
		sigdelset(&others, SIGBUS);
		sigdelset(&others, SIGTRAP);
		sigdelset(&others, SIGFPE);
		sigdelset(&others, thread_suspend_signal());
		sigdelset(&others, credentials_signal());
		pthread_sigmask(SIG_BLOCK, &others, NULL);
	}
	thread->tid = gettid();

	if (syscall_dispatch_enable()) {
		abort();
	}

	bool parked = false;
	if (sigsetjmp(thread->kernel, 1) != 0) {
		thread->continuation_pending = true;
		syscall_trap_reset();
		pthread_mutex_lock(&thread->suspend_lock);
		thread->trap_context = NULL;
		thread->stopped_context = thread->parked_context;
		pthread_mutex_unlock(&thread->suspend_lock);
		parked = true;
	}

	if (thread->continuation_pending) {
		thread->continuation_pending = false;
		bool resumed = !thread->terminating
				&& thread->continuation(thread, &thread->state);
		if (parked) {
			pthread_mutex_lock(&thread->suspend_lock);
			while (resumed && thread->suspend_count != 0) {
				pthread_cond_wait(&thread->resumed,
						&thread->suspend_lock);
			}
			thread->stopped_context = NULL;
			pthread_mutex_unlock(&thread->suspend_lock);
		}
		if (!resumed) {
			thread_destroy(thread);
			return NULL;
		}
	}
#ifndef __x86_64__
	syscall_set_guest_thread_pointer(thread->state.tpidr);
#endif
	thread_enter(&thread->state);
}

static void
thread_destroy(struct thread *thread)
{
	free(thread->parked_context);
	if (thread->stack_size != 0) {
		munmap(thread->stack, thread->stack_size);
	}
	ipc_kobject_destroy(thread->port);
	ipc_port_deallocate(thread->port);
	current = NULL;
	free(thread);
}

#ifdef __x86_64__
void
thread_enter(const struct thread_state *state)
{
	if (state->gs_base != 0) {
		arch_prctl(ARCH_SET_GS, state->gs_base);
	}

	asm volatile("movq 8(%%rax), %%rsp\n"
		     "movq 16(%%rax), %%rdi\n"
		     "movq 24(%%rax), %%rsi\n"
		     "movq 32(%%rax), %%rdx\n"
		     "movq 40(%%rax), %%rcx\n"
		     "movq 48(%%rax), %%r8\n"
		     "movq 56(%%rax), %%r9\n"
		     "jmpq *(%%rax)\n" ::"a"(state));
	__builtin_unreachable();
}
#else
void
thread_enter(const struct thread_state *state)
{
	if (state->tpidr != 0) {
		asm volatile("msr tpidr_el0, %0" ::"r"(state->tpidr));
	}

	/* Pin the base to x16: the general-register loads below overwrite
	 * x0-x7, so the state pointer must live in a register they leave
	 * untouched */
	register const struct thread_state *base asm("x16") = state;
	asm volatile("ldp x0, x1, [%0, #16]\n"
		     "ldp x2, x3, [%0, #32]\n"
		     "ldp x4, x5, [%0, #48]\n"
		     "ldp x6, x7, [%0, #64]\n"
		     "ldr x9, [%0, #8]\n"
		     "ldr x10, [%0]\n"
		     "mov sp, x9\n"
		     "br x10\n" ::"r"(base)
		     : "memory");
	__builtin_unreachable();
}
#endif

void
thread_block(void)
{
	struct thread *thread = current;
	if (thread->trap_context != NULL) {
		if (thread->parked_context == NULL) {
			thread->parked_context = malloc(sizeof(ucontext_t));
		}
		memcpy(thread->parked_context, thread->trap_context,
				sizeof(ucontext_t));
	}
	siglongjmp(thread->kernel, 1);
}

void
thread_exit(void *stack, size_t stack_size)
{
	if (!current->spawned) {
		syscall(SYS_exit, 0);
	}

	current->terminating = true;
	current->stack = stack;
	current->stack_size = stack_size;
	siglongjmp(current->kernel, 1);
}

void
thread_suspend_self(void)
{
	struct thread *thread = thread_current();
	pthread_mutex_lock(&thread->suspend_lock);
	thread->suspend_count++;
	while (thread->suspend_count != 0) {
		pthread_cond_wait(&thread->resumed, &thread->suspend_lock);
	}
	pthread_mutex_unlock(&thread->suspend_lock);
}

int
thread_suspend_signal(void)
{
	return SIGRTMIN + 4;
}

kern_return_t
thread_suspend_other(struct thread *thread)
{
	pthread_mutex_lock(&thread->suspend_lock);
	thread->suspend_count++;
	for (int tries = 0; tries < 500 && thread->stopped_context == NULL
			&& thread->trap_context == NULL;
			tries++) {
		pthread_mutex_unlock(&thread->suspend_lock);
		if (thread->tid != 0) {
			syscall(SYS_tgkill, getpid(), thread->tid,
					thread_suspend_signal());
		}
		usleep(2000);
		pthread_mutex_lock(&thread->suspend_lock);
	}
#ifdef ENABLE_STRACE
	if (thread->stopped_context == NULL && thread->trap_context == NULL) {
		fprintf(stderr, "thread_suspend: thread %d did not stop\n",
				thread->tid);
	}
#endif
	pthread_mutex_unlock(&thread->suspend_lock);
	return KERN_SUCCESS;
}

const void *
thread_guest_context(struct thread *thread)
{
	pthread_mutex_lock(&thread->suspend_lock);
	const void *context = (thread->suspend_count != 0)
			? (thread->stopped_context != NULL
							  ? thread->stopped_context
							  : thread->trap_context)
			: NULL;
	pthread_mutex_unlock(&thread->suspend_lock);
	return context;
}

void
thread_stop_if_suspended(void *context)
{
	struct thread *thread = current;
	if (thread == NULL) {
		return;
	}
	pthread_mutex_lock(&thread->suspend_lock);
	if (thread->suspend_count != 0) {
		thread->stopped_context = context;
		while (thread->suspend_count != 0) {
			pthread_cond_wait(&thread->resumed, &thread->suspend_lock);
		}
		thread->stopped_context = NULL;
	}
	pthread_mutex_unlock(&thread->suspend_lock);
}

void
thread_enter_trap(void *context, void **outer)
{
	struct thread *thread = thread_current();
	pthread_mutex_lock(&thread->suspend_lock);
	*outer = thread->trap_context;
	thread->trap_context = context;
	pthread_mutex_unlock(&thread->suspend_lock);
}

void
thread_leave_trap(void *context, void *outer)
{
	struct thread *thread = thread_current();
	pthread_mutex_lock(&thread->suspend_lock);
	if (thread->suspend_count != 0) {
		thread->stopped_context = context;
		while (thread->suspend_count != 0) {
			pthread_cond_wait(&thread->resumed, &thread->suspend_lock);
		}
		thread->stopped_context = NULL;
	}
	thread->trap_context = outer;
	pthread_mutex_unlock(&thread->suspend_lock);
}

void
thread_resume_thread(struct thread *thread)
{
	pthread_mutex_lock(&thread->suspend_lock);
	if (thread->suspend_count != 0 && --thread->suspend_count == 0) {
		pthread_cond_broadcast(&thread->resumed);
	}
	pthread_mutex_unlock(&thread->suspend_lock);
}
