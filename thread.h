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

#pragma once

#include <mach/mach.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct thread_state {
#ifdef __x86_64__
	uint64_t rip;
	uint64_t rsp;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t r8;
	uint64_t r9;
	uint64_t gs_base;
#else
	uint64_t pc;
	uint64_t sp;
	uint64_t x[8];
	uint64_t tpidr;
	bool full;
	uint64_t regs[31];
#endif
};

struct exception_action {
	mach_port_name_t port;
	exception_behavior_t behavior;
	thread_state_flavor_t flavor;
};

struct thread;

typedef bool (*thread_continuation_t)(
		struct thread *thread, struct thread_state *state);

#define THREAD_NAME_SIZE 64

struct thread {
	mach_port_name_t port;
	pid_t tid;
	thread_continuation_t continuation;
	void *context;
	struct thread_state state;
	sigjmp_buf kernel;
	bool spawned;
	bool continuation_pending;
	bool terminating;
	bool terminate_requested;
	struct exception_action *exception_actions;
	void *stack;
	size_t stack_size;
	pthread_mutex_t suspend_lock;
	pthread_cond_t resumed;
	uint32_t suspend_count;

	void *stopped_context;
	void *trap_context;

	void *parked_context;
	bool workqueue;
	int trap_depth;
	_Atomic int64_t trap_since;
	_Atomic uint64_t tsd_base;
	struct thread *all_next;
	bool guest;
	_Atomic uint32_t restart_acks;
	char name[THREAD_NAME_SIZE];
};

struct thread *thread_current(void);
void thread_fork_child(void);
struct thread *thread_new(thread_continuation_t continuation, void *context);
size_t thread_guest_ports(mach_port_name_t *ports, size_t max);
size_t thread_guest_handles(uint64_t *out, size_t max, bool ids);
mach_port_name_t thread_guest_port_of(uint64_t value, bool id);
bool thread_linux_extended_info(
		pid_t pid, pid_t tid, thread_extended_info_t info);
int thread_start(struct thread *thread, const struct thread_state *state);
int thread_create_own(pthread_t *handle, const pthread_attr_t *attr,
		void *(*start)(void *), void *arg);
void __attribute__((noreturn)) thread_enter(const struct thread_state *state);
void __attribute__((noreturn)) thread_block(void);
void thread_suspend_self(void);
void thread_resume_thread(struct thread *thread);
void thread_terminate_thread(struct thread *thread);
kern_return_t thread_suspend_other(struct thread *thread);
const void *thread_guest_context(struct thread *thread);
void thread_stop_if_suspended(void *context);
void thread_enter_trap(void *context, void **outer);
void thread_leave_trap(void *context, void *outer);
int thread_suspend_signal(void);
int thread_restart_signal(void);
void thread_restart_others(void);
void thread_restart_taken(void);
void __attribute__((noreturn)) thread_exit(void *stack, size_t stack_size);
