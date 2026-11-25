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

#ifndef __x86_64__
#include <asm/sigcontext.h>
#include <errno.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#endif
#include <mach/mach.h>
#pragma pack(push, 4)
#include <mach/exc.h>
#include <mach/mach_exc.h>
#pragma pack(pop)
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>

#include "bsd/handler.h"
#include "bsd/process.h"
#include "commpage.h"
#include "ipc.h"
#include "task.h"
#include "thread.h"

#define DARWIN_ARM_THREAD_STATE64 6
struct darwin_arm_thread_state64 {
	uint64_t x[29];
	uint64_t fp;
	uint64_t lr;
	uint64_t sp;
	uint64_t pc;
	uint32_t cpsr;
	uint32_t flags;
};
#define DARWIN_ARM_THREAD_STATE64_COUNT                                        \
	(sizeof(struct darwin_arm_thread_state64) / sizeof(uint32_t))

#define DARWIN_ARM_THREAD_STATE 1
struct darwin_arm_unified_thread_state {
	uint32_t flavor;
	uint32_t count;
	struct darwin_arm_thread_state64 state64;
};
#define DARWIN_ARM_UNIFIED_THREAD_STATE_COUNT                                  \
	(sizeof(struct darwin_arm_unified_thread_state) / sizeof(uint32_t))

#define DARWIN_ARM_NEON_STATE64 17
struct darwin_arm_neon_state64 {
	__uint128_t v[32];
	uint32_t fpsr;
	uint32_t fpcr;
};
#define DARWIN_ARM_NEON_STATE64_COUNT                                          \
	(sizeof(struct darwin_arm_neon_state64) / sizeof(uint32_t))

#define DARWIN_ARM_DEBUG_STATE64 15
#define DARWIN_ARM_DEBUG_STATE64_COUNT                                         \
	(sizeof(struct thread_debug_state) / sizeof(uint32_t))
#define DEBUG_BCR_E        0x1
#define DEBUG_BCR_PMC      0x6
#define DEBUG_BCR_BAS      0x1e0
#define DEBUG_WCR_E        0x1
#define DEBUG_MDSCR_SS     0x1
#define DEBUG_USER_LIMIT   (1ull << 48)
#define EXC_ARM_BREAKPOINT 1
#define EXCEPTION_REPLY_ID 100

#define DARWIN_X86_THREAD_STATE64 4
struct darwin_x86_thread_state64 {
	uint64_t rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp;
	uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
	uint64_t rip, rflags, cs, fs, gs;
};
#define DARWIN_X86_THREAD_STATE64_COUNT                                        \
	(sizeof(struct darwin_x86_thread_state64) / sizeof(uint32_t))

union exception_request {
	mach_msg_header_t header;
	__Request__exception_raise_t raise;
	__Request__exception_raise_state_t state;
	__Request__exception_raise_state_identity_t identity;
	__Request__mach_exception_raise_t raise64;
	__Request__mach_exception_raise_state_t state64;
	__Request__mach_exception_raise_state_identity_t identity64;
};

union exception_reply {
	mach_msg_header_t header;
	mig_reply_error_t error;
	__Reply__mach_exception_raise_state_t state;
	uint8_t space[sizeof(__Reply__mach_exception_raise_state_t)
			+ MAX_TRAILER_SIZE];
};

struct thread_times {
	uint64_t user;
	uint64_t system;
	integer_t run_state;
};

static const ucontext_t *hold_guest_context(struct thread *thread);
static kern_return_t get_state(const ucontext_t *context,
		thread_state_flavor_t flavor, thread_state_t old_state,
		mach_msg_type_number_t *old_stateCnt);
#ifndef __x86_64__
static void get_arm_thread_state64(
		const mcontext_t *mc, struct darwin_arm_thread_state64 *state);
#endif
static void release_guest_context(struct thread *thread);
#ifndef __x86_64__
static kern_return_t set_debug_state(struct thread *thread, const natural_t *in,
		mach_msg_type_number_t count);
static int open_breakpoint(pid_t tid, uint64_t address);
static void close_breakpoints(int *fds, uint32_t armed);
static void step_disarm(struct thread *thread);
static int step_targets(const mcontext_t *mc, uint64_t next[2]);
static int64_t sign_extend(uint64_t value, unsigned bits);
static bool raise_exception(struct thread *thread, ucontext_t *context,
		exception_type_t exception, const int64_t code[2]);
static kern_return_t deliver(struct thread *thread, ucontext_t *context,
		const struct exception_action *action,
		exception_type_t exception, const int64_t code[2]);
static mach_msg_size_t fill_request(union exception_request *request,
		exception_behavior_t behavior, bool codes64,
		struct thread *thread, const ucontext_t *context,
		const struct exception_action *action,
		exception_type_t exception, const int64_t code[2]);
static kern_return_t take_reply(union exception_reply *reply,
		mach_msg_return_t received, mach_msg_id_t request_id,
		exception_behavior_t behavior, ucontext_t *context);
static void destroy_reply(mach_msg_header_t *header);
#endif
#ifndef __x86_64__
static kern_return_t set_state(ucontext_t *context,
		thread_state_flavor_t flavor, thread_state_t new_state,
		mach_msg_type_number_t new_stateCnt);
static struct fpsimd_context *fpsimd_of(const ucontext_t *context);
static bool thread_state_from_darwin(thread_state_flavor_t flavor,
		const natural_t *in, mach_msg_type_number_t count,
		struct thread_state *out);
#endif
static struct thread_times thread_times(struct thread *thread);
static void extended_info(
		const struct thread_times *times, thread_extended_info_t info);
static uint64_t timeval_nanoseconds(const struct timeval *time);
static integer_t run_state(char linux_state);
static time_value_t time_value(uint64_t nanoseconds);
static uint64_t started_thread_id(struct thread *thread);

static pthread_mutex_t exception_lock = PTHREAD_MUTEX_INITIALIZER;

kern_return_t
thread_terminate(mach_port_t target_act)
{
	struct thread *thread
			= ipc_kobject_lookup(target_act, IPC_KOBJECT_THREAD);
	if (thread == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	thread_terminate_thread(thread);
	return KERN_SUCCESS;
}

kern_return_t
act_get_state(thread_read_t target_act, int flavor, thread_state_t old_state,
		mach_msg_type_number_t *old_stateCnt)
{
	unimplemented();
}

kern_return_t
act_set_state(thread_act_t target_act, int flavor, thread_state_t new_state,
		mach_msg_type_number_t new_stateCnt)
{
	unimplemented();
}

kern_return_t
thread_get_state(thread_read_t target_act, thread_state_flavor_t flavor,
		thread_state_t old_state, mach_msg_type_number_t *old_stateCnt)
{
	struct thread *thread
			= ipc_kobject_lookup(target_act, IPC_KOBJECT_THREAD);
	if (thread == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (flavor == DARWIN_ARM_DEBUG_STATE64) {
		if (*old_stateCnt < DARWIN_ARM_DEBUG_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		pthread_mutex_lock(&thread->suspend_lock);
		memcpy(old_state, &thread->debug_state,
				sizeof(thread->debug_state));
		pthread_mutex_unlock(&thread->suspend_lock);
		*old_stateCnt = DARWIN_ARM_DEBUG_STATE64_COUNT;
		return KERN_SUCCESS;
	}
	const ucontext_t *context = hold_guest_context(thread);
	kern_return_t kr = context != NULL
			? get_state(context, flavor, old_state, old_stateCnt)
			: KERN_FAILURE;
	release_guest_context(thread);
	return kr;
}

static const ucontext_t *
hold_guest_context(struct thread *thread)
{
	if (thread == thread_current()) {
		return thread->trap_context;
	}
	thread_suspend_other(thread);
	return thread_guest_context(thread);
}

static kern_return_t
get_state(const ucontext_t *context, thread_state_flavor_t flavor,
		thread_state_t old_state, mach_msg_type_number_t *old_stateCnt)
{
	const mcontext_t *mc = &context->uc_mcontext;
	switch (flavor) {
#ifdef __x86_64__
	case DARWIN_X86_THREAD_STATE64: {
		if (*old_stateCnt < DARWIN_X86_THREAD_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		const greg_t *gregs = mc->gregs;
		uint64_t segments = (uint64_t)gregs[REG_CSGSFS];
		struct darwin_x86_thread_state64 *state = (void *)old_state;
		*state = (struct darwin_x86_thread_state64){
				.rax = gregs[REG_RAX],
				.rbx = gregs[REG_RBX],
				.rcx = gregs[REG_RCX],
				.rdx = gregs[REG_RDX],
				.rdi = gregs[REG_RDI],
				.rsi = gregs[REG_RSI],
				.rbp = gregs[REG_RBP],
				.rsp = gregs[REG_RSP],
				.r8 = gregs[REG_R8],
				.r9 = gregs[REG_R9],
				.r10 = gregs[REG_R10],
				.r11 = gregs[REG_R11],
				.r12 = gregs[REG_R12],
				.r13 = gregs[REG_R13],
				.r14 = gregs[REG_R14],
				.r15 = gregs[REG_R15],
				.rip = gregs[REG_RIP],
				.rflags = gregs[REG_EFL],
				.cs = segments & 0xffff,
				.gs = (segments >> 16) & 0xffff,
				.fs = (segments >> 32) & 0xffff,
		};
		*old_stateCnt = DARWIN_X86_THREAD_STATE64_COUNT;
		return KERN_SUCCESS;
	}
#else
	case DARWIN_ARM_THREAD_STATE64: {
		if (*old_stateCnt < DARWIN_ARM_THREAD_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		get_arm_thread_state64(mc, (void *)old_state);
		*old_stateCnt = DARWIN_ARM_THREAD_STATE64_COUNT;
		return KERN_SUCCESS;
	}
	case DARWIN_ARM_THREAD_STATE: {
		if (*old_stateCnt < DARWIN_ARM_UNIFIED_THREAD_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		struct darwin_arm_unified_thread_state *unified
				= (void *)old_state;
		unified->flavor = DARWIN_ARM_THREAD_STATE64;
		unified->count = DARWIN_ARM_THREAD_STATE64_COUNT;
		get_arm_thread_state64(mc, &unified->state64);
		*old_stateCnt = DARWIN_ARM_UNIFIED_THREAD_STATE_COUNT;
		return KERN_SUCCESS;
	}
	case DARWIN_ARM_NEON_STATE64: {
		if (*old_stateCnt < DARWIN_ARM_NEON_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		const struct fpsimd_context *fpsimd = fpsimd_of(context);
		struct darwin_arm_neon_state64 neon = {0};
		if (fpsimd != NULL) {
			neon.fpsr = fpsimd->fpsr;
			neon.fpcr = fpsimd->fpcr;
			memcpy(neon.v, fpsimd->vregs, sizeof(neon.v));
		}
		memcpy(old_state, &neon, sizeof(neon));
		*old_stateCnt = DARWIN_ARM_NEON_STATE64_COUNT;
		return KERN_SUCCESS;
	}
#endif
	default:
		return KERN_INVALID_ARGUMENT;
	}
}

#ifndef __x86_64__
static void
get_arm_thread_state64(
		const mcontext_t *mc, struct darwin_arm_thread_state64 *state)
{
	memset(state, 0, sizeof(*state));
	memcpy(state->x, mc->regs, sizeof(state->x));
	state->fp = mc->regs[29];
	state->lr = mc->regs[30];
	state->sp = mc->sp;
	state->pc = mc->pc;
	state->cpsr = (uint32_t)mc->pstate;

	state->flags = 0x1;
}
#endif

static void
release_guest_context(struct thread *thread)
{
	if (thread != thread_current()) {
		thread_resume_thread(thread);
	}
}

kern_return_t
thread_set_state(thread_act_t target_act, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt)
{
#ifdef __x86_64__
	unimplemented();
#else
	struct thread *thread
			= ipc_kobject_lookup(target_act, IPC_KOBJECT_THREAD);
	if (thread == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (flavor == DARWIN_ARM_DEBUG_STATE64) {
		return set_debug_state(thread, new_state, new_stateCnt);
	}
	ucontext_t *context = (ucontext_t *)hold_guest_context(thread);
	kern_return_t kr = context != NULL
			? set_state(context, flavor, new_state, new_stateCnt)
			: KERN_FAILURE;
	release_guest_context(thread);
	return kr;
#endif
}

#ifndef __x86_64__
static kern_return_t
set_debug_state(struct thread *thread, const natural_t *in,
		mach_msg_type_number_t count)
{
	if (count < DARWIN_ARM_DEBUG_STATE64_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}
	struct thread_debug_state state;
	memcpy(&state, in, sizeof(state));
	uint32_t wanted = 0;
	for (int i = 0; i < THREAD_DEBUG_PAIRS; i++) {
		if (state.wcr[i] & DEBUG_WCR_E) {
			return KERN_INVALID_ARGUMENT;
		}
		if (!(state.bcr[i] & DEBUG_BCR_E)) {
			continue;
		}
		if ((state.bcr[i]
				    & ~(uint64_t)(DEBUG_BCR_E | DEBUG_BCR_PMC
						    | DEBUG_BCR_BAS))
				|| (state.bcr[i] & DEBUG_BCR_BAS)
						!= DEBUG_BCR_BAS) {
			return KERN_INVALID_ARGUMENT;
		}
		if (state.bvr[i] >= DEBUG_USER_LIMIT) {
			return KERN_PROTECTION_FAILURE;
		}
		wanted |= 1u << i;
	}
	pid_t tid = __atomic_load_n(&thread->tid, __ATOMIC_ACQUIRE);
	if (wanted != 0 && tid == 0) {
		return KERN_FAILURE;
	}
	int fds[THREAD_DEBUG_PAIRS];
	uint32_t armed = 0;
	for (int i = 0; i < THREAD_DEBUG_PAIRS; i++) {
		if (!(wanted & (1u << i))) {
			continue;
		}
		fds[i] = open_breakpoint(tid, state.bvr[i] & ~3ull);
		if (fds[i] == -1) {
			kern_return_t kr = errno == ENOSPC
					? KERN_RESOURCE_SHORTAGE
					: KERN_FAILURE;
			close_breakpoints(fds, armed);
			return kr;
		}
		armed |= 1u << i;
	}
	pthread_mutex_lock(&thread->suspend_lock);
	close_breakpoints(thread->breakpoint_fds, thread->breakpoints_armed);
	memcpy(thread->breakpoint_fds, fds, sizeof(fds));
	thread->breakpoints_armed = armed;
	thread->debug_state = state;
	pthread_mutex_unlock(&thread->suspend_lock);
	return KERN_SUCCESS;
}

static int
open_breakpoint(pid_t tid, uint64_t address)
{
	struct perf_event_attr attr = {
			.type = PERF_TYPE_BREAKPOINT,
			.size = sizeof(attr),
			.bp_type = HW_BREAKPOINT_X,
			.bp_addr = address,
			.bp_len = HW_BREAKPOINT_LEN_4,
			.sample_period = 1,
			.exclude_kernel = 1,
			.exclude_hv = 1,
			.sigtrap = 1,
			.remove_on_exec = 1,
	};
	return limbo_fd_high((int)syscall(SYS_perf_event_open, &attr, tid, -1,
			-1, PERF_FLAG_FD_CLOEXEC));
}

static void
close_breakpoints(int *fds, uint32_t armed)
{
	for (int i = 0; i < THREAD_DEBUG_PAIRS; i++) {
		if (armed & (1u << i)) {
			close(fds[i]);
		}
	}
}

static void
step_disarm(struct thread *thread)
{
	pthread_mutex_lock(&thread->suspend_lock);
	close_breakpoints(thread->step_fds, thread->steps_armed);
	thread->steps_armed = 0;
	thread->debug_state.mdscr_el1 &= ~(uint64_t)DEBUG_MDSCR_SS;
	pthread_mutex_unlock(&thread->suspend_lock);
}

static int
step_targets(const mcontext_t *mc, uint64_t next[2])
{
	uint64_t pc = mc->pc;
	uint32_t insn;
	struct iovec local = {&insn, sizeof(insn)};
	struct iovec remote = {(void *)(uintptr_t)pc, sizeof(insn)};
	next[0] = pc + 4;
	if (process_vm_readv(getpid(), &local, 1, &remote, 1, 0)
			!= sizeof(insn)) {
		return 1;
	}
	if ((insn & 0x7c000000) == 0x14000000) {
		next[0] = pc + sign_extend((insn & 0x3ffffff) << 2, 28);
		return 1;
	}
	if ((insn & 0xff000000) == 0x54000000
			|| (insn & 0x7e000000) == 0x34000000) {
		next[1] = pc + sign_extend(((insn >> 5) & 0x7ffff) << 2, 21);
		return 2;
	}
	if ((insn & 0x7e000000) == 0x36000000) {
		next[1] = pc + sign_extend(((insn >> 5) & 0x3fff) << 2, 16);
		return 2;
	}
	if ((insn & 0xfe000000) == 0xd6000000) {
		unsigned opc = (insn >> 21) & 0xf;
		unsigned rn = (insn >> 5) & 0x1f;
		bool authenticated_return = opc == 2 && (insn & 0x800);
		bool branches = opc == 0 || opc == 1 || opc == 2 || opc == 8
				|| opc == 9;
		if (branches && (rn != 31 || authenticated_return)) {
			uint64_t target = mc->regs[authenticated_return ? 30
									: rn];
			next[0] = target & (DEBUG_USER_LIMIT - 1);
		}
	}
	return 1;
}

static int64_t
sign_extend(uint64_t value, unsigned bits)
{
	return (int64_t)(value << (64 - bits)) >> (64 - bits);
}
#endif

void
thread_breakpoints_release(struct thread *thread)
{
#ifndef __x86_64__
	close_breakpoints(thread->breakpoint_fds, thread->breakpoints_armed);
	close_breakpoints(thread->step_fds, thread->steps_armed);
#endif
	thread->breakpoints_armed = 0;
	thread->steps_armed = 0;
	memset(&thread->debug_state, 0, sizeof(thread->debug_state));
}

void
thread_step_arm(struct thread *thread, const void *context)
{
#ifdef __x86_64__
	(void)thread;
	(void)context;
#else
	if (!(thread->debug_state.mdscr_el1 & DEBUG_MDSCR_SS)
			|| thread->steps_armed != 0) {
		return;
	}
	const mcontext_t *mc = &((const ucontext_t *)context)->uc_mcontext;
	uint64_t next[2];
	int count = step_targets(mc, next);
	uint32_t armed = 0;
	int fds[2];
	for (int i = 0; i < count; i++) {
		fds[i] = open_breakpoint(thread->tid, next[i]);
		if (fds[i] == -1) {
			close_breakpoints(fds, armed);
			fprintf(stderr,
					"limbo: a single step at %#llx could "
					"not "
					"be armed\n",
					(unsigned long long)mc->pc);
			return;
		}
		armed |= 1u << i;
	}
	pthread_mutex_lock(&thread->suspend_lock);
	memcpy(thread->step_fds, fds, sizeof(fds));
	memcpy(thread->step_at, next, sizeof(next));
	thread->steps_armed = armed;
	pthread_mutex_unlock(&thread->suspend_lock);
#endif
}

bool
thread_breakpoint_hit(void *context)
{
#ifdef __x86_64__
	(void)context;
	return false;
#else
	struct thread *thread = thread_current();
	ucontext_t *uc = context;
	uint64_t pc = uc->uc_mcontext.pc;
	bool armed = false, stepped = false;
	pthread_mutex_lock(&thread->suspend_lock);
	for (int i = 0; i < THREAD_DEBUG_PAIRS; i++) {
		armed |= (thread->breakpoints_armed & (1u << i))
				&& (thread->debug_state.bvr[i] & ~3ull) == pc;
	}
	for (int i = 0; i < 2; i++) {
		stepped |= (thread->steps_armed & (1u << i))
				&& thread->step_at[i] == pc;
	}
	pthread_mutex_unlock(&thread->suspend_lock);
	if (stepped) {
		step_disarm(thread);
	}
	const int64_t code[2] = {EXC_ARM_BREAKPOINT, stepped ? 0 : (int64_t)pc};
	bool raised = (armed || stepped)
			&& raise_exception(thread, uc, EXC_BREAKPOINT, code);
	if (raised) {
		thread_step_arm(thread, uc);
	}
	return raised;
#endif
}

#ifndef __x86_64__
static kern_return_t
set_state(ucontext_t *context, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt)
{
	if (flavor == DARWIN_ARM_NEON_STATE64) {
		if (new_stateCnt < DARWIN_ARM_NEON_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		struct darwin_arm_neon_state64 neon;
		memcpy(&neon, new_state, sizeof(neon));
		struct fpsimd_context *fpsimd = fpsimd_of(context);
		if (fpsimd != NULL) {
			memcpy(fpsimd->vregs, neon.v, sizeof(neon.v));
			fpsimd->fpsr = neon.fpsr;
			fpsimd->fpcr = neon.fpcr;
		}
		return KERN_SUCCESS;
	}
	struct thread_state state;
	if (!thread_state_from_darwin(
			    flavor, new_state, new_stateCnt, &state)) {
		return KERN_INVALID_ARGUMENT;
	}
	mcontext_t *mc = &context->uc_mcontext;
	memcpy(mc->regs, state.regs, sizeof(state.regs));
	mc->sp = state.sp;
	mc->pc = state.pc;
	return KERN_SUCCESS;
}

static struct fpsimd_context *
fpsimd_of(const ucontext_t *context)
{
	uint8_t *p = (uint8_t *)context->uc_mcontext.__reserved;
	uint8_t *end = p + sizeof(context->uc_mcontext.__reserved);
	while (p + sizeof(struct _aarch64_ctx) <= end) {
		struct _aarch64_ctx *head = (void *)p;
		if (head->magic == 0 || head->size == 0) {
			break;
		}
		if (head->magic == FPSIMD_MAGIC) {
			return (struct fpsimd_context *)head;
		}
		p += head->size;
	}
	return NULL;
}
#endif

kern_return_t
thread_create(task_t parent_task, thread_act_t *child_act)
{
	unimplemented();
}

kern_return_t
thread_create_running(task_t parent_task, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt,
		thread_act_t *child_act)
{
#ifdef __x86_64__
	unimplemented();
#else
	struct thread_state state;
	if (!thread_state_from_darwin(
			    flavor, new_state, new_stateCnt, &state)) {
		return KERN_INVALID_ARGUMENT;
	}
	struct thread *thread = thread_new(NULL, NULL);
	*child_act = ipc_kobject_copy_send(thread->port);
	if (thread_start(thread, &state) != 0) {
		return KERN_RESOURCE_SHORTAGE;
	}
	return KERN_SUCCESS;
#endif
}

#ifndef __x86_64__
static bool
thread_state_from_darwin(thread_state_flavor_t flavor, const natural_t *in,
		mach_msg_type_number_t count, struct thread_state *out)
{
	const struct darwin_arm_unified_thread_state *unified
			= (const void *)in;
	const struct darwin_arm_thread_state64 *state;
	if (flavor == DARWIN_ARM_THREAD_STATE
			&& count >= DARWIN_ARM_UNIFIED_THREAD_STATE_COUNT
			&& unified->flavor == DARWIN_ARM_THREAD_STATE64) {
		state = &unified->state64;
	} else if (flavor == DARWIN_ARM_THREAD_STATE64
			&& count >= DARWIN_ARM_THREAD_STATE64_COUNT) {
		state = (const void *)in;
	} else {
		return false;
	}
	memset(out, 0, sizeof(*out));
	out->full = true;
	memcpy(out->regs, state->x, sizeof(state->x));
	out->regs[29] = state->fp;
	out->regs[30] = state->lr;
	out->sp = state->sp;
	out->pc = state->pc;
	return true;
}
#endif

kern_return_t
thread_suspend(thread_read_t target_act)
{
	struct thread *thread
			= ipc_kobject_lookup(target_act, IPC_KOBJECT_THREAD);
	if (thread == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (thread != thread_current()) {
		return thread_suspend_other(thread);
	}
	thread_suspend_self();
	return KERN_SUCCESS;
}

kern_return_t
thread_resume(thread_read_t target_act)
{
	struct thread *thread
			= ipc_kobject_lookup(target_act, IPC_KOBJECT_THREAD);
	if (thread == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	thread_resume_thread(thread);
	return KERN_SUCCESS;
}

kern_return_t
thread_abort(thread_act_t target_act)
{
	unimplemented();
}

kern_return_t
thread_abort_safely(thread_act_t target_act)
{
	unimplemented();
}

kern_return_t
thread_depress_abort(thread_act_t thread)
{
	unimplemented();
}

kern_return_t
thread_get_special_port(thread_inspect_t thr_act, int which_port,
		mach_port_t *special_port)
{
	unimplemented();
}

kern_return_t
thread_set_special_port(
		thread_act_t thr_act, int which_port, mach_port_t special_port)
{
	unimplemented();
}

kern_return_t
thread_info(thread_inspect_t target_act, thread_flavor_t flavor,
		thread_info_t thread_info_out,
		mach_msg_type_number_t *thread_info_outCnt)
{
	struct thread *thread
			= ipc_kobject_lookup(target_act, IPC_KOBJECT_THREAD);
	if (thread == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	switch (flavor) {
	case THREAD_BASIC_INFO: {
		if (*thread_info_outCnt < THREAD_BASIC_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		struct thread_times times = thread_times(thread);
		thread_basic_info_t info = (thread_basic_info_t)thread_info_out;
		*info = (thread_basic_info_data_t){
				.user_time = time_value(times.user),
				.system_time = time_value(times.system),
				.policy = POLICY_TIMESHARE,
				.run_state = times.run_state,
		};
		*thread_info_outCnt = THREAD_BASIC_INFO_COUNT;
		return KERN_SUCCESS;
	}
	case THREAD_EXTENDED_INFO: {
		if (*thread_info_outCnt < THREAD_EXTENDED_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		struct thread_times times = thread_times(thread);
		thread_extended_info_t info
				= (thread_extended_info_t)thread_info_out;
		extended_info(&times, info);
		memcpy(info->pth_name, thread->name, sizeof(info->pth_name));
		*thread_info_outCnt = THREAD_EXTENDED_INFO_COUNT;
		return KERN_SUCCESS;
	}
	case THREAD_SCHED_TIMESHARE_INFO: {
		if (*thread_info_outCnt < POLICY_TIMESHARE_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		policy_timeshare_info_t info
				= (policy_timeshare_info_t)thread_info_out;
		*info = (policy_timeshare_info_data_t){
				.max_priority = 63,
				.base_priority = 31,
				.cur_priority = 31,
		};
		*thread_info_outCnt = POLICY_TIMESHARE_INFO_COUNT;
		return KERN_SUCCESS;
	}
	case THREAD_IDENTIFIER_INFO: {
		if (*thread_info_outCnt < THREAD_IDENTIFIER_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		uint64_t handle = thread->tsd_base;
		uint64_t queue = handle == 0
				? 0
				: handle + bsdthread_dispatch_queue_offset();
		thread_identifier_info_t info
				= (thread_identifier_info_t)thread_info_out;
		*info = (thread_identifier_info_data_t){
				.thread_id = started_thread_id(thread),
				.thread_handle = handle,
				.dispatch_qaddr = queue,
		};
		*thread_info_outCnt = THREAD_IDENTIFIER_INFO_COUNT;
		return KERN_SUCCESS;
	}
	default:
		unimplemented();
	}
}

static struct thread_times
thread_times(struct thread *thread)
{
	struct thread_times times = {.run_state = TH_STATE_RUNNING};
	if (thread == thread_current()) {
		struct rusage usage;
		getrusage(RUSAGE_THREAD, &usage);
		times.user = timeval_nanoseconds(&usage.ru_utime);
		times.system = timeval_nanoseconds(&usage.ru_stime);
		return times;
	}
	pid_t tid = __atomic_load_n(&thread->tid, __ATOMIC_ACQUIRE);
	struct process_thread stat;
	if (process_thread_lookup(getpid(), tid, &stat) == 0) {
		times.user = process_ticks_to_nanoseconds(stat.user_ticks);
		times.system = process_ticks_to_nanoseconds(stat.system_ticks);
		times.run_state = run_state(stat.state);
	}
	return times;
}

static void
extended_info(const struct thread_times *times, thread_extended_info_t info)
{
	*info = (thread_extended_info_data_t){
			.pth_user_time = times->user,
			.pth_system_time = times->system,
			.pth_policy = POLICY_TIMESHARE,
			.pth_run_state = times->run_state,
			.pth_curpri = 31,
			.pth_priority = 31,
			.pth_maxpriority = 63,
	};
}

bool
thread_linux_extended_info(pid_t pid, pid_t tid, thread_extended_info_t info)
{
	struct process_thread stat;
	if (process_thread_lookup(pid, tid, &stat) != 0) {
		return false;
	}
	struct thread_times times = {
			.user = process_ticks_to_nanoseconds(stat.user_ticks),
			.system
			= process_ticks_to_nanoseconds(stat.system_ticks),
			.run_state = run_state(stat.state),
	};
	extended_info(&times, info);
	memcpy(info->pth_name, stat.comm, sizeof(stat.comm));
	return true;
}

static uint64_t
timeval_nanoseconds(const struct timeval *time)
{
	return (uint64_t)time->tv_sec * 1000000000
			+ (uint64_t)time->tv_usec * 1000;
}

static integer_t
run_state(char linux_state)
{
	switch (linux_state) {
	case 'R':
		return TH_STATE_RUNNING;
	case 'D':
		return TH_STATE_UNINTERRUPTIBLE;
	case 'T':
	case 't':
		return TH_STATE_STOPPED;
	case 'Z':
	case 'X':
		return TH_STATE_HALTED;
	default:
		return TH_STATE_WAITING;
	}
}

static time_value_t
time_value(uint64_t nanoseconds)
{
	uint64_t microseconds = nanoseconds / 1000;
	return (time_value_t){
			.seconds = (integer_t)(microseconds / 1000000),
			.microseconds = (integer_t)(microseconds % 1000000),
	};
}

static uint64_t
started_thread_id(struct thread *thread)
{
	pid_t tid;
	while ((tid = __atomic_load_n(&thread->tid, __ATOMIC_ACQUIRE)) == 0
			&& thread->spawned && !thread->terminating) {
		sched_yield();
	}
	return (uint64_t)tid;
}

kern_return_t
thread_set_exception_ports(thread_act_t thread, exception_mask_t exception_mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t new_flavor)
{
	struct thread *target = ipc_kobject_lookup(thread, IPC_KOBJECT_THREAD);
	if (target == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	exception_actions_set(&target->exception_actions, exception_mask,
			new_port, behavior, new_flavor, false);
	return KERN_SUCCESS;
}

kern_return_t
thread_get_exception_ports(thread_act_t thread, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	struct thread *target = ipc_kobject_lookup(thread, IPC_KOBJECT_THREAD);
	if (target == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	exception_actions_get(&target->exception_actions, exception_mask, masks,
			masksCnt, old_handlers, old_behaviors, old_flavors);
	return KERN_SUCCESS;
}

kern_return_t
thread_swap_exception_ports(thread_act_t thread,
		exception_mask_t exception_mask, mach_port_t new_port,
		exception_behavior_t behavior, thread_state_flavor_t new_flavor,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	struct thread *target = ipc_kobject_lookup(thread, IPC_KOBJECT_THREAD);
	if (target == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	exception_actions_get(&target->exception_actions, exception_mask, masks,
			masksCnt, old_handlers, old_behaviors, old_flavors);
	exception_actions_set(&target->exception_actions, exception_mask,
			new_port, behavior, new_flavor, true);
	return KERN_SUCCESS;
}

void
exception_actions_get(struct exception_action **actions, exception_mask_t mask,
		exception_mask_array_t masks, mach_msg_type_number_t *count,
		exception_handler_array_t handlers,
		exception_behavior_array_t behaviors,
		exception_flavor_array_t flavors)
{
	pthread_mutex_lock(&exception_lock);
	if (*actions == NULL) {
		pthread_mutex_unlock(&exception_lock);
		*count = 0;
		return;
	}
	mach_msg_type_number_t found = 0;
	for (int type = FIRST_EXCEPTION; type < EXC_TYPES_COUNT; type++) {
		if (!(mask & (1 << type))) {
			continue;
		}
		const struct exception_action *action = &(*actions)[type];
		mach_msg_type_number_t i = 0;
		while (i < found
				&& !(handlers[i] == action->port
						&& behaviors[i] == action->behavior
						&& flavors[i] == action->flavor)) {
			i++;
		}
		if (i == found) {
			if (found == *count) {
				continue;
			}
			masks[found] = 0;
			handlers[found] = action->port;
			behaviors[found] = action->behavior;
			flavors[found] = action->flavor;
			found++;
		}
		masks[i] |= 1 << type;
	}
	pthread_mutex_unlock(&exception_lock);
	*count = found;
}

void
exception_actions_set(struct exception_action **actions, exception_mask_t mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t flavor, bool keep_old)
{
	pthread_mutex_lock(&exception_lock);
	if (*actions == NULL) {
		*actions = calloc(EXC_TYPES_COUNT, sizeof(**actions));
	}
	for (int type = FIRST_EXCEPTION; type < EXC_TYPES_COUNT; type++) {
		if (!(mask & (1 << type))) {
			continue;
		}
		struct exception_action *action = &(*actions)[type];
		mach_port_name_t old = action->port;
		ipc_port_mod_refs(new_port, MACH_PORT_RIGHT_SEND, 1);
		action->port = new_port;
		action->behavior = behavior;
		action->flavor = flavor;
		if (!keep_old) {
			ipc_port_mod_refs(old, MACH_PORT_RIGHT_SEND, -1);
		}
	}
	pthread_mutex_unlock(&exception_lock);
}

bool
exception_action_take(struct exception_action **actions, exception_type_t type,
		struct exception_action *out)
{
	pthread_mutex_lock(&exception_lock);
	bool found = *actions != NULL && MACH_PORT_VALID((*actions)[type].port);
	if (found) {
		*out = (*actions)[type];
		ipc_port_mod_refs(out->port, MACH_PORT_RIGHT_SEND, 1);
	}
	pthread_mutex_unlock(&exception_lock);
	return found;
}

#ifndef __x86_64__
static bool
raise_exception(struct thread *thread, ucontext_t *context,
		exception_type_t exception, const int64_t code[2])
{
	void *outer;
	thread_enter_trap(context, &outer);
	kern_return_t kr = KERN_FAILURE;
	struct exception_action action;
	if (exception_action_take(
			    &thread->exception_actions, exception, &action)) {
		kr = deliver(thread, context, &action, exception, code);
		ipc_port_mod_refs(action.port, MACH_PORT_RIGHT_SEND, -1);
	}
	if (kr != KERN_SUCCESS && task_exception_action(exception, &action)) {
		kr = deliver(thread, context, &action, exception, code);
		ipc_port_mod_refs(action.port, MACH_PORT_RIGHT_SEND, -1);
	}
	thread_leave_trap(context, outer);
	return kr == KERN_SUCCESS;
}

static kern_return_t
deliver(struct thread *thread, ucontext_t *context,
		const struct exception_action *action,
		exception_type_t exception, const int64_t code[2])
{
	exception_behavior_t behavior = action->behavior & ~MACH_EXCEPTION_MASK;
	if (behavior != EXCEPTION_DEFAULT && behavior != EXCEPTION_STATE
			&& behavior != EXCEPTION_STATE_IDENTITY) {
		return KERN_FAILURE;
	}
	bool codes64 = (action->behavior & MACH_EXCEPTION_CODES) != 0;
	mach_port_name_t reply_port;
	if (ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, &reply_port)
			!= KERN_SUCCESS) {
		return KERN_FAILURE;
	}
	union {
		union exception_request request;
		union exception_reply reply;
	} message;
	memset(&message, 0, sizeof(message));
	mach_msg_size_t size = fill_request(&message.request, behavior, codes64,
			thread, context, action, exception, code);
	if (size == 0) {
		ipc_port_mod_refs(reply_port, MACH_PORT_RIGHT_RECEIVE, -1);
		return KERN_FAILURE;
	}
	message.request.header.msgh_local_port = reply_port;
	mach_msg_id_t id = message.request.header.msgh_id;
	mach_port_name_t moved[2] = {
			message.request.identity.thread.name,
			message.request.identity.task.name,
	};
	mach_msg_return_t mr = ipc_mach_msg_kernel(&message.request.header,
			MACH64_SEND_MSG | MACH64_RCV_MSG, size, sizeof(message),
			reply_port, 0);
	if (mr == MACH_SEND_INVALID_DEST && behavior != EXCEPTION_STATE) {
		ipc_port_mod_refs(moved[0], MACH_PORT_RIGHT_SEND, -1);
		ipc_port_mod_refs(moved[1], MACH_PORT_RIGHT_SEND, -1);
	}
	kern_return_t kr
			= take_reply(&message.reply, mr, id, behavior, context);
	ipc_port_mod_refs(reply_port, MACH_PORT_RIGHT_RECEIVE, -1);
	return kr;
}

static mach_msg_size_t
fill_request(union exception_request *request, exception_behavior_t behavior,
		bool codes64, struct thread *thread, const ucontext_t *context,
		const struct exception_action *action,
		exception_type_t exception, const int64_t code[2])
{
	bool identity = behavior != EXCEPTION_STATE;
	request->header = (mach_msg_header_t){
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
					MACH_MSG_TYPE_MAKE_SEND_ONCE, 0,
					identity ? MACH_MSGH_BITS_COMPLEX : 0),
			.msgh_remote_port = action->port,
			.msgh_id = (codes64 ? 2405 : 2401)
					+ (behavior == EXCEPTION_DEFAULT ? 0
									: behavior == EXCEPTION_STATE
									? 1
									: 2),
	};
	if (identity) {
		request->identity64.msgh_body.msgh_descriptor_count = 2;
		request->identity64.thread = (mach_msg_port_descriptor_t){
				.name = ipc_kobject_copy_send(thread->port),
				.disposition = MACH_MSG_TYPE_MOVE_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
		request->identity64.task = (mach_msg_port_descriptor_t){
				.name = ipc_task_self(),
				.disposition = MACH_MSG_TYPE_MOVE_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
	if (identity) {
		request->identity64.NDR = NDR_record;
		request->identity64.exception = exception;
		request->identity64.codeCnt = 2;
	} else {
		request->state64.NDR = NDR_record;
		request->state64.exception = exception;
		request->state64.codeCnt = 2;
	}
	int *flavor;
	mach_msg_type_number_t *state_count;
	natural_t *state;
	mach_msg_type_number_t capacity;
	if (codes64) {
		int64_t *codes = identity ? request->identity64.code
					  : request->state64.code;
		codes[0] = code[0];
		codes[1] = code[1];
		flavor = identity ? &request->identity64.flavor
				  : &request->state64.flavor;
		state_count = identity ? &request->identity64.old_stateCnt
				       : &request->state64.old_stateCnt;
		state = identity ? request->identity64.old_state
				 : request->state64.old_state;
		capacity = sizeof(request->state64.old_state)
				/ sizeof(natural_t);
	} else {
		integer_t *codes = identity ? request->identity.code
					    : request->state.code;
		codes[0] = (integer_t)code[0];
		codes[1] = (integer_t)code[1];
		flavor = identity ? &request->identity.flavor
				  : &request->state.flavor;
		state_count = identity ? &request->identity.old_stateCnt
				       : &request->state.old_stateCnt;
		state = identity ? request->identity.old_state
				 : request->state.old_state;
		capacity = sizeof(request->state.old_state) / sizeof(natural_t);
	}
	if (behavior == EXCEPTION_DEFAULT) {
		request->header.msgh_size = codes64 ? sizeof(request->raise64)
						    : sizeof(request->raise);
		return request->header.msgh_size;
	}
	*flavor = action->flavor;
	*state_count = capacity;
	if (get_state(context, action->flavor, state, state_count)
			!= KERN_SUCCESS) {
		if (identity) {
			ipc_port_mod_refs(request->identity64.thread.name,
					MACH_PORT_RIGHT_SEND, -1);
			ipc_port_mod_refs(request->identity64.task.name,
					MACH_PORT_RIGHT_SEND, -1);
		}
		return 0;
	}
	request->header.msgh_size = (mach_msg_size_t)((uint8_t *)state
			- (uint8_t *)request
			+ *state_count * sizeof(natural_t));
	return request->header.msgh_size;
}

static kern_return_t
take_reply(union exception_reply *reply, mach_msg_return_t received,
		mach_msg_id_t request_id, exception_behavior_t behavior,
		ucontext_t *context)
{
	if (received != MACH_MSG_SUCCESS) {
		return KERN_FAILURE;
	}
	mach_msg_header_t *header = &reply->header;
	if ((header->msgh_bits & MACH_MSGH_BITS_COMPLEX)
			|| header->msgh_id != request_id + EXCEPTION_REPLY_ID
			|| header->msgh_size < sizeof(mig_reply_error_t)) {
		destroy_reply(header);
		return KERN_FAILURE;
	}
	if (reply->error.RetCode != KERN_SUCCESS
			|| behavior == EXCEPTION_DEFAULT) {
		return header->msgh_size == sizeof(mig_reply_error_t)
				? reply->error.RetCode
				: KERN_FAILURE;
	}
	mach_msg_size_t fixed = offsetof(
			__Reply__mach_exception_raise_state_t, new_state);
	mach_msg_type_number_t count = reply->state.new_stateCnt;
	if (header->msgh_size < fixed
			|| count > sizeof(reply->state.new_state)
							/ sizeof(natural_t)
			|| header->msgh_size
					!= fixed + count * sizeof(natural_t)) {
		return KERN_FAILURE;
	}
	return set_state(context, reply->state.flavor, reply->state.new_state,
			count);
}

static void
destroy_reply(mach_msg_header_t *header)
{
	if (MACH_MSGH_BITS_REMOTE(header->msgh_bits) != 0) {
		ipc_port_mod_refs(header->msgh_remote_port,
				MACH_MSGH_BITS_REMOTE(header->msgh_bits)
								== MACH_MSG_TYPE_PORT_SEND_ONCE
						? MACH_PORT_RIGHT_SEND_ONCE
						: MACH_PORT_RIGHT_SEND,
				-1);
	}
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}
	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	mach_msg_descriptor_t *descriptor = (mach_msg_descriptor_t *)(body + 1);
	uint8_t *end = (uint8_t *)header + header->msgh_size;
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count
			&& (uint8_t *)(descriptor + 1) <= end;
			i++, descriptor++) {
		if (descriptor->type.type == MACH_MSG_PORT_DESCRIPTOR) {
			mach_msg_type_name_t right
					= descriptor->port.disposition;
			ipc_port_mod_refs(descriptor->port.name,
					right == MACH_MSG_TYPE_PORT_RECEIVE
							? MACH_PORT_RIGHT_RECEIVE
							: right == MACH_MSG_TYPE_PORT_SEND_ONCE
							? MACH_PORT_RIGHT_SEND_ONCE
							: MACH_PORT_RIGHT_SEND,
					-1);
		} else if (descriptor->type.type == MACH_MSG_OOL_DESCRIPTOR
				&& descriptor->out_of_line.size != 0) {
			munmap(descriptor->out_of_line.address,
					descriptor->out_of_line.size);
		}
	}
}
#endif

kern_return_t
_kernelrpc_thread_policy(thread_act_t thr_act, policy_t policy,
		policy_base_t base, mach_msg_type_number_t baseCnt,
		boolean_t set_limit)
{
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_thread_policy_set(thread_act_t thread, thread_policy_flavor_t flavor,
		thread_policy_t policy_info,
		mach_msg_type_number_t policy_infoCnt)
{
	return KERN_SUCCESS;
}

kern_return_t
thread_policy_get(thread_inspect_t thread, thread_policy_flavor_t flavor,
		thread_policy_t policy_info,
		mach_msg_type_number_t *policy_infoCnt, boolean_t *get_default)
{
	integer_t *info = policy_info;
	switch (flavor) {
	case THREAD_EXTENDED_POLICY:

		if (*policy_infoCnt >= THREAD_EXTENDED_POLICY_COUNT) {
			((thread_extended_policy_t)info)->timeshare = TRUE;
			*policy_infoCnt = THREAD_EXTENDED_POLICY_COUNT;
		}
		return KERN_SUCCESS;
	case THREAD_TIME_CONSTRAINT_POLICY: {
		if (*policy_infoCnt < THREAD_TIME_CONSTRAINT_POLICY_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		uint32_t numer, denom;
		commpage_timebase(&numer, &denom);
		uint64_t quantum = 10000000ull * denom / numer;
		thread_time_constraint_policy_t policy = (void *)info;
		policy->period = 0;
		policy->computation = (uint32_t)(quantum / 2);
		policy->constraint = (uint32_t)quantum;
		policy->preemptible = TRUE;
		*policy_infoCnt = THREAD_TIME_CONSTRAINT_POLICY_COUNT;
		*get_default = TRUE;
		return KERN_SUCCESS;
	}
	case THREAD_PRECEDENCE_POLICY:
	case THREAD_AFFINITY_POLICY:
	case THREAD_BACKGROUND_POLICY:
	case THREAD_LATENCY_QOS_POLICY:
	case THREAD_THROUGHPUT_QOS_POLICY:

		if (*policy_infoCnt < 1) {
			return KERN_INVALID_ARGUMENT;
		}
		info[0] = 0;
		*policy_infoCnt = 1;
		*get_default = TRUE;
		return KERN_SUCCESS;
	default:
		return KERN_INVALID_ARGUMENT;
	}
}

kern_return_t
thread_sample(thread_act_t thread, mach_port_t reply)
{
	unimplemented();
}

kern_return_t
etap_trace_thread(thread_act_t target_act, boolean_t trace_status)
{
	unimplemented();
}

kern_return_t
thread_assign(thread_act_t thread, processor_set_t new_set)
{
	unimplemented();
}

kern_return_t
thread_assign_default(thread_act_t thread)
{
	unimplemented();
}

kern_return_t
thread_get_assignment(
		thread_inspect_t thread, processor_set_name_t *assigned_set)
{
	unimplemented();
}

kern_return_t
_kernelrpc_thread_set_policy(thread_act_t thr_act, processor_set_t pset,
		policy_t policy, policy_base_t base,
		mach_msg_type_number_t baseCnt, policy_limit_t limit,
		mach_msg_type_number_t limitCnt)
{
	unimplemented();
}

kern_return_t
thread_get_mach_voucher(thread_read_t thr_act, mach_voucher_selector_t which,
		ipc_voucher_t *voucher)
{
	unimplemented();
}

kern_return_t
thread_set_mach_voucher(thread_act_t thr_act, ipc_voucher_t voucher)
{
	unimplemented();
}

kern_return_t
thread_swap_mach_voucher(thread_act_t thr_act, ipc_voucher_t new_voucher,
		ipc_voucher_t *old_voucher)
{
	unimplemented();
}

kern_return_t
thread_convert_thread_state(thread_act_t thread, int direction,
		thread_state_flavor_t flavor, thread_state_t in_state,
		mach_msg_type_number_t in_stateCnt, thread_state_t out_state,
		mach_msg_type_number_t *out_stateCnt)
{
	if (direction != THREAD_CONVERT_THREAD_STATE_TO_SELF
			&& direction != THREAD_CONVERT_THREAD_STATE_FROM_SELF) {
		return KERN_INVALID_ARGUMENT;
	}
	if (*out_stateCnt < in_stateCnt) {
		return KERN_INSUFFICIENT_BUFFER_SIZE;
	}
	memcpy(out_state, in_state, in_stateCnt * sizeof(natural_t));
	*out_stateCnt = in_stateCnt;
	return KERN_SUCCESS;
}

kern_return_t
thread_get_exception_ports_info(mach_port_t port,
		exception_mask_t exception_mask, exception_mask_array_t masks,
		mach_msg_type_number_t *masksCnt,
		exception_handler_info_array_t old_handlers_info,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	unimplemented();
}

kern_return_t
thread_adopt_exception_handler(thread_t thread, mach_port_t exc_port,
		exception_mask_t exc_mask, exception_behavior_t behavior_mask,
		thread_state_flavor_t flavor_mask)
{
	return KERN_SUCCESS;
}

kern_return_t
thread_suspend2(thread_read_t target_act, mach_port_t *suspend_token)
{
	unimplemented();
}

kern_return_t
thread_resume2(mach_port_t suspend_token)
{
	unimplemented();
}
