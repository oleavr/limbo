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

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>

#include "ipc.h"
#include "commpage.h"
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

#define DARWIN_X86_THREAD_STATE64 4
struct darwin_x86_thread_state64 {
	uint64_t rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp;
	uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
	uint64_t rip, rflags, cs, fs, gs;
};
#define DARWIN_X86_THREAD_STATE64_COUNT                                        \
	(sizeof(struct darwin_x86_thread_state64) / sizeof(uint32_t))

kern_return_t
thread_terminate(mach_port_t target_act)
{
	unimplemented();
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
	const ucontext_t *context = thread_guest_context(thread);
	if (context == NULL) {
		return KERN_FAILURE;
	}
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
		struct darwin_arm_thread_state64 *state = (void *)old_state;
		memset(state, 0, sizeof(*state));
		memcpy(state->x, mc->regs, sizeof(state->x));
		state->fp = mc->regs[29];
		state->lr = mc->regs[30];
		state->sp = mc->sp;
		state->pc = mc->pc;
		state->cpsr = (uint32_t)mc->pstate;

		state->flags = 0x1;
		*old_stateCnt = DARWIN_ARM_THREAD_STATE64_COUNT;
		return KERN_SUCCESS;
	}
#endif
	default:
		return KERN_INVALID_ARGUMENT;
	}
}

kern_return_t
thread_set_state(thread_act_t target_act, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt)
{
	unimplemented();
}

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
	switch (flavor) {
	case THREAD_BASIC_INFO: {
		if (*thread_info_outCnt < THREAD_BASIC_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		thread_basic_info_t info = (thread_basic_info_t)thread_info_out;
		*info = (thread_basic_info_data_t){
				.policy = POLICY_TIMESHARE,
				.run_state = TH_STATE_RUNNING,
		};
		*thread_info_outCnt = THREAD_BASIC_INFO_COUNT;
		return KERN_SUCCESS;
	}
	case THREAD_EXTENDED_INFO: {
		if (*thread_info_outCnt < THREAD_EXTENDED_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		thread_extended_info_t info
				= (thread_extended_info_t)thread_info_out;
		*info = (thread_extended_info_data_t){
				.pth_policy = POLICY_TIMESHARE,
				.pth_run_state = TH_STATE_RUNNING,
				.pth_curpri = 31,
				.pth_priority = 31,
				.pth_maxpriority = 63,
		};
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
	default:
		unimplemented();
	}
}

kern_return_t
thread_set_exception_ports(thread_act_t thread, exception_mask_t exception_mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t new_flavor)
{
	return KERN_SUCCESS;
}

kern_return_t
thread_get_exception_ports(thread_act_t thread, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	*masksCnt = 0;
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
	unimplemented();
}

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
	unimplemented();
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
