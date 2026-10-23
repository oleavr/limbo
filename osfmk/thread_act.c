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

#include <mach/mach.h>
#include <stdio.h>

#include "ipc.h"
#include "thread.h"

kern_return_t
thread_terminate(mach_port_t target_act)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_terminate(%p)\n", (void *)target_act);
#endif
	unimplemented();
}

kern_return_t
act_get_state(thread_read_t target_act, int flavor, thread_state_t old_state,
		mach_msg_type_number_t *old_stateCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "act_get_state(%p, %p, %p, %p)\n", (void *)target_act,
			(void *)flavor, (void *)old_state,
			(void *)old_stateCnt);
#endif
	unimplemented();
}

kern_return_t
act_set_state(thread_act_t target_act, int flavor, thread_state_t new_state,
		mach_msg_type_number_t new_stateCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "act_set_state(%p, %p, %p, %p)\n", (void *)target_act,
			(void *)flavor, (void *)new_state,
			(void *)new_stateCnt);
#endif
	unimplemented();
}

kern_return_t
thread_get_state(thread_read_t target_act, thread_state_flavor_t flavor,
		thread_state_t old_state, mach_msg_type_number_t *old_stateCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_get_state(%p, %p, %p, %p)\n",
			(void *)target_act, (void *)flavor, (void *)old_state,
			(void *)old_stateCnt);
#endif
	unimplemented();
}

kern_return_t
thread_set_state(thread_act_t target_act, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_set_state(%p, %p, %p, %p)\n",
			(void *)target_act, (void *)flavor, (void *)new_state,
			(void *)new_stateCnt);
#endif
	unimplemented();
}

kern_return_t
thread_suspend(thread_read_t target_act)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_suspend(%p)\n", (void *)target_act);
#endif
	struct thread *thread
			= ipc_kobject_lookup(target_act, IPC_KOBJECT_THREAD);
	if (thread == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (thread != thread_current()) {
		unimplemented();
	}
	thread_suspend_self();
	return KERN_SUCCESS;
}

kern_return_t
thread_resume(thread_read_t target_act)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_resume(%p)\n", (void *)target_act);
#endif
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
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_abort(%p)\n", (void *)target_act);
#endif
	unimplemented();
}

kern_return_t
thread_abort_safely(thread_act_t target_act)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_abort_safely(%p)\n", (void *)target_act);
#endif
	unimplemented();
}

kern_return_t
thread_depress_abort(thread_act_t thread)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_depress_abort(%p)\n", (void *)thread);
#endif
	unimplemented();
}

kern_return_t
thread_get_special_port(thread_inspect_t thr_act, int which_port,
		mach_port_t *special_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_get_special_port(%p, %p, %p)\n",
			(void *)thr_act, (void *)which_port,
			(void *)special_port);
#endif
	unimplemented();
}

kern_return_t
thread_set_special_port(
		thread_act_t thr_act, int which_port, mach_port_t special_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_set_special_port(%p, %p, %p)\n",
			(void *)thr_act, (void *)which_port,
			(void *)special_port);
#endif
	unimplemented();
}

kern_return_t
thread_info(thread_inspect_t target_act, thread_flavor_t flavor,
		thread_info_t thread_info_out,
		mach_msg_type_number_t *thread_info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_info(%p, %p, %p, %p)\n", (void *)target_act,
			(void *)flavor, (void *)thread_info_out,
			(void *)thread_info_outCnt);
#endif
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
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_set_exception_ports(%p, %p, %p, %p, %p)\n",
			(void *)thread, (void *)exception_mask,
			(void *)new_port, (void *)behavior, (void *)new_flavor);
#endif
	unimplemented();
}

kern_return_t
thread_get_exception_ports(thread_act_t thread, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"thread_get_exception_ports(%p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)thread, (void *)exception_mask, (void *)masks,
			(void *)masksCnt, (void *)old_handlers,
			(void *)old_behaviors, (void *)old_flavors);
#endif
	unimplemented();
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
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"thread_swap_exception_ports(%p, %p, %p, %p, %p, %p, "
			"%p, %p, %p, %p)\n",
			(void *)thread, (void *)exception_mask,
			(void *)new_port, (void *)behavior, (void *)new_flavor,
			(void *)masks, (void *)masksCnt, (void *)old_handlers,
			(void *)old_behaviors, (void *)old_flavors);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_thread_policy(thread_act_t thr_act, policy_t policy,
		policy_base_t base, mach_msg_type_number_t baseCnt,
		boolean_t set_limit)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_thread_policy(%p, %p, %p, %p, %p)\n",
			(void *)thr_act, (void *)policy, (void *)base,
			(void *)baseCnt, (void *)set_limit);
#endif
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_thread_policy_set(thread_act_t thread, thread_policy_flavor_t flavor,
		thread_policy_t policy_info,
		mach_msg_type_number_t policy_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_thread_policy_set(%p, %p, %p, %p)\n",
			(void *)thread, (void *)flavor, (void *)policy_info,
			(void *)policy_infoCnt);
#endif
	return KERN_SUCCESS;
}

kern_return_t
thread_policy_get(thread_inspect_t thread, thread_policy_flavor_t flavor,
		thread_policy_t policy_info,
		mach_msg_type_number_t *policy_infoCnt, boolean_t *get_default)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_policy_get(%p, %p, %p, %p, %p)\n",
			(void *)thread, (void *)flavor, (void *)policy_info,
			(void *)policy_infoCnt, (void *)get_default);
#endif
	unimplemented();
}

kern_return_t
thread_sample(thread_act_t thread, mach_port_t reply)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_sample(%p, %p)\n", (void *)thread,
			(void *)reply);
#endif
	unimplemented();
}

kern_return_t
etap_trace_thread(thread_act_t target_act, boolean_t trace_status)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "etap_trace_thread(%p, %p)\n", (void *)target_act,
			(void *)trace_status);
#endif
	unimplemented();
}

kern_return_t
thread_assign(thread_act_t thread, processor_set_t new_set)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_assign(%p, %p)\n", (void *)thread,
			(void *)new_set);
#endif
	unimplemented();
}

kern_return_t
thread_assign_default(thread_act_t thread)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_assign_default(%p)\n", (void *)thread);
#endif
	unimplemented();
}

kern_return_t
thread_get_assignment(
		thread_inspect_t thread, processor_set_name_t *assigned_set)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_get_assignment(%p, %p)\n", (void *)thread,
			(void *)assigned_set);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_thread_set_policy(thread_act_t thr_act, processor_set_t pset,
		policy_t policy, policy_base_t base,
		mach_msg_type_number_t baseCnt, policy_limit_t limit,
		mach_msg_type_number_t limitCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_thread_set_policy(%p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)thr_act, (void *)pset, (void *)policy,
			(void *)base, (void *)baseCnt, (void *)limit,
			(void *)limitCnt);
#endif
	unimplemented();
}

kern_return_t
thread_get_mach_voucher(thread_read_t thr_act, mach_voucher_selector_t which,
		ipc_voucher_t *voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_get_mach_voucher(%p, %p, %p)\n",
			(void *)thr_act, (void *)which, (void *)voucher);
#endif
	unimplemented();
}

kern_return_t
thread_set_mach_voucher(thread_act_t thr_act, ipc_voucher_t voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_set_mach_voucher(%p, %p)\n", (void *)thr_act,
			(void *)voucher);
#endif
	unimplemented();
}

kern_return_t
thread_swap_mach_voucher(thread_act_t thr_act, ipc_voucher_t new_voucher,
		ipc_voucher_t *old_voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_swap_mach_voucher(%p, %p, %p)\n",
			(void *)thr_act, (void *)new_voucher,
			(void *)old_voucher);
#endif
	unimplemented();
}

kern_return_t
thread_convert_thread_state(thread_act_t thread, int direction,
		thread_state_flavor_t flavor, thread_state_t in_state,
		mach_msg_type_number_t in_stateCnt, thread_state_t out_state,
		mach_msg_type_number_t *out_stateCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"thread_convert_thread_state(%p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)thread, (void *)direction, (void *)flavor,
			(void *)in_state, (void *)in_stateCnt,
			(void *)out_state, (void *)out_stateCnt);
#endif
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
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"thread_get_exception_ports_info(%p, %p, %p, %p, %p, "
			"%p, %p)\n",
			(void *)port, (void *)exception_mask, (void *)masks,
			(void *)masksCnt, (void *)old_handlers_info,
			(void *)old_behaviors, (void *)old_flavors);
#endif
	unimplemented();
}

kern_return_t
thread_adopt_exception_handler(thread_t thread, mach_port_t exc_port,
		exception_mask_t exc_mask, exception_behavior_t behavior_mask,
		thread_state_flavor_t flavor_mask)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_adopt_exception_handler(%p, %p, %p, %p, %p)\n",
			(void *)thread, (void *)exc_port, (void *)exc_mask,
			(void *)behavior_mask, (void *)flavor_mask);
#endif
	unimplemented();
}

kern_return_t
thread_suspend2(thread_read_t target_act, mach_port_t *suspend_token)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_suspend2(%p, %p)\n", (void *)target_act,
			(void *)suspend_token);
#endif
	unimplemented();
}

kern_return_t
thread_resume2(mach_port_t suspend_token)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_resume2(%p)\n", (void *)suspend_token);
#endif
	unimplemented();
}
