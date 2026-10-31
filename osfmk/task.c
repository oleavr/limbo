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

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "ipc.h"
#include "semaphore.h"
#include "task.h"

static mach_port_t special_ports[TASK_MAX_SPECIAL_PORT + 1];
static mach_port_t registered_ports[3];
static mach_vm_address_t dyld_all_image_info_addr;
static mach_vm_size_t dyld_all_image_info_size;

kern_return_t
task_create(task_t target_task, ledger_array_t ledgers,
		mach_msg_type_number_t ledgersCnt, boolean_t inherit_memory,
		task_t *child_task)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_create(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)ledgers,
			(void *)ledgersCnt, (void *)inherit_memory,
			(void *)child_task);
#endif
	unimplemented();
}

kern_return_t
task_terminate(task_t target_task)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_terminate(%p)\n", (void *)target_task);
#endif
	unimplemented();
}

kern_return_t
task_threads(task_inspect_t target_task, thread_act_array_t *act_list,
		mach_msg_type_number_t *act_listCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_threads(%p, %p, %p)\n", (void *)target_task,
			(void *)act_list, (void *)act_listCnt);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_ports_register3(task_t target_task, mach_port_t port1,
		mach_port_t port2, mach_port_t port3)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_ports_register3(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)port1, (void *)port2,
			(void *)port3);
#endif
	mach_port_t ports[] = {port1, port2, port3};
	for (int i = 0; i < 3; i++) {
		ipc_port_mod_refs(
				registered_ports[i], MACH_PORT_RIGHT_SEND, -1);
		ipc_port_mod_refs(ports[i], MACH_PORT_RIGHT_SEND, 1);
		registered_ports[i] = ports[i];
	}
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_mach_ports_lookup3(task_t target_task, mach_port_t *port1,
		mach_port_t *port2, mach_port_t *port3)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_ports_lookup3(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)port1, (void *)port2,
			(void *)port3);
#endif
	*port1 = registered_ports[0];
	*port2 = registered_ports[1];
	*port3 = registered_ports[2];
	return KERN_SUCCESS;
}

static kern_return_t memory_and_time_info(task_flavor_t flavor,
		task_info_t out, mach_msg_type_number_t *count);

/* Darwin's pages, which the guest's sizes count in */
#ifdef __x86_64__
#define GUEST_PAGE_SIZE 4096
#else
#define GUEST_PAGE_SIZE 16384
#endif

/* The bounds of a macOS process's map */
#define GUEST_MIN_ADDRESS 0x100000000ULL
#define GUEST_MAX_ADDRESS 0x7ffffe000000ULL

/* TASK_BASIC_INFO_64 on arm64, whichever the headers were built for */
#define TASK_BASIC_INFO_64_ARM 18
#pragma pack(push, 4)
struct task_basic_info_64_arm {
	integer_t suspend_count;
	mach_vm_size_t virtual_size;
	mach_vm_size_t resident_size;
	time_value_t user_time;
	time_value_t system_time;
	policy_t policy;
};
#pragma pack(pop)

kern_return_t
task_info(task_name_t target_task, task_flavor_t flavor,
		task_info_t task_info_out,
		mach_msg_type_number_t *task_info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_info(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)flavor, (void *)task_info_out,
			(void *)task_info_outCnt);
#endif
	switch (flavor) {
	case TASK_AUDIT_TOKEN: {
		audit_token_t *audit_token_p = (audit_token_t *)task_info_out;
		memset(audit_token_p, 0, sizeof(audit_token_t));
		audit_token_p->val[0] = getuid();
		audit_token_p->val[1] = geteuid();
		audit_token_p->val[2] = getegid();
		audit_token_p->val[3] = getuid();
		audit_token_p->val[4] = getgid();
		audit_token_p->val[5] = getpid();
		/* TODO: idversion_for_pid(getpid()); */
		audit_token_p->val[7] = 10;
		*task_info_outCnt = TASK_AUDIT_TOKEN_COUNT;
	} break;
	case TASK_DYLD_INFO: {
		task_dyld_info_t info = (task_dyld_info_t)task_info_out;
		info->all_image_info_addr = dyld_all_image_info_addr;
		info->all_image_info_size = dyld_all_image_info_size;
		info->all_image_info_format = TASK_DYLD_ALL_IMAGE_INFO_64;
		*task_info_outCnt = TASK_DYLD_INFO_COUNT;
	} break;
	case MACH_TASK_BASIC_INFO:
	case TASK_BASIC_INFO_64_ARM:
	case TASK_VM_INFO:
	case TASK_VM_INFO_PURGEABLE:
	case TASK_THREAD_TIMES_INFO:
	case TASK_EVENTS_INFO:
	case TASK_POWER_INFO:
	case TASK_POWER_INFO_V2:
	case TASK_FLAGS_INFO:
		return memory_and_time_info(flavor, task_info_out,
				task_info_outCnt);
	default:
#ifdef ENABLE_STRACE
		fprintf(stderr, "  task_info: no flavor %d\n", flavor);
#endif
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

struct memory_usage {
	uint64_t virtual_size;
	uint64_t resident_size;
	uint64_t resident_peak;
};

static void
memory_usage(struct memory_usage *usage)
{
	memset(usage, 0, sizeof(*usage));
	long page = sysconf(_SC_PAGESIZE);
	FILE *statm = fopen("/proc/self/statm", "r");
	if (statm != NULL) {
		unsigned long size, resident;
		if (fscanf(statm, "%lu %lu", &size, &resident) == 2) {
			usage->virtual_size = (uint64_t)size * page;
			usage->resident_size = (uint64_t)resident * page;
		}
		fclose(statm);
	}
	FILE *status = fopen("/proc/self/status", "r");
	if (status != NULL) {
		char line[256];
		unsigned long kilobytes;
		while (fgets(line, sizeof(line), status) != NULL) {
			if (sscanf(line, "VmHWM: %lu kB", &kilobytes) == 1) {
				usage->resident_peak = (uint64_t)kilobytes * 1024;
			}
		}
		fclose(status);
	}
	if (usage->resident_peak < usage->resident_size) {
		usage->resident_peak = usage->resident_size;
	}
}

static void
time_value(const struct timeval *from, time_value_t *to)
{
	to->seconds = (integer_t)from->tv_sec;
	to->microseconds = (integer_t)from->tv_usec;
}

static kern_return_t
memory_and_time_info(task_flavor_t flavor, task_info_t out,
		mach_msg_type_number_t *count)
{
	struct memory_usage usage;
	memory_usage(&usage);
	struct rusage rusage;
	getrusage(RUSAGE_SELF, &rusage);

	union {
		struct mach_task_basic_info basic;
		struct task_basic_info_64_arm basic_64;
		struct task_vm_info vm;
		struct task_thread_times_info times;
		struct task_events_info events;
		struct task_power_info_v2 power;
		struct task_flags_info flags;
	} info;
	memset(&info, 0, sizeof(info));
	mach_msg_type_number_t size;
	switch (flavor) {
	case MACH_TASK_BASIC_INFO:
		info.basic.virtual_size = usage.virtual_size;
		info.basic.resident_size = usage.resident_size;
		info.basic.resident_size_max = usage.resident_peak;
		time_value(&rusage.ru_utime, &info.basic.user_time);
		time_value(&rusage.ru_stime, &info.basic.system_time);
		info.basic.policy = POLICY_TIMESHARE;
		size = MACH_TASK_BASIC_INFO_COUNT;
		break;
	case TASK_BASIC_INFO_64_ARM:
		info.basic_64.virtual_size = usage.virtual_size;
		info.basic_64.resident_size = usage.resident_size;
		time_value(&rusage.ru_utime, &info.basic_64.user_time);
		time_value(&rusage.ru_stime, &info.basic_64.system_time);
		info.basic_64.policy = POLICY_TIMESHARE;
		size = sizeof(info.basic_64) / sizeof(natural_t);
		break;
	case TASK_VM_INFO:
	case TASK_VM_INFO_PURGEABLE:
		info.vm.virtual_size = usage.virtual_size;
		info.vm.page_size = GUEST_PAGE_SIZE;
		info.vm.resident_size = usage.resident_size;
		info.vm.resident_size_peak = usage.resident_peak;
		info.vm.internal = usage.resident_size;
		info.vm.internal_peak = usage.resident_peak;
		info.vm.phys_footprint = usage.resident_size;
		info.vm.ledger_phys_footprint_peak = (int64_t)usage.resident_peak;
		info.vm.min_address = GUEST_MIN_ADDRESS;
		info.vm.max_address = GUEST_MAX_ADDRESS;
		info.vm.limit_bytes_remaining = INT64_MAX;
		size = TASK_VM_INFO_COUNT;
		break;
	case TASK_THREAD_TIMES_INFO:
		time_value(&rusage.ru_utime, &info.times.user_time);
		time_value(&rusage.ru_stime, &info.times.system_time);
		size = TASK_THREAD_TIMES_INFO_COUNT;
		break;
	case TASK_EVENTS_INFO:
		info.events.faults = (integer_t)rusage.ru_minflt;
		info.events.pageins = (integer_t)rusage.ru_majflt;
		info.events.csw = (integer_t)(rusage.ru_nvcsw + rusage.ru_nivcsw);
		size = TASK_EVENTS_INFO_COUNT;
		break;
	case TASK_POWER_INFO:
	case TASK_POWER_INFO_V2:
		info.power.cpu_energy.total_user = (uint64_t)rusage.ru_utime.tv_sec
						* 1000000000
				+ (uint64_t)rusage.ru_utime.tv_usec * 1000;
		info.power.cpu_energy.total_system
				= (uint64_t)rusage.ru_stime.tv_sec * 1000000000
				+ (uint64_t)rusage.ru_stime.tv_usec * 1000;
		size = (flavor == TASK_POWER_INFO) ? TASK_POWER_INFO_COUNT
						   : TASK_POWER_INFO_V2_COUNT;
		break;
	case TASK_FLAGS_INFO:
		info.flags.flags = TF_LP64 | TF_64B_DATA;
		size = TASK_FLAGS_INFO_COUNT;
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}
	if (*count < size) {
		size = *count;
	}
	memcpy(out, &info, size * sizeof(natural_t));
	*count = size;
	return KERN_SUCCESS;
}

static kern_return_t memory_and_time_info(task_flavor_t flavor,
		task_info_t out, mach_msg_type_number_t *count);

#ifdef __x86_64__
#define GUEST_PAGE_SIZE 4096
#else
#define GUEST_PAGE_SIZE 16384
#endif

#define GUEST_MIN_ADDRESS 0x100000000ULL
#define GUEST_MAX_ADDRESS 0x7ffffe000000ULL

kern_return_t
task_set_info(task_t target_task, task_flavor_t flavor,
		task_info_t task_info_in,
		mach_msg_type_number_t task_info_inCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_info(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)flavor, (void *)task_info_in,
			(void *)task_info_inCnt);
#endif
	unimplemented();
}

kern_return_t
task_suspend(task_read_t target_task)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_suspend(%p)\n", (void *)target_task);
#endif
	unimplemented();
}

kern_return_t
task_resume(task_read_t target_task)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_resume(%p)\n", (void *)target_task);
#endif
	unimplemented();
}

kern_return_t
task_get_special_port(
		task_inspect_t task, int which_port, mach_port_t *special_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_get_special_port(%p, %p, %p)\n", (void *)task,
			(void *)which_port, (void *)special_port);
#endif
	switch (which_port) {
	case TASK_KERNEL_PORT:
		*special_port = ipc_kobject_name(IPC_KOBJECT_TASK);
		return KERN_SUCCESS;
	case TASK_HOST_PORT:
		*special_port = ipc_kobject_name(IPC_KOBJECT_HOST);
		return KERN_SUCCESS;
	case TASK_BOOTSTRAP_PORT:
		*special_port = ipc_bootstrap_self();
		return KERN_SUCCESS;
	default:
		if (which_port <= 0 || which_port > TASK_MAX_SPECIAL_PORT) {
			return KERN_INVALID_ARGUMENT;
		}
		*special_port = special_ports[which_port];
		return KERN_SUCCESS;
	}
}

kern_return_t
task_set_special_port(task_t task, int which_port, mach_port_t special_port)
{
	if (which_port <= 0 || which_port > TASK_MAX_SPECIAL_PORT) {
		return KERN_INVALID_ARGUMENT;
	}

	ipc_port_mod_refs(special_ports[which_port], MACH_PORT_RIGHT_SEND, -1);
	ipc_port_mod_refs(special_port, MACH_PORT_RIGHT_SEND, 1);
	special_ports[which_port] = special_port;
	return KERN_SUCCESS;
}

kern_return_t
thread_create(task_t parent_task, thread_act_t *child_act)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_create(%p, %p)\n", (void *)parent_task,
			(void *)child_act);
#endif
	unimplemented();
}

kern_return_t
thread_create_running(task_t parent_task, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt,
		thread_act_t *child_act)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_create_running(%p, %p, %p, %p, %p)\n",
			(void *)parent_task, (void *)flavor, (void *)new_state,
			(void *)new_stateCnt, (void *)child_act);
#endif
	unimplemented();
}

kern_return_t
task_set_exception_ports(task_t task, exception_mask_t exception_mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t new_flavor)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_exception_ports(%p, %p, %p, %p, %p)\n",
			(void *)task, (void *)exception_mask, (void *)new_port,
			(void *)behavior, (void *)new_flavor);
#endif

	return KERN_SUCCESS;
}

kern_return_t
task_get_exception_ports(task_t task, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"task_get_exception_ports(%p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)task, (void *)exception_mask, (void *)masks,
			(void *)masksCnt, (void *)old_handlers,
			(void *)old_behaviors, (void *)old_flavors);
#endif

	*masksCnt = 0;
	return KERN_SUCCESS;
}

kern_return_t
task_swap_exception_ports(task_t task, exception_mask_t exception_mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t new_flavor, exception_mask_array_t masks,
		mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"task_swap_exception_ports(%p, %p, %p, %p, %p, %p, %p, "
			"%p, %p, %p)\n",
			(void *)task, (void *)exception_mask, (void *)new_port,
			(void *)behavior, (void *)new_flavor, (void *)masks,
			(void *)masksCnt, (void *)old_handlers,
			(void *)old_behaviors, (void *)old_flavors);
#endif

	*masksCnt = 0;
	return KERN_SUCCESS;
}

kern_return_t
lock_set_create(task_t task, lock_set_t *new_lock_set, int n_ulocks, int policy)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lock_set_create(%p, %p, %p, %p)\n", (void *)task,
			(void *)new_lock_set, (void *)n_ulocks, (void *)policy);
#endif
	unimplemented();
}

kern_return_t
lock_set_destroy(task_t task, lock_set_t lock_set)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lock_set_destroy(%p, %p)\n", (void *)task,
			(void *)lock_set);
#endif
	unimplemented();
}

kern_return_t
semaphore_create(task_t task, semaphore_t *semaphore, int policy, int value)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_create(%p, %p, %p, %p)\n", (void *)task,
			(void *)semaphore, (void *)policy, (void *)value);
#endif
	return semaphore_alloc(value, semaphore);
}

kern_return_t
semaphore_destroy(task_t task, mach_port_t semaphore)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_destroy(%p, %p)\n", (void *)task,
			(void *)semaphore);
#endif
	return semaphore_dealloc(semaphore);
}

kern_return_t
task_policy_set(task_policy_set_t task, task_policy_flavor_t flavor,
		task_policy_t policy_info,
		mach_msg_type_number_t policy_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_policy_set(%p, %p, %p, %p)\n", (void *)task,
			(void *)flavor, (void *)policy_info,
			(void *)policy_infoCnt);
#endif
	return KERN_SUCCESS;
}

kern_return_t
task_policy_get(task_policy_get_t task, task_policy_flavor_t flavor,
		task_policy_t policy_info,
		mach_msg_type_number_t *policy_infoCnt, boolean_t *get_default)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_policy_get(%p, %p, %p, %p, %p)\n", (void *)task,
			(void *)flavor, (void *)policy_info,
			(void *)policy_infoCnt, (void *)get_default);
#endif
	unimplemented();
}

kern_return_t
task_sample(task_t task, mach_port_t reply)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_sample(%p, %p)\n", (void *)task, (void *)reply);
#endif
	unimplemented();
}

kern_return_t
task_policy(task_t task, policy_t policy, policy_base_t base,
		mach_msg_type_number_t baseCnt, boolean_t set_limit,
		boolean_t change)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_policy(%p, %p, %p, %p, %p, %p)\n", (void *)task,
			(void *)policy, (void *)base, (void *)baseCnt,
			(void *)set_limit, (void *)change);
#endif
	unimplemented();
}

kern_return_t
task_set_emulation(task_t target_port, vm_address_t routine_entry_pt,
		int routine_number)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_emulation(%p, %p, %p)\n", (void *)target_port,
			(void *)routine_entry_pt, (void *)routine_number);
#endif
	unimplemented();
}

kern_return_t
task_get_emulation_vector(task_t task, int *vector_start,
		emulation_vector_t *emulation_vector,
		mach_msg_type_number_t *emulation_vectorCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_get_emulation_vector(%p, %p, %p, %p)\n",
			(void *)task, (void *)vector_start,
			(void *)emulation_vector, (void *)emulation_vectorCnt);
#endif
	unimplemented();
}

kern_return_t
task_set_emulation_vector(task_t task, int vector_start,
		emulation_vector_t emulation_vector,
		mach_msg_type_number_t emulation_vectorCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_emulation_vector(%p, %p, %p, %p)\n",
			(void *)task, (void *)vector_start,
			(void *)emulation_vector, (void *)emulation_vectorCnt);
#endif
	unimplemented();
}

kern_return_t
task_set_ras_pc(task_t target_task, vm_address_t basepc, vm_address_t boundspc)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_ras_pc(%p, %p, %p)\n", (void *)target_task,
			(void *)basepc, (void *)boundspc);
#endif
	unimplemented();
}

kern_return_t
task_zone_info(task_inspect_t target_task, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, task_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_zone_info(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)names, (void *)namesCnt,
			(void *)info, (void *)infoCnt);
#endif
	unimplemented();
}

kern_return_t
task_assign(task_t task, processor_set_t new_set, boolean_t assign_threads)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_assign(%p, %p, %p)\n", (void *)task,
			(void *)new_set, (void *)assign_threads);
#endif
	unimplemented();
}

kern_return_t
task_assign_default(task_t task, boolean_t assign_threads)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_assign_default(%p, %p)\n", (void *)task,
			(void *)assign_threads);
#endif
	unimplemented();
}

kern_return_t
task_get_assignment(task_inspect_t task, processor_set_name_t *assigned_set)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_get_assignment(%p, %p)\n", (void *)task,
			(void *)assigned_set);
#endif
	unimplemented();
}

kern_return_t
task_set_policy(task_t task, processor_set_t pset, policy_t policy,
		policy_base_t base, mach_msg_type_number_t baseCnt,
		policy_limit_t limit, mach_msg_type_number_t limitCnt,
		boolean_t change)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_policy(%p, %p, %p, %p, %p, %p, %p, %p)\n",
			(void *)task, (void *)pset, (void *)policy,
			(void *)base, (void *)baseCnt, (void *)limit,
			(void *)limitCnt, (void *)change);
#endif
	unimplemented();
}

kern_return_t
task_get_state(task_read_t task, thread_state_flavor_t flavor,
		thread_state_t old_state, mach_msg_type_number_t *old_stateCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_get_state(%p, %p, %p, %p)\n", (void *)task,
			(void *)flavor, (void *)old_state,
			(void *)old_stateCnt);
#endif
	unimplemented();
}

kern_return_t
task_set_state(task_t task, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_state(%p, %p, %p, %p)\n", (void *)task,
			(void *)flavor, (void *)new_state,
			(void *)new_stateCnt);
#endif
	unimplemented();
}

kern_return_t
task_set_phys_footprint_limit(task_t task, int new_limit, int *old_limit)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_phys_footprint_limit(%p, %p, %p)\n",
			(void *)task, (void *)new_limit, (void *)old_limit);
#endif
	unimplemented();
}

kern_return_t
task_suspend2(task_read_t target_task, task_suspension_token_t *suspend_token)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_suspend2(%p, %p)\n", (void *)target_task,
			(void *)suspend_token);
#endif
	unimplemented();
}

kern_return_t
task_resume2(task_suspension_token_t suspend_token)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_resume2(%p)\n", (void *)suspend_token);
#endif
	unimplemented();
}

kern_return_t
task_purgable_info(task_inspect_t task, task_purgable_info_t *stats)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_purgable_info(%p, %p)\n", (void *)task,
			(void *)stats);
#endif
	unimplemented();
}

kern_return_t
task_get_mach_voucher(task_read_t task, mach_voucher_selector_t which,
		ipc_voucher_t *voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_get_mach_voucher(%p, %p, %p)\n", (void *)task,
			(void *)which, (void *)voucher);
#endif
	unimplemented();
}

kern_return_t
task_set_mach_voucher(task_t task, ipc_voucher_t voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_mach_voucher(%p, %p)\n", (void *)task,
			(void *)voucher);
#endif
	unimplemented();
}

kern_return_t
task_swap_mach_voucher(task_t task, ipc_voucher_t new_voucher,
		ipc_voucher_t *old_voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_swap_mach_voucher(%p, %p, %p)\n", (void *)task,
			(void *)new_voucher, (void *)old_voucher);
#endif
	unimplemented();
}

kern_return_t
task_generate_corpse(task_read_t task, mach_port_t *corpse_task_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_generate_corpse(%p, %p)\n", (void *)task,
			(void *)corpse_task_port);
#endif
	unimplemented();
}

kern_return_t
task_map_corpse_info(task_t task, task_read_t corspe_task,
		vm_address_t *kcd_addr_begin, uint32_t *kcd_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_map_corpse_info(%p, %p, %p, %p)\n", (void *)task,
			(void *)corspe_task, (void *)kcd_addr_begin,
			(void *)kcd_size);
#endif
	unimplemented();
}

kern_return_t
task_register_dyld_image_infos(task_t task,
		dyld_kernel_image_info_array_t dyld_images,
		mach_msg_type_number_t dyld_imagesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_register_dyld_image_infos(%p, %p, %p)\n",
			(void *)task, (void *)dyld_images,
			(void *)dyld_imagesCnt);
#endif
	unimplemented();
}

kern_return_t
task_unregister_dyld_image_infos(task_t task,
		dyld_kernel_image_info_array_t dyld_images,
		mach_msg_type_number_t dyld_imagesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_unregister_dyld_image_infos(%p, %p, %p)\n",
			(void *)task, (void *)dyld_images,
			(void *)dyld_imagesCnt);
#endif
	unimplemented();
}

kern_return_t
task_get_dyld_image_infos(task_read_t task,
		dyld_kernel_image_info_array_t *dyld_images,
		mach_msg_type_number_t *dyld_imagesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_get_dyld_image_infos(%p, %p, %p)\n", (void *)task,
			(void *)dyld_images, (void *)dyld_imagesCnt);
#endif
	unimplemented();
}

kern_return_t
task_register_dyld_shared_cache_image_info(task_t task,
		dyld_kernel_image_info_t dyld_cache_image, boolean_t no_cache,
		boolean_t private_cache)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"task_register_dyld_shared_cache_image_info(%p, %p, "
			"%p, %p)\n",
			(void *)task, (void *)&dyld_cache_image,
			(void *)no_cache, (void *)private_cache);
#endif
	unimplemented();
}

kern_return_t
task_register_dyld_set_dyld_state(task_t task, uint8_t dyld_state)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_register_dyld_set_dyld_state(%p, %p)\n",
			(void *)task, (void *)dyld_state);
#endif
	unimplemented();
}

kern_return_t
task_register_dyld_get_process_state(
		task_t task, dyld_kernel_process_info_t *dyld_process_state)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_register_dyld_get_process_state(%p, %p)\n",
			(void *)task, (void *)dyld_process_state);
#endif
	unimplemented();
}

kern_return_t
task_map_corpse_info_64(task_t task, task_read_t corspe_task,
		mach_vm_address_t *kcd_addr_begin, mach_vm_size_t *kcd_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_map_corpse_info_64(%p, %p, %p, %p)\n",
			(void *)task, (void *)corspe_task,
			(void *)kcd_addr_begin, (void *)kcd_size);
#endif
	unimplemented();
}

kern_return_t
task_inspect(task_inspect_t task, task_inspect_flavor_t flavor,
		task_inspect_info_t info_out,
		mach_msg_type_number_t *info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_inspect(%p, %p, %p, %p)\n", (void *)task,
			(void *)flavor, (void *)info_out, (void *)info_outCnt);
#endif
	unimplemented();
}

kern_return_t
task_get_exc_guard_behavior(
		task_inspect_t task, task_exc_guard_behavior_t *behavior)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_get_exc_guard_behavior(%p, %p)\n", (void *)task,
			(void *)behavior);
#endif
	unimplemented();
}

kern_return_t
task_set_exc_guard_behavior(task_t task, task_exc_guard_behavior_t behavior)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_exc_guard_behavior(%p, %p)\n", (void *)task,
			(void *)behavior);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_task_is_self(task_name_t task, boolean_t *is_self)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_task_is_self(%p, %p)\n", (void *)task,
			(void *)is_self);
#endif
	unimplemented();
}

kern_return_t
task_dyld_process_info_notify_register(
		task_read_t target_task, mach_port_t notify)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_dyld_process_info_notify_register(%p, %p)\n",
			(void *)target_task, (void *)notify);
#endif
	unimplemented();
}

kern_return_t
task_create_identity_token(task_t task, task_id_token_t *token)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_create_identity_token(%p, %p)\n", (void *)task,
			(void *)token);
#endif
	*token = ipc_task_self();
	return KERN_SUCCESS;
}

kern_return_t
task_identity_token_get_task_port(task_id_token_t token, task_flavor_t flavor,
		mach_port_t *task_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_identity_token_get_task_port(%p, %p, %p)\n",
			(void *)token, (void *)flavor, (void *)task_port);
#endif

	if (flavor < TASK_FLAVOR_CONTROL || flavor > TASK_FLAVOR_NAME) {
		return KERN_INVALID_ARGUMENT;
	}
	*task_port = token;
	return KERN_SUCCESS;
}

kern_return_t
task_dyld_process_info_notify_deregister(
		task_read_t target_task, mach_port_name_t notify)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_dyld_process_info_notify_deregister(%p, %p)\n",
			(void *)target_task, (void *)notify);
#endif
	unimplemented();
}

kern_return_t
task_get_exception_ports_info(mach_port_t port, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_info_array_t old_handlers_info,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"task_get_exception_ports_info(%p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)port, (void *)exception_mask, (void *)masks,
			(void *)masksCnt, (void *)old_handlers_info,
			(void *)old_behaviors, (void *)old_flavors);
#endif
	unimplemented();
}

kern_return_t
task_test_sync_upcall(task_t task, mach_port_t port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_test_sync_upcall(%p, %p)\n", (void *)task,
			(void *)port);
#endif
	unimplemented();
}

kern_return_t
task_set_corpse_forking_behavior(
		task_t task, task_corpse_forking_behavior_t behavior)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_corpse_forking_behavior(%p, %p)\n",
			(void *)task, (void *)behavior);
#endif
	unimplemented();
}

kern_return_t
task_test_async_upcall_propagation(
		task_t task, mach_port_t port, int qos, int iotier)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_test_async_upcall_propagation(%p, %p, %p, %p)\n",
			(void *)task, (void *)port, (void *)qos,
			(void *)iotier);
#endif
	unimplemented();
}

kern_return_t
task_map_kcdata_object_64(task_t task, kcdata_object_t kcdata_object,
		mach_vm_address_t *kcd_addr_begin, mach_vm_size_t *kcd_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_map_kcdata_object_64(%p, %p, %p, %p)\n",
			(void *)task, (void *)kcdata_object,
			(void *)kcd_addr_begin, (void *)kcd_size);
#endif
	unimplemented();
}

kern_return_t
task_register_hardened_exception_handler(task_t task, uint32_t signed_pc_key,
		exception_mask_t exceptions_allowed,
		exception_behavior_t behaviors_allowed,
		thread_state_flavor_t flavors_allowed,
		mach_port_t new_exception_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"task_register_hardened_exception_handler(%p, %p, %p, "
			"%p, %p, %p)\n",
			(void *)task, (void *)signed_pc_key,
			(void *)exceptions_allowed, (void *)behaviors_allowed,
			(void *)flavors_allowed, (void *)new_exception_port);
#endif

	return KERN_SUCCESS;
}

void
task_set_dyld_all_image_info(mach_vm_address_t addr, mach_vm_size_t size)
{
	dyld_all_image_info_addr = addr;
	dyld_all_image_info_size = size;
}
