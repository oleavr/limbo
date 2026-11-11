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
	unimplemented();
}

kern_return_t
task_terminate(task_t target_task)
{
	unimplemented();
}

kern_return_t
task_threads(task_inspect_t target_task, thread_act_array_t *act_list,
		mach_msg_type_number_t *act_listCnt)
{
	unimplemented();
}

kern_return_t
_kernelrpc_mach_ports_register3(task_t target_task, mach_port_t port1,
		mach_port_t port2, mach_port_t port3)
{
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
	unimplemented();
}

kern_return_t
task_suspend(task_read_t target_task)
{
	unimplemented();
}

kern_return_t
task_resume(task_read_t target_task)
{
	unimplemented();
}

kern_return_t
task_get_special_port(
		task_inspect_t task, int which_port, mach_port_t *special_port)
{
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
	unimplemented();
}

kern_return_t
thread_create_running(task_t parent_task, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt,
		thread_act_t *child_act)
{
	unimplemented();
}

kern_return_t
task_set_exception_ports(task_t task, exception_mask_t exception_mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t new_flavor)
{
	return KERN_SUCCESS;
}

kern_return_t
task_get_exception_ports(task_t task, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
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
	*masksCnt = 0;
	return KERN_SUCCESS;
}

kern_return_t
lock_set_create(task_t task, lock_set_t *new_lock_set, int n_ulocks, int policy)
{
	unimplemented();
}

kern_return_t
lock_set_destroy(task_t task, lock_set_t lock_set)
{
	unimplemented();
}

kern_return_t
semaphore_create(task_t task, semaphore_t *semaphore, int policy, int value)
{
	return semaphore_alloc(value, semaphore);
}

kern_return_t
semaphore_destroy(task_t task, mach_port_t semaphore)
{
	return semaphore_dealloc(semaphore);
}

kern_return_t
task_policy_set(task_policy_set_t task, task_policy_flavor_t flavor,
		task_policy_t policy_info,
		mach_msg_type_number_t policy_infoCnt)
{
	return KERN_SUCCESS;
}

kern_return_t
task_policy_get(task_policy_get_t task, task_policy_flavor_t flavor,
		task_policy_t policy_info,
		mach_msg_type_number_t *policy_infoCnt, boolean_t *get_default)
{
	unimplemented();
}

kern_return_t
task_sample(task_t task, mach_port_t reply)
{
	unimplemented();
}

kern_return_t
task_policy(task_t task, policy_t policy, policy_base_t base,
		mach_msg_type_number_t baseCnt, boolean_t set_limit,
		boolean_t change)
{
	unimplemented();
}

kern_return_t
task_set_emulation(task_t target_port, vm_address_t routine_entry_pt,
		int routine_number)
{
	unimplemented();
}

kern_return_t
task_get_emulation_vector(task_t task, int *vector_start,
		emulation_vector_t *emulation_vector,
		mach_msg_type_number_t *emulation_vectorCnt)
{
	unimplemented();
}

kern_return_t
task_set_emulation_vector(task_t task, int vector_start,
		emulation_vector_t emulation_vector,
		mach_msg_type_number_t emulation_vectorCnt)
{
	unimplemented();
}

kern_return_t
task_set_ras_pc(task_t target_task, vm_address_t basepc, vm_address_t boundspc)
{
	unimplemented();
}

kern_return_t
task_zone_info(task_inspect_t target_task, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, task_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
	unimplemented();
}

kern_return_t
task_assign(task_t task, processor_set_t new_set, boolean_t assign_threads)
{
	unimplemented();
}

kern_return_t
task_assign_default(task_t task, boolean_t assign_threads)
{
	unimplemented();
}

kern_return_t
task_get_assignment(task_inspect_t task, processor_set_name_t *assigned_set)
{
	unimplemented();
}

kern_return_t
task_set_policy(task_t task, processor_set_t pset, policy_t policy,
		policy_base_t base, mach_msg_type_number_t baseCnt,
		policy_limit_t limit, mach_msg_type_number_t limitCnt,
		boolean_t change)
{
	unimplemented();
}

kern_return_t
task_get_state(task_read_t task, thread_state_flavor_t flavor,
		thread_state_t old_state, mach_msg_type_number_t *old_stateCnt)
{
	unimplemented();
}

kern_return_t
task_set_state(task_t task, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt)
{
	unimplemented();
}

kern_return_t
task_set_phys_footprint_limit(task_t task, int new_limit, int *old_limit)
{
	unimplemented();
}

kern_return_t
task_suspend2(task_read_t target_task, task_suspension_token_t *suspend_token)
{
	unimplemented();
}

kern_return_t
task_resume2(task_suspension_token_t suspend_token)
{
	unimplemented();
}

kern_return_t
task_purgable_info(task_inspect_t task, task_purgable_info_t *stats)
{
	unimplemented();
}

kern_return_t
task_get_mach_voucher(task_read_t task, mach_voucher_selector_t which,
		ipc_voucher_t *voucher)
{
	unimplemented();
}

kern_return_t
task_set_mach_voucher(task_t task, ipc_voucher_t voucher)
{
	unimplemented();
}

kern_return_t
task_swap_mach_voucher(task_t task, ipc_voucher_t new_voucher,
		ipc_voucher_t *old_voucher)
{
	unimplemented();
}

kern_return_t
task_generate_corpse(task_read_t task, mach_port_t *corpse_task_port)
{
	unimplemented();
}

kern_return_t
task_map_corpse_info(task_t task, task_read_t corspe_task,
		vm_address_t *kcd_addr_begin, uint32_t *kcd_size)
{
	unimplemented();
}

kern_return_t
task_register_dyld_image_infos(task_t task,
		dyld_kernel_image_info_array_t dyld_images,
		mach_msg_type_number_t dyld_imagesCnt)
{
	unimplemented();
}

kern_return_t
task_unregister_dyld_image_infos(task_t task,
		dyld_kernel_image_info_array_t dyld_images,
		mach_msg_type_number_t dyld_imagesCnt)
{
	unimplemented();
}

kern_return_t
task_get_dyld_image_infos(task_read_t task,
		dyld_kernel_image_info_array_t *dyld_images,
		mach_msg_type_number_t *dyld_imagesCnt)
{
	unimplemented();
}

kern_return_t
task_register_dyld_shared_cache_image_info(task_t task,
		dyld_kernel_image_info_t dyld_cache_image, boolean_t no_cache,
		boolean_t private_cache)
{
	unimplemented();
}

kern_return_t
task_register_dyld_set_dyld_state(task_t task, uint8_t dyld_state)
{
	unimplemented();
}

kern_return_t
task_register_dyld_get_process_state(
		task_t task, dyld_kernel_process_info_t *dyld_process_state)
{
	unimplemented();
}

kern_return_t
task_map_corpse_info_64(task_t task, task_read_t corspe_task,
		mach_vm_address_t *kcd_addr_begin, mach_vm_size_t *kcd_size)
{
	unimplemented();
}

kern_return_t
task_inspect(task_inspect_t task, task_inspect_flavor_t flavor,
		task_inspect_info_t info_out,
		mach_msg_type_number_t *info_outCnt)
{
	unimplemented();
}

kern_return_t
task_get_exc_guard_behavior(
		task_inspect_t task, task_exc_guard_behavior_t *behavior)
{
	unimplemented();
}

kern_return_t
task_set_exc_guard_behavior(task_t task, task_exc_guard_behavior_t behavior)
{
	unimplemented();
}

kern_return_t
_kernelrpc_mach_task_is_self(task_name_t task, boolean_t *is_self)
{
	unimplemented();
}

kern_return_t
task_dyld_process_info_notify_register(
		task_read_t target_task, mach_port_t notify)
{
	unimplemented();
}

kern_return_t
task_create_identity_token(task_t task, task_id_token_t *token)
{
	*token = ipc_task_self();
	return KERN_SUCCESS;
}

kern_return_t
task_identity_token_get_task_port(task_id_token_t token, task_flavor_t flavor,
		mach_port_t *task_port)
{
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
	unimplemented();
}

kern_return_t
task_get_exception_ports_info(mach_port_t port, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_info_array_t old_handlers_info,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	unimplemented();
}

kern_return_t
task_test_sync_upcall(task_t task, mach_port_t port)
{
	unimplemented();
}

kern_return_t
task_set_corpse_forking_behavior(
		task_t task, task_corpse_forking_behavior_t behavior)
{
	unimplemented();
}

kern_return_t
task_test_async_upcall_propagation(
		task_t task, mach_port_t port, int qos, int iotier)
{
	unimplemented();
}

kern_return_t
task_map_kcdata_object_64(task_t task, kcdata_object_t kcdata_object,
		mach_vm_address_t *kcd_addr_begin, mach_vm_size_t *kcd_size)
{
	unimplemented();
}

kern_return_t
task_register_hardened_exception_handler(task_t task, uint32_t signed_pc_key,
		exception_mask_t exceptions_allowed,
		exception_behavior_t behaviors_allowed,
		thread_state_flavor_t flavors_allowed,
		mach_port_t new_exception_port)
{
	return KERN_SUCCESS;
}

void
task_set_dyld_all_image_info(mach_vm_address_t addr, mach_vm_size_t size)
{
	dyld_all_image_info_addr = addr;
	dyld_all_image_info_size = size;
}
