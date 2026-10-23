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
#include <sys/sysinfo.h>
#include <unistd.h>

#include "ipc.h"
#include "shared_cache.h"

#ifdef __arm64__
#define HOST_CPU_TYPE CPU_TYPE_ARM64
#else
#define HOST_CPU_TYPE CPU_TYPE_X86_64
#endif

kern_return_t
host_info(host_t host, host_flavor_t flavor, host_info_t host_info_out,
		mach_msg_type_number_t *host_info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_info(%p, %p, %p, %p)\n", (void *)host,
			(void *)flavor, (void *)host_info_out,
			(void *)host_info_outCnt);
#endif
	switch (flavor) {
	case HOST_BASIC_INFO: {
		host_basic_info_t basic_info = (host_basic_info_t)host_info_out;
		memset(basic_info, 0, sizeof(*basic_info));
		int cpus = sysconf(_SC_NPROCESSORS_ONLN);
		uint64_t memory_size = (uint64_t)sysconf(_SC_PHYS_PAGES)
				* getpagesize();
		basic_info->max_cpus = cpus;
		basic_info->avail_cpus = cpus;
		basic_info->memory_size = (memory_size > UINT32_MAX)
				? UINT32_MAX
				: memory_size;
		basic_info->cpu_type = HOST_CPU_TYPE;
		basic_info->cpu_subtype = shared_cache_cpu_subtype;
		basic_info->cpu_threadtype = CPU_THREADTYPE_NONE;
		basic_info->physical_cpu = cpus;
		basic_info->physical_cpu_max = cpus;
		basic_info->logical_cpu = cpus;
		basic_info->logical_cpu_max = cpus;
		basic_info->max_mem = memory_size;
		*host_info_outCnt = HOST_BASIC_INFO_COUNT;
	} break;
	case HOST_PRIORITY_INFO: {
		host_priority_info_t priority_info
				= (host_priority_info_t)host_info_out;
		memset(priority_info, 0, sizeof(*priority_info));
		/* TODO: This struct should be non-zero */
		*host_info_outCnt = HOST_PRIORITY_INFO_COUNT;
	} break;
	case HOST_SCHED_INFO: {
		host_sched_info_t sched_info = (host_sched_info_t)host_info_out;
		sched_info->min_timeout = 1;
		sched_info->min_quantum = 1;
		*host_info_outCnt = HOST_SCHED_INFO_COUNT;
	} break;
	case HOST_PREFERRED_USER_ARCH: {
		host_preferred_user_arch_t preferred_arch
				= (host_preferred_user_arch_t)host_info_out;
		preferred_arch->cpu_type = HOST_CPU_TYPE;
		preferred_arch->cpu_subtype = shared_cache_cpu_subtype;
		*host_info_outCnt = HOST_PREFERRED_USER_ARCH_COUNT;
	} break;
	default:
		unimplemented();
	}

	return KERN_SUCCESS;
}

kern_return_t
host_kernel_version(host_t host, kernel_version_t kernel_version)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_kernel_version(%p, %p)\n", (void *)host,
			(void *)kernel_version);
#endif
	unimplemented();
}

kern_return_t
_host_page_size(host_t host, vm_size_t *out_page_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_host_page_size(%p, %p)\n", (void *)host,
			(void *)out_page_size);
#endif
	unimplemented();
}

kern_return_t
mach_memory_object_memory_entry(host_t host, boolean_t internal, vm_size_t size,
		vm_prot_t permission, memory_object_t pager,
		mach_port_t *entry_handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_memory_object_memory_entry(%p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)host, (void *)internal, (void *)size,
			(void *)permission, (void *)pager,
			(void *)entry_handle);
#endif
	unimplemented();
}

kern_return_t
host_processor_info(host_t host, processor_flavor_t flavor,
		natural_t *out_processor_count,
		processor_info_array_t *out_processor_info,
		mach_msg_type_number_t *out_processor_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_processor_info(%p, %p, %p, %p, %p)\n",
			(void *)host, (void *)flavor,
			(void *)out_processor_count, (void *)out_processor_info,
			(void *)out_processor_infoCnt);
#endif
	unimplemented();
}

kern_return_t
host_get_io_main(host_t host, io_main_t *io_main)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_get_io_main(%p, %p)\n", (void *)host,
			(void *)io_main);
#endif
	*io_main = ipc_kobject_name(IPC_KOBJECT_IO_MAIN);
	return KERN_SUCCESS;
}

kern_return_t
host_get_clock_service(
		host_t host, clock_id_t clock_id, clock_serv_t *clock_serv)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_get_clock_service(%p, %p, %p)\n", (void *)host,
			(void *)clock_id, (void *)clock_serv);
#endif
	switch (clock_id) {
	case SYSTEM_CLOCK:
		*clock_serv = ipc_kobject_name(IPC_KOBJECT_CLOCK);
		return KERN_SUCCESS;
	case CALENDAR_CLOCK:
		*clock_serv = ipc_kobject_name(IPC_KOBJECT_CALENDAR_CLOCK);
		return KERN_SUCCESS;
	default:
		return KERN_INVALID_ARGUMENT;
	}
}

kern_return_t
kmod_get_info(host_t host, kmod_args_t *modules,
		mach_msg_type_number_t *modulesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kmod_get_info(%p, %p, %p)\n", (void *)host,
			(void *)modules, (void *)modulesCnt);
#endif
	unimplemented();
}

kern_return_t
host_virtual_physical_table_info(host_t host, hash_info_bucket_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_virtual_physical_table_info(%p, %p, %p)\n",
			(void *)host, (void *)info, (void *)infoCnt);
#endif
	unimplemented();
}

kern_return_t
processor_set_default(host_t host, processor_set_name_t *default_set)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "processor_set_default(%p, %p)\n", (void *)host,
			(void *)default_set);
#endif
	unimplemented();
}

kern_return_t
processor_set_create(host_t host, processor_set_t *new_set,
		processor_set_name_t *new_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "processor_set_create(%p, %p, %p)\n", (void *)host,
			(void *)new_set, (void *)new_name);
#endif
	unimplemented();
}

kern_return_t
mach_memory_object_memory_entry_64(host_t host, boolean_t internal,
		memory_object_size_t size, vm_prot_t permission,
		memory_object_t pager, mach_port_t *entry_handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_memory_object_memory_entry_64(%p, %p, %p, %p, "
			"%p, %p)\n",
			(void *)host, (void *)internal, (void *)size,
			(void *)permission, (void *)pager,
			(void *)entry_handle);
#endif
	unimplemented();
}

kern_return_t
host_statistics(host_t host_priv, host_flavor_t flavor,
		host_info_t host_info_out,
		mach_msg_type_number_t *host_info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_statistics(%p, %p, %p, %p)\n", (void *)host_priv,
			(void *)flavor, (void *)host_info_out,
			(void *)host_info_outCnt);
#endif
	if (flavor != HOST_VM_INFO) {
		unimplemented();
	}

	struct sysinfo info;
	sysinfo(&info);
	natural_t page_size = getpagesize();
	natural_t total = (uint64_t)info.totalram * info.mem_unit / page_size;
	natural_t free = (uint64_t)info.freeram * info.mem_unit / page_size;

	vm_statistics_t statistics = (vm_statistics_t)host_info_out;
	memset(statistics, 0, sizeof(*statistics));
	statistics->free_count = free;
	statistics->active_count = (total - free) / 2;
	statistics->inactive_count = (total - free) - statistics->active_count;
	*host_info_outCnt = HOST_VM_INFO_COUNT;
	return KERN_SUCCESS;
}

kern_return_t
host_request_notification(
		host_t host, host_flavor_t notify_type, mach_port_t notify_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_request_notification(%p, %p, %p)\n", (void *)host,
			(void *)notify_type, (void *)notify_port);
#endif
	return KERN_SUCCESS;
}

kern_return_t
host_lockgroup_info(host_t host, lockgroup_info_array_t *lockgroup_info,
		mach_msg_type_number_t *lockgroup_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_lockgroup_info(%p, %p, %p)\n", (void *)host,
			(void *)lockgroup_info, (void *)lockgroup_infoCnt);
#endif
	unimplemented();
}

kern_return_t
host_statistics64(host_t host_priv, host_flavor_t flavor,
		host_info64_t host_info64_out,
		mach_msg_type_number_t *host_info64_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_statistics64(%p, %p, %p, %p)\n",
			(void *)host_priv, (void *)flavor,
			(void *)host_info64_out, (void *)host_info64_outCnt);
#endif
	unimplemented();
}

kern_return_t
mach_zone_info(mach_port_t host, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_zone_info(%p, %p, %p, %p, %p)\n", (void *)host,
			(void *)names, (void *)namesCnt, (void *)info,
			(void *)infoCnt);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_host_create_mach_voucher(host_t host,
		mach_voucher_attr_raw_recipe_array_t recipes,
		mach_msg_type_number_t recipesCnt, ipc_voucher_t *voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_host_create_mach_voucher(%p, %p, %p, %p)\n",
			(void *)host, (void *)recipes, (void *)recipesCnt,
			(void *)voucher);
#endif
	unimplemented();
}

kern_return_t
host_register_mach_voucher_attr_manager(host_t host,
		mach_voucher_attr_manager_t attr_manager,
		mach_voucher_attr_value_handle_t default_value,
		mach_voucher_attr_key_t *new_key,
		ipc_voucher_attr_control_t *new_attr_control)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"host_register_mach_voucher_attr_manager(%p, %p, %p, "
			"%p, %p)\n",
			(void *)host, (void *)attr_manager,
			(void *)default_value, (void *)new_key,
			(void *)new_attr_control);
#endif
	unimplemented();
}

kern_return_t
host_register_well_known_mach_voucher_attr_manager(host_t host,
		mach_voucher_attr_manager_t attr_manager,
		mach_voucher_attr_value_handle_t default_value,
		mach_voucher_attr_key_t key,
		ipc_voucher_attr_control_t *new_attr_control)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"host_register_well_known_mach_voucher_attr_manager(%p,"
			" %p, %p, %p, %p)\n",
			(void *)host, (void *)attr_manager,
			(void *)default_value, (void *)key,
			(void *)new_attr_control);
#endif
	unimplemented();
}

kern_return_t
host_set_atm_diagnostic_flag(host_t host, uint32_t diagnostic_flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_set_atm_diagnostic_flag(%p, %p)\n", (void *)host,
			(void *)diagnostic_flag);
#endif
	unimplemented();
}

kern_return_t
mach_memory_info(mach_port_t host, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt,
		mach_memory_info_array_t *memory_info,
		mach_msg_type_number_t *memory_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_memory_info(%p, %p, %p, %p, %p, %p, %p)\n",
			(void *)host, (void *)names, (void *)namesCnt,
			(void *)info, (void *)infoCnt, (void *)memory_info,
			(void *)memory_infoCnt);
#endif
	unimplemented();
}

kern_return_t
host_set_multiuser_config_flags(host_priv_t host_priv, uint32_t multiuser_flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_set_multiuser_config_flags(%p, %p)\n",
			(void *)host_priv, (void *)multiuser_flags);
#endif
	unimplemented();
}

kern_return_t
mach_zone_info_for_zone(
		host_priv_t host, mach_zone_name_t name, mach_zone_info_t *info)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_zone_info_for_zone(%p, %p, %p)\n", (void *)host,
			(void *)&name, (void *)info);
#endif
	unimplemented();
}

kern_return_t
mach_memory_info_redacted(mach_port_t host, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt,
		mach_memory_info_array_t *memory_info,
		mach_msg_type_number_t *memory_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_memory_info_redacted(%p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)host, (void *)names, (void *)namesCnt,
			(void *)info, (void *)infoCnt, (void *)memory_info,
			(void *)memory_infoCnt);
#endif
	unimplemented();
}
