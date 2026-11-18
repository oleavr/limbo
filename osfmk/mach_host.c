/*
 * Copyright © 2021 Keegan Saunders
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

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ipc.h"
#include "mach_vm.h"
#include "shared_cache.h"

#ifdef __arm64__
#define HOST_CPU_TYPE CPU_TYPE_ARM64
#else
#define HOST_CPU_TYPE CPU_TYPE_X86_64
#endif

struct linux_vm {
	uint64_t total, free, active, inactive, internal, external;
	uint64_t faults, pageins, pageouts, swapins, swapouts;
	uint64_t compressed_pages, compressor_pages;
};

static kern_return_t host_load(host_info_t host_info_out,
		mach_msg_type_number_t *host_info_outCnt);
static void read_linux_vm(struct linux_vm *vm);
static uint64_t meminfo_bytes(const char *meminfo, const char *key);
static natural_t truncate_to_32_bit(uint64_t count);
static uint64_t wired_pages(const struct linux_vm *vm);

kern_return_t
host_info(host_t host, host_flavor_t flavor, host_info_t host_info_out,
		mach_msg_type_number_t *host_info_outCnt)
{
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
	unimplemented();
}

kern_return_t
_host_page_size(host_t host, vm_size_t *out_page_size)
{
	unimplemented();
}

kern_return_t
mach_memory_object_memory_entry(host_t host, boolean_t internal, vm_size_t size,
		vm_prot_t permission, memory_object_t pager,
		mach_port_t *entry_handle)
{
	unimplemented();
}

kern_return_t
host_processor_info(host_t host, processor_flavor_t flavor,
		natural_t *out_processor_count,
		processor_info_array_t *out_processor_info,
		mach_msg_type_number_t *out_processor_infoCnt)
{
	natural_t count = 0;
	natural_t ticks[256][CPU_STATE_MAX];
	FILE *stat = fopen("/proc/stat", "r");
	if (stat != NULL) {
		char line[512];
		while (count < 256 && fgets(line, sizeof(line), stat) != NULL) {
			unsigned long long user, nice, system, idle;
			if (strncmp(line, "cpu", 3) != 0 || line[3] == ' '
					|| sscanf(line, "%*s %llu %llu %llu %llu",
							   &user, &nice, &system,
							   &idle)
							!= 4) {
				continue;
			}
			ticks[count][CPU_STATE_USER] = (natural_t)user;
			ticks[count][CPU_STATE_NICE] = (natural_t)nice;
			ticks[count][CPU_STATE_SYSTEM] = (natural_t)system;
			ticks[count][CPU_STATE_IDLE] = (natural_t)idle;
			count++;
		}
		fclose(stat);
	}
	if (count == 0) {
		return KERN_FAILURE;
	}

	size_t words;
	switch (flavor) {
	case PROCESSOR_CPU_LOAD_INFO:
		words = PROCESSOR_CPU_LOAD_INFO_COUNT;
		break;
	case PROCESSOR_BASIC_INFO:
		words = PROCESSOR_BASIC_INFO_COUNT;
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}
	size_t size = (size_t)count * words * sizeof(natural_t);
	mach_vm_address_t address = 0;
	if (_kernelrpc_mach_vm_allocate(0, &address, size, VM_FLAGS_ANYWHERE)
			!= KERN_SUCCESS) {
		return KERN_RESOURCE_SHORTAGE;
	}
	natural_t *info = (natural_t *)address;
	for (natural_t i = 0; i < count; i++) {
		natural_t *entry = info + i * words;
		if (flavor == PROCESSOR_CPU_LOAD_INFO) {
			memcpy(entry, ticks[i], sizeof(ticks[i]));
		} else {
			processor_basic_info_t basic = (processor_basic_info_t)entry;
			basic->cpu_type = HOST_CPU_TYPE;
			basic->cpu_subtype = shared_cache_cpu_subtype;
			basic->running = TRUE;
			basic->slot_num = (int)i;
			basic->is_master = i == 0;
		}
	}
	*out_processor_count = count;
	*out_processor_info = (processor_info_array_t)info;
	*out_processor_infoCnt = (mach_msg_type_number_t)(count * words);
	return KERN_SUCCESS;
}

kern_return_t
host_get_io_main(host_t host, io_main_t *io_main)
{
	*io_main = ipc_kobject_name(IPC_KOBJECT_IO_MAIN);
	return KERN_SUCCESS;
}

kern_return_t
host_get_clock_service(
		host_t host, clock_id_t clock_id, clock_serv_t *clock_serv)
{
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
	unimplemented();
}

kern_return_t
host_virtual_physical_table_info(host_t host, hash_info_bucket_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
	unimplemented();
}

kern_return_t
processor_set_default(host_t host, processor_set_name_t *default_set)
{
	unimplemented();
}

kern_return_t
processor_set_create(host_t host, processor_set_t *new_set,
		processor_set_name_t *new_name)
{
	unimplemented();
}

kern_return_t
mach_memory_object_memory_entry_64(host_t host, boolean_t internal,
		memory_object_size_t size, vm_prot_t permission,
		memory_object_t pager, mach_port_t *entry_handle)
{
	unimplemented();
}

static kern_return_t
host_cpu_load(host_info_t host_info_out,
		mach_msg_type_number_t *host_info_outCnt)
{
	if (*host_info_outCnt < HOST_CPU_LOAD_INFO_COUNT) {
		return KERN_FAILURE;
	}
	unsigned long long user, nice, system, idle;
	FILE *stat = fopen("/proc/stat", "r");
	if (stat == NULL) {
		return KERN_FAILURE;
	}
	int fields = fscanf(stat, "cpu %llu %llu %llu %llu", &user, &nice,
			&system, &idle);
	fclose(stat);
	if (fields != 4) {
		return KERN_FAILURE;
	}
	host_cpu_load_info_t load = (host_cpu_load_info_t)host_info_out;
	load->cpu_ticks[CPU_STATE_USER] = (natural_t)user;
	load->cpu_ticks[CPU_STATE_NICE] = (natural_t)nice;
	load->cpu_ticks[CPU_STATE_SYSTEM] = (natural_t)system;
	load->cpu_ticks[CPU_STATE_IDLE] = (natural_t)idle;
	*host_info_outCnt = HOST_CPU_LOAD_INFO_COUNT;
	return KERN_SUCCESS;
}

kern_return_t
host_statistics(host_t host_priv, host_flavor_t flavor,
		host_info_t host_info_out,
		mach_msg_type_number_t *host_info_outCnt)
{
	if (flavor == HOST_CPU_LOAD_INFO) {
		return host_cpu_load(host_info_out, host_info_outCnt);
	}
	if (flavor == HOST_LOAD_INFO) {
		return host_load(host_info_out, host_info_outCnt);
	}
	if (flavor != HOST_VM_INFO) {
		unimplemented();
	}

	struct linux_vm vm;
	read_linux_vm(&vm);
	vm_statistics_t statistics = (vm_statistics_t)host_info_out;
	memset(statistics, 0, sizeof(*statistics));
	statistics->free_count = truncate_to_32_bit(vm.free);
	statistics->active_count = truncate_to_32_bit(vm.active);
	statistics->inactive_count = truncate_to_32_bit(vm.inactive);
	statistics->wire_count = truncate_to_32_bit(wired_pages(&vm));
	statistics->pageins = truncate_to_32_bit(vm.pageins);
	statistics->pageouts = truncate_to_32_bit(vm.pageouts);
	statistics->faults = truncate_to_32_bit(vm.faults);
	*host_info_outCnt = HOST_VM_INFO_COUNT;
	return KERN_SUCCESS;
}

static kern_return_t
host_load(host_info_t host_info_out, mach_msg_type_number_t *host_info_outCnt)
{
	if (*host_info_outCnt < HOST_LOAD_INFO_COUNT) {
		return KERN_FAILURE;
	}
	double averages[3];
	FILE *file = fopen("/proc/loadavg", "re");
	fscanf(file, "%lf %lf %lf", &averages[0], &averages[1], &averages[2]);
	fclose(file);
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	host_load_info_t load = (host_load_info_t)host_info_out;
	for (int i = 0; i < 3; i++) {
		load->avenrun[i] = (integer_t)(averages[i] * LOAD_SCALE + 0.5);
		double idle = averages[i] < cpus ? cpus - averages[i] : 0;
		load->mach_factor[i] = (integer_t)(idle * LOAD_SCALE);
	}
	*host_info_outCnt = HOST_LOAD_INFO_COUNT;
	return KERN_SUCCESS;
}

kern_return_t
host_request_notification(
		host_t host, host_flavor_t notify_type, mach_port_t notify_port)
{
	return KERN_SUCCESS;
}

kern_return_t
host_lockgroup_info(host_t host, lockgroup_info_array_t *lockgroup_info,
		mach_msg_type_number_t *lockgroup_infoCnt)
{
	unimplemented();
}

kern_return_t
host_statistics64(host_t host_priv, host_flavor_t flavor,
		host_info64_t host_info64_out,
		mach_msg_type_number_t *host_info64_outCnt)
{
	if (flavor != HOST_VM_INFO64
			|| *host_info64_outCnt < HOST_VM_INFO64_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}

	struct linux_vm vm;
	read_linux_vm(&vm);
	vm_statistics64_t statistics = (vm_statistics64_t)host_info64_out;
	memset(statistics, 0, sizeof(*statistics));
	statistics->free_count = vm.free;
	statistics->active_count = vm.active;
	statistics->inactive_count = vm.inactive;
	statistics->wire_count = wired_pages(&vm);
	statistics->pageins = vm.pageins;
	statistics->pageouts = vm.pageouts;
	statistics->faults = vm.faults;
	statistics->swapins = vm.swapins;
	statistics->swapouts = vm.swapouts;
	statistics->compressor_page_count = vm.compressor_pages;
	statistics->total_uncompressed_pages_in_compressor
			= vm.compressed_pages;
	statistics->internal_page_count = vm.internal;
	statistics->external_page_count = vm.external;
	*host_info64_outCnt = HOST_VM_INFO64_COUNT;
	return KERN_SUCCESS;
}

static void
read_linux_vm(struct linux_vm *vm)
{
	memset(vm, 0, sizeof(*vm));
	uint64_t page = getpagesize();
	char meminfo[8192];
	FILE *file = fopen("/proc/meminfo", "re");
	meminfo[fread(meminfo, 1, sizeof(meminfo) - 1, file)] = '\0';
	fclose(file);
	vm->total = meminfo_bytes(meminfo, "MemTotal:") / page;
	vm->free = meminfo_bytes(meminfo, "MemFree:") / page;
	vm->active = meminfo_bytes(meminfo, "Active:") / page;
	vm->inactive = meminfo_bytes(meminfo, "Inactive:") / page;
	vm->internal = meminfo_bytes(meminfo, "Active(anon):") / page
			+ meminfo_bytes(meminfo, "Inactive(anon):") / page;
	vm->external = meminfo_bytes(meminfo, "Active(file):") / page
			+ meminfo_bytes(meminfo, "Inactive(file):") / page;

	file = fopen("/proc/vmstat", "re");
	char line[128];
	while (fgets(line, sizeof(line), file) != NULL) {
		char key[64];
		unsigned long long value;
		sscanf(line, "%63s %llu", key, &value);
		if (strcmp(key, "pgfault") == 0) {
			vm->faults = value;
		} else if (strcmp(key, "pgpgin") == 0) {
			vm->pageins = value * 1024 / page;
		} else if (strcmp(key, "pgpgout") == 0) {
			vm->pageouts = value * 1024 / page;
		} else if (strcmp(key, "pswpin") == 0) {
			vm->swapins = value;
		} else if (strcmp(key, "pswpout") == 0) {
			vm->swapouts = value;
		}
	}
	fclose(file);

	file = fopen("/sys/block/zram0/mm_stat", "re");
	if (file != NULL) {
		unsigned long long original, compressed, used;
		fscanf(file, "%llu %llu %llu", &original, &compressed, &used);
		fclose(file);
		vm->compressed_pages = original / page;
		vm->compressor_pages = used / page;
	}
}

static uint64_t
meminfo_bytes(const char *meminfo, const char *key)
{
	unsigned long long kilobytes;
	sscanf(strstr(meminfo, key) + strlen(key), " %llu", &kilobytes);
	return kilobytes * 1024;
}

static natural_t
truncate_to_32_bit(uint64_t count)
{
	return count > UINT32_MAX ? UINT32_MAX : (natural_t)count;
}

static uint64_t
wired_pages(const struct linux_vm *vm)
{
	return vm->total - vm->free - vm->active - vm->inactive
			- vm->compressor_pages;
}

kern_return_t
mach_zone_info(mach_port_t host, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
	unimplemented();
}

kern_return_t
_kernelrpc_host_create_mach_voucher(host_t host,
		mach_voucher_attr_raw_recipe_array_t recipes,
		mach_msg_type_number_t recipesCnt, ipc_voucher_t *voucher)
{
	unimplemented();
}

kern_return_t
host_register_mach_voucher_attr_manager(host_t host,
		mach_voucher_attr_manager_t attr_manager,
		mach_voucher_attr_value_handle_t default_value,
		mach_voucher_attr_key_t *new_key,
		ipc_voucher_attr_control_t *new_attr_control)
{
	unimplemented();
}

kern_return_t
host_register_well_known_mach_voucher_attr_manager(host_t host,
		mach_voucher_attr_manager_t attr_manager,
		mach_voucher_attr_value_handle_t default_value,
		mach_voucher_attr_key_t key,
		ipc_voucher_attr_control_t *new_attr_control)
{
	unimplemented();
}

kern_return_t
host_set_atm_diagnostic_flag(host_t host, uint32_t diagnostic_flag)
{
	unimplemented();
}

kern_return_t
mach_memory_info(mach_port_t host, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt,
		mach_memory_info_array_t *memory_info,
		mach_msg_type_number_t *memory_infoCnt)
{
	unimplemented();
}

kern_return_t
host_set_multiuser_config_flags(host_priv_t host_priv, uint32_t multiuser_flags)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
mach_zone_info_for_zone(
		host_priv_t host, mach_zone_name_t name, mach_zone_info_t *info)
{
	unimplemented();
}

kern_return_t
mach_memory_info_redacted(mach_port_t host, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt,
		mach_memory_info_array_t *memory_info,
		mach_msg_type_number_t *memory_infoCnt)
{
	unimplemented();
}
