/*
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

#include <dirent.h>
#include <mach/mach_types.h>
#include <mach/processor_set.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ipc.h"
#include "mach_vm.h"

#define LOAD_SCALE 1000

kern_return_t
host_processor_sets(host_priv_t host_priv,
		processor_set_name_array_t *processor_sets,
		mach_msg_type_number_t *processor_setsCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_processor_sets(%p, %p, %p)\n", (void *)host_priv,
			(void *)processor_sets, (void *)processor_setsCnt);
#endif
	mach_vm_address_t address = 0;
	if (_kernelrpc_mach_vm_allocate(0, &address, sizeof(mach_port_name_t),
			    VM_FLAGS_ANYWHERE)
			!= KERN_SUCCESS) {
		return KERN_RESOURCE_SHORTAGE;
	}
	mach_port_name_t *names = (mach_port_name_t *)address;
	names[0] = ipc_kobject_name(IPC_KOBJECT_PROCESSOR_SET);
	*processor_sets = (processor_set_name_array_t)names;
	*processor_setsCnt = 1;
	return KERN_SUCCESS;
}

static void
read_load(int *tasks, int *threads, double *load)
{
	*tasks = 0;
	*threads = 0;
	*load = 0;
	FILE *file = fopen("/proc/loadavg", "re");
	if (file != NULL) {
		if (fscanf(file, "%lf %*f %*f %*d/%d", load, threads) != 2) {
			*threads = 0;
		}
		fclose(file);
	}
	DIR *proc = opendir("/proc");
	if (proc != NULL) {
		struct dirent *entry;
		while ((entry = readdir(proc)) != NULL) {
			if (entry->d_name[0] >= '1'
					&& entry->d_name[0] <= '9') {
				(*tasks)++;
			}
		}
		closedir(proc);
	}
}

kern_return_t
processor_set_statistics(processor_set_name_t pset,
		processor_set_flavor_t flavor, processor_set_info_t info_out,
		mach_msg_type_number_t *info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "processor_set_statistics(%p, %p, %p, %p)\n",
			(void *)(uintptr_t)pset, (void *)(intptr_t)flavor,
			(void *)info_out, (void *)info_outCnt);
#endif
	if (flavor != PROCESSOR_SET_LOAD_INFO
			|| *info_outCnt < PROCESSOR_SET_LOAD_INFO_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}
	int tasks, threads;
	double load;
	read_load(&tasks, &threads, &load);
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	processor_set_load_info_t info = (processor_set_load_info_t)info_out;
	info->task_count = tasks;
	info->thread_count = threads;
	info->load_average = (integer_t)(load * LOAD_SCALE);
	double factor = load > cpus ? cpus / load : 1;
	info->mach_factor = (integer_t)(factor * cpus * LOAD_SCALE / cpus);
	*info_outCnt = PROCESSOR_SET_LOAD_INFO_COUNT;
	return KERN_SUCCESS;
}

kern_return_t
processor_set_info(processor_set_name_t set_name, int flavor, host_t *host,
		processor_set_info_t info_out,
		mach_msg_type_number_t *info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "processor_set_info(%p, %p, %p, %p, %p)\n",
			(void *)(uintptr_t)set_name, (void *)(intptr_t)flavor,
			(void *)host, (void *)info_out, (void *)info_outCnt);
#endif
	if (flavor != PROCESSOR_SET_BASIC_INFO
			|| *info_outCnt < PROCESSOR_SET_BASIC_INFO_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}
	processor_set_basic_info_t info = (processor_set_basic_info_t)info_out;
	info->processor_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
	info->default_policy = POLICY_TIMESHARE;
	*host = ipc_kobject_name(IPC_KOBJECT_HOST);
	*info_outCnt = PROCESSOR_SET_BASIC_INFO_COUNT;
	return KERN_SUCCESS;
}

kern_return_t
processor_set_destroy(processor_set_t set)
{
	(void)set;
	return KERN_FAILURE;
}

kern_return_t
processor_set_max_priority(processor_set_t processor_set, int max_priority,
		boolean_t change_threads)
{
	(void)processor_set;
	(void)max_priority;
	(void)change_threads;
	return KERN_FAILURE;
}

kern_return_t
processor_set_policy_enable(processor_set_t processor_set, int policy)
{
	(void)processor_set;
	(void)policy;
	return KERN_FAILURE;
}

kern_return_t
processor_set_policy_disable(processor_set_t processor_set, int policy,
		boolean_t change_threads)
{
	(void)processor_set;
	(void)policy;
	(void)change_threads;
	return KERN_FAILURE;
}

kern_return_t
processor_set_tasks(processor_set_t processor_set, task_array_t *task_list,
		mach_msg_type_number_t *task_listCnt)
{
	(void)processor_set;
	(void)task_list;
	(void)task_listCnt;
	return KERN_FAILURE;
}

kern_return_t
processor_set_threads(processor_set_t processor_set,
		thread_act_array_t *thread_list,
		mach_msg_type_number_t *thread_listCnt)
{
	(void)processor_set;
	(void)thread_list;
	(void)thread_listCnt;
	return KERN_FAILURE;
}

kern_return_t
processor_set_policy_control(processor_set_t pset,
		processor_set_flavor_t flavor, processor_set_info_t policy_info,
		mach_msg_type_number_t policy_infoCnt, boolean_t change)
{
	(void)pset;
	(void)flavor;
	(void)policy_info;
	(void)policy_infoCnt;
	(void)change;
	return KERN_FAILURE;
}

kern_return_t
processor_set_stack_usage(processor_set_t pset, unsigned *ltotal,
		vm_size_t *space, vm_size_t *resident, vm_size_t *maxusage,
		vm_offset_t *maxstack)
{
	(void)pset;
	(void)ltotal;
	(void)space;
	(void)resident;
	(void)maxusage;
	(void)maxstack;
	return KERN_FAILURE;
}

kern_return_t
processor_set_tasks_with_flavor(processor_set_t processor_set,
		mach_task_flavor_t flavor, task_array_t *task_list,
		mach_msg_type_number_t *task_listCnt)
{
	(void)processor_set;
	(void)flavor;
	(void)task_list;
	(void)task_listCnt;
	return KERN_FAILURE;
}
