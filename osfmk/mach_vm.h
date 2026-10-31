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

#pragma once

#include <mach/mach_types.h>
#include <stdbool.h>

kern_return_t _kernelrpc_mach_vm_allocate(vm_task_entry_t target,
		mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t _kernelrpc_mach_vm_deallocate(vm_task_entry_t target,
		mach_vm_address_t address, mach_vm_size_t size);
kern_return_t _kernelrpc_mach_vm_protect(vm_task_entry_t target_task,
		mach_vm_address_t address, mach_vm_size_t size,
		boolean_t set_maximum, vm_prot_t new_protection);
mach_port_name_t memory_entry_create(mach_vm_size_t size, void **contents);
mach_port_name_t memory_entry_share(int fd, mach_vm_size_t size);
bool memory_entry_describe(const void *kobject, int *fd, mach_vm_size_t *size,
		mach_vm_offset_t *data_offset);
void memory_entry_destroy(void *kobject);
void *memory_entry_adopt(
		int fd, mach_vm_size_t size, mach_vm_offset_t data_offset);
kern_return_t mach_vm_allocate_anywhere(
		mach_vm_address_t *address, mach_vm_size_t size);
kern_return_t mach_vm_map_fd(int fd, mach_vm_size_t size, vm_prot_t protection,
		mach_vm_address_t *address);
kern_return_t _kernelrpc_mach_vm_purgable_control(vm_map_t target_task,
		mach_vm_address_t address, vm_purgable_t control, int *state);
kern_return_t _kernelrpc_mach_vm_map(vm_task_entry_t target_task,
		mach_vm_address_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, mem_entry_name_port_t object,
		memory_object_offset_t offset, boolean_t copy,
		vm_prot_t cur_protection, vm_prot_t max_protection,
		vm_inherit_t inheritance);
