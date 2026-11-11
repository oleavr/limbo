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
#include <stdbool.h>
#include <mach/host_special_ports.h>
#include <stdio.h>
#include <string.h>

#include "ipc.h"
#include "mach_vm.h"

#define kOSReturnSuccess         0
#define kOSKextReturnUnsupported 0xdc008009

static const struct {
	const char *predicate;
	const char *response;
	kern_return_t result;
} kext_requests[] = {
		{"Get Kexts in Collection", "<dict></dict>", kOSReturnSuccess},
		{"DaemonReady", NULL, kOSReturnSuccess},
		{"Get Kernel Requests", "<array></array>", kOSReturnSuccess},
		{"LoadCodelessKext", NULL, kOSKextReturnUnsupported},
};

static bool request_predicate_is(
		const char *request, size_t size, const char *predicate);

kern_return_t
host_get_boot_info(host_priv_t host_priv, kernel_boot_info_t boot_info)
{
	unimplemented();
}

kern_return_t
host_reboot(host_priv_t host_priv, int options)
{
	unimplemented();
}

kern_return_t
host_priv_statistics(host_priv_t host_priv, host_flavor_t flavor,
		host_info_t host_info_out,
		mach_msg_type_number_t *host_info_outCnt)
{
	unimplemented();
}

kern_return_t
host_default_memory_manager(host_priv_t host_priv,
		memory_object_default_t *default_manager,
		memory_object_cluster_size_t cluster_size)
{
	unimplemented();
}

kern_return_t
vm_wire(host_priv_t host_priv, vm_map_t task, vm_address_t address,
		vm_size_t size, vm_prot_t desired_access)
{
	unimplemented();
}

kern_return_t
thread_wire(host_priv_t host_priv, thread_act_t thread, boolean_t wired)
{
	unimplemented();
}

kern_return_t
vm_allocate_cpm(host_priv_t host_priv, vm_map_t task, vm_address_t *address,
		vm_size_t size, int flags)
{
	unimplemented();
}

kern_return_t
host_processors(host_priv_t host_priv, processor_array_t *out_processor_list,
		mach_msg_type_number_t *out_processor_listCnt)
{
	unimplemented();
}

kern_return_t
host_get_clock_control(
		host_priv_t host_priv, clock_id_t clock_id, clock_ctrl_t *clock_ctrl)
{
	unimplemented();
}

kern_return_t
kmod_create(host_priv_t host_priv, vm_address_t info, kmod_t *module)
{
	unimplemented();
}

kern_return_t
kmod_destroy(host_priv_t host_priv, kmod_t module)
{
	unimplemented();
}

kern_return_t
kmod_control(host_priv_t host_priv, kmod_t module,
		kmod_control_flavor_t flavor, kmod_args_t *data,
		mach_msg_type_number_t *dataCnt)
{
	unimplemented();
}

kern_return_t
host_get_special_port(
		host_priv_t host_priv, int node, int which, mach_port_t *port)
{
	if (which != HOST_IO_MASTER_PORT) {
		return KERN_INVALID_ARGUMENT;
	}
	*port = ipc_kobject_name(IPC_KOBJECT_IO_MAIN);
	return KERN_SUCCESS;
}

kern_return_t
host_set_special_port(host_priv_t host_priv, int which, mach_port_t port)
{
	unimplemented();
}

kern_return_t
host_set_exception_ports(host_priv_t host_priv, exception_mask_t exception_mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t new_flavor)
{
	unimplemented();
}

kern_return_t
host_get_exception_ports(host_priv_t host_priv, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	unimplemented();
}

kern_return_t
host_swap_exception_ports(host_priv_t host_priv,
		exception_mask_t exception_mask, mach_port_t new_port,
		exception_behavior_t behavior, thread_state_flavor_t new_flavor,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlerss,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	unimplemented();
}

kern_return_t
mach_vm_wire(host_priv_t host_priv, vm_map_t task, mach_vm_address_t address,
		mach_vm_size_t size, vm_prot_t desired_access)
{
	unimplemented();
}

kern_return_t
host_processor_set_priv(host_priv_t host_priv,
		processor_set_name_t set_name, processor_set_t *set)
{
	unimplemented();
}

kern_return_t
host_set_UNDServer(host_priv_t host, UNDServerRef server)
{
	unimplemented();
}

kern_return_t
host_get_UNDServer(host_priv_t host, UNDServerRef *server)
{
	unimplemented();
}

kern_return_t
kext_request(host_priv_t host_priv, uint32_t user_log_flags,
		vm_offset_t request_data, mach_msg_type_number_t request_dataCnt,
		vm_offset_t *response_data,
		mach_msg_type_number_t *response_dataCnt, vm_offset_t *log_data,
		mach_msg_type_number_t *log_dataCnt, kern_return_t *op_result)
{
	for (size_t i = 0; i < sizeof(kext_requests) / sizeof(kext_requests[0]);
			i++) {
		if (!request_predicate_is((const char *)request_data,
				    request_dataCnt,
				    kext_requests[i].predicate)) {
			continue;
		}
		const char *response = kext_requests[i].response;
		*response_data = 0;
		*response_dataCnt = 0;
		if (response != NULL) {
			size_t size = strlen(response) + 1;
			mach_vm_address_t address = 0;
			if (_kernelrpc_mach_vm_allocate(0, &address, size,
					    VM_FLAGS_ANYWHERE)
					!= KERN_SUCCESS) {
				return KERN_RESOURCE_SHORTAGE;
			}
			memcpy((void *)address, response, size);
			*response_data = (vm_offset_t)address;
			*response_dataCnt = (mach_msg_type_number_t)size;
		}
		*log_data = 0;
		*log_dataCnt = 0;
		*op_result = kext_requests[i].result;
		return KERN_SUCCESS;
	}
	unimplemented();
}

static bool
request_predicate_is(const char *request, size_t size, const char *predicate)
{
	static const char key[] = "<key>Kext Request Predicate</key><string>";
	const char *found = memmem(request, size, key, sizeof(key) - 1);
	if (found == NULL) {
		return false;
	}
	const char *value = found + sizeof(key) - 1;
	size_t length = strlen(predicate);
	return (size_t)(request + size - value) > length
			&& memcmp(value, predicate, length) == 0
			&& value[length] == '<';
}
