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

#include <device/device_types.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "ipc.h"
#include "osserialize.h"

#define kOSSerializeBinarySignature 0x000000d3
#define kOSSerializeEndCollection   0x80000000
#define kOSSerializeString          0x09000000
#define kOSSerializeData            0x0a000000

enum identity_kind {
	IDENTITY_STRING,
	IDENTITY_DATA,
};

struct identity_property {
	const char *name;
	enum identity_kind kind;
	const void *value;
	uint32_t len;
};

struct io_iterator {
	bool yielded;
};

static kern_return_t exhausted_iterator(mach_port_t *empty);

static const char platform_expert;
#define PLATFORM_EXPERT ((void *)&platform_expert)

static char platform_serial[32];
static char platform_uuid[64];
static uint8_t serial_number[32];
static uint8_t mlb_serial_number[32];
static const uint8_t region_info[32] = "H/A";

static const struct identity_property identity[] = {
	{"IOPlatformSerialNumber", IDENTITY_STRING, platform_serial, 0},
	{"IOPlatformUUID", IDENTITY_STRING, platform_uuid, 0},
	{"model", IDENTITY_DATA, "Mac17,2\0", 8},
	{"board-id", IDENTITY_DATA, "J704\0", 5},
	{"target-type", IDENTITY_DATA, "J704\0", 5},
	{"serial-number", IDENTITY_DATA, serial_number, sizeof(serial_number)},
	{"region-info", IDENTITY_DATA, region_info, sizeof(region_info)},
	{"mlb-serial-number", IDENTITY_DATA, mlb_serial_number,
			sizeof(mlb_serial_number)},
	{"manufacturer", IDENTITY_DATA, "Apple Inc.\0", 11},
};

static kern_return_t match_platform_expert(mach_port_t *service);
static kern_return_t match_iterator(mach_port_t *existing);
static const struct identity_property *identity_lookup(const char *name);
static void identity_configure(void);
static void *identity_serialize(const struct identity_property *prop,
		mach_msg_type_number_t *out_size);


kern_return_t
is_io_object_get_class(mach_port_t object, io_name_t className)
{
	strcpy(className, "IOPlatformExpertDevice");
	return KERN_SUCCESS;
}

kern_return_t
is_io_object_conforms_to(
		mach_port_t object, io_name_t className, boolean_t *conforms)
{
	*conforms = strcmp(className, "IOPlatformExpertDevice") == 0
			|| strcmp(className, "IOService") == 0
			|| strcmp(className, "IORegistryEntry") == 0;
	return KERN_SUCCESS;
}

kern_return_t
is_io_iterator_next(mach_port_t iterator, mach_port_t *object)
{
	struct io_iterator *state
			= ipc_kobject_lookup(iterator, IPC_KOBJECT_IO_OBJECT);
	if (state->yielded) {
		*object = MACH_PORT_NULL;
		return KERN_FAILURE;
	}
	state->yielded = true;
	return match_platform_expert(object);
}

static kern_return_t
match_platform_expert(mach_port_t *service)
{
	*service = ipc_kobject_alloc(IPC_KOBJECT_IO_OBJECT, PLATFORM_EXPERT);
	return KERN_SUCCESS;
}

kern_return_t
is_io_iterator_reset(mach_port_t iterator)
{
	struct io_iterator *state
			= ipc_kobject_lookup(iterator, IPC_KOBJECT_IO_OBJECT);
	state->yielded = false;
	return KERN_SUCCESS;
}

kern_return_t
is_io_service_get_matching_services(
		mach_port_t main_port, io_string_t matching, mach_port_t *existing)
{
	return match_iterator(existing);
}

static kern_return_t
match_iterator(mach_port_t *existing)
{
	struct io_iterator *iterator = calloc(1, sizeof(*iterator));
	*existing = ipc_kobject_alloc(IPC_KOBJECT_IO_OBJECT, iterator);
	return KERN_SUCCESS;
}

static kern_return_t
exhausted_iterator(mach_port_t *empty)
{
	struct io_iterator *iterator = calloc(1, sizeof(*iterator));
	iterator->yielded = true;
	*empty = ipc_kobject_alloc(IPC_KOBJECT_IO_OBJECT, iterator);
	return KERN_SUCCESS;
}

kern_return_t
is_io_registry_entry_get_property(mach_port_t registry_entry,
		io_name_t property_name, io_buf_ptr_t *properties,
		mach_msg_type_number_t *propertiesCnt)
{
	const struct identity_property *prop = identity_lookup(property_name);
	if (prop == NULL) {
		return KERN_NOT_SUPPORTED;
	}
	*properties = identity_serialize(prop, propertiesCnt);
	return KERN_SUCCESS;
}

static const struct identity_property *
identity_lookup(const char *name)
{
	static bool configured;
	if (!configured) {
		identity_configure();
		configured = true;
	}

	for (size_t i = 0; i < sizeof(identity) / sizeof(identity[0]); i++) {
		const struct identity_property *prop = &identity[i];
		if (strcmp(prop->name, name) == 0
				&& ((const char *)prop->value)[0] != '\0') {
			return prop;
		}
	}
	return NULL;
}

static void
identity_configure(void)
{
	const char *serial = getenv("LIMBO_SERIAL_NUMBER");
	const char *uuid = getenv("LIMBO_PLATFORM_UUID");
	const char *mlb = getenv("LIMBO_MLB_SERIAL_NUMBER");

	if (serial != NULL) {
		strcpy(platform_serial, serial);
		memcpy(serial_number, serial, strlen(serial));
	}
	if (uuid != NULL) {
		strcpy(platform_uuid, uuid);
	}
	if (mlb != NULL) {
		memcpy(mlb_serial_number, mlb, strlen(mlb));
	}
}

static void *
identity_serialize(const struct identity_property *prop,
		mach_msg_type_number_t *out_size)
{
	uint32_t type = (prop->kind == IDENTITY_STRING) ? kOSSerializeString
							: kOSSerializeData;
	uint32_t payload = (prop->kind == IDENTITY_STRING)
			? (uint32_t)strlen(prop->value) + 1
			: prop->len;
	uint32_t size = 2 * sizeof(uint32_t) + ((payload + 3) & ~3u);

	uint32_t *buffer = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	buffer[0] = kOSSerializeBinarySignature;
	buffer[1] = type | kOSSerializeEndCollection | payload;
	memcpy(&buffer[2], prop->value, payload);

	*out_size = size;
	return buffer;
}

kern_return_t
is_io_registry_create_iterator(mach_port_t main_port,
		io_name_t plane,
		uint32_t options,
		mach_port_t *iterator)
{
	return exhausted_iterator(iterator);
}

kern_return_t
is_io_registry_iterator_enter_entry(mach_port_t iterator)
{
	return KERN_SUCCESS;
}

kern_return_t
is_io_registry_iterator_exit_entry(mach_port_t iterator)
{
	return KERN_SUCCESS;
}

kern_return_t
is_io_registry_entry_from_path(mach_port_t main_port,
		io_string_t path,
		mach_port_t *registry_entry)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_name(mach_port_t registry_entry, io_name_t name)
{
	strcpy(name, "device");
	return KERN_SUCCESS;
}

kern_return_t
is_io_registry_entry_get_properties(mach_port_t registry_entry,
		io_buf_ptr_t *properties,
		mach_msg_type_number_t *propertiesCnt)
{
	struct os_object *empty = os_dictionary_create();
	size_t size;
	void *serialized = os_serialize(empty, &size);
	os_release(empty);
	void *copy = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	memcpy(copy, serialized, size);
	free(serialized);
	*properties = copy;
	*propertiesCnt = size;
	return KERN_SUCCESS;
}

kern_return_t
is_io_registry_entry_get_property_bytes(mach_port_t registry_entry,
		io_name_t property_name, io_struct_inband_t data,
		mach_msg_type_number_t *dataCnt)
{
	const struct identity_property *prop = identity_lookup(property_name);
	if (prop == NULL) {
		return KERN_NOT_SUPPORTED;
	}
	uint32_t size = (prop->kind == IDENTITY_STRING)
			? (uint32_t)strlen(prop->value) + 1
			: prop->len;
	if (size > *dataCnt) {
		size = *dataCnt;
	}
	memcpy(data, prop->value, size);
	*dataCnt = size;
	return KERN_SUCCESS;
}

kern_return_t
is_io_registry_entry_get_child_iterator(mach_port_t registry_entry,
		io_name_t plane,
		mach_port_t *iterator)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_parent_iterator(mach_port_t registry_entry,
		io_name_t plane,
		mach_port_t *iterator)
{
	return exhausted_iterator(iterator);
}

kern_return_t
is_io_connect_map_shared_memory(mach_port_t connection,
		uint32_t memory_type,
		task_t into_task,
		mach_vm_address_t *address,
		mach_vm_size_t *size,
		uint32_t flags,
		io_name_t property_name,
		io_struct_inband_t inband_output,
		mach_msg_type_number_t *inband_outputCnt)
{
	unimplemented();
}

kern_return_t
is_io_service_close(mach_port_t connection)
{
	unimplemented();
}

kern_return_t
is_io_connect_get_service(mach_port_t connection,
		mach_port_t *service)
{
	unimplemented();
}

kern_return_t
is_io_connect_add_client(mach_port_t connection,
		mach_port_t connect_to)
{
	unimplemented();
}

kern_return_t
is_io_connect_set_properties(mach_port_t connection,
		io_buf_ptr_t properties,
		mach_msg_type_number_t propertiesCnt,
		kern_return_t *result)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_path(mach_port_t registry_entry,
		io_name_t plane,
		io_string_t path)
{
	unimplemented();
}

kern_return_t
is_io_registry_get_root_entry(mach_port_t main_port,
		mach_port_t *root)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_set_properties(mach_port_t registry_entry,
		io_buf_ptr_t properties,
		mach_msg_type_number_t propertiesCnt,
		kern_return_t *result)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_in_plane(mach_port_t registry_entry,
		io_name_t plane,
		boolean_t *inPlane)
{
	unimplemented();
}

kern_return_t
is_io_object_get_retain_count(mach_port_t object,
		uint32_t *retainCount)
{
	unimplemented();
}

kern_return_t
is_io_service_get_busy_state(mach_port_t service,
		uint32_t *busyState)
{
	unimplemented();
}

kern_return_t
is_io_service_wait_quiet(mach_port_t service,
		mach_timespec_t wait_time)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_create_iterator(mach_port_t registry_entry,
		io_name_t plane,
		uint32_t options,
		mach_port_t *iterator)
{
	/* The registry here has no tree to walk, only entries found by path
	 * or by matching */
	return exhausted_iterator(iterator);
}

kern_return_t
is_io_iterator_is_valid(mach_port_t iterator,
		boolean_t *is_valid)
{
	*is_valid = TRUE;
	return KERN_SUCCESS;
}

kern_return_t
is_io_catalog_send_data(mach_port_t main_port,
		uint32_t flag,
		io_buf_ptr_t inData,
		mach_msg_type_number_t inDataCnt,
		kern_return_t *result)
{
	unimplemented();
}

kern_return_t
is_io_catalog_terminate(mach_port_t main_port,
		uint32_t flag,
		io_name_t name)
{
	unimplemented();
}

kern_return_t
is_io_catalog_get_data(mach_port_t main_port,
		uint32_t flag,
		io_buf_ptr_t *outData,
		mach_msg_type_number_t *outDataCnt)
{
	unimplemented();
}

kern_return_t
is_io_catalog_get_gen_count(mach_port_t main_port,
		uint32_t *genCount)
{
	unimplemented();
}

kern_return_t
is_io_catalog_module_loaded(mach_port_t main_port,
		io_name_t name)
{
	unimplemented();
}

kern_return_t
is_io_catalog_reset(mach_port_t main_port,
		uint32_t flag)
{
	unimplemented();
}

kern_return_t
is_io_service_request_probe(mach_port_t service,
		uint32_t options)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_name_in_plane(mach_port_t registry_entry,
		io_name_t plane,
		io_name_t name)
{
	unimplemented();
}

kern_return_t
is_io_service_match_property_table(mach_port_t service,
		io_string_t matching,
		boolean_t *matches)
{
	unimplemented();
}

kern_return_t
is_io_connect_get_notification_semaphore(mach_port_t connection,
		natural_t notification_type,
		semaphore_t *semaphore)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_location_in_plane(mach_port_t registry_entry,
		io_name_t plane,
		io_name_t location)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_property_recursively(mach_port_t registry_entry,
		io_name_t plane,
		io_name_t property_name,
		uint32_t options,
		io_buf_ptr_t *properties,
		mach_msg_type_number_t *propertiesCnt)
{
	unimplemented();
}

kern_return_t
is_io_service_get_state(mach_port_t service,
		uint64_t *state,
		uint32_t *busy_state,
		uint64_t *accumulated_busy_time)
{
	unimplemented();
}

kern_return_t
is_io_service_get_matching_services_ool(mach_port_t main_port,
		io_buf_ptr_t matching, mach_msg_type_number_t matchingCnt,
		kern_return_t *result, mach_port_t *existing)
{
	*result = match_iterator(existing);
	return KERN_SUCCESS;
}

kern_return_t
is_io_service_match_property_table_ool(mach_port_t service,
		io_buf_ptr_t matching,
		mach_msg_type_number_t matchingCnt,
		kern_return_t *result,
		boolean_t *matches)
{
	unimplemented();
}

kern_return_t
is_io_object_get_superclass(mach_port_t main_port,
		io_name_t obj_name,
		io_name_t class_name)
{
	unimplemented();
}

kern_return_t
is_io_object_get_bundle_identifier(mach_port_t main_port,
		io_name_t obj_name,
		io_name_t class_name)
{
	unimplemented();
}

kern_return_t
is_io_service_open_extended(mach_port_t service,
		task_t owningTask,
		uint32_t connect_type,
		NDR_record_t ndr,
		io_buf_ptr_t properties,
		mach_msg_type_number_t propertiesCnt,
		kern_return_t *result,
		mach_port_t *connection)
{
	unimplemented();
}

kern_return_t
is_io_connect_map_memory_into_task(mach_port_t connection,
		uint32_t memory_type,
		task_t into_task,
		mach_vm_address_t *address,
		mach_vm_size_t *size,
		uint32_t flags)
{
	unimplemented();
}

kern_return_t
is_io_connect_unmap_memory_from_task(mach_port_t connection,
		uint32_t memory_type,
		task_t from_task,
		mach_vm_address_t address)
{
	unimplemented();
}

kern_return_t
is_io_connect_method(mach_port_t connection,
		uint32_t selector,
		io_scalar_inband64_t scalar_input,
		mach_msg_type_number_t scalar_inputCnt,
		io_struct_inband_t inband_input,
		mach_msg_type_number_t inband_inputCnt,
		mach_vm_address_t ool_input,
		mach_vm_size_t ool_input_size,
		io_struct_inband_t inband_output,
		mach_msg_type_number_t *inband_outputCnt,
		io_scalar_inband64_t scalar_output,
		mach_msg_type_number_t *scalar_outputCnt,
		mach_vm_address_t ool_output,
		mach_vm_size_t *ool_output_size)
{
	unimplemented();
}

kern_return_t
is_io_connect_async_method(mach_port_t connection,
		mach_port_t wake_port,
		io_async_ref64_t reference,
		mach_msg_type_number_t referenceCnt,
		uint32_t selector,
		io_scalar_inband64_t scalar_input,
		mach_msg_type_number_t scalar_inputCnt,
		io_struct_inband_t inband_input,
		mach_msg_type_number_t inband_inputCnt,
		mach_vm_address_t ool_input,
		mach_vm_size_t ool_input_size,
		io_struct_inband_t inband_output,
		mach_msg_type_number_t *inband_outputCnt,
		io_scalar_inband64_t scalar_output,
		mach_msg_type_number_t *scalar_outputCnt,
		mach_vm_address_t ool_output,
		mach_vm_size_t *ool_output_size)
{
	unimplemented();
}

kern_return_t
is_io_connect_set_notification_port(mach_port_t connection,
		uint32_t notification_type,
		mach_port_t port,
		io_user_reference_t reference)
{
	unimplemented();
}

kern_return_t
is_io_service_add_notification(mach_port_t main_port,
		io_name_t notification_type,
		io_string_t matching,
		mach_port_t wake_port,
		io_async_ref64_t reference,
		mach_msg_type_number_t referenceCnt,
		mach_port_t *notification)
{
	unimplemented();
}

kern_return_t
is_io_service_add_interest_notification(mach_port_t service,
		io_name_t type_of_interest,
		mach_port_t wake_port,
		io_async_ref64_t reference,
		mach_msg_type_number_t referenceCnt,
		mach_port_t *notification)
{
	unimplemented();
}

kern_return_t
is_io_service_add_notification_ool(mach_port_t main_port,
		io_name_t notification_type,
		io_buf_ptr_t matching,
		mach_msg_type_number_t matchingCnt,
		mach_port_t wake_port,
		io_async_ref64_t reference,
		mach_msg_type_number_t referenceCnt,
		kern_return_t *result,
		mach_port_t *notification)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_registry_entry_id(
		mach_port_t registry_entry, uint64_t *entry_id)
{
	*entry_id = 0x100000100;
	return KERN_SUCCESS;
}

kern_return_t
is_io_connect_method_var_output(mach_port_t connection,
		uint32_t selector,
		io_scalar_inband64_t scalar_input,
		mach_msg_type_number_t scalar_inputCnt,
		io_struct_inband_t inband_input,
		mach_msg_type_number_t inband_inputCnt,
		mach_vm_address_t ool_input,
		mach_vm_size_t ool_input_size,
		io_struct_inband_t inband_output,
		mach_msg_type_number_t *inband_outputCnt,
		io_scalar_inband64_t scalar_output,
		mach_msg_type_number_t *scalar_outputCnt,
		io_buf_ptr_t *var_output,
		mach_msg_type_number_t *var_outputCnt)
{
	unimplemented();
}

kern_return_t
is_io_service_get_matching_service(
		mach_port_t main_port, io_string_t matching, mach_port_t *service)
{
	return match_platform_expert(service);
}

kern_return_t
is_io_service_get_matching_service_ool(mach_port_t main_port,
		io_buf_ptr_t matching, mach_msg_type_number_t matchingCnt,
		kern_return_t *result, mach_port_t *service)
{
	*result = match_platform_expert(service);
	return KERN_SUCCESS;
}

kern_return_t
is_io_service_get_authorization_id(mach_port_t service,
		uint64_t *authorization_id)
{
	unimplemented();
}

kern_return_t
is_io_service_set_authorization_id(mach_port_t service,
		uint64_t authorization_id)
{
	unimplemented();
}

kern_return_t
is_io_server_version(mach_port_t main_port,
		uint64_t *version)
{
	*version = 0x20220000;
	return KERN_SUCCESS;
}

kern_return_t
is_io_registry_entry_get_properties_bin(mach_port_t registry_entry,
		io_buf_ptr_t *properties,
		mach_msg_type_number_t *propertiesCnt)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_property_bin(mach_port_t registry_entry,
		io_name_t plane, io_name_t property_name, uint32_t options,
		io_buf_ptr_t *properties, mach_msg_type_number_t *propertiesCnt)
{
	const struct identity_property *prop = identity_lookup(property_name);
	if (prop == NULL) {
		return KERN_NOT_SUPPORTED;
	}
	*properties = identity_serialize(prop, propertiesCnt);
	return KERN_SUCCESS;
}

kern_return_t
is_io_service_get_matching_service_bin(mach_port_t main_port,
		io_struct_inband_t matching, mach_msg_type_number_t matchingCnt,
		mach_port_t *service)
{
	return match_platform_expert(service);
}

kern_return_t
is_io_service_get_matching_services_bin(mach_port_t main_port,
		io_struct_inband_t matching, mach_msg_type_number_t matchingCnt,
		mach_port_t *existing)
{
	return match_iterator(existing);
}

kern_return_t
is_io_service_match_property_table_bin(mach_port_t service,
		io_struct_inband_t matching,
		mach_msg_type_number_t matchingCnt,
		boolean_t *matches)
{
	unimplemented();
}

kern_return_t
is_io_service_add_notification_bin(mach_port_t main_port,
		io_name_t notification_type,
		io_struct_inband_t matching,
		mach_msg_type_number_t matchingCnt,
		mach_port_t wake_port,
		io_async_ref64_t reference,
		mach_msg_type_number_t referenceCnt,
		mach_port_t *notification)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_path_ool(mach_port_t registry_entry,
		io_name_t plane,
		io_string_inband_t path,
		io_buf_ptr_t *path_ool,
		mach_msg_type_number_t *path_oolCnt)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_from_path_ool(mach_port_t main_port,
		io_string_inband_t path,
		io_buf_ptr_t path_ool,
		mach_msg_type_number_t path_oolCnt,
		kern_return_t *result,
		mach_port_t *registry_entry)
{
	unimplemented();
}

kern_return_t
is_io_device_tree_entry_exists_with_name(mach_port_t main_port,
		io_name_t name,
		boolean_t *exists)
{
	unimplemented();
}

kern_return_t
is_io_registry_entry_get_properties_bin_buf(mach_port_t registry_entry,
		mach_vm_address_t buf,
		mach_vm_size_t *bufsize,
		io_buf_ptr_t *properties,
		mach_msg_type_number_t *propertiesCnt)
{
	struct os_object *dictionary = os_dictionary_create();
	if (ipc_kobject_lookup(registry_entry, IPC_KOBJECT_IO_OBJECT)
			== PLATFORM_EXPERT) {
		identity_lookup("");
		for (size_t i = 0; i < sizeof(identity) / sizeof(identity[0]);
				i++) {
			const struct identity_property *prop = &identity[i];
			if (((const char *)prop->value)[0] == '\0') {
				continue;
			}
			os_dictionary_set(dictionary, prop->name,
					prop->kind == IDENTITY_STRING
							? os_string_create(
									  prop->value)
							: os_data_create(prop->value,
									  prop->len));
		}
	}
	size_t size;
	void *serialized = os_serialize(dictionary, &size);
	os_release(dictionary);

	*properties = NULL;
	*propertiesCnt = 0;
	if (buf != 0 && *bufsize >= size) {
		memcpy((void *)buf, serialized, size);
		*bufsize = size;
	} else {
		void *copy = mmap(NULL, size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, -1, 0);
		memcpy(copy, serialized, size);
		*properties = copy;
		*propertiesCnt = size;
		*bufsize = 0;
	}
	free(serialized);
	return KERN_SUCCESS;
}

kern_return_t
is_io_registry_entry_get_property_bin_buf(mach_port_t registry_entry,
		io_name_t plane,
		io_name_t property_name,
		uint32_t options,
		mach_vm_address_t buf,
		mach_vm_size_t *bufsize,
		io_buf_ptr_t *properties,
		mach_msg_type_number_t *propertiesCnt)
{
	const struct identity_property *prop = identity_lookup(property_name);
	if (prop == NULL) {
		return KERN_NOT_SUPPORTED;
	}
	*bufsize = 0;
	*properties = identity_serialize(prop, propertiesCnt);
	return KERN_SUCCESS;
}

kern_return_t
is_io_service_wait_quiet_with_options(mach_port_t service,
		mach_timespec_t wait_time,
		uint32_t options)
{
	unimplemented();
}

kern_return_t
is_io_service_get_wait_info(mach_port_t service,
		uint32_t index,
		io_name_t resolver_name,
		uint64_t *resolver_id,
		uint64_t *start_ns,
		uint64_t *end_ns,
		boolean_t *blocking)
{
	unimplemented();
}
