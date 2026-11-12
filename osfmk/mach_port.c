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

#include <mach/mach_types.h>
#include <mach_debug/mach_debug_types.h>
#include <stdio.h>
#include <string.h>

#include "ipc.h"

kern_return_t
mach_port_names(ipc_space_t task, mach_port_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_port_type_array_t *types,
		mach_msg_type_number_t *typesCnt)
{
	uint32_t count;
	kern_return_t kr = ipc_port_names(names, types, &count);
	*namesCnt = count;
	*typesCnt = count;
	return kr;
}

kern_return_t
mach_port_type(ipc_space_t task, mach_port_name_t name, mach_port_type_t *ptype)
{
	return ipc_port_type(name, ptype);
}

kern_return_t
mach_port_rename(ipc_space_t task, mach_port_name_t old_name,
		mach_port_name_t new_name)
{
	unimplemented();
}

kern_return_t
mach_port_allocate_name(ipc_space_t task, mach_port_right_t right,
		mach_port_name_t name)
{
	unimplemented();
}

kern_return_t
mach_port_allocate(ipc_space_t task, mach_port_right_t right,
		mach_port_name_t *name)
{
	return ipc_port_allocate(right, name);
}

kern_return_t
mach_port_destroy(ipc_space_t task, mach_port_name_t name)
{
	mach_port_type_t type;
	kern_return_t result = ipc_port_type(name, &type);
	if (result != KERN_SUCCESS) {
		return result;
	}
	static const struct {
		mach_port_type_t type;
		mach_port_right_t right;
	} rights[] = {
		{MACH_PORT_TYPE_SEND, MACH_PORT_RIGHT_SEND},
		{MACH_PORT_TYPE_SEND_ONCE, MACH_PORT_RIGHT_SEND_ONCE},
		{MACH_PORT_TYPE_RECEIVE, MACH_PORT_RIGHT_RECEIVE},
		{MACH_PORT_TYPE_PORT_SET, MACH_PORT_RIGHT_PORT_SET},
		{MACH_PORT_TYPE_DEAD_NAME, MACH_PORT_RIGHT_DEAD_NAME},
	};
	for (size_t i = 0; i < sizeof(rights) / sizeof(rights[0]); i++) {
		if (ipc_port_type(name, &type) != KERN_SUCCESS) {
			break;
		}
		if (!(type & rights[i].type)) {
			continue;
		}
		mach_port_urefs_t refs = 1;
		ipc_port_get_refs(name, rights[i].right, &refs);
		if (refs != 0) {
			ipc_port_mod_refs(name, rights[i].right,
					-(mach_port_delta_t)refs);
		}
	}
	return KERN_SUCCESS;
}

kern_return_t
mach_port_deallocate(ipc_space_t task, mach_port_name_t name)
{
	return ipc_port_deallocate(name);
}

kern_return_t
mach_port_get_refs(ipc_space_t task, mach_port_name_t name,
		mach_port_right_t right, mach_port_urefs_t *refs)
{
	return ipc_port_get_refs(name, right, refs);
}

kern_return_t
mach_port_mod_refs(ipc_space_t task, mach_port_name_t name,
		mach_port_right_t right, mach_port_delta_t delta)
{
	return ipc_port_mod_refs(name, right, delta);
}

kern_return_t
mach_port_peek(ipc_space_t task, mach_port_name_t name,
		mach_msg_trailer_type_t trailer_type,
		mach_port_seqno_t *request_seqnop, mach_msg_size_t *msg_sizep,
		mach_msg_id_t *msg_idp, mach_msg_trailer_info_t trailer_infop,
		mach_msg_type_number_t *trailer_infopCnt)
{
	unimplemented();
}

kern_return_t
mach_port_set_mscount(ipc_space_t task, mach_port_name_t name,
		mach_port_mscount_t mscount)
{
	unimplemented();
}

kern_return_t
mach_port_get_set_status(ipc_space_read_t task, mach_port_name_t name,
		mach_port_name_array_t *members,
		mach_msg_type_number_t *membersCnt)
{
	unimplemented();
}

kern_return_t
mach_port_move_member(ipc_space_t task, mach_port_name_t member,
		mach_port_name_t after)
{
	return ipc_port_move_member(member, after);
}

kern_return_t
mach_port_request_notification(ipc_space_t task, mach_port_name_t name,
		mach_msg_id_t msgid, mach_port_mscount_t sync,
		mach_port_t notify, mach_port_t *previous)
{
	*previous = MACH_PORT_NULL;
	return KERN_SUCCESS;
}

kern_return_t
mach_port_insert_right(ipc_space_t task, mach_port_name_t name,
		mach_port_t poly, mach_msg_type_name_t polyPoly)
{
	return ipc_port_insert_right(name, poly, polyPoly);
}

kern_return_t
mach_port_extract_right(ipc_space_t task, mach_port_name_t name,
		mach_msg_type_name_t msgt_name, mach_port_t *poly,
		mach_msg_type_name_t *polyPoly)
{
	return ipc_port_extract_right(name, msgt_name, poly, polyPoly);
}

kern_return_t
mach_port_set_seqno(ipc_space_t task, mach_port_name_t name,
		mach_port_seqno_t seqno)
{
	unimplemented();
}

kern_return_t
mach_port_get_attributes(ipc_space_read_t task, mach_port_name_t name,
		mach_port_flavor_t flavor, mach_port_info_t port_info_out,
		mach_msg_type_number_t *port_info_outCnt)
{
	switch (flavor) {
	case MACH_PORT_LIMITS_INFO: {
		mach_port_limits_t *limits
				= (mach_port_limits_t *)port_info_out;
		limits->mpl_qlimit = MACH_PORT_QLIMIT_DEFAULT;
		*port_info_outCnt = MACH_PORT_LIMITS_INFO_COUNT;
		return KERN_SUCCESS;
	}
	case MACH_PORT_RECEIVE_STATUS:
		*port_info_outCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
		return ipc_port_get_status(
				name, (mach_port_status_t *)port_info_out);
	case MACH_PORT_DNREQUESTS_SIZE:
		*(int *)port_info_out = 0;
		*port_info_outCnt = MACH_PORT_DNREQUESTS_SIZE_COUNT;
		return KERN_SUCCESS;
	case MACH_PORT_INFO_EXT: {
		mach_port_info_ext_t *info
				= (mach_port_info_ext_t *)port_info_out;
		memset(info, 0, sizeof(*info));
		*port_info_outCnt = MACH_PORT_INFO_EXT_COUNT;
		return ipc_port_get_status(name, &info->mpie_status);
	}
	default:
		unimplemented();
	}
}

kern_return_t
mach_port_set_attributes(ipc_space_t task, mach_port_name_t name,
		mach_port_flavor_t flavor, mach_port_info_t port_info,
		mach_msg_type_number_t port_infoCnt)
{
	switch (flavor) {
	case MACH_PORT_LIMITS_INFO:
	case MACH_PORT_TEMPOWNER:
	case MACH_PORT_IMPORTANCE_RECEIVER:
	case MACH_PORT_DENAP_RECEIVER:
		return KERN_SUCCESS;
	default:
		unimplemented();
	}
}

kern_return_t
mach_port_allocate_qos(ipc_space_t task, mach_port_right_t right,
		mach_port_qos_t *qos, mach_port_name_t *name)
{
	unimplemented();
}

kern_return_t
mach_port_allocate_full(ipc_space_t task, mach_port_right_t right,
		mach_port_t proto, mach_port_qos_t *qos, mach_port_name_t *name)
{
	unimplemented();
}

kern_return_t
task_set_port_space(ipc_space_t task, int table_entries)
{
	unimplemented();
}

kern_return_t
mach_port_get_srights(ipc_space_t task, mach_port_name_t name,
		mach_port_rights_t *srights)
{
	unimplemented();
}

kern_return_t
mach_port_space_info(ipc_space_read_t space, ipc_info_space_t *space_info,
		ipc_info_name_array_t *table_info,
		mach_msg_type_number_t *table_infoCnt,
		ipc_info_tree_name_array_t *tree_info,
		mach_msg_type_number_t *tree_infoCnt)
{
	unimplemented();
}

kern_return_t
mach_port_dnrequest_info(ipc_space_t task, mach_port_name_t name,
		unsigned *dnr_total, unsigned *dnr_used)
{
	unimplemented();
}

kern_return_t
mach_port_kernel_object(ipc_space_read_t task, mach_port_name_t name,
		unsigned *object_type, unsigned *object_addr)
{
	unimplemented();
}

kern_return_t
mach_port_insert_member(
		ipc_space_t task, mach_port_name_t name, mach_port_name_t pset)
{
	return ipc_port_insert_member(name, pset);
}

kern_return_t
mach_port_extract_member(
		ipc_space_t task, mach_port_name_t name, mach_port_name_t pset)
{
	return ipc_port_extract_member(name, pset);
}

kern_return_t
mach_port_get_context(ipc_space_read_t task, mach_port_name_t name,
		mach_vm_address_t *context)
{
	return ipc_port_get_context(name, context);
}

kern_return_t
mach_port_set_context(ipc_space_t task, mach_port_name_t name,
		mach_vm_address_t context)
{
	return ipc_port_set_context(name, context);
}

kern_return_t
mach_port_kobject(ipc_space_read_t task, mach_port_name_t name,
		ipc_info_object_type_t *object_type,
		mach_vm_address_t *object_addr)
{
	unimplemented();
}

kern_return_t
mach_port_construct(ipc_space_t task, mach_port_options_ptr_t options,
		uint64_t context, mach_port_name_t *name)
{
	return ipc_port_construct(options, context, name);
}

kern_return_t
mach_port_destruct(ipc_space_t task, mach_port_name_t name,
		mach_port_delta_t srdelta, uint64_t guard)
{
	return ipc_port_destruct(name, srdelta, guard);
}

kern_return_t
mach_port_guard(ipc_space_t task, mach_port_name_t name, uint64_t guard,
		boolean_t strict)
{
	return ipc_port_set_context(name, guard);
}

kern_return_t
mach_port_unguard(ipc_space_t task, mach_port_name_t name, uint64_t guard)
{
	return ipc_port_set_context(name, 0);
}

kern_return_t
mach_port_space_basic_info(
		ipc_space_inspect_t task, ipc_info_space_basic_t *basic_info)
{
	unimplemented();
}

kern_return_t
mach_port_special_reply_port_reset_link(ipc_space_t task, mach_port_name_t name,
		boolean_t *srp_lost_link)
{
	unimplemented();
}

kern_return_t
mach_port_guard_with_flags(ipc_space_t task, mach_port_name_t name,
		uint64_t guard, uint64_t flags)
{
	return ipc_port_set_context(name, guard);
}

kern_return_t
mach_port_swap_guard(ipc_space_t task, mach_port_name_t name,
		uint64_t old_guard, uint64_t new_guard)
{
	return ipc_port_set_context(name, new_guard);
}

kern_return_t
mach_port_kobject_description(ipc_space_read_t task, mach_port_name_t name,
		ipc_info_object_type_t *object_type,
		mach_vm_address_t *object_addr,
		kobject_description_t description)
{
	unimplemented();
}

kern_return_t
mach_port_is_connection_for_service(ipc_space_t task,
		mach_port_name_t connection_port, mach_port_name_t service_port,
		uint64_t *filter_policy_id)
{
	*filter_policy_id = 0;
	return KERN_SUCCESS;
}

kern_return_t
mach_port_get_service_port_info(ipc_space_read_t task, mach_port_name_t name,
		mach_service_port_info_data_t *sp_info_out)
{
	unimplemented();
}

kern_return_t
mach_port_assert_attributes(ipc_space_t task, mach_port_name_t name,
		mach_port_flavor_t flavor, mach_port_info_t info,
		mach_msg_type_number_t infoCnt)
{
	unimplemented();
}
