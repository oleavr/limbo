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
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_names(%p, %p, %p, %p, %p)\n", (void *)task,
			(void *)names, (void *)namesCnt, (void *)types,
			(void *)typesCnt);
#endif
	uint32_t count;
	kern_return_t kr = ipc_port_names(names, types, &count);
	*namesCnt = count;
	*typesCnt = count;
	return kr;
}

kern_return_t
mach_port_type(ipc_space_t task, mach_port_name_t name, mach_port_type_t *ptype)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_type(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)ptype);
#endif
	return ipc_port_type(name, ptype);
}

kern_return_t
mach_port_rename(ipc_space_t task, mach_port_name_t old_name,
		mach_port_name_t new_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_rename(%p, %p, %p)\n", (void *)task,
			(void *)old_name, (void *)new_name);
#endif
	unimplemented();
}

kern_return_t
mach_port_allocate_name(ipc_space_t task, mach_port_right_t right,
		mach_port_name_t name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_allocate_name(%p, %p, %p)\n", (void *)task,
			(void *)right, (void *)name);
#endif
	unimplemented();
}

kern_return_t
mach_port_allocate(ipc_space_t task, mach_port_right_t right,
		mach_port_name_t *name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_allocate(%p, %p, %p)\n", (void *)task,
			(void *)right, (void *)name);
#endif
	return ipc_port_allocate(right, name);
}

kern_return_t
mach_port_destroy(ipc_space_t task, mach_port_name_t name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_destroy(%p, %p)\n", (void *)task,
			(void *)name);
#endif
	unimplemented();
}

kern_return_t
mach_port_deallocate(ipc_space_t task, mach_port_name_t name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_deallocate(%p, %p)\n", (void *)task,
			(void *)name);
#endif
	return ipc_port_deallocate(name);
}

kern_return_t
mach_port_get_refs(ipc_space_t task, mach_port_name_t name,
		mach_port_right_t right, mach_port_urefs_t *refs)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_get_refs(%p, %p, %p, %p)\n", (void *)task,
			(void *)name, (void *)right, (void *)refs);
#endif
	return ipc_port_get_refs(name, right, refs);
}

kern_return_t
mach_port_mod_refs(ipc_space_t task, mach_port_name_t name,
		mach_port_right_t right, mach_port_delta_t delta)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_mod_refs(%p, %p, %p, %p)\n", (void *)task,
			(void *)name, (void *)right, (void *)delta);
#endif
	return ipc_port_mod_refs(name, right, delta);
}

kern_return_t
mach_port_peek(ipc_space_t task, mach_port_name_t name,
		mach_msg_trailer_type_t trailer_type,
		mach_port_seqno_t *request_seqnop, mach_msg_size_t *msg_sizep,
		mach_msg_id_t *msg_idp, mach_msg_trailer_info_t trailer_infop,
		mach_msg_type_number_t *trailer_infopCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_peek(%p, %p, %p, %p, %p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)trailer_type,
			(void *)request_seqnop, (void *)msg_sizep,
			(void *)msg_idp, (void *)trailer_infop,
			(void *)trailer_infopCnt);
#endif
	unimplemented();
}

kern_return_t
mach_port_set_mscount(ipc_space_t task, mach_port_name_t name,
		mach_port_mscount_t mscount)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_set_mscount(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)mscount);
#endif
	unimplemented();
}

kern_return_t
mach_port_get_set_status(ipc_space_read_t task, mach_port_name_t name,
		mach_port_name_array_t *members,
		mach_msg_type_number_t *membersCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_get_set_status(%p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)members,
			(void *)membersCnt);
#endif
	unimplemented();
}

kern_return_t
mach_port_move_member(ipc_space_t task, mach_port_name_t member,
		mach_port_name_t after)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_move_member(%p, %p, %p)\n", (void *)task,
			(void *)member, (void *)after);
#endif
	return ipc_port_move_member(member, after);
}

kern_return_t
mach_port_request_notification(ipc_space_t task, mach_port_name_t name,
		mach_msg_id_t msgid, mach_port_mscount_t sync,
		mach_port_t notify, mach_port_t *previous)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_port_request_notification(%p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)task, (void *)name, (void *)msgid, (void *)sync,
			(void *)notify, (void *)previous);
#endif
	*previous = MACH_PORT_NULL;
	return KERN_SUCCESS;
}

kern_return_t
mach_port_insert_right(ipc_space_t task, mach_port_name_t name,
		mach_port_t poly, mach_msg_type_name_t polyPoly)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_insert_right(%p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)poly,
			(void *)polyPoly);
#endif
	return ipc_port_insert_right(name, poly, polyPoly);
}

kern_return_t
mach_port_extract_right(ipc_space_t task, mach_port_name_t name,
		mach_msg_type_name_t msgt_name, mach_port_t *poly,
		mach_msg_type_name_t *polyPoly)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_extract_right(%p, %p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)msgt_name,
			(void *)poly, (void *)polyPoly);
#endif
	return ipc_port_extract_right(name, msgt_name, poly, polyPoly);
}

kern_return_t
mach_port_set_seqno(ipc_space_t task, mach_port_name_t name,
		mach_port_seqno_t seqno)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_set_seqno(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)seqno);
#endif
	unimplemented();
}

kern_return_t
mach_port_get_attributes(ipc_space_read_t task, mach_port_name_t name,
		mach_port_flavor_t flavor, mach_port_info_t port_info_out,
		mach_msg_type_number_t *port_info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_get_attributes(%p, %p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)flavor,
			(void *)port_info_out, (void *)port_info_outCnt);
#endif
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
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_set_attributes(%p, %p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)flavor,
			(void *)port_info, (void *)port_infoCnt);
#endif
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
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_allocate_qos(%p, %p, %p, %p)\n",
			(void *)task, (void *)right, (void *)qos, (void *)name);
#endif
	unimplemented();
}

kern_return_t
mach_port_allocate_full(ipc_space_t task, mach_port_right_t right,
		mach_port_t proto, mach_port_qos_t *qos, mach_port_name_t *name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_allocate_full(%p, %p, %p, %p, %p)\n",
			(void *)task, (void *)right, (void *)proto, (void *)qos,
			(void *)name);
#endif
	unimplemented();
}

kern_return_t
task_set_port_space(ipc_space_t task, int table_entries)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_set_port_space(%p, %p)\n", (void *)task,
			(void *)table_entries);
#endif
	unimplemented();
}

kern_return_t
mach_port_get_srights(ipc_space_t task, mach_port_name_t name,
		mach_port_rights_t *srights)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_get_srights(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)srights);
#endif
	unimplemented();
}

kern_return_t
mach_port_space_info(ipc_space_read_t space, ipc_info_space_t *space_info,
		ipc_info_name_array_t *table_info,
		mach_msg_type_number_t *table_infoCnt,
		ipc_info_tree_name_array_t *tree_info,
		mach_msg_type_number_t *tree_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_space_info(%p, %p, %p, %p, %p, %p)\n",
			(void *)space, (void *)space_info, (void *)table_info,
			(void *)table_infoCnt, (void *)tree_info,
			(void *)tree_infoCnt);
#endif
	unimplemented();
}

kern_return_t
mach_port_dnrequest_info(ipc_space_t task, mach_port_name_t name,
		unsigned *dnr_total, unsigned *dnr_used)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_dnrequest_info(%p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)dnr_total,
			(void *)dnr_used);
#endif
	unimplemented();
}

kern_return_t
mach_port_kernel_object(ipc_space_read_t task, mach_port_name_t name,
		unsigned *object_type, unsigned *object_addr)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_kernel_object(%p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)object_type,
			(void *)object_addr);
#endif
	unimplemented();
}

kern_return_t
mach_port_insert_member(
		ipc_space_t task, mach_port_name_t name, mach_port_name_t pset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_insert_member(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)pset);
#endif
	return ipc_port_insert_member(name, pset);
}

kern_return_t
mach_port_extract_member(
		ipc_space_t task, mach_port_name_t name, mach_port_name_t pset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_extract_member(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)pset);
#endif
	return ipc_port_extract_member(name, pset);
}

kern_return_t
mach_port_get_context(ipc_space_read_t task, mach_port_name_t name,
		mach_vm_address_t *context)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_get_context(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)context);
#endif
	return ipc_port_get_context(name, context);
}

kern_return_t
mach_port_set_context(ipc_space_t task, mach_port_name_t name,
		mach_vm_address_t context)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_set_context(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)context);
#endif
	return ipc_port_set_context(name, context);
}

kern_return_t
mach_port_kobject(ipc_space_read_t task, mach_port_name_t name,
		ipc_info_object_type_t *object_type,
		mach_vm_address_t *object_addr)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_kobject(%p, %p, %p, %p)\n", (void *)task,
			(void *)name, (void *)object_type, (void *)object_addr);
#endif
	unimplemented();
}

kern_return_t
mach_port_construct(ipc_space_t task, mach_port_options_ptr_t options,
		uint64_t context, mach_port_name_t *name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_construct(%p, %p, %p, %p)\n", (void *)task,
			(void *)options, (void *)context, (void *)name);
#endif
	return ipc_port_construct(options, context, name);
}

kern_return_t
mach_port_destruct(ipc_space_t task, mach_port_name_t name,
		mach_port_delta_t srdelta, uint64_t guard)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_destruct(%p, %p, %p, %p)\n", (void *)task,
			(void *)name, (void *)srdelta, (void *)guard);
#endif
	return ipc_port_destruct(name, srdelta, guard);
}

kern_return_t
mach_port_guard(ipc_space_t task, mach_port_name_t name, uint64_t guard,
		boolean_t strict)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_guard(%p, %p, %p, %p)\n", (void *)task,
			(void *)name, (void *)guard, (void *)strict);
#endif
	return ipc_port_set_context(name, guard);
}

kern_return_t
mach_port_unguard(ipc_space_t task, mach_port_name_t name, uint64_t guard)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_unguard(%p, %p, %p)\n", (void *)task,
			(void *)name, (void *)guard);
#endif
	return ipc_port_set_context(name, 0);
}

kern_return_t
mach_port_space_basic_info(
		ipc_space_inspect_t task, ipc_info_space_basic_t *basic_info)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_space_basic_info(%p, %p)\n", (void *)task,
			(void *)basic_info);
#endif
	unimplemented();
}

kern_return_t
mach_port_special_reply_port_reset_link(ipc_space_t task, mach_port_name_t name,
		boolean_t *srp_lost_link)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_special_reply_port_reset_link(%p, %p, %p)\n",
			(void *)task, (void *)name, (void *)srp_lost_link);
#endif
	unimplemented();
}

kern_return_t
mach_port_guard_with_flags(ipc_space_t task, mach_port_name_t name,
		uint64_t guard, uint64_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_guard_with_flags(%p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)guard,
			(void *)flags);
#endif
	return ipc_port_set_context(name, guard);
}

kern_return_t
mach_port_swap_guard(ipc_space_t task, mach_port_name_t name,
		uint64_t old_guard, uint64_t new_guard)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_swap_guard(%p, %p, %p, %p)\n", (void *)task,
			(void *)name, (void *)old_guard, (void *)new_guard);
#endif
	return ipc_port_set_context(name, new_guard);
}

kern_return_t
mach_port_kobject_description(ipc_space_read_t task, mach_port_name_t name,
		ipc_info_object_type_t *object_type,
		mach_vm_address_t *object_addr,
		kobject_description_t description)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_kobject_description(%p, %p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)object_type,
			(void *)object_addr, (void *)description);
#endif
	unimplemented();
}

kern_return_t
mach_port_is_connection_for_service(ipc_space_t task,
		mach_port_name_t connection_port, mach_port_name_t service_port,
		uint64_t *filter_policy_id)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_is_connection_for_service(%p, %p, %p, %p)\n",
			(void *)task, (void *)connection_port,
			(void *)service_port, (void *)filter_policy_id);
#endif
	*filter_policy_id = 0;
	return KERN_SUCCESS;
}

kern_return_t
mach_port_get_service_port_info(ipc_space_read_t task, mach_port_name_t name,
		mach_service_port_info_data_t *sp_info_out)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_get_service_port_info(%p, %p, %p)\n",
			(void *)task, (void *)name, (void *)sp_info_out);
#endif
	unimplemented();
}

kern_return_t
mach_port_assert_attributes(ipc_space_t task, mach_port_name_t name,
		mach_port_flavor_t flavor, mach_port_info_t info,
		mach_msg_type_number_t infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_port_assert_attributes(%p, %p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)flavor,
			(void *)info, (void *)infoCnt);
#endif
	unimplemented();
}
