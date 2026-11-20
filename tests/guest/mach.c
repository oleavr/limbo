/*
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

#include <bank/bank_types.h>
#include <bsm/audit.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher.h>
#include <mach/memory_entry.h>
#include <mach_debug/ipc_info.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "check.h"

mach_port_name_t mk_timer_create(void);
kern_return_t mk_timer_arm(mach_port_name_t name, uint64_t expire_time);
kern_return_t mk_timer_destroy(mach_port_name_t name);
kern_return_t _kernelrpc_mach_task_is_self(
		task_name_t task, boolean_t *is_self);

typedef struct {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t port;
	mach_msg_ool_descriptor_t data;
} request_t;

typedef struct {
	request_t request;
	mach_msg_trailer_t trailer;
} received_t;

typedef struct {
	mach_msg_type_number_t count;
	exception_mask_t masks[EXC_TYPES_COUNT];
	mach_port_t ports[EXC_TYPES_COUNT];
	exception_behavior_t behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t flavors[EXC_TYPES_COUNT];
} handlers_t;

static semaphore_t semaphore;

static void check_space_info(void);
static void check_messages(void);
static void check_port_sets(void);
static void check_make_send_count(void);
static mach_port_mscount_t make_send_count(mach_port_t port);
static void check_semaphores(void);
static void *signal_semaphore(void *arg);
static void check_time(void);
static void check_timers(void);
static void check_memory_entries(void);
static void check_remaps(void);
static void check_mincore(void);
static void check_madvise_zero(void);
static void check_regions(void);
static void check_region_recurse(void);
static mach_msg_type_number_t submap_info_count(
		mach_vm_address_t address, mach_msg_type_number_t room);
static unsigned char share_mode(mach_vm_address_t address);
static void check_shared_range_entries(void);
static void check_shared_range_kept(void);
static mach_port_t range_entry(mach_vm_address_t range);
static void check_shared_anonymous_entry(void);
static void check_exception_ports(void);
static void check_vouchers(void);
static void check_destroy(void);
static void check_tasks(void);
static void check_thread_exception_ports(void);
static handlers_t thread_handlers(mach_port_t thread, exception_mask_t mask);
static mach_port_urefs_t send_refs(mach_port_t port);
static void *handle_own_exceptions(void *arg);
static mach_port_t allocate_port(void);

int
main(void)
{
	check_space_info();
	check_messages();
	check_port_sets();
	check_make_send_count();
	check_semaphores();
	check_time();
	check_timers();
	check_memory_entries();
	check_remaps();
	check_mincore();
	check_madvise_zero();
	check_regions();
	check_region_recurse();
	check_exception_ports();
	check_vouchers();
	check_destroy();
	check_tasks();
	check_thread_exception_ports();
	return 0;
}

static void
check_space_info(void)
{
	ipc_info_space_basic_t before, after;
	CHECK(mach_port_space_basic_info(mach_task_self(), &before)
			== KERN_SUCCESS);
	CHECK(before.iisb_genno_mask
			== MACH_PORT_MAKE(0, MACH_PORT_GEN(MACH_PORT_DEAD)));
	CHECK(before.iisb_table_inuse > 0);
	CHECK(before.iisb_table_size > before.iisb_table_inuse);

	mach_port_t port = allocate_port();
	CHECK(mach_port_space_basic_info(mach_task_self(), &after)
			== KERN_SUCCESS);
	CHECK(after.iisb_table_inuse == before.iisb_table_inuse + 1);
	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_space_basic_info(mach_task_self(), &after)
			== KERN_SUCCESS);
	CHECK(after.iisb_table_inuse == before.iisb_table_inuse);
}

static void
check_destroy(void)
{
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(mach_task_self(), port, port,
			      MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, 2)
			== KERN_SUCCESS);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	CHECK(mach_port_destroy(mach_task_self(), port) == KERN_SUCCESS);
#pragma clang diagnostic pop
	mach_port_type_t type;
	CHECK(mach_port_type(mach_task_self(), port, &type)
			== KERN_INVALID_NAME);
}

static void
check_mincore(void)
{
#ifdef __x86_64__
	const vm_size_t page = 4096;
#else
	const vm_size_t page = 16384;
#endif
	mach_vm_address_t address = 0;
	CHECK(mach_vm_allocate(mach_task_self(), &address, 4 * page,
			      VM_FLAGS_ANYWHERE)
			== KERN_SUCCESS);
	((volatile char *)address)[0] = 1;
	((volatile char *)address)[2 * page + 100] = 1;
	char vec[5] = {0, 0, 0, 0, 0x5a};
	CHECK(mincore((void *)address, 4 * page, vec) == 0);
	CHECK(vec[0] & MINCORE_INCORE);
	CHECK(!(vec[1] & MINCORE_INCORE));
	CHECK(vec[2] & MINCORE_INCORE);
	CHECK(!(vec[3] & MINCORE_INCORE));
	CHECK(vec[4] == 0x5a);
	CHECK(mach_vm_deallocate(mach_task_self(), address, 4 * page)
			== KERN_SUCCESS);
}

static void
check_madvise_zero(void)
{
	size_t page = vm_page_size;
	char *data = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	CHECK(data != MAP_FAILED);
	memset(data, 0x5a, 2 * page);
	CHECK(madvise(data, page, MADV_ZERO) == 0);
	CHECK(data[0] == 0 && data[page - 1] == 0 && data[page] == 0x5a);

	char *none = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	CHECK(none != MAP_FAILED);
	CHECK(madvise(none, page, MADV_ZERO) == -1 && errno == EPERM);
	CHECK(mprotect(data + page, page, PROT_READ) == 0);
	CHECK(madvise(data, 2 * page, MADV_ZERO) == -1 && errno == EPERM);
	CHECK(data[page] == 0x5a);
	CHECK(munmap(none, page) == 0);
	CHECK(madvise(none, page, MADV_ZERO) == -1 && errno == EINVAL);
	CHECK(munmap(data, 2 * page) == 0);
}

static void
check_regions(void)
{
	mach_vm_address_t address = 0;
	int own_tag = VM_MAKE_TAG(VM_MEMORY_APPLICATION_SPECIFIC_1);
	CHECK(mach_vm_allocate(mach_task_self(), &address, 4096,
			      VM_FLAGS_ANYWHERE | own_tag)
			== KERN_SUCCESS);
	CHECK(mach_vm_protect(mach_task_self(), address, 4096, FALSE,
			      VM_PROT_READ)
			== KERN_SUCCESS);

	mach_vm_address_t found = address;
	mach_vm_size_t size = 0;
	vm_region_basic_info_data_64_t basic;
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
	mach_port_t object;
	CHECK(mach_vm_region(mach_task_self(), &found, &size,
			      VM_REGION_BASIC_INFO, (vm_region_info_t)&basic,
			      &count, &object)
			== KERN_INVALID_ARGUMENT);
	count = VM_REGION_BASIC_INFO_COUNT_64;
	CHECK(mach_vm_region(mach_task_self(), &found, &size,
			      VM_REGION_BASIC_INFO, (vm_region_info_t)&basic,
			      &count, &object)
			== KERN_SUCCESS);
	CHECK(found == address && size >= 4096);
	CHECK(basic.protection == VM_PROT_READ);
	CHECK(count == VM_REGION_BASIC_INFO_COUNT_64);

	found = address;
	vm_region_top_info_data_t top;
	count = VM_REGION_TOP_INFO_COUNT;
	CHECK(mach_vm_region(mach_task_self(), &found, &size,
			      VM_REGION_TOP_INFO, (vm_region_info_t)&top,
			      &count, &object)
			== KERN_SUCCESS);
	CHECK(count == VM_REGION_TOP_INFO_COUNT);
	CHECK(top.share_mode == SM_EMPTY || top.share_mode == SM_PRIVATE);
	CHECK(mach_vm_deallocate(mach_task_self(), address, 4096)
			== KERN_SUCCESS);

#ifdef __arm64__
	found = 1ULL << 45;
	vm_region_basic_info_data_64_t basic_64;
	count = VM_REGION_BASIC_INFO_COUNT_64;
	CHECK(mach_vm_region(mach_task_self(), &found, &size,
			      VM_REGION_BASIC_INFO_64,
			      (vm_region_info_t)&basic_64, &count, &object)
			== KERN_INVALID_ADDRESS);
#endif
}

static void
check_region_recurse(void)
{
	mach_vm_address_t image = (mach_vm_address_t)(uintptr_t)&main;
	mach_vm_address_t address = image;
	mach_vm_size_t size = 0;
	natural_t depth = 0;
	vm_region_submap_short_info_data_64_t info;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	CHECK(mach_vm_region_recurse(mach_task_self(), &address, &size, &depth,
			      (vm_region_recurse_info_t)&info, &count)
			== KERN_SUCCESS);
	CHECK(count == VM_REGION_SUBMAP_SHORT_INFO_COUNT_64);
	CHECK(address <= image && image < address + size);
	CHECK((info.protection & VM_PROT_EXECUTE) != 0);

	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 - 1;
	CHECK(mach_vm_region_recurse(mach_task_self(), &address, &size, &depth,
			      (vm_region_recurse_info_t)&info, &count)
			== KERN_INVALID_ARGUMENT);

	CHECK(submap_info_count(image, VM_REGION_SUBMAP_INFO_V0_COUNT_64 - 1)
			== VM_REGION_SUBMAP_SHORT_INFO_COUNT_64);
	CHECK(submap_info_count(image, VM_REGION_SUBMAP_INFO_V0_COUNT_64)
			== VM_REGION_SUBMAP_INFO_V0_COUNT_64);
	CHECK(submap_info_count(image, VM_REGION_SUBMAP_INFO_V1_COUNT_64)
			== VM_REGION_SUBMAP_INFO_V1_COUNT_64);
	CHECK(submap_info_count(image, VM_REGION_SUBMAP_INFO_V2_COUNT_64 - 1)
			== VM_REGION_SUBMAP_INFO_V1_COUNT_64);
	CHECK(submap_info_count(image, VM_REGION_SUBMAP_INFO_V2_COUNT_64)
			== VM_REGION_SUBMAP_INFO_V2_COUNT_64);

	mach_vm_address_t fresh = 0;
	int own_tag = VM_MAKE_TAG(VM_MEMORY_APPLICATION_SPECIFIC_1);
	CHECK(mach_vm_allocate(mach_task_self(), &fresh, vm_page_size,
			      VM_FLAGS_ANYWHERE | own_tag)
			== KERN_SUCCESS);
	CHECK(share_mode(fresh) == SM_EMPTY);
	*(volatile char *)fresh = 1;
	CHECK(share_mode(fresh) == SM_PRIVATE);
	CHECK(mach_vm_deallocate(mach_task_self(), fresh, vm_page_size)
			== KERN_SUCCESS);
}

static mach_msg_type_number_t
submap_info_count(mach_vm_address_t address, mach_msg_type_number_t room)
{
	mach_vm_size_t size = 0;
	natural_t depth = 0;
	vm_region_submap_info_data_64_t info;
	CHECK(mach_vm_region_recurse(mach_task_self(), &address, &size, &depth,
			      (vm_region_recurse_info_t)&info, &room)
			== KERN_SUCCESS);
	CHECK((info.protection & VM_PROT_EXECUTE) != 0);
	return room;
}

static unsigned char
share_mode(mach_vm_address_t address)
{
	mach_vm_size_t size = 0;
	natural_t depth = 0;
	vm_region_submap_short_info_data_64_t info;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	CHECK(mach_vm_region_recurse(mach_task_self(), &address, &size, &depth,
			      (vm_region_recurse_info_t)&info, &count)
			== KERN_SUCCESS);
	return info.share_mode;
}

static void
check_exception_ports(void)
{
	exception_mask_t masks[EXC_TYPES_COUNT];
	mach_msg_type_number_t count = EXC_TYPES_COUNT;
	mach_port_t handlers[EXC_TYPES_COUNT];
	exception_behavior_t behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t flavors[EXC_TYPES_COUNT];
	CHECK(task_get_exception_ports(mach_task_self(), EXC_MASK_CRASH, masks,
			      &count, handlers, behaviors, flavors)
			== KERN_SUCCESS);

	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(mach_task_self(), port, port,
			      MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(task_set_exception_ports(mach_task_self(), EXC_MASK_CRASH, port,
			      EXCEPTION_DEFAULT, THREAD_STATE_NONE)
			== KERN_SUCCESS);
}

static void
check_messages(void)
{
	mach_port_t port = allocate_port();
	mach_port_t attached = allocate_port();
	const char payload[] = "out-of-line payload";

	request_t request = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_MAKE_SEND,
							0, 0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(request),
					.msgh_remote_port = port,
					.msgh_id = 1234,
			},
			.body = {.msgh_descriptor_count = 2},
			.port = {
					.name = attached,
					.disposition = MACH_MSG_TYPE_MAKE_SEND,
					.type = MACH_MSG_PORT_DESCRIPTOR,
			},
			.data = {
					.address = (void *)payload,
					.size = sizeof(payload),
					.copy = MACH_MSG_VIRTUAL_COPY,
					.type = MACH_MSG_OOL_DESCRIPTOR,
			},
	};
	CHECK(mach_msg(&request.header, MACH_SEND_MSG, sizeof(request), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);

	mach_port_status_t status;
	mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
	CHECK(mach_port_get_attributes(mach_task_self(), port,
			      MACH_PORT_RECEIVE_STATUS,
			      (mach_port_info_t)&status, &count)
			== KERN_SUCCESS);
	CHECK(status.mps_msgcount == 1);

	received_t received;
	CHECK(mach_msg(&received.request.header, MACH_RCV_MSG, 0,
			      sizeof(received), port, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(received.request.header.msgh_id == 1234);
	CHECK(received.request.port.name == attached);
	CHECK(received.request.data.size == sizeof(payload));
	CHECK(memcmp(received.request.data.address, payload, sizeof(payload))
			== 0);

	mach_port_type_t type;
	CHECK(mach_port_type(mach_task_self(), attached, &type)
			== KERN_SUCCESS);
	CHECK(type & MACH_PORT_TYPE_SEND);

	CHECK(mach_msg(&received.request.header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(received), port, 10, MACH_PORT_NULL)
			== MACH_RCV_TIMED_OUT);
}

static void
check_port_sets(void)
{
	mach_port_t set;
	CHECK(mach_port_allocate(
			      mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &set)
			== KERN_SUCCESS);
	mach_port_t member = allocate_port();
	CHECK(mach_port_move_member(mach_task_self(), member, set)
			== KERN_SUCCESS);

	mach_msg_header_t message = {
			.msgh_bits
			= MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, 0),
			.msgh_size = sizeof(message),
			.msgh_remote_port = member,
			.msgh_id = 42,
	};
	CHECK(mach_msg(&message, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);

	struct {
		mach_msg_header_t header;
		mach_msg_trailer_t trailer;
	} received;
	CHECK(mach_msg(&received.header, MACH_RCV_MSG, 0, sizeof(received), set,
			      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(received.header.msgh_id == 42);
	CHECK(received.header.msgh_local_port == member);
}

static void
check_make_send_count(void)
{
	mach_port_t port = allocate_port();
	CHECK(make_send_count(port) == 0);
	CHECK(mach_port_insert_right(mach_task_self(), port, port,
			      MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(make_send_count(port) == 1);
	CHECK(mach_port_insert_right(mach_task_self(), port, port,
			      MACH_MSG_TYPE_COPY_SEND)
			== KERN_SUCCESS);
	CHECK(make_send_count(port) == 1);
	mach_port_t extracted;
	mach_msg_type_name_t extracted_type;
	CHECK(mach_port_extract_right(mach_task_self(), port,
			      MACH_MSG_TYPE_MAKE_SEND, &extracted,
			      &extracted_type)
			== KERN_SUCCESS);
	CHECK(make_send_count(port) == 2);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
	} message = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_MAKE_SEND,
							0, 0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(message),
					.msgh_remote_port = port,
			},
			.body = {.msgh_descriptor_count = 1},
			.port = {
					.name = port,
					.disposition = MACH_MSG_TYPE_MAKE_SEND,
					.type = MACH_MSG_PORT_DESCRIPTOR,
			},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(make_send_count(port) == 4);

	mach_port_mscount_t set_count = 7;
	CHECK(mach_port_set_mscount(mach_task_self(), port, set_count)
			== KERN_SUCCESS);
	CHECK(make_send_count(port) == set_count);
	CHECK(mach_port_set_mscount(
			      mach_task_self(), mach_task_self(), set_count)
			== KERN_INVALID_RIGHT);
	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);

	mach_port_options_t options = {.flags = MPO_INSERT_SEND_RIGHT};
	CHECK(mach_port_construct(mach_task_self(), &options, 0, &port)
			== KERN_SUCCESS);
	CHECK(make_send_count(port) == 1);
}

static mach_port_mscount_t
make_send_count(mach_port_t port)
{
	mach_port_status_t status;
	mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
	CHECK(mach_port_get_attributes(mach_task_self(), port,
			      MACH_PORT_RECEIVE_STATUS,
			      (mach_port_info_t)&status, &count)
			== KERN_SUCCESS);
	return status.mps_mscount;
}

static void
check_semaphores(void)
{
	CHECK(semaphore_create(
			      mach_task_self(), &semaphore, SYNC_POLICY_FIFO, 0)
			== KERN_SUCCESS);
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, signal_semaphore, NULL) == 0);
	CHECK(semaphore_wait(semaphore) == KERN_SUCCESS);
	CHECK(pthread_join(thread, NULL) == 0);
	mach_timespec_t timeout = {0, 10000000};
	CHECK(semaphore_timedwait(semaphore, timeout)
			== KERN_OPERATION_TIMED_OUT);
	CHECK(semaphore_destroy(mach_task_self(), semaphore) == KERN_SUCCESS);
}

static void *
signal_semaphore(void *arg)
{
	usleep(10000);
	CHECK(semaphore_signal(semaphore) == KERN_SUCCESS);
	return NULL;
}

static void
check_time(void)
{
	mach_timebase_info_data_t timebase;
	CHECK(mach_timebase_info(&timebase) == KERN_SUCCESS);
	CHECK(timebase.numer != 0 && timebase.denom != 0);

	uint64_t start = mach_absolute_time();
	usleep(50000);
	uint64_t elapsed = (mach_absolute_time() - start) * timebase.numer
			/ timebase.denom;
	CHECK(elapsed >= 45000000 && elapsed < 1000000000);

	uint64_t deadline = mach_absolute_time()
			+ 20000000ULL * timebase.denom / timebase.numer;
	CHECK(mach_wait_until(deadline) == KERN_SUCCESS);
	CHECK(mach_absolute_time() >= deadline);
}

static void
check_timers(void)
{
	mach_port_name_t timer = mk_timer_create();
	CHECK(MACH_PORT_VALID(timer));
	for (int round = 0; round < 20000; round++) {
		CHECK(mk_timer_arm(timer, mach_absolute_time() + round % 240)
				== KERN_SUCCESS);
		struct {
			mach_msg_header_t header;
			uint64_t unused[3];
			mach_msg_trailer_t trailer;
		} expiry;
		CHECK(mach_msg(&expiry.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
				      0, sizeof(expiry), timer, 1000,
				      MACH_PORT_NULL)
				== KERN_SUCCESS);
	}
	CHECK(mk_timer_destroy(timer) == KERN_SUCCESS);
}

static void
check_vouchers(void)
{
	mach_voucher_attr_recipe_data_t recipe = {
			.key = MACH_VOUCHER_ATTR_KEY_BANK,
			.command = MACH_VOUCHER_ATTR_BANK_CREATE,
	};
	mach_voucher_t voucher = MACH_PORT_NULL, again = MACH_PORT_NULL;
	CHECK(host_create_mach_voucher(mach_host_self(),
			      (mach_voucher_attr_raw_recipe_array_t)&recipe,
			      sizeof(recipe), &voucher)
			== KERN_SUCCESS);
	CHECK(host_create_mach_voucher(mach_host_self(),
			      (mach_voucher_attr_raw_recipe_array_t)&recipe,
			      sizeof(recipe), &again)
			== KERN_SUCCESS);
	CHECK(MACH_PORT_VALID(voucher) && again == voucher);

	uint32_t pid = 0;
	mach_msg_type_number_t size = sizeof(pid);
	CHECK(mach_voucher_attr_command(voucher, MACH_VOUCHER_ATTR_KEY_BANK,
			      BANK_ORIGINATOR_PID, NULL, 0,
			      (mach_voucher_attr_content_t)&pid, &size)
			== KERN_SUCCESS);
	CHECK(size == sizeof(pid) && pid == (uint32_t)getpid());

	boolean_t adopt_any = TRUE;
	size = sizeof(adopt_any);
	CHECK(mach_voucher_attr_command(voucher, MACH_VOUCHER_ATTR_KEY_BANK,
			      BANK_PERSONA_ADOPT_ANY, NULL, 0,
			      (mach_voucher_attr_content_t)&adopt_any, &size)
			== KERN_SUCCESS);
	CHECK(size == sizeof(adopt_any) && !adopt_any);
	size = 0;
	CHECK(mach_voucher_attr_command(voucher, MACH_VOUCHER_ATTR_KEY_BANK,
			      BANK_PERSONA_ADOPT_ANY, NULL, 0,
			      (mach_voucher_attr_content_t)&adopt_any, &size)
			== KERN_NO_SPACE);

	CHECK(mach_port_deallocate(mach_task_self(), voucher) == KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), again) == KERN_SUCCESS);
}

/*
 * A named memory entry, as Games makes a purgeable one: new memory, zeroed,
 * of whole pages, which every map of it shares
 */
static void
check_memory_entries(void)
{
	memory_object_size_t size = 3 * vm_page_size - 100;
	mach_port_t entry = MACH_PORT_NULL;
	CHECK(mach_make_memory_entry_64(mach_task_self(), &size, 0,
			      MAP_MEM_NAMED_CREATE | MAP_MEM_PURGABLE
					      | VM_PROT_READ | VM_PROT_WRITE,
			      &entry, MACH_PORT_NULL)
			== KERN_SUCCESS);
	CHECK(size == 3 * vm_page_size && MACH_PORT_VALID(entry));

	mach_vm_address_t first = 0, second = 0;
	vm_prot_t rw = VM_PROT_READ | VM_PROT_WRITE;
	CHECK(mach_vm_map(mach_task_self(), &first, size, 0, VM_FLAGS_ANYWHERE,
			      entry, 0, false, rw, rw, VM_INHERIT_NONE)
			== KERN_SUCCESS);
	CHECK(mach_vm_map(mach_task_self(), &second, size, 0,
			      VM_FLAGS_ANYWHERE, entry, 0, false, rw, rw,
			      VM_INHERIT_NONE)
			== KERN_SUCCESS);
	CHECK(first != second && ((volatile char *)first)[size - 1] == 0);
	((volatile char *)first)[vm_page_size + 5] = 42;
	CHECK(((volatile char *)second)[vm_page_size + 5] == 42);

	CHECK(mach_memory_entry_ownership(entry, mach_task_self(),
			      VM_LEDGER_TAG_GRAPHICS, 0)
			== KERN_SUCCESS);
	CHECK(mach_memory_entry_ownership(
			      entry, TASK_NULL, VM_LEDGER_TAG_DEFAULT, 0)
			== KERN_SUCCESS);
	CHECK(mach_memory_entry_ownership(entry, mach_task_self(),
			      VM_LEDGER_TAG_MEDIA, VM_LEDGER_FLAG_NO_FOOTPRINT)
			== KERN_NO_ACCESS);
	CHECK(mach_memory_entry_ownership(
			      entry, mach_task_self(), VM_LEDGER_TAG_MAX + 1, 0)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_memory_entry_ownership(mach_task_self(), mach_task_self(),
			      VM_LEDGER_TAG_DEFAULT, 0)
			== KERN_INVALID_ARGUMENT);
	int state = 0;
	CHECK(mach_memory_entry_purgable_control(
			      entry, VM_PURGABLE_GET_STATE, &state)
			== KERN_SUCCESS);
	CHECK(state == VM_PURGABLE_NONVOLATILE);

	CHECK(mach_vm_deallocate(mach_task_self(), first, size) == KERN_SUCCESS);
	CHECK(mach_vm_deallocate(mach_task_self(), second, size)
			== KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), entry) == KERN_SUCCESS);

	check_shared_range_entries();
	check_shared_range_kept();
	check_shared_anonymous_entry();
}

/*
 * Entries of a range of the task, without VM_SHARE or VM_COPY, name its
 * memory, the second as the first, as coreservicesd makes one of a segment
 * for each client and writes to it after: every map sees the writes
 */
static void
check_shared_range_entries(void)
{
	mach_vm_address_t range = 0;
	mach_vm_size_t size = 2 * vm_page_size;
	vm_prot_t rw = VM_PROT_READ | VM_PROT_WRITE;
	CHECK(mach_vm_allocate(mach_task_self(), &range, size,
			      VM_FLAGS_ANYWHERE)
			== KERN_SUCCESS);
	mach_vm_address_t maps[2] = { 0, 0 };
	mach_port_t entries[2];
	for (int i = 0; i < 2; i++) {
		memory_object_size_t entry_size = size;
		CHECK(mach_make_memory_entry_64(mach_task_self(), &entry_size,
				      range, rw, &entries[i], MACH_PORT_NULL)
				== KERN_SUCCESS);
		CHECK(mach_vm_map(mach_task_self(), &maps[i], size, 0,
				      VM_FLAGS_ANYWHERE, entries[i], 0, false,
				      VM_PROT_READ, VM_PROT_READ,
				      VM_INHERIT_NONE)
				== KERN_SUCCESS);
	}
	((volatile char *)range)[vm_page_size + 7] = 42;
	CHECK(((volatile char *)maps[0])[vm_page_size + 7] == 42);
	CHECK(((volatile char *)maps[1])[vm_page_size + 7] == 42);

	for (int i = 0; i < 2; i++) {
		CHECK(mach_vm_deallocate(mach_task_self(), maps[i], size)
				== KERN_SUCCESS);
		CHECK(mach_port_deallocate(mach_task_self(), entries[i])
				== KERN_SUCCESS);
	}
	CHECK(mach_vm_deallocate(mach_task_self(), range, size)
			== KERN_SUCCESS);
}

#define OTHER_RANGES 200

static void
check_shared_range_kept(void)
{
	mach_vm_address_t kept = 0;
	CHECK(mach_vm_allocate(mach_task_self(), &kept, vm_page_size,
			      VM_FLAGS_ANYWHERE)
			== KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), range_entry(kept))
			== KERN_SUCCESS);

	for (int i = 0; i < OTHER_RANGES; i++) {
		mach_vm_address_t other = 0;
		CHECK(mach_vm_allocate(mach_task_self(), &other, vm_page_size,
				      VM_FLAGS_ANYWHERE)
				== KERN_SUCCESS);
		CHECK(mach_port_deallocate(mach_task_self(), range_entry(other))
				== KERN_SUCCESS);
		CHECK(mach_vm_deallocate(mach_task_self(), other, vm_page_size)
				== KERN_SUCCESS);
	}

	mach_port_t entry = range_entry(kept);
	mach_vm_address_t map = 0;
	CHECK(mach_vm_map(mach_task_self(), &map, vm_page_size, 0,
			      VM_FLAGS_ANYWHERE, entry, 0, false, VM_PROT_READ,
			      VM_PROT_READ, VM_INHERIT_NONE)
			== KERN_SUCCESS);
	*(volatile char *)kept = 42;
	CHECK(*(volatile char *)map == 42);

	CHECK(mach_vm_deallocate(mach_task_self(), map, vm_page_size)
			== KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), entry) == KERN_SUCCESS);
	CHECK(mach_vm_deallocate(mach_task_self(), kept, vm_page_size)
			== KERN_SUCCESS);
}

static mach_port_t
range_entry(mach_vm_address_t range)
{
	memory_object_size_t size = vm_page_size;
	mach_port_t entry;
	CHECK(mach_make_memory_entry_64(mach_task_self(), &size, range,
			      VM_PROT_READ | VM_PROT_WRITE, &entry,
			      MACH_PORT_NULL)
			== KERN_SUCCESS);
	return entry;
}

static void
check_shared_anonymous_entry(void)
{
	size_t size = 2 * vm_page_size;
	volatile char *memory = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_ANON | MAP_SHARED, -1, 0);
	CHECK(memory != MAP_FAILED);
	memory[0] = 1;
	memory_object_size_t entry_size = size;
	mach_port_t entry;
	CHECK(mach_make_memory_entry_64(mach_task_self(), &entry_size,
			      (memory_object_offset_t)(uintptr_t)memory,
			      MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
			      &entry, MACH_PORT_NULL)
			== KERN_SUCCESS);
	mach_vm_address_t map = 0;
	CHECK(mach_vm_map(mach_task_self(), &map, size, 0, VM_FLAGS_ANYWHERE,
			      entry, 0, false, VM_PROT_READ | VM_PROT_WRITE,
			      VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE)
			== KERN_SUCCESS);
	volatile char *other = (volatile char *)map;
	memory[vm_page_size + 3] = 2;
	CHECK(other[0] == 1 && other[vm_page_size + 3] == 2);
	other[5] = 3;
	CHECK(memory[5] == 3);

	CHECK(mach_vm_deallocate(mach_task_self(), map, size) == KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), entry) == KERN_SUCCESS);
	CHECK(munmap((void *)memory, size) == 0);
}

static mach_port_t
allocate_port(void)
{
	mach_port_t port;
	CHECK(mach_port_allocate(
			      mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)
			== KERN_SUCCESS);
	return port;
}

static void
check_remaps(void)
{
	mach_vm_size_t sizes[3] = {
			4 * vm_page_size,
			16 * vm_page_size,
			64 * vm_page_size,
	};
	mach_vm_address_t tables[3];
	for (int i = 0; i < 3; i++) {
		tables[i] = 0;
		CHECK(mach_vm_allocate(mach_task_self(), &tables[i], sizes[i],
				      VM_FLAGS_ANYWHERE)
				== KERN_SUCCESS);
		((volatile char *)tables[i])[sizes[i] - 1] = (char)(i + 1);
		if (i == 0) {
			continue;
		}
		vm_prot_t current, maximum;
		CHECK(mach_vm_remap(mach_task_self(), &tables[i], sizes[i - 1],
				      0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
				      mach_task_self(), tables[i - 1], false,
				      &current, &maximum, VM_INHERIT_NONE)
				== KERN_SUCCESS);
	}
	volatile char *first = (volatile char *)tables[0];
	volatile char *second = (volatile char *)tables[1];
	volatile char *third = (volatile char *)tables[2];
	CHECK(third[sizes[0] - 1] == 1 && third[sizes[1] - 1] == 2);

	third[7] = 42;
	CHECK(first[7] == 42 && second[7] == 42);
	third[sizes[0] + 7] = 43;
	CHECK(second[sizes[0] + 7] == 43);
	second[sizes[0] + 9] = 44;
	CHECK(third[sizes[0] + 9] == 44);
	first[9] = 45;
	CHECK(third[9] == 45);

	for (int i = 0; i < 3; i++) {
		CHECK(mach_vm_deallocate(mach_task_self(), tables[i], sizes[i])
				== KERN_SUCCESS);
	}
}

static void
check_tasks(void)
{
	mach_port_t task = mach_task_self();
	vm_address_t corpse_info;
	uint32_t corpse_size;
	CHECK(task_map_corpse_info(task, task, &corpse_info, &corpse_size)
			== KERN_INVALID_ARGUMENT);
	mach_vm_address_t corpse_info_64;
	mach_vm_size_t corpse_size_64;
	CHECK(task_map_corpse_info_64(
			      task, task, &corpse_info_64, &corpse_size_64)
			== KERN_INVALID_ARGUMENT);

	task_category_policy_data_t category
			= {.role = TASK_FOREGROUND_APPLICATION};
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;
	CHECK(task_policy_get(task, TASK_CATEGORY_POLICY,
			      (task_policy_t)&category, &count, &get_default)
			== KERN_SUCCESS);
	CHECK(category.role == TASK_UNSPECIFIED);
	struct task_qos_policy qos
			= {LATENCY_QOS_TIER_0, THROUGHPUT_QOS_TIER_0};
	count = TASK_QOS_POLICY_COUNT;
	CHECK(task_policy_get(task, TASK_BASE_QOS_POLICY, (task_policy_t)&qos,
			      &count, &get_default)
			== KERN_SUCCESS);
	CHECK(qos.task_latency_qos_tier == LATENCY_QOS_TIER_UNSPECIFIED);
	CHECK(qos.task_throughput_qos_tier == THROUGHPUT_QOS_TIER_UNSPECIFIED);
	count = TASK_QOS_POLICY_COUNT - 1;
	CHECK(task_policy_get(task, TASK_BASE_QOS_POLICY, (task_policy_t)&qos,
			      &count, &get_default)
			== KERN_INVALID_ARGUMENT);
	count = TASK_QOS_POLICY_COUNT;
	CHECK(task_policy_get(task, TASK_BASE_LATENCY_QOS_POLICY,
			      (task_policy_t)&qos, &count, &get_default)
			== KERN_INVALID_ARGUMENT);

	boolean_t is_self = FALSE;
	CHECK(_kernelrpc_mach_task_is_self(task, &is_self) == KERN_SUCCESS);
	CHECK(is_self);
}

static void
check_thread_exception_ports(void)
{
	mach_port_t handler = allocate_port();
	CHECK(mach_port_insert_right(mach_task_self(), handler, handler,
			      MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	mach_port_t self = pthread_mach_thread_np(pthread_self());
	exception_mask_t both = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION;
	exception_behavior_t behavior = EXCEPTION_STATE | MACH_EXCEPTION_CODES;
	CHECK(thread_handlers(self, both).count == 0);

	CHECK(thread_set_exception_ports(
			      self, 0, handler, behavior, MACHINE_THREAD_STATE)
			== KERN_SUCCESS);
	CHECK(send_refs(handler) == 1);

	CHECK(thread_set_exception_ports(self, both, handler, behavior,
			      MACHINE_THREAD_STATE)
			== KERN_SUCCESS);
	mach_port_urefs_t refs = send_refs(handler);
	handlers_t set = thread_handlers(self, both);
	CHECK(set.count == 1);
	CHECK(set.masks[0] == both);
	CHECK(set.ports[0] == handler);
	CHECK(set.behaviors[0] == behavior);
	CHECK(set.flavors[0] == MACHINE_THREAD_STATE);
	CHECK(send_refs(handler) == refs + 1);
	CHECK(mach_port_deallocate(mach_task_self(), handler) == KERN_SUCCESS);

	handlers_t old = {.count = EXC_TYPES_COUNT};
	CHECK(thread_swap_exception_ports(self, EXC_MASK_BAD_ACCESS,
			      MACH_PORT_NULL, EXCEPTION_DEFAULT,
			      THREAD_STATE_NONE, old.masks, &old.count,
			      old.ports, old.behaviors, old.flavors)
			== KERN_SUCCESS);
	CHECK(old.count == 1);
	CHECK(old.masks[0] == EXC_MASK_BAD_ACCESS);
	CHECK(old.ports[0] == handler);
	CHECK(mach_port_deallocate(mach_task_self(), handler) == KERN_SUCCESS);

	handlers_t swapped = thread_handlers(self, both);
	CHECK(swapped.count == 2);
	CHECK(swapped.masks[0] == EXC_MASK_BAD_ACCESS);
	CHECK(swapped.ports[0] == MACH_PORT_NULL);
	CHECK(swapped.behaviors[0] == EXCEPTION_DEFAULT);
	CHECK(swapped.flavors[0] == THREAD_STATE_NONE);
	CHECK(swapped.masks[1] == EXC_MASK_BAD_INSTRUCTION);
	CHECK(swapped.ports[1] == handler);
	CHECK(mach_port_deallocate(mach_task_self(), handler) == KERN_SUCCESS);

	CHECK(thread_set_exception_ports(self, both, MACH_PORT_NULL,
			      EXCEPTION_DEFAULT, THREAD_STATE_NONE)
			== KERN_SUCCESS);
	handlers_t cleared = thread_handlers(self, both);
	CHECK(cleared.count == 1);
	CHECK(cleared.ports[0] == MACH_PORT_NULL);

	refs = send_refs(handler);
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, handle_own_exceptions,
			      (void *)(uintptr_t)handler)
			== 0);
	CHECK(pthread_join(thread, NULL) == 0);
	for (int i = 0; i < 100 && send_refs(handler) != refs; i++) {
		usleep(10000);
	}
	CHECK(send_refs(handler) == refs);
}

static handlers_t
thread_handlers(mach_port_t thread, exception_mask_t mask)
{
	handlers_t handlers = {.count = EXC_TYPES_COUNT};
	CHECK(thread_get_exception_ports(thread, mask, handlers.masks,
			      &handlers.count, handlers.ports,
			      handlers.behaviors, handlers.flavors)
			== KERN_SUCCESS);
	return handlers;
}

static mach_port_urefs_t
send_refs(mach_port_t port)
{
	mach_port_urefs_t refs;
	CHECK(mach_port_get_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND,
			      &refs)
			== KERN_SUCCESS);
	return refs;
}

static void *
handle_own_exceptions(void *arg)
{
	mach_port_t handler = (mach_port_t)(uintptr_t)arg;
	CHECK(thread_set_exception_ports(pthread_mach_thread_np(pthread_self()),
			      EXC_MASK_BAD_ACCESS, handler,
			      EXCEPTION_STATE | MACH_EXCEPTION_CODES,
			      MACHINE_THREAD_STATE)
			== KERN_SUCCESS);
	return NULL;
}
