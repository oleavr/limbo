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
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher.h>
#include <mach/memory_entry.h>
#include <mach_debug/ipc_info.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

mach_port_name_t mk_timer_create(void);
kern_return_t mk_timer_arm(mach_port_name_t name, uint64_t expire_time);
kern_return_t mk_timer_destroy(mach_port_name_t name);
kern_return_t _kernelrpc_mach_task_is_self(
		task_name_t task, boolean_t *is_self);
int fileport_makeport(int fd, mach_port_t *port);
int fileport_makefd(mach_port_t port);

#define LARGEST_MESSAGE (2u << 20)
#define MANY_FILEPORTS  300

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
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool forked;

static void check_space_info(void);
static void check_messages(void);
static void check_out_of_line_copies(void);
static void check_large_messages(void);
static void check_large_message(mach_msg_size_t size);
static void check_fileports(void);
static void check_many_fileports(void);
static void check_port_sets(void);
static void check_receive_on_destroyed(void);
static mach_msg_return_t receive_on_destroyed(mach_port_right_t right);
static void *receive_nothing(void *arg);
static void check_queued_rights_destroyed(void);
static void check_refused_reply(void);
static void check_right_moved_twice(void);
static void check_refused_body(void);
static void check_refused_type(void);
static void check_destroyed_memory(void);
static void check_circular_message(void);
static void check_dead_send_once_rights(void);
static void check_send_once_destroyed(void);
static void expect_send_once_notification(mach_port_t port);
static void check_dead_name(void);
static mach_port_rights_t send_once_rights(mach_port_t port);
static void check_request_rights(void);
static void check_send_possible_on_dead_name(void);
static void check_send_possible(void);
static void check_dead_thread_name(void);
static void *pass_gate(void *arg);
static void check_port_deleted(void);
static void check_no_senders(void);
static void request_no_senders(
		mach_port_t port, mach_port_mscount_t sync, mach_port_t notify);
static bool receive_no_senders(mach_port_t notify, mach_msg_timeout_t timeout,
		mach_port_mscount_t *count);
static void check_port_destroyed(void);
static void check_unknown_request(void);
static void check_make_send_count(void);
static mach_port_mscount_t make_send_count(mach_port_t port);
static void check_reference_deltas(void);
static void check_fork_during_port_calls(void);
static void *allocate_ports(void *arg);
static void check_task_for_pid(void);
static void check_pid_for_task(void);
static void check_task_names(void);
static void check_named_task_memory(void);
static mach_vm_size_t resident_size(mach_port_t task);
static void check_semaphores(void);
static void *signal_semaphore(void *arg);
static void check_time(void);
static void check_timers(void);
static void check_memory_entries(void);
static void check_memory_entries_freed(void);
static void check_memory_entry_sent(void);
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
static void check_host_statistics(void);
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
	check_out_of_line_copies();
	check_large_messages();
	check_fileports();
	check_many_fileports();
	check_port_sets();
	check_receive_on_destroyed();
	check_queued_rights_destroyed();
	check_refused_reply();
	check_right_moved_twice();
	check_refused_body();
	check_refused_type();
	check_destroyed_memory();
	check_circular_message();
	check_dead_send_once_rights();
	check_send_once_destroyed();
	check_dead_name();
	check_request_rights();
	check_send_possible_on_dead_name();
	check_send_possible();
	check_dead_thread_name();
	check_port_deleted();
	check_no_senders();
	check_port_destroyed();
	check_unknown_request();
	check_make_send_count();
	check_reference_deltas();
	check_fork_during_port_calls();
	check_task_for_pid();
	check_pid_for_task();
	check_task_names();
	check_host_statistics();
	check_named_task_memory();
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
check_out_of_line_copies(void)
{
	mach_port_t port = allocate_port();
	const char payload[] = "out-of-line payload";
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_ool_descriptor_t data;
	} sent = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_MAKE_SEND,
							0, 0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(sent),
					.msgh_remote_port = port,
			},
			.body = {.msgh_descriptor_count = 1},
			.data = {
					.address = (void *)payload,
					.size = sizeof(payload),
					.copy = MACH_MSG_VIRTUAL_COPY,
					.type = MACH_MSG_OOL_DESCRIPTOR,
			},
	};
	for (int i = 0; i < 2; i++) {
		CHECK(mach_msg(&sent.header, MACH_SEND_MSG, sizeof(sent), 0,
				      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
				      MACH_PORT_NULL)
				== MACH_MSG_SUCCESS);
	}
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_ool_descriptor_t data;
		mach_msg_trailer_t trailer;
	} received;
	void *copies[2];
	for (int i = 0; i < 2; i++) {
		CHECK(mach_msg(&received.header, MACH_RCV_MSG, 0,
				      sizeof(received), port,
				      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)
				== MACH_MSG_SUCCESS);
		copies[i] = received.data.address;
		CHECK((uintptr_t)copies[i] % vm_page_size == 0);
	}
	CHECK(vm_deallocate(mach_task_self(), (vm_address_t)copies[0],
			      sizeof(payload))
			== KERN_SUCCESS);
	CHECK(memcmp(copies[1], payload, sizeof(payload)) == 0);
	CHECK(vm_deallocate(mach_task_self(), (vm_address_t)copies[1],
			      sizeof(payload))
			== KERN_SUCCESS);
}

static void
check_large_messages(void)
{
	check_large_message(300 * 1024);
	check_large_message(LARGEST_MESSAGE);
}

static void
check_large_message(mach_msg_size_t size)
{
	static union {
		mach_msg_header_t header;
		char bytes[LARGEST_MESSAGE + sizeof(mach_msg_trailer_t)];
	} sent, received;
	mach_port_t port = allocate_port();

	sent.header = (mach_msg_header_t){
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0),
			.msgh_size = size,
			.msgh_remote_port = port,
	};
	for (mach_msg_size_t i = sizeof(sent.header); i < size; i++) {
		sent.bytes[i] = (char)(i * 7 + size);
	}
	CHECK(mach_msg(&sent.header, MACH_SEND_MSG, size, 0, MACH_PORT_NULL,
			      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);

	CHECK(mach_msg(&received.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(received), port, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(received.header.msgh_size == size);
	CHECK(memcmp(received.bytes + sizeof(received.header),
			      sent.bytes + sizeof(sent.header),
			      size - sizeof(sent.header))
			== 0);
	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
check_fileports(void)
{
	char path[] = "/tmp/limbo-fileport-XXXXXX";
	int fd = mkstemp(path);
	CHECK(fd != -1 && unlink(path) == 0);
	mach_port_t fileport;
	CHECK(fileport_makeport(fd, &fileport) == 0);
	mach_port_t port = allocate_port();

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
		mach_msg_trailer_t trailer;
	} message = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_MAKE_SEND,
							0, 0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(message)
							- sizeof(message.trailer),
					.msgh_remote_port = port,
			},
			.body = {.msgh_descriptor_count = 1},
			.port = {
					.name = fileport,
					.disposition = MACH_MSG_TYPE_COPY_SEND,
					.type = MACH_MSG_PORT_DESCRIPTOR,
			},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size,
			      0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(mach_msg(&message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), port, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.port.name == fileport);
	CHECK(send_refs(fileport) == 2);

	int made = fileport_makefd(message.port.name);
	CHECK(made != -1 && made != fd);
	CHECK(fcntl(made, F_GETFD) & FD_CLOEXEC);
	CHECK(lseek(fd, 123, SEEK_SET) == 123);
	CHECK(lseek(made, 0, SEEK_CUR) == 123);

	CHECK(close(made) == 0 && close(fd) == 0);
	CHECK(mach_port_mod_refs(mach_task_self(), fileport,
			      MACH_PORT_RIGHT_SEND, -2)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
check_many_fileports(void)
{
	struct rlimit files;
	CHECK(getrlimit(RLIMIT_NOFILE, &files) == 0);
	struct rlimit more = {.rlim_cur = 1024, .rlim_max = files.rlim_max};
	CHECK(setrlimit(RLIMIT_NOFILE, &more) == 0);

	static struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t ports[MANY_FILEPORTS];
		mach_msg_trailer_t trailer;
	} message;
	mach_port_t port = allocate_port();
	message.header = (mach_msg_header_t){
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND,
					0, 0, MACH_MSGH_BITS_COMPLEX),
			.msgh_size = sizeof(message) - sizeof(message.trailer),
			.msgh_remote_port = port,
	};
	message.body.msgh_descriptor_count = MANY_FILEPORTS;
	char path[] = "/tmp/limbo-fileports-XXXXXX";
	int first = mkstemp(path);
	CHECK(first != -1);
	for (int i = 0; i != MANY_FILEPORTS; i++) {
		int fd = open(path, O_RDONLY);
		CHECK(fd != -1 && lseek(fd, i, SEEK_SET) == i);
		mach_port_t fileport;
		CHECK(fileport_makeport(fd, &fileport) == 0);
		CHECK(close(fd) == 0);
		message.ports[i] = (mach_msg_port_descriptor_t){
				.name = fileport,
				.disposition = MACH_MSG_TYPE_MOVE_SEND,
				.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
	CHECK(unlink(path) == 0 && close(first) == 0);

	CHECK(mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size,
			      0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(mach_msg(&message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), port, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	for (int i = 0; i != MANY_FILEPORTS; i++) {
		int fd = fileport_makefd(message.ports[i].name);
		CHECK(fd != -1 && lseek(fd, 0, SEEK_CUR) == i);
		CHECK(close(fd) == 0);
		CHECK(mach_port_deallocate(
				      mach_task_self(), message.ports[i].name)
				== KERN_SUCCESS);
	}

	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(setrlimit(RLIMIT_NOFILE, &files) == 0);
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
check_receive_on_destroyed(void)
{
	CHECK(receive_on_destroyed(MACH_PORT_RIGHT_RECEIVE)
			== MACH_RCV_PORT_CHANGED);
	CHECK(receive_on_destroyed(MACH_PORT_RIGHT_PORT_SET)
			== MACH_RCV_PORT_CHANGED);
}

static mach_msg_return_t
receive_on_destroyed(mach_port_right_t right)
{
	mach_port_t task = mach_task_self();
	void *result = (void *)(uintptr_t)MACH_RCV_INVALID_NAME;
	while ((uintptr_t)result == MACH_RCV_INVALID_NAME) {
		mach_port_t name;
		CHECK(mach_port_allocate(task, right, &name) == KERN_SUCCESS);
		pthread_t receiver;
		CHECK(pthread_create(&receiver, NULL, receive_nothing,
				      (void *)(uintptr_t)name)
				== 0);
		usleep(100000);
		CHECK(mach_port_mod_refs(task, name, right, -1)
				== KERN_SUCCESS);
		CHECK(pthread_join(receiver, &result) == 0);
	}
	return (mach_msg_return_t)(uintptr_t)result;
}

static void *
receive_nothing(void *arg)
{
	struct {
		mach_msg_header_t header;
		mach_msg_trailer_t trailer;
	} message;
	return (void *)(uintptr_t)mach_msg(&message.header,
			MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(message),
			(mach_port_t)(uintptr_t)arg, 3000, MACH_PORT_NULL);
}

static void
check_queued_rights_destroyed(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t reply = allocate_port();
	mach_port_t moved = allocate_port();
	mach_port_t held = allocate_port();
	CHECK(mach_port_insert_right(
			      task, moved, moved, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_insert_right(task, held, held, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t ports[3];
	} message = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_MAKE_SEND,
							MACH_MSG_TYPE_MAKE_SEND_ONCE,
							0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(message),
					.msgh_remote_port = port,
					.msgh_local_port = reply,
			},
			.body = {.msgh_descriptor_count = 3},
			.ports = {
					{
							.name = moved,
							.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
							.type = MACH_MSG_PORT_DESCRIPTOR,
					},
					{
							.name = moved,
							.disposition = MACH_MSG_TYPE_MOVE_SEND,
							.type = MACH_MSG_PORT_DESCRIPTOR,
					},
					{
							.name = held,
							.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
							.type = MACH_MSG_PORT_DESCRIPTOR,
					},
			},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);

	mach_port_type_t type;
	CHECK(mach_port_type(task, moved, &type) == KERN_INVALID_NAME);
	CHECK(mach_port_type(task, held, &type) == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);
	mach_port_urefs_t reply_refs;
	CHECK(mach_port_get_refs(task, reply, MACH_PORT_RIGHT_SEND_ONCE,
			      &reply_refs)
			== KERN_SUCCESS);
	CHECK(reply_refs == 0);
}

static void
check_refused_reply(void)
{
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(mach_task_self(), port, port,
			      MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);

	mach_msg_header_t message = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND,
					MACH_MSG_TYPE_COPY_SEND),
			.msgh_size = sizeof(message),
			.msgh_remote_port = port,
			.msgh_local_port = allocate_port(),
	};
	CHECK(mach_msg(&message, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_REPLY);
	CHECK(send_refs(port) == 1);
}

static void
check_right_moved_twice(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);

	mach_msg_header_t message = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND,
					MACH_MSG_TYPE_MOVE_SEND),
			.msgh_size = sizeof(message),
			.msgh_remote_port = port,
			.msgh_local_port = port,
	};
	CHECK(mach_msg(&message, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_DEST);
	CHECK(send_refs(port) == 1);

	mach_port_t once;
	mach_msg_type_name_t once_type;
	CHECK(mach_port_extract_right(task, port, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &once, &once_type)
			== KERN_SUCCESS);
	message.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE,
			MACH_MSG_TYPE_MOVE_SEND_ONCE);
	message.msgh_remote_port = once;
	message.msgh_local_port = once;
	CHECK(mach_msg(&message, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_DEST);
	mach_port_urefs_t once_refs;
	CHECK(mach_port_get_refs(
			      task, once, MACH_PORT_RIGHT_SEND_ONCE, &once_refs)
			== KERN_SUCCESS);
	CHECK(once_refs == 1);
}

static void
check_refused_body(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t reply = allocate_port();
	mach_port_t copied = allocate_port();
	mach_port_t moved = allocate_port();
	mach_port_t listed = allocate_port();
	CHECK(mach_port_insert_right(
			      task, copied, copied, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_insert_right(
			      task, moved, moved, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_insert_right(
			      task, listed, listed, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);

	mach_port_t names[] = {listed, port};
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t ports[2];
		mach_msg_ool_ports_descriptor_t list;
	} message = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_MAKE_SEND,
							MACH_MSG_TYPE_MAKE_SEND_ONCE,
							0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(message),
					.msgh_remote_port = port,
					.msgh_local_port = reply,
			},
			.body = {.msgh_descriptor_count = 3},
			.ports = {
					{
							.name = copied,
							.disposition = MACH_MSG_TYPE_COPY_SEND,
							.type = MACH_MSG_PORT_DESCRIPTOR,
					},
					{
							.name = moved,
							.disposition = MACH_MSG_TYPE_MOVE_SEND,
							.type = MACH_MSG_PORT_DESCRIPTOR,
					},
			},
			.list = {
					.address = names,
					.count = 2,
					.disposition = MACH_MSG_TYPE_COPY_SEND,
					.type = MACH_MSG_OOL_PORTS_DESCRIPTOR,
			},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_RIGHT);
	CHECK(send_refs(copied) == 1);
	CHECK(send_refs(moved) == 0);
	CHECK(send_refs(listed) == 1);
	mach_port_urefs_t reply_refs;
	CHECK(mach_port_get_refs(task, reply, MACH_PORT_RIGHT_SEND_ONCE,
			      &reply_refs)
			== KERN_SUCCESS);
	CHECK(reply_refs == 0);
}

static void
check_refused_type(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t reply = allocate_port();
	mach_port_t copied = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_insert_right(
			      task, copied, copied, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t ports[2];
	} message = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_MOVE_SEND,
							MACH_MSG_TYPE_MAKE_SEND_ONCE,
							0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(message),
					.msgh_remote_port = port,
					.msgh_local_port = reply,
			},
			.body = {.msgh_descriptor_count = 2},
			.ports = {
					{
							.name = copied,
							.disposition = MACH_MSG_TYPE_COPY_SEND,
							.type = MACH_MSG_PORT_DESCRIPTOR,
					},
					{
							.type = MACH_MSG_GUARDED_PORT_DESCRIPTOR
									+ 1,
					},
			},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_TYPE);
	CHECK(send_refs(port) == 1);
	CHECK(send_refs(copied) == 1);
	mach_port_urefs_t reply_refs;
	CHECK(mach_port_get_refs(task, reply, MACH_PORT_RIGHT_SEND_ONCE,
			      &reply_refs)
			== KERN_SUCCESS);
	CHECK(reply_refs == 0);
}

static void
check_destroyed_memory(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	vm_address_t given = 0;
	CHECK(vm_allocate(task, &given, vm_page_size, VM_FLAGS_ANYWHERE)
			== KERN_SUCCESS);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_ool_descriptor_t data;
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
			.body = {.msgh_descriptor_count = 2},
			.data = {
					.address = (void *)given,
					.size = vm_page_size,
					.deallocate = TRUE,
					.copy = MACH_MSG_VIRTUAL_COPY,
					.type = MACH_MSG_OOL_DESCRIPTOR,
			},
			.port = {
					.name = port,
					.disposition = MACH_MSG_TYPE_COPY_SEND,
					.type = MACH_MSG_PORT_DESCRIPTOR,
			},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_RIGHT);
	CHECK(vm_allocate(task, &given, vm_page_size, VM_FLAGS_FIXED)
			== KERN_SUCCESS);

	message.port.disposition = MACH_MSG_TYPE_MAKE_SEND;
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(vm_allocate(task, &given, vm_page_size, VM_FLAGS_FIXED)
			== KERN_SUCCESS);
}

static void
check_circular_message(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t reply = allocate_port();
	mach_port_t moved = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_insert_right(
			      task, moved, moved, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t ports[2];
	} message = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_COPY_SEND,
							MACH_MSG_TYPE_MAKE_SEND_ONCE,
							0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(message),
					.msgh_remote_port = port,
					.msgh_local_port = reply,
			},
			.body = {.msgh_descriptor_count = 2},
			.ports = {
					{
							.name = moved,
							.disposition = MACH_MSG_TYPE_MOVE_SEND,
							.type = MACH_MSG_PORT_DESCRIPTOR,
					},
					{
							.name = port,
							.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
							.type = MACH_MSG_PORT_DESCRIPTOR,
					},
			},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);

	mach_port_type_t type;
	CHECK(mach_port_type(task, port, &type) == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);
	CHECK(send_refs(moved) == 0);
	mach_port_urefs_t reply_refs;
	CHECK(mach_port_get_refs(task, reply, MACH_PORT_RIGHT_SEND_ONCE,
			      &reply_refs)
			== KERN_SUCCESS);
	CHECK(reply_refs == 0);
}

static void
check_dead_send_once_rights(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t once;
	mach_msg_type_name_t once_type;
	CHECK(mach_port_extract_right(task, port, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &once, &once_type)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);

	mach_port_type_t type;
	CHECK(mach_port_type(task, once, &type) == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);
	mach_msg_header_t message = {
			.msgh_bits
			= MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0),
			.msgh_size = sizeof(message),
			.msgh_remote_port = once,
	};
	CHECK(mach_msg(&message, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_DEST);
	CHECK(mach_port_deallocate(task, once) == KERN_SUCCESS);
	CHECK(mach_port_type(task, once, &type) == KERN_INVALID_NAME);

	port = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_extract_right(task, port, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &once, &once_type)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);

	mach_port_urefs_t once_refs;
	CHECK(mach_port_get_refs(
			      task, once, MACH_PORT_RIGHT_SEND_ONCE, &once_refs)
			== KERN_SUCCESS);
	CHECK(once_refs == 0);
	CHECK(mach_port_deallocate(task, once) == KERN_SUCCESS);
	CHECK(mach_port_type(task, port, &type) == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);
}

static void
check_send_once_destroyed(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t right;
	mach_msg_type_name_t type;
	CHECK(mach_port_extract_right(task, port, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &right, &type)
			== KERN_SUCCESS);
	CHECK(type == MACH_MSG_TYPE_PORT_SEND_ONCE);
	CHECK(mach_port_deallocate(task, right) == KERN_SUCCESS);
	expect_send_once_notification(port);

	CHECK(mach_port_extract_right(task, port, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &right, &type)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, right, MACH_PORT_RIGHT_SEND_ONCE, -1)
			== KERN_SUCCESS);
	expect_send_once_notification(port);

	mach_port_t server = allocate_port();
	struct {
		mach_msg_header_t header;
		mach_msg_trailer_t trailer;
	} request = {
		.header = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND,
					MACH_MSG_TYPE_MAKE_SEND_ONCE),
			.msgh_size = sizeof(request.header),
			.msgh_remote_port = server,
			.msgh_local_port = port,
		},
	};
	CHECK(mach_msg(&request.header, MACH_SEND_MSG, sizeof(request.header),
			      0, MACH_PORT_NULL, 0, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(mach_msg(&request.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(request), server, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(MACH_MSGH_BITS_REMOTE(request.header.msgh_bits)
			== MACH_MSG_TYPE_PORT_SEND_ONCE);
	mach_msg_destroy(&request.header);
	expect_send_once_notification(port);

	request.header.msgh_bits = MACH_MSGH_BITS(
			MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	request.header.msgh_remote_port = server;
	request.header.msgh_local_port = port;
	CHECK(mach_msg(&request.header, MACH_SEND_MSG, sizeof(request.header),
			      0, MACH_PORT_NULL, 0, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);

	CHECK(mach_port_mod_refs(task, server, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	expect_send_once_notification(port);

	server = allocate_port();
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t right;
	} refused = {
		.header = {
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND,
					MACH_MSG_TYPE_MAKE_SEND_ONCE, 0,
					MACH_MSGH_BITS_COMPLEX),
			.msgh_size = sizeof(refused),
			.msgh_remote_port = server,
			.msgh_local_port = port,
		},
		.body = {.msgh_descriptor_count = 1},
		.right = {
			.name = server,
			.disposition = MACH_MSG_TYPE_MOVE_SEND,
			.type = MACH_MSG_PORT_DESCRIPTOR,
		},
	};
	CHECK(mach_msg(&refused.header, MACH_SEND_MSG, sizeof(refused), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_RIGHT);
	expect_send_once_notification(port);

	CHECK(mach_port_mod_refs(task, server, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
expect_send_once_notification(mach_port_t port)
{
	struct {
		mach_send_once_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), port, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.notification.not_header.msgh_id == MACH_NOTIFY_SEND_ONCE);
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), port, 100, MACH_PORT_NULL)
			== MACH_RCV_TIMED_OUT);
}

static void
check_dead_name(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	mach_port_t notify = allocate_port();
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_SUCCESS);
	CHECK(previous == MACH_PORT_NULL);
	CHECK(send_once_rights(notify) == 1);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	mach_port_type_t type;
	CHECK(mach_port_type(task, port, &type) == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);

	struct {
		mach_dead_name_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.notification.not_header.msgh_id == MACH_NOTIFY_DEAD_NAME);
	CHECK(message.notification.not_port == port);
	mach_port_urefs_t refs;
	CHECK(mach_port_get_refs(task, port, MACH_PORT_RIGHT_DEAD_NAME, &refs)
			== KERN_SUCCESS);
	CHECK(refs == 2);
	CHECK(send_once_rights(notify) == 0);

	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      1, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_INVALID_ARGUMENT);
	expect_send_once_notification(notify);
	mach_port_t set;
	CHECK(mach_port_allocate(task, MACH_PORT_RIGHT_PORT_SET, &set)
			== KERN_SUCCESS);
	CHECK(mach_port_request_notification(task, set, MACH_NOTIFY_DEAD_NAME,
			      0, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_INVALID_RIGHT);
	expect_send_once_notification(notify);
	CHECK(mach_port_mod_refs(task, set, MACH_PORT_RIGHT_PORT_SET, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_DEAD_NAME, -2)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, notify, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static mach_port_rights_t
send_once_rights(mach_port_t port)
{
	mach_port_status_t status;
	mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
	CHECK(mach_port_get_attributes(mach_task_self(), port,
			      MACH_PORT_RECEIVE_STATUS,
			      (mach_port_info_t)&status, &count)
			== KERN_SUCCESS);
	return status.mps_sorights;
}

static void
check_request_rights(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	mach_port_t first = allocate_port();
	mach_port_t second = allocate_port();
	mach_port_t right;
	mach_msg_type_name_t right_type;
	CHECK(mach_port_extract_right(task, first, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &right, &right_type)
			== KERN_SUCCESS);
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, right, MACH_MSG_TYPE_MOVE_SEND_ONCE, &previous)
			== KERN_SUCCESS);
	CHECK(previous == MACH_PORT_NULL);
	CHECK(send_once_rights(first) == 1);

	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, second, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_SUCCESS);
	mach_port_type_t type;
	CHECK(mach_port_type(task, previous, &type) == KERN_SUCCESS);
	CHECK(type & MACH_PORT_TYPE_SEND_ONCE);
	CHECK(send_once_rights(first) == 1);
	CHECK(send_once_rights(second) == 1);
	CHECK(mach_port_deallocate(task, previous) == KERN_SUCCESS);
	expect_send_once_notification(first);

	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, MACH_PORT_NULL, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_SUCCESS);
	CHECK(mach_port_type(task, previous, &type) == KERN_SUCCESS);
	CHECK(type & MACH_PORT_TYPE_SEND_ONCE);
	CHECK(mach_port_deallocate(task, previous) == KERN_SUCCESS);
	expect_send_once_notification(second);
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, MACH_PORT_NULL, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_SUCCESS);
	CHECK(previous == MACH_PORT_NULL);

	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, first, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, first, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, second, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_SUCCESS);
	CHECK(previous == MACH_PORT_DEAD);

	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, task, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_INVALID_RIGHT);
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, port, MACH_MSG_TYPE_MOVE_SEND_ONCE, &previous)
			== KERN_INVALID_RIGHT);
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, MACH_PORT_DEAD, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_INVALID_CAPABILITY);

	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_deallocate(task, port) == KERN_SUCCESS);
	CHECK(mach_port_deallocate(task, port) == KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, second, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
check_send_possible_on_dead_name(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	mach_port_t notify = allocate_port();
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port,
			      MACH_NOTIFY_SEND_POSSIBLE, 0, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);

	struct {
		mach_dead_name_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.notification.not_header.msgh_id == MACH_NOTIFY_DEAD_NAME);
	CHECK(message.notification.not_port == port);
	mach_port_urefs_t refs;
	CHECK(mach_port_get_refs(task, port, MACH_PORT_RIGHT_DEAD_NAME, &refs)
			== KERN_SUCCESS);
	CHECK(refs == 2);

	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_DEAD_NAME, -2)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, notify, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
check_send_possible(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	mach_port_t notify = allocate_port();
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port,
			      MACH_NOTIFY_SEND_POSSIBLE, 0, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);
	struct {
		mach_send_possible_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 100, MACH_PORT_NULL)
			== MACH_RCV_TIMED_OUT);

	CHECK(mach_port_request_notification(task, port,
			      MACH_NOTIFY_SEND_POSSIBLE, 1, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.notification.not_header.msgh_id
			== MACH_NOTIFY_SEND_POSSIBLE);
	CHECK(message.notification.not_port == port);

	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 100, MACH_PORT_NULL)
			== MACH_RCV_TIMED_OUT);
	CHECK(mach_port_deallocate(task, port) == KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, notify, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
check_dead_thread_name(void)
{
	mach_port_t task = mach_task_self();
	CHECK(pthread_mutex_lock(&gate) == 0);
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, pass_gate, NULL) == 0);
	mach_port_t port = pthread_mach_thread_np(thread);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_SEND, 1)
			== KERN_SUCCESS);
	mach_port_t notify = allocate_port();
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_SUCCESS);
	CHECK(pthread_mutex_unlock(&gate) == 0);
	CHECK(pthread_join(thread, NULL) == 0);

	struct {
		mach_dead_name_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.notification.not_header.msgh_id == MACH_NOTIFY_DEAD_NAME);
	CHECK(message.notification.not_port == port);
	mach_port_type_t type;
	CHECK(mach_port_type(task, port, &type) == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);

	CHECK(mach_port_deallocate(task, port) == KERN_SUCCESS);
	CHECK(mach_port_deallocate(task, port) == KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, notify, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void *
pass_gate(void *arg)
{
	CHECK(pthread_mutex_lock(&gate) == 0);
	CHECK(pthread_mutex_unlock(&gate) == 0);
	return NULL;
}

static void
check_port_deleted(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	mach_port_t notify = allocate_port();
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_DEAD_NAME,
			      0, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_SUCCESS);
	CHECK(mach_port_deallocate(task, port) == KERN_SUCCESS);
	struct {
		mach_port_deleted_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 100, MACH_PORT_NULL)
			== MACH_RCV_TIMED_OUT);

	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.notification.not_header.msgh_id
			== MACH_NOTIFY_PORT_DELETED);
	CHECK(message.notification.not_port == port);
	mach_port_type_t type;
	CHECK(mach_port_type(task, port, &type) == KERN_INVALID_NAME);
	CHECK(mach_port_mod_refs(task, notify, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
check_no_senders(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t notify = allocate_port();
	mach_port_mscount_t count = 99;

	request_no_senders(port, 0, notify);
	CHECK(receive_no_senders(notify, 1000, &count));
	CHECK(count == 0);

	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	request_no_senders(port, 0, notify);
	CHECK(!receive_no_senders(notify, 100, &count));
	CHECK(mach_port_deallocate(task, port) == KERN_SUCCESS);
	CHECK(receive_no_senders(notify, 1000, &count));
	CHECK(count == 1);

	request_no_senders(port, count + 1, notify);
	CHECK(!receive_no_senders(notify, 100, &count));
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_SEND, -1)
			== KERN_SUCCESS);
	CHECK(receive_no_senders(notify, 1000, &count));
	CHECK(count == 2);

	request_no_senders(port, 1, notify);
	CHECK(receive_no_senders(notify, 1000, &count));
	CHECK(count == 2);

	mach_port_options_t options = {.flags = MPO_INSERT_SEND_RIGHT};
	mach_port_t constructed;
	CHECK(mach_port_construct(task, &options, 0, &constructed)
			== KERN_SUCCESS);
	request_no_senders(constructed, 1, notify);
	CHECK(!receive_no_senders(notify, 100, &count));
	CHECK(mach_port_deallocate(task, constructed) == KERN_SUCCESS);
	CHECK(receive_no_senders(notify, 1000, &count));
	CHECK(count == 1);

	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	mach_port_t server = allocate_port();
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t right;
	} message = {
		.header = {
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND,
					0, 0, MACH_MSGH_BITS_COMPLEX),
			.msgh_size = sizeof(message),
			.msgh_remote_port = server,
		},
		.body = {.msgh_descriptor_count = 1},
		.right = {
			.name = port,
			.disposition = MACH_MSG_TYPE_MOVE_SEND,
			.type = MACH_MSG_PORT_DESCRIPTOR,
		},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0,
			      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	request_no_senders(port, 0, notify);
	CHECK(!receive_no_senders(notify, 100, &count));
	CHECK(mach_port_mod_refs(task, server, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(receive_no_senders(notify, 1000, &count));
	CHECK(count == 3);

	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	request_no_senders(port, 0, notify);
	mach_port_t other = allocate_port();
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_NO_SENDERS,
			      0, other, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);
	mach_port_type_t type;
	CHECK(mach_port_type(task, previous, &type) == KERN_SUCCESS);
	CHECK(type & MACH_PORT_TYPE_SEND_ONCE);
	CHECK(mach_port_deallocate(task, previous) == KERN_SUCCESS);
	expect_send_once_notification(notify);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	expect_send_once_notification(other);

	CHECK(mach_port_deallocate(task, port) == KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, constructed, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, other, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, notify, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
request_no_senders(
		mach_port_t port, mach_port_mscount_t sync, mach_port_t notify)
{
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(mach_task_self(), port,
			      MACH_NOTIFY_NO_SENDERS, sync, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);
}

static bool
receive_no_senders(mach_port_t notify, mach_msg_timeout_t timeout,
		mach_port_mscount_t *count)
{
	struct {
		mach_no_senders_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	if (mach_msg(&message.notification.not_header,
			    MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(message),
			    notify, timeout, MACH_PORT_NULL)
			!= MACH_MSG_SUCCESS) {
		return false;
	}
	CHECK(message.notification.not_header.msgh_id
			== MACH_NOTIFY_NO_SENDERS);
	*count = message.notification.not_count;
	return true;
}

static void
check_port_destroyed(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t notify = allocate_port();
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port,
			      MACH_NOTIFY_PORT_DESTROYED, 1, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_INVALID_VALUE);
	expect_send_once_notification(notify);
	CHECK(mach_port_request_notification(task, port,
			      MACH_NOTIFY_PORT_DESTROYED, 0, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);
	CHECK(mach_port_request_notification(task, port,
			      MACH_NOTIFY_PORT_DESTROYED, 0, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_FAILURE);
	expect_send_once_notification(notify);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);

	struct {
		mach_port_destroyed_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.notification.not_header.msgh_id
			== MACH_NOTIFY_PORT_DESTROYED);
	mach_port_t back = message.notification.not_port.name;
	mach_port_type_t type;
	CHECK(mach_port_type(task, back, &type) == KERN_SUCCESS);
	CHECK(type & MACH_PORT_TYPE_RECEIVE);

	CHECK(mach_port_insert_right(task, back, back, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_request_notification(task, back,
			      MACH_NOTIFY_PORT_DESTROYED, 0, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, notify, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, back, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_type(task, back, &type) == KERN_SUCCESS);
	CHECK(type == MACH_PORT_TYPE_DEAD_NAME);
	CHECK(mach_port_deallocate(task, back) == KERN_SUCCESS);
}

static void
check_unknown_request(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	mach_port_t notify = allocate_port();
	mach_port_t previous = MACH_PORT_NULL;
	CHECK(mach_port_request_notification(task, port, MACH_NOTIFY_LAST + 1,
			      0, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			      &previous)
			== KERN_INVALID_VALUE);
	expect_send_once_notification(notify);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, notify, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
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
check_reference_deltas(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t port = allocate_port();
	CHECK(mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_SEND, 2)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_SEND, -4)
			== KERN_INVALID_VALUE);
	CHECK(send_refs(port) == 3);

	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_DEAD_NAME, -4)
			== KERN_INVALID_VALUE);
	CHECK(mach_port_mod_refs(task, port, MACH_PORT_RIGHT_DEAD_NAME, -3)
			== KERN_SUCCESS);

	mach_port_t once;
	mach_msg_type_name_t once_type;
	CHECK(mach_port_extract_right(task, allocate_port(),
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &once, &once_type)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(task, once, MACH_PORT_RIGHT_SEND_ONCE, -2)
			== KERN_INVALID_VALUE);
	CHECK(mach_port_mod_refs(task, once, MACH_PORT_RIGHT_SEND_ONCE, -1)
			== KERN_SUCCESS);
}

#define FORKS 200

static void
check_fork_during_port_calls(void)
{
	pthread_t allocator;
	CHECK(pthread_create(&allocator, NULL, allocate_ports, NULL) == 0);
	for (int i = 0; i < FORKS; i++) {
		pid_t child = fork();
		CHECK(child != -1);
		if (child == 0) {
			allocate_port();
			_exit(0);
		}
		int status;
		CHECK(waitpid(child, &status, 0) == child);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	forked = true;
	CHECK(pthread_join(allocator, NULL) == 0);
}

static void *
allocate_ports(void *arg)
{
	while (!forked) {
		CHECK(mach_port_mod_refs(mach_task_self(), allocate_port(),
				      MACH_PORT_RIGHT_RECEIVE, -1)
				== KERN_SUCCESS);
	}
	return NULL;
}

static void
check_task_for_pid(void)
{
	mach_port_t task = mach_task_self();
	mach_port_urefs_t refs = send_refs(task);
	mach_port_t found;
	CHECK(task_for_pid(task, getpid(), &found) == KERN_SUCCESS);
	CHECK(found == task);
	CHECK(send_refs(task) == refs + 1);
	CHECK(mach_port_deallocate(task, found) == KERN_SUCCESS);
}

static void
check_pid_for_task(void)
{
	int pid;
	CHECK(pid_for_task(mach_task_self(), &pid) == KERN_SUCCESS);
	CHECK(pid == getpid());
	CHECK(pid_for_task(mach_host_self(), &pid) == KERN_FAILURE);
	CHECK(pid == -1);
}

static void
check_task_names(void)
{
	mach_port_t task = mach_task_self();
	mach_port_t name;
	CHECK(task_name_for_pid(task, getppid(), &name) == KERN_SUCCESS);
	CHECK(name != task);
	int pid;
	CHECK(pid_for_task(name, &pid) == KERN_SUCCESS);
	CHECK(pid == getppid());
	audit_token_t token;
	mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
	CHECK(task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&token, &count)
			== KERN_SUCCESS);
	CHECK(token.val[1] == geteuid());
	CHECK(token.val[3] == getuid());
	CHECK(token.val[5] == (unsigned int)getppid());
	struct task_dyld_info dyld;
	count = TASK_DYLD_INFO_COUNT;
	CHECK(task_info(name, TASK_DYLD_INFO, (task_info_t)&dyld, &count)
			== KERN_INVALID_ARGUMENT);
	CHECK(mach_port_deallocate(task, name) == KERN_SUCCESS);
	mach_port_type_t type;
	CHECK(mach_port_type(task, name, &type) == KERN_INVALID_NAME);

	CHECK(task_name_for_pid(task, getpid(), &name) == KERN_SUCCESS);
	count = TASK_AUDIT_TOKEN_COUNT;
	CHECK(task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&token, &count)
			== KERN_SUCCESS);
	CHECK(token.val[5] == (unsigned int)getpid());
	CHECK(mach_port_deallocate(task, name) == KERN_SUCCESS);
	CHECK(task_name_for_pid(task, -1, &name) == KERN_FAILURE);

	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		_exit(0);
	}
	kern_return_t named = KERN_SUCCESS;
	for (int tries = 0; tries < 100 && named == KERN_SUCCESS; tries++) {
		usleep(10000);
		named = task_name_for_pid(task, child, &name);
		if (named == KERN_SUCCESS) {
			CHECK(mach_port_deallocate(task, name) == KERN_SUCCESS);
		}
	}
	CHECK(named == KERN_FAILURE);
	CHECK(waitpid(child, NULL, 0) == child);
}

static void
check_named_task_memory(void)
{
	const size_t touched = 64 << 20;
	int sockets[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	char byte = 0;
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		close(sockets[0]);
		char *memory = malloc(touched);
		CHECK(write(sockets[1], &byte, 1) == 1);
		CHECK(read(sockets[1], &byte, 1) == 1);
		memset(memory, 1, touched);
		CHECK(write(sockets[1], &byte, 1) == 1);
		CHECK(read(sockets[1], &byte, 1) == 1);
		_exit(memory[touched - 1] - 1);
	}

	close(sockets[1]);
	mach_port_t name;
	CHECK(task_name_for_pid(mach_task_self(), child, &name)
			== KERN_SUCCESS);
	CHECK(read(sockets[0], &byte, 1) == 1);
	mach_vm_size_t untouched = resident_size(name);
	CHECK(write(sockets[0], &byte, 1) == 1);
	CHECK(read(sockets[0], &byte, 1) == 1);
	CHECK(resident_size(name) > untouched + touched / 2);

	CHECK(write(sockets[0], &byte, 1) == 1);
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(mach_port_deallocate(mach_task_self(), name) == KERN_SUCCESS);
	close(sockets[0]);
}

static mach_vm_size_t
resident_size(mach_port_t task)
{
	mach_task_basic_info_data_t info;
	mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
	CHECK(task_info(task, MACH_TASK_BASIC_INFO, (task_info_t)&info, &count)
			== KERN_SUCCESS);
	return info.resident_size;
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
	check_memory_entries_freed();
	check_memory_entry_sent();
}

static void
check_memory_entry_sent(void)
{
	memory_object_size_t size = vm_page_size;
	mach_port_t entry = MACH_PORT_NULL;
	vm_prot_t rw = VM_PROT_READ | VM_PROT_WRITE;
	CHECK(mach_make_memory_entry_64(mach_task_self(), &size, 0,
			      MAP_MEM_NAMED_CREATE | rw, &entry, MACH_PORT_NULL)
			== KERN_SUCCESS);
	mach_port_t port = allocate_port();

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
		mach_msg_trailer_t trailer;
	} message = {
			.header = {
					.msgh_bits = MACH_MSGH_BITS_SET(
							MACH_MSG_TYPE_MAKE_SEND,
							0, 0,
							MACH_MSGH_BITS_COMPLEX),
					.msgh_size = sizeof(message)
							- sizeof(message.trailer),
					.msgh_remote_port = port,
			},
			.body = {.msgh_descriptor_count = 1},
			.port = {
					.name = entry,
					.disposition = MACH_MSG_TYPE_MOVE_SEND,
					.type = MACH_MSG_PORT_DESCRIPTOR,
			},
	};
	CHECK(mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size,
			      0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(mach_msg(&message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), port, 1000, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);

	mach_vm_address_t first = 0, second = 0;
	CHECK(mach_vm_map(mach_task_self(), &first, size, 0, VM_FLAGS_ANYWHERE,
			      message.port.name, 0, false, rw, rw,
			      VM_INHERIT_NONE)
			== KERN_SUCCESS);
	CHECK(mach_vm_map(mach_task_self(), &second, size, 0, VM_FLAGS_ANYWHERE,
			      message.port.name, 0, false, rw, rw,
			      VM_INHERIT_NONE)
			== KERN_SUCCESS);
	((volatile char *)first)[7] = 42;
	CHECK(((volatile char *)second)[7] == 42);

	CHECK(mach_vm_deallocate(mach_task_self(), first, size)
			== KERN_SUCCESS);
	CHECK(mach_vm_deallocate(mach_task_self(), second, size)
			== KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), message.port.name)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
check_memory_entries_freed(void)
{
	struct rlimit files;
	CHECK(getrlimit(RLIMIT_NOFILE, &files) == 0);
	struct rlimit few = {.rlim_cur = 256, .rlim_max = files.rlim_max};
	CHECK(setrlimit(RLIMIT_NOFILE, &few) == 0);

	for (int i = 0; i != 1000; i++) {
		memory_object_size_t size = vm_page_size;
		mach_port_t entry = MACH_PORT_NULL;
		CHECK(mach_make_memory_entry_64(mach_task_self(), &size, 0,
				      MAP_MEM_NAMED_CREATE | VM_PROT_READ
						      | VM_PROT_WRITE,
				      &entry, MACH_PORT_NULL)
				== KERN_SUCCESS);
		CHECK(mach_port_deallocate(mach_task_self(), entry)
				== KERN_SUCCESS);
	}

	CHECK(setrlimit(RLIMIT_NOFILE, &files) == 0);
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

static void
check_host_statistics(void)
{
	enum { GUARD = 0x5a5a5a5a };
	integer_t info[HOST_VM_INFO_COUNT + 1];
	mach_msg_type_number_t counts[][2] = {
			{HOST_VM_INFO_COUNT + 1, HOST_VM_INFO_COUNT},
			{HOST_VM_INFO_REV1_COUNT, HOST_VM_INFO_REV1_COUNT},
			{HOST_VM_INFO_REV0_COUNT + 1, HOST_VM_INFO_REV0_COUNT},
			{HOST_VM_INFO_REV0_COUNT, HOST_VM_INFO_REV0_COUNT},
	};
	for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		for (size_t j = 0; j <= HOST_VM_INFO_COUNT; j++) {
			info[j] = GUARD;
		}
		mach_msg_type_number_t count = counts[i][0];
		CHECK(host_statistics(mach_host_self(), HOST_VM_INFO, info,
				      &count)
				== KERN_SUCCESS);
		CHECK(count == counts[i][1]);
		CHECK(info[count] == GUARD);
	}
	mach_msg_type_number_t count = HOST_VM_INFO_REV0_COUNT - 1;
	CHECK(host_statistics(mach_host_self(), HOST_VM_INFO, info, &count)
			== KERN_FAILURE);
}
