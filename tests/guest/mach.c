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

#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "check.h"

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

static semaphore_t semaphore;

static void check_messages(void);
static void check_port_sets(void);
static void check_semaphores(void);
static void *signal_semaphore(void *arg);
static void check_time(void);
static void check_memory_entries(void);
static void check_remaps(void);
static void check_shared_range_entries(void);
static void check_exception_ports(void);
static void check_destroy(void);
static mach_port_t allocate_port(void);

int
main(void)
{
	check_messages();
	check_port_sets();
	check_semaphores();
	check_time();
	check_memory_entries();
	check_remaps();
	check_exception_ports();
	check_destroy();
	return 0;
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

	CHECK(mach_vm_deallocate(mach_task_self(), first, size) == KERN_SUCCESS);
	CHECK(mach_vm_deallocate(mach_task_self(), second, size)
			== KERN_SUCCESS);
	CHECK(mach_port_deallocate(mach_task_self(), entry) == KERN_SUCCESS);

	check_shared_range_entries();
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
