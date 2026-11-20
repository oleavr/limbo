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

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "check.h"

#define SIZE                  0x20000
#define IN_PAGE               0x20
#define MAIN_THREAD_EXIT_USEC 300000
#define COPY_FILL             0x31
#define READ_FILL             0x52
#define WRITE_FILL            0x73

static void *copy_after_main(void *arg);
static void fill(mach_vm_address_t at, mach_vm_size_t size, uint8_t base);
static bool filled(mach_vm_address_t at, mach_vm_size_t size, uint8_t base);

int
main(void)
{
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, copy_after_main, NULL) == 0);
	pthread_exit(NULL);
}

static void *
copy_after_main(void *arg)
{
	usleep(MAIN_THREAD_EXIT_USEC);

	task_t self = mach_task_self();
	mach_vm_address_t from = 0, to = 0;
	CHECK(mach_vm_allocate(self, &from, SIZE + vm_page_size,
			      VM_FLAGS_ANYWHERE)
			== KERN_SUCCESS);
	CHECK(mach_vm_allocate(
			      self, &to, SIZE + vm_page_size, VM_FLAGS_ANYWHERE)
			== KERN_SUCCESS);

	fill(from + IN_PAGE, SIZE, COPY_FILL);
	CHECK(mach_vm_copy(self, from + IN_PAGE, SIZE, to + IN_PAGE)
			== KERN_SUCCESS);
	CHECK(filled(to + IN_PAGE, SIZE, COPY_FILL));

	fill(from, vm_page_size, READ_FILL);
	mach_vm_size_t got = 0;
	CHECK(mach_vm_read_overwrite(self, from, vm_page_size, to, &got)
			== KERN_SUCCESS);
	CHECK(got == vm_page_size && filled(to, vm_page_size, READ_FILL));

	fill(from, vm_page_size, WRITE_FILL);
	CHECK(mach_vm_write(self, to, (vm_offset_t)from,
			      (mach_msg_type_number_t)vm_page_size)
			== KERN_SUCCESS);
	CHECK(filled(to, vm_page_size, WRITE_FILL));

	vm_offset_t data = 0;
	mach_msg_type_number_t count = 0;
	CHECK(mach_vm_read(self, to, vm_page_size, &data, &count)
			== KERN_SUCCESS);
	CHECK(count == vm_page_size && filled(data, vm_page_size, WRITE_FILL));
	CHECK(mach_vm_deallocate(self, data, count) == KERN_SUCCESS);

	CHECK(mach_vm_deallocate(self, from, SIZE + vm_page_size)
			== KERN_SUCCESS);
	CHECK(mach_vm_copy(self, from, vm_page_size, to)
			== KERN_INVALID_ADDRESS);
	CHECK(mach_vm_read_overwrite(self, from, vm_page_size, to, &got)
			== KERN_INVALID_ADDRESS);
	CHECK(mach_vm_read(self, from, vm_page_size, &data, &count)
			== KERN_INVALID_ADDRESS);
	CHECK(mach_vm_write(self, from, (vm_offset_t)to,
			      (mach_msg_type_number_t)vm_page_size)
			== KERN_INVALID_ADDRESS);

	CHECK(mach_vm_protect(self, to, vm_page_size, FALSE, VM_PROT_READ)
			== KERN_SUCCESS);
	CHECK(mach_vm_write(self, to, (vm_offset_t)to + vm_page_size,
			      (mach_msg_type_number_t)vm_page_size)
			== KERN_INVALID_ADDRESS);
	CHECK(filled(to, vm_page_size, WRITE_FILL));
	exit(0);
}

static void
fill(mach_vm_address_t at, mach_vm_size_t size, uint8_t base)
{
	volatile uint8_t *bytes = (volatile uint8_t *)at;
	for (mach_vm_size_t i = 0; i < size; i++) {
		bytes[i] = (uint8_t)(base + i);
	}
}

static bool
filled(mach_vm_address_t at, mach_vm_size_t size, uint8_t base)
{
	volatile uint8_t *bytes = (volatile uint8_t *)at;
	for (mach_vm_size_t i = 0; i < size; i++) {
		if (bytes[i] != (uint8_t)(base + i)) {
			return false;
		}
	}
	return true;
}
