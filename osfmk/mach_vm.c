/*
 * Copyright © 2021 Keegan Saunders
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <mach/mach_types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "commpage.h"

#include "ipc.h"
#include "mach_vm.h"

struct memory_entry {
	int fd;
	mach_vm_size_t size;
	mach_vm_offset_t data_offset;
};

#define VM_FLAGS_ANYWHERE  0x0001
#define VM_FLAGS_OVERWRITE 0x4000
#define LOW_ANYWHERE_BASE  0x100000000

static kern_return_t map_anonymous(mach_vm_address_t *address,
		mach_vm_size_t size, mach_vm_offset_t mask, int flags,
		vm_prot_t protection);
static int move_to_memfd(mach_vm_address_t address, mach_vm_size_t size,
		vm_prot_t protection);
static void *map_aligned(mach_vm_size_t size, mach_vm_offset_t mask,
		vm_prot_t protection);
static kern_return_t remap_share(mach_vm_address_t *target_address,
		mach_vm_size_t size, mach_vm_offset_t mask, int flags,
		mach_vm_address_t src_address);
static int share_piece(mach_vm_address_t address, mach_vm_size_t size,
		mach_vm_address_t start, vm_prot_t protection, bool shared,
		uint64_t file_offset, off_t *offset);
static int share_in_place(mach_vm_address_t address, mach_vm_size_t size,
		vm_prot_t protection);
static int shared_range_fd(mach_vm_address_t start);
static void shared_range_add(mach_vm_address_t start, int fd);
static int held_fd(mach_vm_address_t start);
static bool region_inode(mach_vm_address_t start, dev_t *device, ino_t *inode);
static int copy_range(mach_vm_address_t address, mach_vm_size_t size);
static kern_return_t remap_copy(mach_vm_address_t *target_address,
		mach_vm_size_t size, mach_vm_offset_t mask, int flags,
		mach_vm_address_t src_address, vm_prot_t *protection);
static vm_prot_t region_protection(mach_vm_address_t address);
static bool region_find(mach_vm_address_t address, mach_vm_address_t *start,
		mach_vm_size_t *size, vm_prot_t *protection, bool *shared,
		uint64_t *offset);
static kern_return_t map_entry(mach_vm_address_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags,
		const struct memory_entry *entry, memory_object_offset_t offset,
		boolean_t copy, vm_prot_t protection);
static uint64_t *reclaim_index(size_t offset);
static uint64_t absolute_per_second(void);
static uint64_t reclaim_next_deadline(void);

kern_return_t
_kernelrpc_mach_vm_allocate(vm_task_entry_t target, mach_vm_address_t *address,
		mach_vm_size_t size, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_allocate(%p, %p, %p, %p)\n",
			(void *)target, (void *)address, (void *)size,
			(void *)flags);
#endif
	return map_anonymous(address, size, 0, flags, VM_PROT_DEFAULT);
}

static kern_return_t
map_anonymous(mach_vm_address_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, vm_prot_t protection)
{
	size = (size + PAGE_MASK) & ~PAGE_MASK;

	void *base;
	if (flags & VM_FLAGS_ANYWHERE) {
		base = map_aligned(size, mask | PAGE_MASK, protection);
	} else {
		int placement = (flags & VM_FLAGS_OVERWRITE)
				? MAP_FIXED
				: MAP_FIXED_NOREPLACE;
		base = mmap((void *)*address, size, protection,
				MAP_PRIVATE | MAP_ANON | MAP_NORESERVE | placement,
				-1, 0);
	}
	if (base == MAP_FAILED) {
		return KERN_NO_SPACE;
	}

	*address = (mach_vm_address_t)base;
	return KERN_SUCCESS;
}

static void *
map_aligned(mach_vm_size_t size, mach_vm_offset_t mask, vm_prot_t protection)
{
	mach_vm_size_t padded_size = size + mask + 1;
#ifdef __x86_64__
	uint8_t *padded = mmap(NULL, padded_size, protection,
			MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
	if (padded == MAP_FAILED) {
		return MAP_FAILED;
	}
#else
	static uintptr_t bump = LOW_ANYWHERE_BASE;
	uint8_t *padded;
	while (true) {
		padded = mmap((void *)bump, padded_size, protection,
				MAP_PRIVATE | MAP_ANON | MAP_NORESERVE
						| MAP_FIXED_NOREPLACE,
				-1, 0);
		bump += (padded_size + PAGE_MASK) & ~(uintptr_t)PAGE_MASK;
		if (padded != MAP_FAILED) {
			break;
		}
		if (errno != EEXIST) {
			return MAP_FAILED;
		}
	}
#endif

	uint8_t *base = (uint8_t *)(((uintptr_t)padded + mask) & ~mask);
	uint8_t *end = base + size;
	uint8_t *padded_end = padded + padded_size;
	if (base != padded) {
		munmap(padded, base - padded);
	}
	if (end != padded_end) {
		munmap(end, padded_end - end);
	}
	return base;
}

kern_return_t
_kernelrpc_mach_vm_deallocate(vm_task_entry_t target, mach_vm_address_t address,
		mach_vm_size_t size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_deallocate(%p, %p, %p)\n",
			(void *)target, (void *)address, (void *)size);
#endif
	mach_vm_address_t start = address & ~PAGE_MASK;
	mach_vm_address_t end = (address + size + PAGE_MASK) & ~PAGE_MASK;
	if (start != end && munmap((void *)start, end - start) == -1) {
		return KERN_INVALID_ADDRESS;
	}
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_mach_vm_protect(vm_task_entry_t target_task,
		mach_vm_address_t address, mach_vm_size_t size,
		boolean_t set_maximum, vm_prot_t new_protection)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_protect(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)set_maximum, (void *)new_protection);
#endif
	if (set_maximum) {
		return KERN_SUCCESS;
	}

	mach_vm_address_t start = address & ~PAGE_MASK;
	mach_vm_address_t end = (address + size + PAGE_MASK) & ~PAGE_MASK;
	if (mprotect((void *)start, end - start, new_protection & VM_PROT_ALL)
			== -1) {
		return KERN_PROTECTION_FAILURE;
	}
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_inherit(vm_task_entry_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_inherit_t new_inheritance)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_inherit(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)new_inheritance);
#endif

	(void)target_task;
	(void)address;
	(void)size;
	(void)new_inheritance;
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_mach_vm_read(vm_map_read_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_offset_t *data,
		mach_msg_type_number_t *dataCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_read(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)data, (void *)dataCnt);
#endif
	(void)target_task;

	if (size > 64 * 1024 * 1024) {
		return KERN_INVALID_ARGUMENT;
	}
	if (size == 0) {
		*data = 0;
		*dataCnt = 0;
		return KERN_SUCCESS;
	}
	mach_vm_address_t buf = 0;
	kern_return_t kr = _kernelrpc_mach_vm_allocate(
			MACH_PORT_NULL, &buf, size, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	memcpy((void *)buf, (const void *)address, size);
	*data = (vm_offset_t)buf;
	*dataCnt = size;
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_read_list(vm_map_read_t target_task, mach_vm_read_entry_t data_list,
		natural_t count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_read_list(%p, %p, %p)\n", (void *)target_task,
			(void *)data_list, (void *)count);
#endif
	unimplemented();
}

kern_return_t
mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data,
		mach_msg_type_number_t dataCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_write(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)address, (void *)data, (void *)dataCnt);
#endif
	memmove((void *)address, (void *)data, dataCnt);
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_copy(vm_map_t target_task, mach_vm_address_t source_address,
		mach_vm_size_t size, mach_vm_address_t dest_address)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_copy(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)source_address, (void *)size,
			(void *)dest_address);
#endif
	memmove((void *)dest_address, (void *)source_address, size);
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_read_overwrite(vm_map_read_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, mach_vm_address_t data,
		mach_vm_size_t *outsize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_read_overwrite(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)data, (void *)outsize);
#endif
	memmove((void *)data, (void *)address, size);
	*outsize = size;
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_msync(vm_map_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_sync_t sync_flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_msync(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)address, (void *)size, (void *)sync_flags);
#endif
	unimplemented();
}

kern_return_t
mach_vm_behavior_set(vm_map_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_behavior_t new_behavior)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_behavior_set(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)new_behavior);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_map(vm_task_entry_t target_task, mach_vm_address_t *address,
		mach_vm_size_t size, mach_vm_offset_t mask, int flags,
		mem_entry_name_port_t object, memory_object_offset_t offset,
		boolean_t copy, vm_prot_t cur_protection,
		vm_prot_t max_protection, vm_inherit_t inheritance)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_map(%p, %p, %p, %p, %p, %p, %p, "
			"%p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)mask, (void *)flags, (void *)object,
			(void *)offset, (void *)copy, (void *)cur_protection,
			(void *)max_protection, (void *)inheritance);
#endif
	cur_protection &= VM_PROT_ALL;
	if (object != MACH_PORT_NULL) {
		struct memory_entry *entry = ipc_kobject_lookup(
				object, IPC_KOBJECT_MEMORY_ENTRY);
		if (entry == NULL) {
			unimplemented();
		}
		kern_return_t kr = map_entry(address, size, mask, flags, entry,
				offset, copy, cur_protection);
		if (kr == KERN_SUCCESS && (flags & VM_FLAGS_RETURN_DATA_ADDR)) {
			*address += entry->data_offset;
		}
#ifdef ENABLE_STRACE
		fprintf(stderr,
				"  mach_vm_map: entry of %#llx bytes: %d, at "
				"%#llx\n",
				(unsigned long long)entry->size, kr,
				(unsigned long long)*address);
#endif
		return kr;
	}

	return map_anonymous(address, size, mask, flags, cur_protection);
}

mach_port_name_t
memory_entry_create(mach_vm_size_t size, void **contents)
{
	size = (size + PAGE_MASK) & ~PAGE_MASK;
	int fd = memfd_create("memory entry", MFD_CLOEXEC);
	if (fd == -1 || ftruncate(fd, size) == -1) {
		perror("memfd_create");
		abort();
	}
	*contents = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (*contents == MAP_FAILED) {
		perror("mmap");
		abort();
	}

	struct memory_entry *entry = malloc(sizeof(*entry));
	*entry = (struct memory_entry){.fd = fd, .size = size};
	return ipc_kobject_alloc(IPC_KOBJECT_MEMORY_ENTRY, entry);
}

mach_port_name_t
memory_entry_share(int fd, mach_vm_size_t size)
{
	int own = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (own == -1) {
		perror("fcntl");
		abort();
	}
	return ipc_kobject_alloc(IPC_KOBJECT_MEMORY_ENTRY,
			memory_entry_adopt(own, (size + PAGE_MASK) & ~PAGE_MASK,
					0));
}

bool
memory_entry_describe(const void *kobject, int *fd, mach_vm_size_t *size,
		mach_vm_offset_t *data_offset)
{
	const struct memory_entry *entry = kobject;
	*fd = entry->fd;
	*size = entry->size;
	*data_offset = entry->data_offset;
	return true;
}

void *
memory_entry_adopt(int fd, mach_vm_size_t size, mach_vm_offset_t data_offset)
{
	struct memory_entry *entry = malloc(sizeof(*entry));
	*entry = (struct memory_entry){
			.fd = fd,
			.size = size,
			.data_offset = data_offset,
	};
	return entry;
}

void
memory_entry_destroy(void *kobject)
{
	struct memory_entry *entry = kobject;
	close(entry->fd);
	free(entry);
}

kern_return_t
mach_vm_allocate_anywhere(mach_vm_address_t *address, mach_vm_size_t size)
{
	return map_anonymous(address, size, 0, VM_FLAGS_ANYWHERE,
			VM_PROT_READ | VM_PROT_WRITE);
}

kern_return_t
mach_vm_map_fd(int fd, mach_vm_size_t size, vm_prot_t protection,
		mach_vm_address_t *address)
{
	struct memory_entry entry = {.fd = fd, .size = size};
	return map_entry(address, size, 0, VM_FLAGS_ANYWHERE, &entry, 0, false,
			protection);
}

static kern_return_t
map_entry(mach_vm_address_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags,
		const struct memory_entry *entry, memory_object_offset_t offset,
		boolean_t copy, vm_prot_t protection)
{
	size = (size + PAGE_MASK) & ~PAGE_MASK;
	if (offset + size > entry->size) {
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t kr = map_anonymous(
			address, size, mask, flags, VM_PROT_NONE);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	void *base = mmap((void *)*address, size, protection,
			(copy ? MAP_PRIVATE : MAP_SHARED) | MAP_FIXED,
			entry->fd, offset);
	if (base == MAP_FAILED) {
		munmap((void *)*address, size);
		return KERN_NO_SPACE;
	}
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_machine_attribute(vm_map_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_machine_attribute_t attribute,
		vm_machine_attribute_val_t *value)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_machine_attribute(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)attribute, (void *)value);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_remap(vm_map_t target_task,
		mach_vm_address_t *target_address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, vm_map_t src_task,
		mach_vm_address_t src_address, boolean_t copy,
		vm_prot_t *cur_protection, vm_prot_t *max_protection,
		vm_inherit_t inheritance)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_remap(%p, %p, %p, %p, %p, %p, %p, "
			"%p, %p, %p, %p)\n",
			(void *)target_task, (void *)target_address,
			(void *)size, (void *)mask, (void *)flags,
			(void *)src_task, (void *)src_address, (void *)copy,
			(void *)cur_protection, (void *)max_protection,
			(void *)inheritance);
#endif
	*cur_protection = region_protection(src_address);
	*max_protection = VM_PROT_ALL;
	if (!copy) {
		return remap_share(
				target_address, size, mask, flags, src_address);
	}
	return remap_copy(target_address, size, mask, flags, src_address,
			cur_protection);
}

static kern_return_t
remap_share(mach_vm_address_t *target_address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, mach_vm_address_t src_address)
{
	size = (size + PAGE_MASK) & ~PAGE_MASK;
	kern_return_t kr = map_anonymous(
			target_address, size, mask, flags, VM_PROT_NONE);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	mach_vm_address_t end = src_address + size;
	mach_vm_address_t address = src_address;
	while (address < end) {
		mach_vm_address_t start;
		mach_vm_size_t region_size;
		vm_prot_t protection;
		bool shared;
		uint64_t file_offset;
		if (!region_find(address, &start, &region_size, &protection,
				    &shared, &file_offset)
				|| start >= end) {
			break;
		}
		if (start > address) {
			address = start;
			continue;
		}
		mach_vm_address_t last = start + region_size < end
				? start + region_size
				: end;
		off_t offset;
		int fd = share_piece(address, last - address, start, protection,
				shared, file_offset, &offset);
		void *at = (void *)(*target_address + (address - src_address));
		if (fd == -1
				|| mmap(at, last - address, protection,
						   MAP_SHARED | MAP_FIXED, fd,
						   offset)
						== MAP_FAILED) {
			if (fd != -1) {
				close(fd);
			}
			munmap((void *)*target_address, size);
			return KERN_NO_SPACE;
		}
		close(fd);
		address = last;
	}
	return KERN_SUCCESS;
}

static bool
copy_readable(int fd, mach_vm_address_t address, mach_vm_size_t size,
		bool *shared)
{
	*shared = false;
	FILE *maps = fopen("/proc/thread-self/maps", "r");
	if (maps == NULL) {
		return false;
	}
	char line[512];
	bool ok = true;
	mach_vm_address_t end = address + size;
	while (ok && fgets(line, sizeof(line), maps) != NULL) {
		unsigned long from, to;
		char perms[5];
		if (sscanf(line, "%lx-%lx %4s", &from, &to, perms) != 3
				|| to <= address || from >= end) {
			continue;
		}
		*shared |= perms[3] == 's';
		if (perms[0] != 'r') {
			continue;
		}
		mach_vm_address_t first = from > address ? from : address;
		mach_vm_address_t last = to < end ? to : end;
		ok = pwrite(fd, (void *)first, last - first,
				     (off_t)(first - address))
				== (ssize_t)(last - first);
	}
	fclose(maps);
	return ok;
}

static int
share_in_place(mach_vm_address_t address, mach_vm_size_t size,
		vm_prot_t protection)
{
	/*
	 * A range shared in place by an entry made before is the memory that
	 * entry names, and a second entry of it must name the same memory, not
	 * a copy of it: coreservicesd makes an entry of its store's segment
	 * for every client (limbo-19k.96). The mapping's file is the memfd
	 * the range was moved into, which limbo keeps, as /proc's map_files
	 * would need a privilege; or, for a range mapped from an entry, the
	 * memfd that entry holds
	 */
	mach_vm_address_t start;
	mach_vm_size_t region_size;
	vm_prot_t region_prot;
	bool region_shared;
	uint64_t file_offset;
	if (region_find(address, &start, &region_size, &region_prot,
			    &region_shared, &file_offset)
			&& region_shared && start <= address
			&& address + size <= start + region_size
			&& file_offset + (address - start) == 0) {
		int same = shared_range_fd(start);
		if (same == -1) {
			same = held_fd(start);
		}
		if (same != -1) {
			return same;
		}
	}

	return move_to_memfd(address, size, protection);
}

static int
share_piece(mach_vm_address_t address, mach_vm_size_t size,
		mach_vm_address_t start, vm_prot_t protection, bool shared,
		uint64_t file_offset, off_t *offset)
{
	if (shared) {
		int same = shared_range_fd(start);
		if (same == -1) {
			same = held_fd(start);
		}
		if (same != -1) {
			*offset = (off_t)(file_offset + (address - start));
			return same;
		}
	}
	*offset = 0;
	return move_to_memfd(address, size, protection);
}

static int
move_to_memfd(mach_vm_address_t address, mach_vm_size_t size,
		vm_prot_t protection)
{
	bool shared;
	int fd = memfd_create("remap", MFD_CLOEXEC);
	if (fd == -1 || ftruncate(fd, size) == -1
			|| !copy_readable(fd, address, size, &shared)
			|| (!shared
					&& mmap((void *)address, size, protection,
							   MAP_SHARED | MAP_FIXED, fd, 0)
							== MAP_FAILED)) {
		if (fd != -1) {
			close(fd);
		}
		return -1;
	}
	if (!shared) {
		shared_range_add(address, fd);
	}
	return fd;
}

/*
 * The memfds ranges were moved into, by where they start, while the range is
 * still mapped from it
 */
struct shared_range {
	struct shared_range *next;
	mach_vm_address_t start;
	int fd;
};

static struct shared_range *shared_ranges;
static pthread_mutex_t shared_ranges_lock = PTHREAD_MUTEX_INITIALIZER;

/* A descriptor of the memfd the range at START is mapped from, or -1 */
static int
shared_range_fd(mach_vm_address_t start)
{
	dev_t device;
	ino_t inode;
	bool mapped = region_inode(start, &device, &inode);
	int fd = -1;
	pthread_mutex_lock(&shared_ranges_lock);
	struct shared_range **link = &shared_ranges;
	while (*link != NULL) {
		struct shared_range *range = *link;
		struct stat status;
		if (range->start != start) {
			link = &range->next;
			continue;
		}
		if (mapped && fstat(range->fd, &status) == 0
				&& status.st_dev == device
				&& status.st_ino == inode) {
			fd = fcntl(range->fd, F_DUPFD_CLOEXEC, 0);
			break;
		}
		/* The range was unmapped or mapped anew since */
		*link = range->next;
		close(range->fd);
		free(range);
	}
	pthread_mutex_unlock(&shared_ranges_lock);
	return fd;
}

static void
shared_range_add(mach_vm_address_t start, int fd)
{
	struct shared_range *range = malloc(sizeof(*range));
	range->start = start;
	range->fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (range->fd == -1) {
		free(range);
		return;
	}
	pthread_mutex_lock(&shared_ranges_lock);
	range->next = shared_ranges;
	shared_ranges = range;
	pthread_mutex_unlock(&shared_ranges_lock);
}

static int
held_fd(mach_vm_address_t start)
{
	dev_t device;
	ino_t inode;
	DIR *fds = opendir("/proc/thread-self/fd");
	if (!region_inode(start, &device, &inode) || fds == NULL) {
		if (fds != NULL) {
			closedir(fds);
		}
		return -1;
	}
	int found = -1;
	struct dirent *name;
	while (found == -1 && (name = readdir(fds)) != NULL) {
		int fd = atoi(name->d_name);
		struct stat status;
		if (name->d_name[0] != '.' && fd != dirfd(fds)
				&& (fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR
				&& fstat(fd, &status) == 0
				&& S_ISREG(status.st_mode)
				&& status.st_dev == device
				&& status.st_ino == inode) {
			found = fcntl(fd, F_DUPFD_CLOEXEC, 0);
		}
	}
	closedir(fds);
	return found;
}

/* The inode of the file the mapping that starts at START maps */
static bool
region_inode(mach_vm_address_t start, dev_t *device, ino_t *inode)
{
	FILE *maps = fopen("/proc/thread-self/maps", "r");
	char line[512];
	bool found = false;
	while (maps != NULL && fgets(line, sizeof(line), maps) != NULL) {
		unsigned long low;
		unsigned int major, minor;
		unsigned long long number;
		if (sscanf(line, "%lx-%*x %*s %*x %x:%x %llu", &low, &major,
				    &minor,
				    &number) == 4
				&& low == start) {
			*device = makedev(major, minor);
			*inode = (ino_t)number;
			found = true;
			break;
		}
	}
	if (maps != NULL) {
		fclose(maps);
	}
	return found;
}

static kern_return_t
remap_copy(mach_vm_address_t *target_address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, mach_vm_address_t src_address,
		vm_prot_t *protection)
{
	kern_return_t kr = map_anonymous(target_address, size, mask, flags,
			VM_PROT_READ | VM_PROT_WRITE);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	memcpy((void *)*target_address, (void *)src_address, size);
	mprotect((void *)*target_address, size, *protection);
	return KERN_SUCCESS;
}

static vm_prot_t
region_protection(mach_vm_address_t address)
{
	FILE *maps = fopen("/proc/thread-self/maps", "r");
	char line[512];
	vm_prot_t protection = VM_PROT_NONE;
	while (fgets(line, sizeof(line), maps) != NULL) {
		unsigned long start, end;
		char perms[5];
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3
				&& address >= start && address < end) {
			protection = ((perms[0] == 'r') ? VM_PROT_READ : 0)
					| ((perms[1] == 'w') ? VM_PROT_WRITE
							     : 0)
					| ((perms[2] == 'x') ? VM_PROT_EXECUTE
							     : 0);
			break;
		}
	}
	fclose(maps);
	return protection;
}

kern_return_t
mach_vm_page_query(vm_map_read_t target_map, mach_vm_offset_t offset,
		integer_t *disposition, integer_t *ref_count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_page_query(%p, %p, %p, %p)\n",
			(void *)target_map, (void *)offset, (void *)disposition,
			(void *)ref_count);
#endif
	unimplemented();
}

kern_return_t
mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t *address,
		mach_vm_size_t *size, natural_t *nesting_depth,
		vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_region_recurse(%p, %p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)nesting_depth, (void *)info, (void *)infoCnt);
#endif
	if (*infoCnt < VM_REGION_SUBMAP_INFO_COUNT_64) {
		return KERN_INVALID_ARGUMENT;
	}
	vm_prot_t protection;
	bool shared;
	uint64_t offset;
	if (!region_find(*address, address, size, &protection, &shared,
			    &offset)) {
		return KERN_INVALID_ADDRESS;
	}
	vm_region_submap_info_data_64_t *submap = (void *)info;
	*submap = (vm_region_submap_info_data_64_t){
			.protection = protection,
			.max_protection = VM_PROT_ALL,
			.inheritance = VM_INHERIT_COPY,
			.offset = offset,
			.share_mode = shared ? SM_SHARED : SM_PRIVATE,
			.user_tag = 0,
	};
	*nesting_depth = 0;
	*infoCnt = VM_REGION_SUBMAP_INFO_COUNT_64;
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_region(vm_map_read_t target_task, mach_vm_address_t *address,
		mach_vm_size_t *size, vm_region_flavor_t flavor,
		vm_region_info_t info, mach_msg_type_number_t *infoCnt,
		mach_port_t *object_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_region(%p, %p, %p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)flavor, (void *)info, (void *)infoCnt,
			(void *)object_name);
#endif
	if (flavor != VM_REGION_BASIC_INFO_64
			|| *infoCnt < VM_REGION_BASIC_INFO_COUNT_64) {
		unimplemented();
	}
	vm_prot_t protection;
	bool shared;
	uint64_t offset;
	if (!region_find(*address, address, size, &protection, &shared,
			    &offset)) {
		return KERN_INVALID_ADDRESS;
	}
	vm_region_basic_info_data_64_t *basic = (void *)info;
	*basic = (vm_region_basic_info_data_64_t){
			.protection = protection,
			.max_protection = VM_PROT_ALL,
			.inheritance = VM_INHERIT_COPY,
			.shared = shared,
			.offset = offset,
	};
	*infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
	if (object_name != NULL) {
		*object_name = MACH_PORT_NULL;
	}
	return KERN_SUCCESS;
}

static bool
region_find(mach_vm_address_t address, mach_vm_address_t *start,
		mach_vm_size_t *size, vm_prot_t *protection, bool *shared,
		uint64_t *offset)
{
	FILE *maps = fopen("/proc/thread-self/maps", "r");
	char line[512];
	bool found = false;
	while (fgets(line, sizeof(line), maps) != NULL) {
		unsigned long low, high, file_offset;
		char perms[5];
		if (sscanf(line, "%lx-%lx %4s %lx", &low, &high, perms,
				    &file_offset)
						== 4
				&& high > address) {
			*start = low;
			*size = high - low;
			*protection = ((perms[0] == 'r') ? VM_PROT_READ : 0)
					| ((perms[1] == 'w') ? VM_PROT_WRITE
							     : 0)
					| ((perms[2] == 'x') ? VM_PROT_EXECUTE
							     : 0);
			*shared = perms[3] == 's';
			*offset = file_offset;
			found = true;
			break;
		}
	}
	fclose(maps);
	return found;
}

kern_return_t
mach_make_memory_entry(vm_map_t target_task, memory_object_size_t *size,
		memory_object_offset_t offset, vm_prot_t permission,
		mach_port_t *object_handle, mem_entry_name_port_t parent_handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_make_memory_entry(%p, %p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)size, (void *)offset,
			(void *)permission, (void *)object_handle,
			(void *)parent_handle);
#endif
	if (parent_handle != MACH_PORT_NULL) {
		unimplemented();
	}
	/*
	 * A memory object of its own, zeroed, of the size rounded to pages,
	 * which every map of the entry shares; a purgeable one is never purged
	 */
	if (permission & MAP_MEM_NAMED_CREATE) {
		mach_vm_size_t rounded = (*size + PAGE_MASK) & ~PAGE_MASK;
		int fd = memfd_create("memory entry", MFD_CLOEXEC);
		if (fd == -1 || ftruncate(fd, (off_t)rounded) == -1) {
			if (fd != -1) {
				close(fd);
			}
			return KERN_RESOURCE_SHORTAGE;
		}
		struct memory_entry *entry = malloc(sizeof(*entry));
		*entry = (struct memory_entry){.fd = fd, .size = rounded};
		*size = rounded;
		*object_handle = ipc_kobject_alloc(IPC_KOBJECT_MEMORY_ENTRY, entry);
		return KERN_SUCCESS;
	}

	mach_vm_address_t start = offset & ~(mach_vm_address_t)PAGE_MASK;
	mach_vm_address_t end = (offset + *size + PAGE_MASK) & ~PAGE_MASK;
	int fd = (permission & MAP_MEM_VM_COPY)
			? copy_range(start, end - start)
			: share_in_place(start, end - start,
					  region_protection(start));
	if (fd == -1) {
#ifdef ENABLE_STRACE
		fprintf(stderr, "  mach_make_memory_entry: %#llx-%#llx: %s\n",
				(unsigned long long)start,
				(unsigned long long)end, strerror(errno));
		FILE *maps = fopen("/proc/thread-self/maps", "r");
		char line[512];
		while (maps != NULL
				&& fgets(line, sizeof(line), maps) != NULL) {
			unsigned long from, to;
			if (sscanf(line, "%lx-%lx", &from, &to) == 2
					&& to > start && from < end) {
				fprintf(stderr, "    %s", line);
			}
		}
		if (maps != NULL) {
			fclose(maps);
		}
#endif
		return KERN_INVALID_ADDRESS;
	}

	struct memory_entry *entry = malloc(sizeof(*entry));
	*entry = (struct memory_entry){
			.fd = fd,
			.size = end - start,
			.data_offset = (permission & MAP_MEM_USE_DATA_ADDR)
					? offset - start
					: 0,
	};
	if (!(permission & MAP_MEM_USE_DATA_ADDR)) {
		*size = end - start;
	}
	*object_handle = ipc_kobject_alloc(IPC_KOBJECT_MEMORY_ENTRY, entry);
	return KERN_SUCCESS;
}

static int
copy_range(mach_vm_address_t address, mach_vm_size_t size)
{
	bool shared;
	int fd = memfd_create("memory entry", MFD_CLOEXEC);
	if (fd == -1 || ftruncate(fd, size) == -1
			|| !copy_readable(fd, address, size, &shared)) {
		if (fd != -1) {
			close(fd);
		}
		return -1;
	}
	return fd;
}

kern_return_t
_kernelrpc_mach_vm_purgable_control(vm_map_t target_task,
		mach_vm_address_t address, vm_purgable_t control, int *state)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_purgable_control(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)control,
			(void *)state);
#endif
	*state = VM_PURGABLE_NONVOLATILE;
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_page_info(vm_map_read_t target_task, mach_vm_address_t address,
		vm_page_info_flavor_t flavor, vm_page_info_t info,
		mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_page_info(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)flavor,
			(void *)info, (void *)infoCnt);
#endif
	unimplemented();
}

kern_return_t
mach_vm_page_range_query(vm_map_read_t target_map, mach_vm_offset_t address,
		mach_vm_size_t size, mach_vm_address_t dispositions,
		mach_vm_size_t *dispositions_count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_page_range_query(%p, %p, %p, %p, %p)\n",
			(void *)target_map, (void *)address, (void *)size,
			(void *)dispositions, (void *)dispositions_count);
#endif

	mach_vm_address_t start = address & ~(mach_vm_address_t)PAGE_MASK;
	mach_vm_size_t pages = (address + size - start + PAGE_MASK) / PAGE_SIZE;
	if (pages > *dispositions_count) {
		pages = *dispositions_count;
	}
	size_t host_page = getpagesize();
	size_t per_page = PAGE_SIZE / host_page;
	int *out = (int *)dispositions;
	unsigned char resident[PAGE_SIZE / 4096];
	for (mach_vm_size_t i = 0; i < pages; i++) {
		void *page = (void *)(start + i * PAGE_SIZE);
		int disposition = 0;
		if (mincore(page, PAGE_SIZE, resident) == 0) {
			for (size_t j = 0; j < per_page; j++) {
				if (resident[j] & 1) {
					disposition = VM_PAGE_QUERY_PAGE_PRESENT;
				}
			}
		}
		out[i] = disposition;
	}
	*dispositions_count = pages;
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_mach_vm_remap_new(vm_map_t target_task,
		mach_vm_address_t *target_address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, vm_map_read_t src_task,
		mach_vm_address_t src_address, boolean_t copy,
		vm_prot_t *cur_protection, vm_prot_t *max_protection,
		vm_inherit_t inheritance)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_remap_new(%p, %p, %p, %p, %p, %p, "
			"%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)target_address,
			(void *)size, (void *)mask, (void *)flags,
			(void *)src_task, (void *)src_address, (void *)copy,
			(void *)cur_protection, (void *)max_protection,
			(void *)inheritance);
#endif
	if (!copy) {
		unimplemented();
	}

	return remap_copy(target_address, size, mask, flags, src_address,
			cur_protection);
}

#define RECLAIM_LEN_OFFSET       0x10
#define RECLAIM_BYTES_OFFSET     0x48
#define RECLAIM_MIN_BYTES_OFFSET 0x50
#define RECLAIM_HEAD_OFFSET      0x58
#define RECLAIM_BUSY_OFFSET      0x60
#define RECLAIM_TAIL_OFFSET      0x68
#define RECLAIM_ENTRIES_OFFSET   0x80
#define RECLAIM_CHUNK            512
#define RECLAIM_TRIM_THRESHOLD   (1 << 20)

enum {
	RECLAIM_FREE = 1,
	RECLAIM_DEALLOCATE = 2,
};

struct reclaim_entry {
	uint64_t address;
	uint32_t size;
	uint8_t action;
	uint8_t unused[3];
};

_Static_assert(sizeof(struct reclaim_entry) == 16, "mach_vm_reclaim_entry_s");

#define RECLAIM_ABANDONED_SECONDS 10

static uint8_t *reclaim_ring;
static mach_vm_size_t reclaim_ring_size;
static uint32_t reclaim_len;
static pthread_mutex_t reclaim_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t reclaim_last_update;
static uint64_t reclaim_unreported;

static uint64_t reclaim(uint64_t count, uint64_t limit);

static uint64_t
reclaim_take_unreported(void)
{
	return __atomic_exchange_n(&reclaim_unreported, 0, __ATOMIC_RELAXED);
}

static void *
reclaim_abandoned(void *unused)
{
	(void)unused;
	uint64_t frequency = absolute_per_second();
	for (;;) {
		sleep(RECLAIM_ABANDONED_SECONDS / 2);
		uint64_t last = __atomic_load_n(
				&reclaim_last_update, __ATOMIC_RELAXED);
		if (commpage_absolute_time() - last
				< RECLAIM_ABANDONED_SECONDS * frequency) {
			continue;
		}
		uint64_t bytes = reclaim(UINT64_MAX, UINT64_MAX);
		__atomic_fetch_add(
				&reclaim_unreported, bytes, __ATOMIC_RELAXED);
		__atomic_store_n(&reclaim_last_update, commpage_absolute_time(),
				__ATOMIC_RELAXED);
	}
	return NULL;
}

static uint64_t
absolute_per_second(void)
{
	uint32_t numer, denom;
	commpage_timebase(&numer, &denom);
	return 1000000000ull * denom / numer;
}

static uint64_t
reclaim(uint64_t count, uint64_t limit)
{
	uint64_t total = 0;
	pthread_mutex_lock(&reclaim_lock);
	while (reclaim_ring != NULL && count != 0 && total < limit) {
		uint64_t head = __atomic_load_n(
				reclaim_index(RECLAIM_HEAD_OFFSET),
				__ATOMIC_SEQ_CST);
		uint64_t tail = __atomic_load_n(
				reclaim_index(RECLAIM_TAIL_OFFSET),
				__ATOMIC_SEQ_CST);
		if (tail <= head) {
			break;
		}
		uint64_t take = tail - head;
		uint64_t busy;
		for (;;) {
			take = take < count ? take : count;
			take = take < RECLAIM_CHUNK ? take : RECLAIM_CHUNK;
			busy = head + take;
			__atomic_store_n(reclaim_index(RECLAIM_BUSY_OFFSET),
					busy, __ATOMIC_SEQ_CST);
			tail = __atomic_load_n(
					reclaim_index(RECLAIM_TAIL_OFFSET),
					__ATOMIC_SEQ_CST);
			if (tail >= busy) {
				break;
			}
			take = tail > head ? tail - head : 0;
			if (take == 0) {
				break;
			}
		}
		if (take == 0) {
			__atomic_store_n(reclaim_index(RECLAIM_BUSY_OFFSET),
					head, __ATOMIC_SEQ_CST);
			break;
		}
		struct reclaim_entry *entries
				= (struct reclaim_entry *)(reclaim_ring
						+ RECLAIM_ENTRIES_OFFSET);
		uint64_t done = 0;
		for (; done < take && total < limit; done++) {
			struct reclaim_entry entry
					= entries[(head + done) % reclaim_len];
			if (entry.address == 0 || entry.size == 0) {
				continue;
			}
			mach_vm_address_t start = entry.address & ~PAGE_MASK;
			mach_vm_address_t end = (entry.address + entry.size
								+ PAGE_MASK)
					& ~PAGE_MASK;
			if (entry.action == RECLAIM_DEALLOCATE) {
				munmap((void *)start, end - start);
			} else {
				madvise((void *)start, end - start, MADV_FREE);
			}
			total += entry.size;
		}
		__atomic_store_n(reclaim_index(RECLAIM_HEAD_OFFSET),
				head + done, __ATOMIC_SEQ_CST);
		__atomic_store_n(reclaim_index(RECLAIM_BUSY_OFFSET),
				head + done, __ATOMIC_SEQ_CST);
		count -= done;
		if (done < take) {
			break;
		}
	}
	pthread_mutex_unlock(&reclaim_lock);
	return total;
}

static uint64_t *
reclaim_index(size_t offset)
{
	return (uint64_t *)(reclaim_ring + offset);
}

kern_return_t
mach_vm_deferred_reclamation_buffer_allocate(task_t target_task,
		mach_vm_address_t *address, uint64_t *next_deadline,
		uint32_t len, uint32_t max_len)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_deferred_reclamation_buffer_allocate(%p, %p, "
			"%p, %p, %p)\n",
			(void *)target_task, (void *)address,
			(void *)next_deadline, (void *)len, (void *)max_len);
#endif
	if (len == 0 || max_len < len) {
		return KERN_INVALID_ARGUMENT;
	}
	pthread_mutex_lock(&reclaim_lock);
	if (reclaim_ring != NULL) {
		pthread_mutex_unlock(&reclaim_lock);
		return KERN_NO_SPACE;
	}
	mach_vm_address_t ring = 0;
	mach_vm_size_t size
			= (RECLAIM_ENTRIES_OFFSET
					  + (mach_vm_size_t)max_len
							  * sizeof(struct reclaim_entry)
					  + PAGE_MASK)
			& ~PAGE_MASK;
	kern_return_t kr = map_anonymous(&ring, size, 0, VM_FLAGS_ANYWHERE,
			VM_PROT_READ | VM_PROT_WRITE);
	if (kr == KERN_SUCCESS) {
		reclaim_ring = (uint8_t *)ring;
		reclaim_ring_size = size;
		reclaim_len = len;
		*address = ring;
		*next_deadline = reclaim_next_deadline();
		reclaim_last_update = commpage_absolute_time();
		sigset_t all, previous;
		sigfillset(&all);
		pthread_sigmask(SIG_SETMASK, &all, &previous);
		pthread_t thread;
		if (pthread_create(&thread, NULL, reclaim_abandoned, NULL)
				== 0) {
			pthread_detach(thread);
		}
		pthread_sigmask(SIG_SETMASK, &previous, NULL);
	}
	pthread_mutex_unlock(&reclaim_lock);
	return kr;
}

static uint64_t
reclaim_next_deadline(void)
{
	return commpage_absolute_time() + absolute_per_second();
}

kern_return_t
mach_vm_deferred_reclamation_buffer_flush(task_t target_task,
		uint32_t num_entries_to_reclaim, uint64_t *bytes_reclaimed,
		uint64_t *next_deadline)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_deferred_reclamation_buffer_flush(%p, %p, %p, "
			"%p)\n",
			(void *)target_task, (void *)num_entries_to_reclaim,
			(void *)bytes_reclaimed, (void *)next_deadline);
#endif
	if (reclaim_ring == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	*bytes_reclaimed = reclaim(num_entries_to_reclaim, UINT64_MAX)
			+ reclaim_take_unreported();
	*next_deadline = reclaim_next_deadline();
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_reclaim_update_kernel_accounting(
		uint64_t *bytes_reclaimed, uint64_t *next_deadline)
{
	if (reclaim_ring == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	uint64_t unneeded = __atomic_load_n(
			reclaim_index(RECLAIM_MIN_BYTES_OFFSET),
			__ATOMIC_RELAXED);
	uint64_t current = __atomic_load_n(
			reclaim_index(RECLAIM_BYTES_OFFSET), __ATOMIC_RELAXED);
	__atomic_store_n(reclaim_index(RECLAIM_MIN_BYTES_OFFSET), current,
			__ATOMIC_RELAXED);
	__atomic_store_n(&reclaim_last_update, commpage_absolute_time(),
			__ATOMIC_RELAXED);
	*bytes_reclaimed
			= (unneeded >= RECLAIM_TRIM_THRESHOLD
							  ? reclaim(UINT64_MAX,
									    unneeded)
							  : 0)
			+ reclaim_take_unreported();
	*next_deadline = reclaim_next_deadline();
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_reclaim_update_kernel_accounting: %llu of "
			"%llu "
			"bytes, head %llu, tail %llu\n",
			(unsigned long long)*bytes_reclaimed,
			(unsigned long long)unneeded,
			(unsigned long long)*reclaim_index(RECLAIM_HEAD_OFFSET),
			(unsigned long long)*reclaim_index(
					RECLAIM_TAIL_OFFSET));
#endif
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_range_create(vm_map_t target_task, mach_vm_range_flavor_t flavor,
		mach_vm_range_recipes_raw_t recipes,
		mach_msg_type_number_t recipesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_range_create(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)flavor, (void *)recipes,
			(void *)recipesCnt);
#endif
	unimplemented();
}

kern_return_t
mach_vm_deferred_reclamation_buffer_resize(task_t target_task, uint32_t new_len,
		uint64_t *bytes_reclaimed, uint64_t *next_deadline)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_deferred_reclamation_buffer_resize(%p, %p, "
			"%p, %p)\n",
			(void *)target_task, (void *)new_len,
			(void *)bytes_reclaimed, (void *)next_deadline);
#endif
	if (reclaim_ring == NULL || new_len == 0
			|| RECLAIM_ENTRIES_OFFSET
							+ (mach_vm_size_t)new_len
									* sizeof(struct reclaim_entry)
					> reclaim_ring_size) {
		return KERN_INVALID_ARGUMENT;
	}
	*bytes_reclaimed = reclaim(UINT64_MAX, UINT64_MAX)
			+ reclaim_take_unreported();
	pthread_mutex_lock(&reclaim_lock);
	reclaim_len = new_len;
	pthread_mutex_unlock(&reclaim_lock);
	*next_deadline = reclaim_next_deadline();
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_mach_vm_update_pointers_with_remote_tags(vm_map_t target,
		mach_vm_offset_list_t in_pointer_list,
		mach_msg_type_number_t in_pointer_listCnt,
		mach_vm_offset_list_t out_pointer_list,
		mach_msg_type_number_t *out_pointer_listCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_update_pointers_with_remote_tags(%"
			"p, %p, %p, %p, %p)\n",
			(void *)target, (void *)in_pointer_list,
			(void *)in_pointer_listCnt, (void *)out_pointer_list,
			(void *)out_pointer_listCnt);
#endif
	unimplemented();
}

kern_return_t
mach_vm_deferred_reclamation_buffer_query(task_read_t target,
		mach_vm_address_t *addr, mach_vm_size_t *size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_deferred_reclamation_buffer_query(%p, %p, "
			"%p)\n",
			(void *)target, (void *)addr, (void *)size);
#endif
	*addr = (mach_vm_address_t)reclaim_ring;
	*size = reclaim_ring_size;
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_mach_vm_reallocate(vm_map_t target_task, mach_vm_address_t src,
		mach_vm_size_t src_size, mach_vm_address_t *dst,
		mach_vm_size_t dst_size, mach_vm_offset_t align_mask,
		int options, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_reallocate(%p, %p, %p, %p, %p, %p, "
			"%p, %p)\n",
			(void *)target_task, (void *)src, (void *)src_size,
			(void *)dst, (void *)dst_size, (void *)align_mask,
			(void *)options, (void *)flags);
#endif
	kern_return_t kr = map_anonymous(dst, dst_size, align_mask,
			flags | VM_FLAGS_ANYWHERE,
			VM_PROT_READ | VM_PROT_WRITE);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	memcpy((void *)*dst, (void *)src,
			src_size < dst_size ? src_size : dst_size);
	mach_vm_address_t start = src & ~(mach_vm_address_t)PAGE_MASK;
	mach_vm_address_t end = (src + src_size + PAGE_MASK) & ~PAGE_MASK;
	munmap((void *)start, end - start);
	return KERN_SUCCESS;
}
