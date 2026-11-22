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

#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/ldsyms.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "check.h"

#ifdef __arm64__
#define CPU_NUMBER_MASK 7

typedef uintptr_t (*reader_t)(void);

static uintptr_t read_thread_pointer(void);
static void check_names_the_thread(uintptr_t thread_pointer);
static void check_mapped_file(void);
static void *check_on_thread(void *arg);

int
main(void)
{
	check_names_the_thread(read_thread_pointer());
	check_mapped_file();
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, check_on_thread, NULL) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	printf("thread_pointer: ok\n");
	return 0;
}

__attribute__((noinline)) static uintptr_t
read_thread_pointer(void)
{
	uintptr_t value;
	__asm__("mrs %0, tpidrro_el0" : "=r"(value));
	return value;
}

static void
check_names_the_thread(uintptr_t thread_pointer)
{
	pthread_t *self = (pthread_t *)(thread_pointer
			& ~(uintptr_t)CPU_NUMBER_MASK);
	CHECK(*self == pthread_self());
}

static void
check_mapped_file(void)
{
	char path[PATH_MAX];
	uint32_t size = sizeof(path);
	CHECK(_NSGetExecutablePath(path, &size) == 0);
	int fd = open(path, O_RDONLY);
	CHECK(fd != -1);
	size_t offset = (uintptr_t)read_thread_pointer
			- (uintptr_t)&_mh_execute_header;
	size_t length = (offset + 2 * getpagesize()) & ~(getpagesize() - 1);
	uint8_t *image = mmap(NULL, length, PROT_READ | PROT_EXEC, MAP_PRIVATE,
			fd, 0);
	CHECK(image != MAP_FAILED);
	check_names_the_thread(((reader_t)(image + offset))());
	CHECK(munmap(image, length) == 0);

	uint8_t *reserved = mmap(
			NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	CHECK(reserved != MAP_FAILED);
	image = mmap(reserved, length, PROT_READ | PROT_EXEC,
			MAP_PRIVATE | MAP_FIXED, fd, 0);
	CHECK(image == reserved && close(fd) == 0);
	check_names_the_thread(((reader_t)(image + offset))());
	CHECK(munmap(image, length) == 0);
}

static void *
check_on_thread(void *arg)
{
	(void)arg;
	check_names_the_thread(read_thread_pointer());
	check_mapped_file();
	return NULL;
}
#else
int
main(void)
{
	printf("thread_pointer: skipped (arm64's register)\n");
	return 77;
}
#endif
