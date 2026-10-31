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

#include <fcntl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <ucontext.h>
#include <unistd.h>

#include "commpage.h"
#include "linker.h"
#include "shared_cache.h"
#include "syscall.h"
#include "sysroot.h"
#include "thread.h"

/* Temporary TLS for dyld */
static char dyld_ls[0x1000];

static int run(int argc, char *argv[], char *envp[]);
#ifdef __arm64__
static void reserve_high_address_space(void);
#endif
static uintptr_t build_stack(uint8_t *exe_base, const char *path, int argc,
		char *argv[], char *envp[]);
static int restart_without_aslr(char *argv[], char *envp[]);
static void raise_file_limit(void);

int
main(int argc, char *argv[], char *envp[])
{
	if (!(personality(0xffffffff) & ADDR_NO_RANDOMIZE)) {
		return restart_without_aslr(argv, envp);
	}

	raise_file_limit();

	if (syscall_dispatch_enable()) {
		return 1;
	}

	return run(argc, argv, envp);
}

static void
raise_file_limit(void)
{
	struct rlimit limit;
	if (getrlimit(RLIMIT_NOFILE, &limit) == 0
			&& limit.rlim_cur < limit.rlim_max) {
		limit.rlim_cur = limit.rlim_max;
		setrlimit(RLIMIT_NOFILE, &limit);
	}
}

#ifdef __arm64__
#define GUEST_ADDRESS_LIMIT (1ULL << 45)
#define STACK_HEADROOM      (256ULL << 20)

static void
reserve_high_address_space(void)
{
	static char maps[0x4000];
	int f = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
	if (f == -1) {
		return;
	}
	ssize_t length = 0, n;
	while (length < (ssize_t)sizeof(maps) - 1
			&& (n = read(f, maps + length,
					    sizeof(maps) - 1 - length))
					> 0) {
		length += n;
	}
	close(f);
	maps[length] = '\0';

	uint64_t cursor = GUEST_ADDRESS_LIMIT;
	for (char *line = maps; *line != '\0';) {
		char *next = strchrnul(line, '\n');
		unsigned long start, end;
		if (sscanf(line, "%lx-%lx", &start, &end) == 2
				&& end > cursor) {
			uint64_t gap_end = start;
			if (memmem(line, next - line, "[stack]", 7) != NULL) {
				gap_end = start > STACK_HEADROOM
						? start - STACK_HEADROOM
						: 0;
			}
			if (gap_end > cursor) {
				mmap((void *)cursor, gap_end - cursor,
						PROT_NONE,
						MAP_PRIVATE | MAP_ANON
								| MAP_NORESERVE
								| MAP_FIXED_NOREPLACE,
						-1, 0);
			}
			cursor = end;
		}
		line = *next == '\n' ? next + 1 : next;
	}
}
#endif

static int
restart_without_aslr(char *argv[], char *envp[])
{
	if (personality(personality(0xffffffff) | ADDR_NO_RANDOMIZE) == -1) {
		perror("personality");
		return 1;
	}

	execve("/proc/self/exe", argv, envp);
	perror("execve");
	return 1;
}

static int
run(int argc, char *argv[], char *envp[])
{
	if (argc < 3) {
		fprintf(stderr, "limbo: no path\n");
		return 1;
	}

#ifdef __arm64__
	reserve_high_address_space();
#endif
	if (sysroot_open() || syscall_handler_install()) {
		goto error;
	}
	prctl(PR_SET_NAME, basename(argv[1]));
	prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);

	/* Map the target executable and determine its interpreter */
	const char *dylinker_path = NULL;
	uintptr_t entry = 0;
	uint8_t *exe_base = linker_link(argv[1], &dylinker_path, &entry);
	if (exe_base == NULL) {
		fprintf(stderr, "limbo: failed to load binary %s\n", argv[1]);
		return 1;
	}
#ifdef __arm64__
	/* Leave pointer authentication off, as XNU does for an arm64 process,
	 * and for an arm64e one too. Linux gives each exec keys of its own, so
	 * with them on, the shared cache's signed pointers differ in every
	 * process and the prepared cache can't be shared. It must be off
	 * before the shared cache's pointers are signed */
	prctl(PR_PAC_SET_ENABLED_KEYS,
			PR_PAC_APIAKEY | PR_PAC_APIBKEY | PR_PAC_APDAKEY
					| PR_PAC_APDBKEY,
			0, 0, 0);
#endif

	/* Map the interpreter (dyld); a preload binary runs its own entry */
	char dylinker_host_path[PATH_MAX];
	if (dylinker_path != NULL) {
		/* Map the shared cache into our memory space, persisted across
		 * fork(); only dyld-based binaries consult it */
		if (shared_cache_mmap()) {
			fprintf(stderr,
					"limbo: could not map and rebase shared "
					"cache\n");
			return 1;
		}

		entry = 0;
		uint8_t *dyld_base = linker_link(
				sysroot_host_path(dylinker_path, 0,
						dylinker_host_path),
				NULL, &entry);
		if (dyld_base == NULL || entry == 0) {
			fprintf(stderr,
					"limbo: failed to load binary "
					"interpreter\n");
			return 1;
		}
	} else if (entry == 0) {
		fprintf(stderr, "limbo: binary has no entry point\n");
		return 1;
	}

	/* Set up the stack in the way that dyld expects */
	uintptr_t stack_base = build_stack(
			exe_base, argv[1], argc - 2, argv + 2, envp);
	if (stack_base == 0) {
		goto error;
	}

	if (commpage_mmap()) {
		goto error;
	}

	/* Set up the temporary zero-ed TLS storage for dyld */
	memset(dyld_ls, 0, sizeof(dyld_ls));
#ifdef __x86_64__
	struct thread_state state = {
			.rip = entry,
			.rsp = stack_base,
			.gs_base = (uint64_t)dyld_ls,
	};
#else
	struct thread_state state = {
			.pc = entry,
			.sp = stack_base,
			.tpidr = (dylinker_path != NULL) ? (uint64_t)dyld_ls : 0,
	};
#endif
	thread_enter(&state);
error:
	exit(1);
}

static uintptr_t
build_stack(uint8_t *exe_base, const char *path, int argc, char *argv[],
		char *envp[])
{
	/* Map 64mb of stack with  MAP_GROWSDOWN so that the stack automatically
	 * grows down */
	void *stack = mmap(
			(void *)((uintptr_t)VM_USRSTACK64 - 64 * 1024 * 1024),
			64 * 1024 * 1024, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED | MAP_ANON | MAP_GROWSDOWN, -1,
			0);
	if (stack == MAP_FAILED) {
		perror("mmap");
		return 0;
	}

	uint64_t entropy[8];
	if (getrandom(entropy, sizeof(entropy), 0) != sizeof(entropy)) {
		perror("getrandom");
		return 0;
	}

	char *apple[5];
	uint32_t applec = sizeof(apple) / sizeof(apple[0]);
	asprintf(&apple[0], "executable_path=%s", sysroot_guest_path(path));
	asprintf(&apple[1], "stack_guard=0x%lx", entropy[0]);
	asprintf(&apple[2], "malloc_entropy=0x%lx,0x%lx", entropy[1],
			entropy[2]);
	asprintf(&apple[3], "ptr_munge=0x%lx", entropy[3]);
	asprintf(&apple[4], "executable_boothash=%016lX%016lX%016lX%016lX",
			entropy[4], entropy[5], entropy[6], entropy[7]);

	uint32_t envc;
	for (envc = 0; envp[envc] != NULL; envc++)
		;

	uintptr_t stack_base = (uintptr_t)VM_USRSTACK64;
	stack_base -= (applec + 1) * sizeof(void *); /* Apple env pointers */
	stack_base -= (envc + 1) * sizeof(void *);   /* Env pointers */
	stack_base -= (argc + 1) * sizeof(void *);   /* Arg pointers */
	stack_base -= sizeof(long) * 2;              /* Main frame */
	stack_base = (stack_base & ~0xf);

	unsigned long *sp = (unsigned long *)stack_base;
	/* Main frame */
	*sp++ = (unsigned long)exe_base;
	*sp++ = (unsigned long)argc;

	/* Arguments */
	for (int i = 0; i < argc; i++) {
		*sp++ = (unsigned long)argv[i];
	}
	*sp++ = 0; /* End of arguments */

	/* Environment */
	for (uint32_t i = 0; i < envc; i++) {
		*sp++ = (unsigned long)envp[i];
	}
	*sp++ = 0; /* End of environment */

	/* Apple environment */
	for (uint32_t i = 0; i < applec; i++) {
		*sp++ = (unsigned long)apple[i];
	}
	*sp++ = 0; /* End of environment */

	return stack_base;
}
