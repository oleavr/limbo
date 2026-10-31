/*
 * Copyright © 2021 Keegan Saunders
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

#include <arpa/inet.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/machine/thread_status.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "linker.h"

#ifndef MAP_32BIT
#define MAP_32BIT 0
#endif

#ifdef __x86_64__
#define LIMBO_CPU_TYPE CPU_TYPE_X86_64
#else
#define LIMBO_CPU_TYPE CPU_TYPE_ARM64
#endif

static size_t image_span(const struct mach_header_64 *header);
static struct mach_header_64 *header_compatible(struct fat_header *fat);
static void zero_bss(struct segment_command_64 *cmd, uintptr_t base_address);

/*
 * Enumerate Mach-O load commands and load into memory
 */
uint8_t *
linker_link(const char *path, const char **dylinker_path, uintptr_t *entry)
{
	void *base = NULL;
	size_t base_size = 0;
	int f = 0;

	base = linker_mmap(path, &base_size, &f);
	if (base == NULL) {
		goto error;
	}

	struct fat_header *fat = (struct fat_header *)base;
	struct mach_header_64 *header;
	if (fat->magic == MH_MAGIC_64) {
		header = (struct mach_header_64 *)base;
		if (header->cputype != LIMBO_CPU_TYPE) {
			goto error;
		}
	} else {
		header = header_compatible(fat);
	}

	if (header == NULL || header->magic != MH_MAGIC_64) {
		goto error;
	}

	uint32_t offset = (uint32_t)((char *)header - (char *)fat);
	size_t span = image_span(header);

	uintptr_t base_address = 0;
#ifdef NDEBUG
	/* HACK: This is kind of ugly, but in debug we want to disable dyld ASLR
	 */
	if (strcmp(path, "/usr/lib/dyld") == 0) {
		base_address = 0x10000000000;
	}
#endif

	/* Find a load address for the Mach-O, preferrably a low address */
	/* TODO: This code is sketchy, but since it is used during start up
	 * it should not race and lose */
	if (base_address == 0) {
#ifdef __x86_64__
		void *landing = mmap(NULL, 0x1000000, PROT_READ,
				MAP_PRIVATE | MAP_ANON | MAP_32BIT, -1, 0);
		if (landing == MAP_FAILED) {
			goto error;
		}
		munmap(landing, 0x1000000);
		base_address = (uintptr_t)landing;
#else
		for (uintptr_t candidate = 0x10000000;
				candidate < 0x80000000;
				candidate += 0x1000000) {
			void *landing = mmap((void *)candidate, span, PROT_READ,
					MAP_PRIVATE | MAP_ANON
							| MAP_FIXED_NOREPLACE,
					-1, 0);
			if (landing == (void *)candidate) {
				munmap(landing, span);
				base_address = candidate;
				break;
			}
			if (landing != MAP_FAILED) {
				munmap(landing, span);
			}
		}
		if (base_address == 0) {
			goto error;
		}
#endif
	}
	uintptr_t start = 0;

	/* Enumerate and interpret each load command in the Mach-O */
	struct load_command *command = (struct load_command *)(header + 1);
	for (uint32_t i = 0; i < header->ncmds; i++) {
		switch (command->cmd) {
		case LC_SEGMENT_64: {
			struct segment_command_64 *cmd
					= (struct segment_command_64 *)command;

			unsigned long prot = 0;
			if (cmd->initprot & VM_PROT_READ) {
				prot |= PROT_READ;
			}
			if (cmd->initprot & VM_PROT_WRITE) {
				prot |= PROT_WRITE;
			}
			if (cmd->initprot & VM_PROT_EXECUTE) {
				prot |= PROT_EXEC;
			}

			/* HACK: Do not map __PAGEZERO */
			if (cmd->vmsize == 0x100000000) {
				break;
			}

			if (cmd->flags & SG_PROTECTED_VERSION_1) {
				fprintf(stderr,
						"limbo: %s: the %.16s segment is "
						"Apple-protected (encrypted): it can't run\n",
						path, cmd->segname);
				goto error;
			}

			if (cmd->vmsize == 0) {
				break;
			}

			if (start == 0) {
				start = base_address + cmd->vmaddr;
			}

			uint64_t page = (uint64_t)getpagesize();
			uint64_t in_file = (cmd->filesize + page - 1)
					& ~(page - 1);
			if (in_file > cmd->vmsize) {
				in_file = cmd->vmsize;
			}
			uint8_t *at = (uint8_t *)(base_address + cmd->vmaddr);
			if (in_file != 0
					&& mmap(at, in_file, prot,
							   MAP_PRIVATE | MAP_FIXED_NOREPLACE,
							   f,
							   offset + cmd->fileoff)
							== MAP_FAILED) {
				goto error;
			}
			if (in_file < cmd->vmsize
					&& mmap(at + in_file,
							   cmd->vmsize - in_file,
							   prot,
							   MAP_PRIVATE | MAP_ANON
									   | MAP_FIXED_NOREPLACE,
							   -1, 0)
							== MAP_FAILED) {
				goto error;
			}

			/* HACK: Zero the BSS */
			zero_bss(cmd, base_address);
		} break;
		/* The dynamic linker that handles this binary */
		case LC_LOAD_DYLINKER: {
			struct dylinker_command *cmd
					= (struct dylinker_command *)command;
			if (dylinker_path) {
				/* Read dylinker path from the Mach-O instead */
				*dylinker_path = (char *)cmd + cmd->name.offset
						- (char *)header
						+ (char *)start;
			}
		} break;
		case LC_UNIXTHREAD: {
			uint32_t *flavor = (uint32_t *)(command + 1);
#ifdef __x86_64__
			if (*flavor == x86_THREAD_STATE64) {
				_STRUCT_X86_THREAD_STATE64 *state
						= (_STRUCT_X86_THREAD_STATE64 *)(
								flavor + 2);
				if (entry) {
					*entry = base_address + state->rip;
				}
			}
#else
			if (*flavor == ARM_THREAD_STATE64) {
				_STRUCT_ARM_THREAD_STATE64 *state
						= (_STRUCT_ARM_THREAD_STATE64 *)(
								flavor + 2);
				if (entry) {
					*entry = base_address + state->pc;
				}
			}
#endif
		} break;
		}

		command = (struct load_command *)((char *)command
				+ command->cmdsize);
	}

	close(f);
	munmap(base, base_size);
	return (uint8_t *)start;
error:
	if (f > 0) {
		close(f);
	}
	if (base != NULL) {
		munmap(base, base_size);
	}
	return NULL;
}

/*
 * Map a file into memory as read-only
 */
uint8_t *
linker_mmap(const char *path, size_t *size, int *handle)
{
	int f;
	struct stat s;
	uint8_t *base = NULL;

	f = open(path, O_RDONLY);
	if (f < 0) {
		goto error;
	}

	if (fstat(f, &s) < 0) {
		goto error;
	}

	*size = s.st_size;
	base = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, f, 0);
	if (base == MAP_FAILED) {
		goto error;
	}

	if (handle) {
		*handle = f;
	} else {
		close(f);
	}
	return base;
error:
	if (f > 0)
		close(f);
	return NULL;
}

/*
 * Zero the BSS segments in a mapped Mach-O
 *
 * During the open(2) call, the handler attempts to check and call
 * _system_version_compat_check_path_suffix which is located in the __common
 * section. This is located in bss, so you'd think that dyld would zero its own
 * bss on entry. Seems like it doesn't, so this will have to do for now
 */
static void
zero_bss(struct segment_command_64 *cmd, uintptr_t base_address)
{
	struct section_64 *sects = (struct section_64 *)(cmd + 1);
	for (uint32_t j = 0; j < cmd->nsects; j++) {
		if (strncmp(sects[j].sectname, SECT_BSS, 16) == 0) {
			memset((void *)(base_address + sects[j].addr), 0,
					sects[j].size);
			continue;
		}

		if (strncmp(sects[j].sectname, SECT_COMMON, 16) == 0) {
			memset((void *)(base_address + sects[j].addr), 0,
					sects[j].size);
		}
	}
}

static size_t
image_span(const struct mach_header_64 *header)
{
	uint64_t low = UINT64_MAX;
	uint64_t high = 0;
	const struct load_command *command
			= (const struct load_command *)(header + 1);
	for (uint32_t i = 0; i < header->ncmds; i++) {
		if (command->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *cmd
					= (const struct segment_command_64 *)command;

			if (cmd->vmsize != 0x100000000 && cmd->vmsize != 0) {
				if (cmd->vmaddr < low) {
					low = cmd->vmaddr;
				}
				if (cmd->vmaddr + cmd->vmsize > high) {
					high = cmd->vmaddr + cmd->vmsize;
				}
			}
		}
		command = (const struct load_command *)((const char *)command
				+ command->cmdsize);
	}
	size_t span = (high > low) ? high - low : 0x1000000;
	return span < 0x1000000 ? 0x1000000 : span;
}

/*
 * Thin a Fat Mach-O and return the first compatible architecture header
 *
 * The Fat Mach-O header must be the beginning of the mapping
 */
static struct mach_header_64 *
header_compatible(struct fat_header *fat)
{
	if (ntohl(fat->magic) != FAT_MAGIC) {
		return NULL;
	}

	uint32_t nfat_arch = ntohl(fat->nfat_arch);

	struct mach_header_64 *header = NULL;

	/* Find a matching Mach-O by enumerating the Fat Mach-O headers */
	struct fat_arch *fat_archs = (struct fat_arch *)(fat + 1);
	for (uint32_t i = 0; i < nfat_arch; i++) {
		uint32_t cputype = ntohl(fat_archs[i].cputype);
		uint32_t offset = ntohl(fat_archs[i].offset);
		if (cputype == LIMBO_CPU_TYPE) {
			header = (struct mach_header_64 *)((char *)fat
					+ offset);
			break;
		}
	}

	return header;
}
