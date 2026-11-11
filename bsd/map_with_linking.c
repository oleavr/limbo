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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <mach-o/fixup-chains.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "handler.h"
#include "xnu-errno.h"

struct mwl_region {
	int mwlr_fd;
	vm_prot_t mwlr_protections;
	uint64_t mwlr_file_offset;
	mach_vm_address_t mwlr_address;
	mach_vm_size_t mwlr_size;
};

struct mwl_info_hdr {
	uint32_t mwli_version;
	uint16_t mwli_page_size;
	uint16_t mwli_pointer_format;
	uint32_t mwli_binds_offset;
	uint32_t mwli_binds_count;
	uint32_t mwli_chains_offset;
	uint32_t mwli_chains_size;
	uint64_t mwli_slide;
	uint64_t mwli_image_address;
};

static void apply_fixups(const struct mwl_region *regions,
		uint32_t region_count, const struct mwl_info_hdr *info);
static bool contains(const struct mwl_region *regions, uint32_t region_count,
		uint64_t address);
static void apply_chain(uint8_t *location, const struct mwl_info_hdr *info,
		const uint64_t *binds);
#ifndef __x86_64__
static void apply_chain_arm64e(uint8_t *location,
		const struct mwl_info_hdr *info, const uint64_t *binds);
static uint64_t sign_pointer(uint64_t value, void *location, bool address_div,
		uint16_t diversity, uint32_t key);
#endif

int
sys_map_with_linking_np(user_addr_t regions, uint32_t region_count,
		user_addr_t blob, uint32_t blob_size)
{
	const struct mwl_region *r = regions;

	for (uint32_t i = 0; i < region_count; i++) {
		void *mapping = mmap((void *)r[i].mwlr_address, r[i].mwlr_size,
				PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
				r[i].mwlr_fd, r[i].mwlr_file_offset);
		if (mapping == MAP_FAILED) {
			return err_map(errno);
		}
	}

	apply_fixups(r, region_count, blob);

	for (uint32_t i = 0; i < region_count; i++) {
		if (mprotect((void *)r[i].mwlr_address, r[i].mwlr_size,
				    r[i].mwlr_protections & VM_PROT_ALL)
				== -1) {
			return err_map(errno);
		}
	}

	return 0;
}

static void
apply_fixups(const struct mwl_region *regions, uint32_t region_count,
		const struct mwl_info_hdr *info)
{
	const uint8_t *base = (const uint8_t *)info;
	const struct dyld_chained_starts_in_image *starts
			= (const void *)(base + info->mwli_chains_offset);
	const uint64_t *binds = (const void *)(base + info->mwli_binds_offset);

	for (uint32_t i = 0; i < starts->seg_count; i++) {
		if (starts->seg_info_offset[i] == 0) {
			continue;
		}

		const struct dyld_chained_starts_in_segment *segment
				= (const void *)((const uint8_t *)starts
						+ starts->seg_info_offset[i]);
		uint64_t segment_address = info->mwli_image_address
				+ segment->segment_offset;
		for (uint16_t page = 0; page < segment->page_count; page++) {
			uint16_t start = segment->page_start[page];
			uint64_t page_address = segment_address
					+ (uint64_t)page * segment->page_size;
			if (start == DYLD_CHAINED_PTR_START_NONE
					|| !contains(regions, region_count,
							page_address)) {
				continue;
			}
			apply_chain((uint8_t *)page_address + start, info,
					binds);
		}
	}
}

static bool
contains(const struct mwl_region *regions, uint32_t region_count,
		uint64_t address)
{
	for (uint32_t i = 0; i < region_count; i++) {
		if (address >= regions[i].mwlr_address
				&& address < regions[i].mwlr_address
								+ regions[i].mwlr_size) {
			return true;
		}
	}
	return false;
}

static void
apply_chain(uint8_t *location, const struct mwl_info_hdr *info,
		const uint64_t *binds)
{
#ifndef __x86_64__
	if (info->mwli_pointer_format != DYLD_CHAINED_PTR_64
			&& info->mwli_pointer_format
					!= DYLD_CHAINED_PTR_64_OFFSET) {
		apply_chain_arm64e(location, info, binds);
		return;
	}
#endif
	while (true) {
		union {
			uint64_t raw;
			struct dyld_chained_ptr_64_rebase rebase;
			struct dyld_chained_ptr_64_bind bind;
		} fixup;
		memcpy(&fixup.raw, location, sizeof(fixup.raw));

		uint64_t value;
		if (fixup.bind.bind) {
			value = binds[fixup.bind.ordinal] + fixup.bind.addend;
		} else {
			uint64_t target = fixup.rebase.target;
			if (info->mwli_pointer_format
					== DYLD_CHAINED_PTR_64_OFFSET) {
				target += info->mwli_image_address;
			} else {
				target += info->mwli_slide;
			}
			value = target | ((uint64_t)fixup.rebase.high8 << 56);
		}
		memcpy(location, &value, sizeof(value));

		if (fixup.rebase.next == 0) {
			break;
		}
		location += fixup.rebase.next * 4;
	}
}

#ifndef __x86_64__
static void
apply_chain_arm64e(uint8_t *location, const struct mwl_info_hdr *info,
		const uint64_t *binds)
{
	uint16_t format = info->mwli_pointer_format;
	uint32_t stride = (format == DYLD_CHAINED_PTR_ARM64E_KERNEL
					  || format == DYLD_CHAINED_PTR_ARM64E_FIRMWARE)
			? 4
			: 8;

	while (true) {
		union {
			uint64_t raw;
			struct dyld_chained_ptr_arm64e_rebase rebase;
			struct dyld_chained_ptr_arm64e_auth_rebase auth_rebase;
			struct dyld_chained_ptr_arm64e_bind24 bind;
			struct dyld_chained_ptr_arm64e_auth_bind24 auth_bind;
		} fixup;
		memcpy(&fixup.raw, location, sizeof(fixup.raw));

		uint64_t value;
		if (fixup.rebase.bind) {
			uint64_t target = binds[fixup.bind.ordinal];
			if (fixup.rebase.auth) {
				value = sign_pointer(target, location,
						fixup.auth_bind.addrDiv,
						fixup.auth_bind.diversity,
						fixup.auth_bind.key);
			} else {
				int64_t addend = fixup.bind.addend;
				if (addend & (1 << 18)) {
					addend |= ~(((int64_t)1 << 19) - 1);
				}
				value = target + addend;
			}
		} else if (fixup.rebase.auth) {
			uint64_t target = info->mwli_image_address
					+ fixup.auth_rebase.target;
			value = sign_pointer(target, location,
					fixup.auth_rebase.addrDiv,
					fixup.auth_rebase.diversity,
					fixup.auth_rebase.key);
		} else {
			uint64_t target = fixup.rebase.target;
			if (format == DYLD_CHAINED_PTR_ARM64E
					|| format == DYLD_CHAINED_PTR_ARM64E_FIRMWARE) {
				target += info->mwli_slide;
			} else {
				target += info->mwli_image_address;
			}
			value = target | ((uint64_t)fixup.rebase.high8 << 56);
		}
		memcpy(location, &value, sizeof(value));

		if (fixup.rebase.next == 0) {
			break;
		}
		location += fixup.rebase.next * stride;
	}
}

static uint64_t
sign_pointer(uint64_t value, void *location, bool address_div,
		uint16_t diversity, uint32_t key)
{
	uint64_t modifier = diversity;
	if (address_div) {
		modifier = ((uint64_t)location & 0x0000ffffffffffffULL)
				| ((uint64_t)diversity << 48);
	}

	switch (key) {
	case 0:
		asm("pacia %0, %1" : "+r"(value) : "r"(modifier));
		break;
	case 1:
		asm("pacib %0, %1" : "+r"(value) : "r"(modifier));
		break;
	case 2:
		asm("pacda %0, %1" : "+r"(value) : "r"(modifier));
		break;
	case 3:
		asm("pacdb %0, %1" : "+r"(value) : "r"(modifier));
		break;
	}
	return value;
}
#endif
