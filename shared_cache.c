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

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <mach/machine.h>
#include <mach/vm_prot.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "shared_cache.h"
#include "sidt.h"
#include "sysroot.h"

#define PREPARED_ROOT "/private/var/db/limbo"
#define PREPARED_DIRECTORY_SIZE                                                \
	(sizeof(PREPARED_ROOT "/") + 36 + sizeof("-nosidt"))
#define PAGE_SIZE 0x1000

struct prepared_trampolines {
	uint64_t address;
	uint64_t size;
};

void *shared_cache_start = NULL;
int shared_cache_cpu_subtype = CPU_SUBTYPE_X86_64_ALL;

static int reserve_shared_region(dyld_cache_header_t *header);
static const char *prepared_cache_path(const dyld_cache_header_t *header,
		const char *name, char *path, char *buffer);
static int map_cache(
		const char *path, dyld_cache_header_t *header, bool prepared);
static void prepare_cache(const char *path, dyld_cache_header_t *header);
static void make_prepared_root(void);
static int map_dynamic_data(
		int f, const char *path, dyld_cache_header_t *header);
static void prepared_cache_directory(
		const dyld_cache_header_t *header, char *buffer);
static int map_cache_file(int f, dyld_cache_header_t *header, bool prepared);
static int map_subcaches(
		const char *path, dyld_cache_header_t *header, bool prepared);
static void prepare_cache_locked(const char *path, const char *directory,
		dyld_cache_header_t *header);
static int map_cache_mapping(
		int f, dyld_cache_mapping_and_slide_info_t *m, bool prepared);
static int map_trampolines(int f, dyld_cache_header_t *header);
static const dyld_subcache_entry_t *subcache_entries(
		const dyld_cache_header_t *header);
static int map_subcache(const char *path, const dyld_subcache_entry_t *entry,
		bool prepared);
static void remove_directory(const char *path);
static int prepare_cache_directory(const char *source, const char *directory,
		const dyld_cache_header_t *header);
static void rebase_page(dyld_cache_slide_info2_t *info, uint64_t address);
#ifndef __x86_64__
static void rebase_page_v5(dyld_cache_slide_info5_t *info, uint64_t address);
static uint64_t sign_pointer(uint64_t value, void *location, bool address_div,
		uint16_t diversity, bool key_is_data);
static void pac_key_fingerprint(uint64_t fingerprint[2]);
static bool prepared_cache_matches_key(const dyld_cache_header_t *header);
static int write_pac_fingerprint(const char *directory_host);
static void patch_thread_self_reads(uint64_t address, uint64_t size);
#endif
static uint64_t trampolines_offset(const dyld_cache_header_t *header);
static int prepare_subcache(const char *source, const char *destination,
		const dyld_subcache_entry_t *entry,
		const dyld_cache_header_t *main_header);
static int prepare_cache_file(const char *source, const char *destination,
		const dyld_cache_header_t *main_header);
static void rebase_chain(uint8_t *page_content, uint16_t page_start_offset,
		dyld_cache_slide_info2_t *info);
static int clone_file(int source, int destination);
static int write_prepared_file(int source, int destination,
		const dyld_cache_header_t *main_header);
static int write_mappings(int f,
		const dyld_cache_mapping_and_slide_info_t *mappings,
		uint32_t count, const dyld_cache_header_t *main_header,
		struct sidt_patches *patches);
static int write_trampolines(int f, const dyld_cache_header_t *header,
		const struct sidt_patches *patches);
#ifdef __x86_64__
static int patch_text(int f, const dyld_cache_mapping_and_slide_info_t *text,
		const dyld_cache_header_t *main_header,
		struct sidt_patches *patches);
static void find_patches(struct sidt_patches *patches,
		const dyld_cache_mapping_and_slide_info_t *text,
		const dyld_cache_header_t *main_header);
static int write_patches(int f, const struct sidt_patches *patches,
		const dyld_cache_mapping_and_slide_info_t *text);
static int fix_eh_frame_personalities(int f,
		const dyld_cache_mapping_and_slide_info_t *text);
#endif
static int write_all(int f, const void *data, size_t size, uint64_t offset);

static const char *
find_cache(const char *name, char path[PATH_MAX], char *buffer)
{
	static const char *const folders[] = {
			"/System/Cryptexes/OS/System/Library/dyld",
			"/System/Library/dyld",
	};
	for (size_t i = 0; i < sizeof(folders) / sizeof(folders[0]); i++) {
		snprintf(path, PATH_MAX, "%s/%s", folders[i], name);
		const char *host_path = sysroot_host_path(path, 0, buffer);
		if (host_path != NULL && access(host_path, F_OK) == 0) {
			return host_path;
		}
	}
	return NULL;
}

int
shared_cache_mmap(void)
{
	char path[PATH_MAX], buffer[PATH_MAX];
#ifdef __x86_64__
	const char *host_path
			= find_cache("dyld_shared_cache_x86_64", path, buffer);
	if (host_path == NULL) {
		host_path = find_cache(
				"dyld_shared_cache_x86_64h", path, buffer);
		shared_cache_cpu_subtype = CPU_SUBTYPE_X86_64_H;
	}
#else
	const char *host_path
			= find_cache("dyld_shared_cache_arm64e", path, buffer);
	shared_cache_cpu_subtype = CPU_SUBTYPE_ARM64E;
#endif
	if (host_path == NULL) {
		fprintf(stderr,
				"limbo: no shared cache in the sysroot's "
				"System/Cryptexes/OS/System/Library/dyld or "
				"System/Library/dyld\n");
		return 1;
	}

	int f = open(host_path, O_RDONLY);
	if (f == -1) {
		perror("open");
		return 1;
	}

	dyld_cache_header_t header;
	if (pread(f, &header, sizeof(header), 0) != sizeof(header)) {
		perror("pread");
		goto error;
	}

	if (reserve_shared_region(&header)) {
		goto error;
	}

	char prepared_path[PATH_MAX], prepared_buffer[PATH_MAX];
	const char *prepared_host_path = prepared_cache_path(&header,
			strrchr(path, '/') + 1, prepared_path, prepared_buffer);
	bool usable = true;
#ifndef __x86_64__
	usable = prepared_cache_matches_key(&header);
#endif
	if (!usable || map_cache(prepared_host_path, &header, true) != 0) {
		if (map_cache(host_path, &header, false)) {
			goto error;
		}
		prepare_cache(host_path, &header);
	}

	if (map_dynamic_data(f, path, &header)) {
		goto error;
	}

	close(f);
	shared_cache_start = (void *)header.sharedRegionStart;
	return 0;
error:
	close(f);
	return 1;
}

static int
reserve_shared_region(dyld_cache_header_t *header)
{
	void *region = mmap((void *)header->sharedRegionStart,
			header->sharedRegionSize, PROT_NONE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE
					| MAP_NORESERVE,
			-1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	return 0;
}

static const char *
prepared_cache_path(const dyld_cache_header_t *header, const char *name,
		char *path, char *buffer)
{
	char directory[PREPARED_DIRECTORY_SIZE];
	prepared_cache_directory(header, directory);
	snprintf(path, PATH_MAX, "%s/%s", directory, name);
	return sysroot_host_path(path, 0, buffer);
}

static int
map_cache(const char *path, dyld_cache_header_t *header, bool prepared)
{
	int f = open(path, O_RDONLY | O_CLOEXEC);
	if (f == -1) {
		return 1;
	}

	int result = map_cache_file(f, header, prepared)
			|| map_subcaches(path, header, prepared);
	close(f);
	return result;
}

static void
prepare_cache(const char *path, dyld_cache_header_t *header)
{
	char directory[PREPARED_DIRECTORY_SIZE];
	char lock_path[PATH_MAX], buffer[PATH_MAX];
	prepared_cache_directory(header, directory);
	snprintf(lock_path, sizeof(lock_path), "%s.lock", directory);

	make_prepared_root();
	int lock = open(sysroot_host_path(lock_path, 0, buffer),
			O_CREAT | O_RDWR | O_CLOEXEC, 0644);
	if (lock == -1) {
		return;
	}
	if (flock(lock, LOCK_EX | LOCK_NB) == 0) {
		prepare_cache_locked(path, directory, header);
	}
	close(lock);
}

static void
make_prepared_root(void)
{
	char path[] = PREPARED_ROOT, buffer[PATH_MAX];
	for (char *c = path + 1;; c++) {
		if (*c != '/' && *c != '\0') {
			continue;
		}
		char saved = *c;
		*c = '\0';
		mkdir(sysroot_host_path(path, 0, buffer), 0755);
		if (saved == '\0') {
			return;
		}
		*c = saved;
	}
}

static int
map_dynamic_data(int f, const char *path, dyld_cache_header_t *header)
{
	if (header->mappingOffset
			<= offsetof(dyld_cache_header_t, dynamicDataMaxSize)) {
		return 0;
	}

	struct statfs fs;
	struct stat st;
	if (fstatfs(f, &fs) == -1 || fstat(f, &st) == -1) {
		perror("stat");
		return 1;
	}

	dyld_cache_dynamic_data_header_t *data = mmap(
			(void *)(header->sharedRegionStart
					+ header->dynamicDataOffset),
			header->dynamicDataMaxSize, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
	if (data == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	strcpy(data->magic, "dyld_data    v4");
	memcpy(&data->fsId, &fs.f_fsid, sizeof(data->fsId));
	data->fsObjId = st.st_ino;
	data->cachePathOffset
			= offsetof(dyld_cache_dynamic_data_header_t, strings);
	data->cachePathSize = strlen(path) + 1;
	memcpy(data->strings, path, data->cachePathSize);

	if (mprotect(data, header->dynamicDataMaxSize, PROT_READ) == -1) {
		perror("mprotect");
		return 1;
	}
	return 0;
}

static void
prepared_cache_directory(const dyld_cache_header_t *header, char *buffer)
{
	const uint8_t *u = header->uuid;
#ifdef __x86_64__
	const char *suffix = __builtin_cpu_supports("rdpid") ? "" : "-nosidt";
#else
	const char *suffix = "";
#endif
	snprintf(buffer, PREPARED_DIRECTORY_SIZE,
			PREPARED_ROOT "/%02X%02X%02X%02X-%02X%02X-%02X%02X-"
				      "%02X%02X-%02X%02X%02X%02X%02X%02X%s",
			u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8],
			u[9], u[10], u[11], u[12], u[13], u[14], u[15], suffix);
}

#ifndef __x86_64__
static bool
prepared_cache_matches_key(const dyld_cache_header_t *header)
{
	char directory[PREPARED_DIRECTORY_SIZE], path[PATH_MAX], buffer[PATH_MAX];
	prepared_cache_directory(header, directory);
	snprintf(path, sizeof(path), "%s/pac-key", directory);
	int f = open(sysroot_host_path(path, 0, buffer), O_RDONLY | O_CLOEXEC);
	if (f == -1) {
		return false;
	}
	uint64_t stored[2], current[2];
	pac_key_fingerprint(current);
	bool match = read(f, stored, sizeof(stored)) == (ssize_t)sizeof(stored)
			&& stored[0] == current[0] && stored[1] == current[1];
	close(f);
	return match;
}
#endif

static int
map_cache_file(int f, dyld_cache_header_t *header, bool prepared)
{
	uint32_t count = header->mappingWithSlideCount;
	dyld_cache_mapping_and_slide_info_t mappings[count];
	ssize_t size = sizeof(mappings);
	if (pread(f, mappings, size, header->mappingWithSlideOffset) != size) {
		perror("pread");
		return 1;
	}

	for (uint32_t i = 0; i < count; i++) {
		if (map_cache_mapping(f, &mappings[i], prepared)) {
			return 1;
		}
	}
	return prepared ? map_trampolines(f, header) : 0;
}

static int
map_subcaches(const char *path, dyld_cache_header_t *header, bool prepared)
{
	const dyld_subcache_entry_t *entries = subcache_entries(header);
	for (uint32_t i = 0; i < header->subCacheArrayCount; i++) {
		if (map_subcache(path, &entries[i], prepared)) {
			return 1;
		}
	}
	return 0;
}

static void
prepare_cache_locked(const char *path, const char *directory,
		dyld_cache_header_t *header)
{
	char staging[PATH_MAX], staging_host[PATH_MAX], final_host[PATH_MAX];
	char buffer[PATH_MAX];
	snprintf(final_host, sizeof(final_host), "%s",
			sysroot_host_path(directory, 0, buffer));
	if (access(final_host, F_OK) == 0) {
		return;
	}
	snprintf(staging, sizeof(staging), "%s.tmp", directory);
	snprintf(staging_host, sizeof(staging_host), "%s",
			sysroot_host_path(staging, 0, buffer));

	remove_directory(staging_host);
	if (mkdir(staging_host, 0755) != 0
			|| prepare_cache_directory(path, staging_host, header)
					!= 0) {
		return;
	}
#ifndef __x86_64__
	if (write_pac_fingerprint(staging_host) != 0) {
		return;
	}
#endif
	rename(staging_host, final_host);
}

#ifndef __x86_64__
static int
write_pac_fingerprint(const char *directory_host)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/pac-key", directory_host);
	int f = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
	if (f == -1) {
		return 1;
	}
	uint64_t fingerprint[2];
	pac_key_fingerprint(fingerprint);
	int result = write(f, fingerprint, sizeof(fingerprint))
			!= (ssize_t)sizeof(fingerprint);
	close(f);
	return result;
}
#endif

static int
map_cache_mapping(int f, dyld_cache_mapping_and_slide_info_t *m, bool prepared)
{
	if (prepared || m->slideInfoFileSize == 0) {
#ifndef __x86_64__
		if (!prepared && (m->initProt & VM_PROT_EXECUTE)) {
			void *base = mmap((void *)m->address, m->size,
					PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_FIXED, f, m->fileOffset);
			if (base == MAP_FAILED) {
				perror("mmap");
				return 1;
			}
			patch_thread_self_reads(m->address, m->size);
			if (mprotect(base, m->size, m->initProt) == -1) {
				perror("mprotect");
				return 1;
			}
			return 0;
		}
#endif
		void *base = mmap((void *)m->address, m->size, m->initProt,
				MAP_PRIVATE | MAP_FIXED, f, m->fileOffset);
		if (base == MAP_FAILED) {
			perror("mmap");
			return 1;
		}
		return 0;
	}

	void *base = mmap((void *)m->address, m->size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED, f, m->fileOffset);
	if (base == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	void *info = malloc(m->slideInfoFileSize);
	ssize_t size = m->slideInfoFileSize;
	if (pread(f, info, size, m->slideInfoFileOffset) != size) {
		perror("pread");
		free(info);
		return 1;
	}

	uint32_t version = *(uint32_t *)info;
	if (version == 2) {
		dyld_cache_slide_info2_t *info2 = info;
		assert(info2->page_size == 0x1000);
		assert(info2->delta_mask == 0x00ffff0000000000);
		assert(info2->page_starts_count == m->size / info2->page_size);
		rebase_page(info2, m->address);
	}
#ifndef __x86_64__
	else if (version == 5) {
		rebase_page_v5(info, m->address);
	}
#endif
	else {
		fprintf(stderr, "limbo: unsupported slide info v%u\n", version);
		free(info);
		return 1;
	}
	free(info);

	if (mprotect(base, m->size, m->initProt) == -1) {
		perror("mprotect");
		return 1;
	}
	return 0;
}

static int
map_trampolines(int f, dyld_cache_header_t *header)
{
	uint64_t offset = trampolines_offset(header);
	struct prepared_trampolines t;
	if (pread(f, &t, sizeof(t), offset) != sizeof(t)) {
		return 1;
	}
	if (t.size == 0) {
		return 0;
	}

	void *base = mmap((void *)t.address, t.size, PROT_READ | PROT_EXEC,
			MAP_PRIVATE | MAP_FIXED, f, offset + PAGE_SIZE);
	if (base == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	return 0;
}

static const dyld_subcache_entry_t *
subcache_entries(const dyld_cache_header_t *header)
{
	return (const void *)((const uint8_t *)header->sharedRegionStart
			+ header->subCacheArrayOffset);
}

static int
map_subcache(const char *path, const dyld_subcache_entry_t *entry,
		bool prepared)
{
	char subcache_path[PATH_MAX];
	snprintf(subcache_path, sizeof(subcache_path), "%s%s", path,
			entry->fileSuffix);

	int f = open(subcache_path, O_RDONLY | O_CLOEXEC);
	if (f == -1) {
		perror("open");
		return 1;
	}

	dyld_cache_header_t header;
	int result = 1;
	if (pread(f, &header, sizeof(header), 0) != sizeof(header)) {
		perror("pread");
	} else {
		result = map_cache_file(f, &header, prepared);
	}

	close(f);
	return result;
}

static void
remove_directory(const char *path)
{
	DIR *dir = opendir(path);
	if (dir == NULL) {
		return;
	}
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		unlinkat(dirfd(dir), entry->d_name, 0);
	}
	closedir(dir);
	rmdir(path);
}

static int
prepare_cache_directory(const char *source, const char *directory,
		const dyld_cache_header_t *header)
{
	const dyld_cache_header_t *main_header
			= (const void *)header->sharedRegionStart;
	char destination[PATH_MAX];
	snprintf(destination, sizeof(destination), "%s/%s", directory,
			strrchr(source, '/') + 1);
	if (prepare_cache_file(source, destination, main_header)) {
		return 1;
	}

	const dyld_subcache_entry_t *entries = subcache_entries(header);
	for (uint32_t i = 0; i < header->subCacheArrayCount; i++) {
		if (prepare_subcache(source, destination, &entries[i],
				    main_header)) {
			return 1;
		}
	}
	return 0;
}

static int
prepare_subcache(const char *source, const char *destination,
		const dyld_subcache_entry_t *entry,
		const dyld_cache_header_t *main_header)
{
	char subcache_source[PATH_MAX], subcache_destination[PATH_MAX];
	snprintf(subcache_source, sizeof(subcache_source), "%s%s", source,
			entry->fileSuffix);
	snprintf(subcache_destination, sizeof(subcache_destination), "%s%s",
			destination, entry->fileSuffix);
	return prepare_cache_file(
			subcache_source, subcache_destination, main_header);
}

/*
 * For details on how sliding the dyld cache works, see dyld_cache_slide_info2
 * in dyld_cache_format.h
 */
static void
rebase_page(dyld_cache_slide_info2_t *info, uint64_t address)
{
	uint16_t *page_starts = (uint16_t *)((uintptr_t)info
			+ info->page_starts_offset);
	uint16_t *page_extras = (uint16_t *)((uintptr_t)info
			+ info->page_extras_offset);

	for (uint32_t j = 0; j < info->page_starts_count; j++) {
		uint8_t *page_content
				= (uint8_t *)(address + j * info->page_size);
		uint16_t page_entry = page_starts[j];
		uint16_t page_start_offset = page_entry << 2;

		if (page_entry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
			continue;
		}

		if (page_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) {
			/* Multiple linked-lists are needed to rebase */
			uint16_t chain_index = page_entry & 0x3fff;
			uint16_t extra;

			/* High-level algorithm described in dyld_cache_format.h
			 */
			do {
				uint16_t page_start_offset;

				assert(chain_index < info->page_extras_count);

				extra = page_extras[chain_index];
				page_start_offset = (uint16_t)(
						(extra & 0x3fff) << 2);

				rebase_chain(page_content, page_start_offset,
						info);

				chain_index++;
			} while (!(extra & DYLD_CACHE_SLIDE_PAGE_ATTR_END));
		} else {
			/* Standalone linked-list provides rebase details */
			rebase_chain(page_content, page_start_offset, info);
		}
	}
}

#ifndef __x86_64__
static void
rebase_page_v5(dyld_cache_slide_info5_t *info, uint64_t address)
{
	for (uint32_t i = 0; i < info->page_starts_count; i++) {
		uint16_t start = info->page_starts[i];
		if (start == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE) {
			continue;
		}

		uint8_t *page = (uint8_t *)(address + (uint64_t)i
						    * info->page_size);
		uint32_t offset = start;
		uint32_t delta;
		do {
			dyld_cache_slide_pointer5_t *location
					= (void *)(page + offset);
			dyld_cache_slide_pointer5_t p = *location;
			uint64_t target = info->value_add
					+ p.regular.runtimeOffset;

			if (p.auth.auth) {
				location->raw = sign_pointer(target, location,
						p.auth.addrDiv, p.auth.diversity,
						p.auth.keyIsData);
			} else {
				location->raw = target
						| ((uint64_t)p.regular.high8
								<< 56);
			}

			delta = p.regular.next;
			offset += delta * sizeof(uint64_t);
		} while (delta != 0);
	}
}

static uint64_t
sign_pointer(uint64_t value, void *location, bool address_div,
		uint16_t diversity, bool key_is_data)
{
	uint64_t modifier = diversity;
	if (address_div) {
		modifier = ((uint64_t)location & 0x0000ffffffffffffULL)
				| ((uint64_t)diversity << 48);
	}

	if (key_is_data) {
		asm("pacda %0, %1" : "+r"(value) : "r"(modifier));
	} else {
		asm("pacia %0, %1" : "+r"(value) : "r"(modifier));
	}
	return value;
}

static void
pac_key_fingerprint(uint64_t fingerprint[2])
{
	fingerprint[0] = sign_pointer(0x1000, NULL, false, 0, false);
	fingerprint[1] = sign_pointer(0x1000, NULL, false, 0, true);
}

#define MRS_TPIDRRO_EL0 0xd53bd060
#define MRS_TPIDR_EL0   0xd53bd040
#define MRS_REGISTER    0x0000001f
#define MOVZ_IMM0       0xd2800000

static void
patch_thread_self_reads(uint64_t address, uint64_t size)
{
	uint32_t *code = (uint32_t *)address;
	for (uint64_t i = 0; i < size / sizeof(uint32_t); i++) {
		if ((code[i] & ~MRS_REGISTER) == MRS_TPIDRRO_EL0) {
			code[i] = MRS_TPIDR_EL0 | (code[i] & MRS_REGISTER);
		} else if ((code[i] & ~MRS_REGISTER) == MRS_TPIDR_EL0) {
			code[i] = MOVZ_IMM0 | (code[i] & MRS_REGISTER);
		}
	}
}
#endif

static uint64_t
trampolines_offset(const dyld_cache_header_t *header)
{
	return header->codeSignatureOffset + header->codeSignatureSize;
}

static int
prepare_cache_file(const char *source, const char *destination,
		const dyld_cache_header_t *main_header)
{
	int s = open(source, O_RDONLY | O_CLOEXEC);
	if (s == -1) {
		return 1;
	}
	int d = open(destination, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
			0644);
	int result = d == -1 || clone_file(s, d)
			|| write_prepared_file(s, d, main_header) || fsync(d);
	if (d != -1) {
		close(d);
	}
	close(s);
	return result;
}

static void
rebase_chain(uint8_t *page_content, uint16_t page_offset,
		dyld_cache_slide_info2_t *info)
{
	uint32_t last_page_offset = info->page_size - sizeof(uint64_t);

	uint64_t delta_mask = info->delta_mask;
	uint64_t value_mask = ~delta_mask;
	uint64_t value_add = info->value_add;
	uint64_t delta_shift = __builtin_ctzll(delta_mask) - 2;

	uint32_t delta;
	for (delta = 1; delta != 0 && page_offset <= last_page_offset;
			page_offset += delta) {
		uint8_t *l = page_content + page_offset;

		uint64_t value;
		memcpy(&value, l, sizeof(value));

		delta = (uint32_t)((value & delta_mask) >> delta_shift);
		value &= value_mask;

		if (value != 0) {
			value += value_add;
			/* No need to add slide, we don't rebase it */
		}

		memcpy(l, &value, sizeof(value));
	}
}

static int
clone_file(int source, int destination)
{
	if (ioctl(destination, FICLONE, source) == 0) {
		return 0;
	}

	struct stat st;
	if (fstat(source, &st) == -1) {
		return 1;
	}
	off_t remaining = st.st_size;
	while (remaining > 0) {
		ssize_t copied = copy_file_range(
				source, NULL, destination, NULL, remaining, 0);
		if (copied <= 0) {
			return 1;
		}
		remaining -= copied;
	}
	return 0;
}

static int
write_prepared_file(int source, int destination,
		const dyld_cache_header_t *main_header)
{
	dyld_cache_header_t header;
	if (pread(source, &header, sizeof(header), 0) != sizeof(header)) {
		return 1;
	}

	uint32_t count = header.mappingWithSlideCount;
	dyld_cache_mapping_and_slide_info_t mappings[count];
	ssize_t size = sizeof(mappings);
	if (pread(source, mappings, size, header.mappingWithSlideOffset)
			!= size) {
		return 1;
	}

	struct sidt_patches patches;
	sidt_patches_init(&patches, 0);
	int result = write_mappings(destination, mappings, count, main_header,
				     &patches)
			|| write_trampolines(destination, &header, &patches);
	sidt_patches_free(&patches);
	return result;
}

static int
write_mappings(int f, const dyld_cache_mapping_and_slide_info_t *mappings,
		uint32_t count, const dyld_cache_header_t *main_header,
		struct sidt_patches *patches)
{
	for (uint32_t i = 0; i < count; i++) {
		const dyld_cache_mapping_and_slide_info_t *m = &mappings[i];
		if (m->slideInfoFileSize != 0) {
			if (write_all(f, (const void *)m->address, m->size,
					    m->fileOffset)) {
				return 1;
			}
		} else if (m->initProt & VM_PROT_EXECUTE) {
#ifdef __x86_64__
			if (patch_text(f, m, main_header, patches)) {
				return 1;
			}
#else
			if (write_all(f, (const void *)m->address, m->size,
					    m->fileOffset)) {
				return 1;
			}
#endif
		}
	}
	return 0;
}

static int
write_trampolines(int f, const dyld_cache_header_t *header,
		const struct sidt_patches *patches)
{
	uint64_t offset = trampolines_offset(header);
	struct prepared_trampolines t = {
			.address = patches->trampoline_base,
			.size = (patches->trampolines_size + PAGE_SIZE - 1)
					& ~(uint64_t)(PAGE_SIZE - 1),
	};
	uint8_t page[PAGE_SIZE] = {0};
	memcpy(page, &t, sizeof(t));
	return write_all(f, page, sizeof(page), offset)
			|| write_all(f, patches->trampolines,
					patches->trampolines_size,
					offset + PAGE_SIZE)
			|| ftruncate(f, offset + PAGE_SIZE + t.size);
}

#ifdef __x86_64__
static int
patch_text(int f, const dyld_cache_mapping_and_slide_info_t *text,
		const dyld_cache_header_t *main_header,
		struct sidt_patches *patches)
{
	sidt_patches_init(patches,
			(text->address + text->size + PAGE_SIZE - 1)
					& ~(uint64_t)(PAGE_SIZE - 1));
	if (__builtin_cpu_supports("rdpid")) {
		find_patches(patches, text, main_header);
	}
	return write_patches(f, patches, text)
			|| fix_eh_frame_personalities(f, text);
}

static void
find_patches(struct sidt_patches *patches,
		const dyld_cache_mapping_and_slide_info_t *text,
		const dyld_cache_header_t *main_header)
{
	const dyld_cache_image_info_t *images
			= (const void *)((const uint8_t *)main_header
					+ main_header->imagesOffset);
	for (uint32_t i = 0; i < main_header->imagesCount; i++) {
		uint64_t address = images[i].address;
		if (address >= text->address
				&& address < text->address + text->size) {
			sidt_patch_image(patches, (const void *)address);
		}
	}
}

static int
write_patches(int f, const struct sidt_patches *patches,
		const dyld_cache_mapping_and_slide_info_t *text)
{
	for (size_t i = 0; i < patches->count; i++) {
		const struct sidt_patch *patch = &patches->items[i];
		if (write_all(f, patch->code, patch->length,
				    text->fileOffset + patch->address
						    - text->address)) {
			return 1;
		}
	}
	return 0;
}

static int
fix_eh_frame_personalities(int f,
		const dyld_cache_mapping_and_slide_info_t *text)
{
	const uint8_t *base = (const uint8_t *)text->address;
	static const uint8_t cie_start[] = {0, 0, 0, 0, 1, 'z', 'P'};
	for (uint64_t at = 4; at + sizeof(cie_start) < text->size; at++) {
		if (memcmp(base + at, cie_start, sizeof(cie_start)) != 0) {
			continue;
		}
		uint32_t length;
		memcpy(&length, base + at - 4, sizeof(length));
		const uint8_t *cie = base + at - 4;
		const uint8_t *end = cie + 4 + length;
		if (length < 16 || length > 64 || at - 4 + 4 + length > text->size) {
			continue;
		}

		const uint8_t *p = cie + 9;
		if (strcmp((const char *)p, "zPR") != 0) {
			continue;
		}
		p += 4;

		if ((p[0] | p[1] | p[2]) & 0x80 || p[3] != 6) {
			continue;
		}
		const uint8_t *augmentation = p + 4;

		if (augmentation[0] != 0x9b) {
			continue;
		}
		int32_t delta;
		memcpy(&delta, augmentation + 1, sizeof(delta));
		uint64_t target = (uint64_t)(uintptr_t)(augmentation + 1)
				+ (uint64_t)(int64_t)delta;
		bool in_text = target >= text->address
				&& target < text->address + text->size;
		if (!in_text && target % 8 == 0) {
			continue;
		}
		const uint8_t *instructions = augmentation + 6;
		uint8_t fixed[4 + 64] = {0};
		size_t n = 0;
		memcpy(fixed, cie, 4 + 4 + 1);
		n = 9;
		memcpy(fixed + n, "zR", 3);
		n += 3;
		memcpy(fixed + n, p, 3);
		n += 3;
		fixed[n++] = 1;
		fixed[n++] = augmentation[5];
		memcpy(fixed + n, instructions, (size_t)(end - instructions));

#ifdef ENABLE_STRACE
		fprintf(stderr, "limbo: the CIE at %#llx names a personality at "
				"%#llx, which is no slot: made one without\n",
				(unsigned long long)(uintptr_t)cie,
				(unsigned long long)target);
#endif
		if (write_all(f, fixed, 4 + length,
				    text->fileOffset + (uint64_t)(uintptr_t)cie
						    - text->address)) {
			return 1;
		}
	}
	return 0;
}
#endif

static int
write_all(int f, const void *data, size_t size, uint64_t offset)
{
	const uint8_t *cursor = data;
	while (size > 0) {
		ssize_t written = pwrite(f, cursor, size, offset);
		if (written <= 0) {
			return 1;
		}
		cursor += written;
		size -= written;
		offset += written;
	}
	return 0;
}
