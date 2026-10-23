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

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "codesign.h"
#include "process.h"
#include "sha.h"
#include "xnu-errno.h"

enum {
	CS_OPS_STATUS = 0,
	CS_OPS_CDHASH = 5,
	CS_OPS_PIDOFFSET = 6,
	CS_OPS_ENTITLEMENTS_BLOB = 7,
	CS_OPS_IDENTITY = 11,
	CS_OPS_TEAMID = 14,
	CS_OPS_DER_ENTITLEMENTS_BLOB = 16,
	CS_OPS_VALIDATION_CATEGORY = 17,
};

#define CS_VALID                  0x00000001
#define CS_ADHOC                  0x00000002
#define CS_HARD                   0x00000100
#define CS_KILL                   0x00000200
#define CS_RESTRICT               0x00000800
#define CS_ENFORCEMENT            0x00001000
#define CS_REQUIRE_LV             0x00002000
#define CS_ENTITLEMENTS_VALIDATED 0x00004000
#define CS_RUNTIME                0x00010000
#define CS_LINKER_SIGNED          0x00020000
#define CS_DYLD_PLATFORM          0x02000000
#define CS_PLATFORM_BINARY        0x04000000
#define CS_SIGNED                 0x20000000

#define CS_VALIDATION_CATEGORY_PLATFORM  1
#define CS_VALIDATION_CATEGORY_DEVELOPER 6

#define FAT_MAGIC                  0xcafebabe
#define FAT_MAGIC_64               0xcafebabf
#define MH_MAGIC_64                0xfeedfacf
#define LC_CODE_SIGNATURE          0x1d
#define CPU_TYPE_ARM64             0x0100000c
#define CPU_SUBTYPE_ARM64E         2
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_CODEDIRECTORY      0xfade0c02
#define CSSLOT_CODEDIRECTORY       0
#define CSSLOT_ENTITLEMENTS        5
#define CSSLOT_DER_ENTITLEMENTS    7
#define CSSLOT_ALTERNATE_FIRST     0x1000
#define CS_HASHTYPE_SHA1           1
#define CS_CDHASH_LEN              20

struct signature {
	uint8_t *bytes;
	uint32_t size;
	uint64_t slice_offset;
	const uint8_t *code_directory;
	const uint8_t *entitlements;
	const uint8_t *der_entitlements;
};

static bool signature_load(int32_t pid, struct signature *signature);
static bool read_slice(int fd, uint64_t *offset);
static bool read_signature(
		int fd, uint64_t offset, struct signature *signature);
static void index_blobs(struct signature *signature);
static uint32_t status_flags(const struct signature *signature);
static const char *code_directory_string(const struct signature *signature,
		uint32_t field, uint32_t version);
static void code_directory_hash(
		const struct signature *signature, uint8_t hash[CS_CDHASH_LEN]);
static int reply_blob(const uint8_t *blob, void *buffer, size_t size);
static int reply_string(const char *string, void *buffer, size_t size);
static uint32_t big(const uint8_t *bytes);

int
codesign_ops(int32_t pid, uint32_t ops, void *buffer, size_t size)
{
	struct signature signature;
	if (!signature_load(pid, &signature)) {
		if (ops == CS_OPS_STATUS && size >= sizeof(uint32_t)) {
			memset(buffer, 0, sizeof(uint32_t));
			return 0;
		}
		return _EINVAL;
	}

	int r;
	switch (ops) {
	case CS_OPS_STATUS: {
		uint32_t flags = status_flags(&signature);
		if (size < sizeof(flags)) {
			r = _EINVAL;
			break;
		}
		memcpy(buffer, &flags, sizeof(flags));
		r = 0;
		break;
	}
	case CS_OPS_ENTITLEMENTS_BLOB:
		r = reply_blob(signature.entitlements, buffer, size);
		break;
	case CS_OPS_DER_ENTITLEMENTS_BLOB:
		r = reply_blob(signature.der_entitlements, buffer, size);
		break;
	case CS_OPS_IDENTITY:
		r = reply_string(code_directory_string(&signature, 20, 0),
				buffer, size);
		break;
	case CS_OPS_TEAMID:
		r = reply_string(code_directory_string(&signature, 48, 0x20200),
				buffer, size);
		break;
	case CS_OPS_VALIDATION_CATEGORY: {
		uint32_t category = (status_flags(&signature)
						    & CS_PLATFORM_BINARY)
				? CS_VALIDATION_CATEGORY_PLATFORM
				: CS_VALIDATION_CATEGORY_DEVELOPER;
		if (size < sizeof(category)) {
			r = _EINVAL;
			break;
		}
		memcpy(buffer, &category, sizeof(category));
		r = 0;
		break;
	}
	case CS_OPS_PIDOFFSET: {
		uint64_t offset = signature.slice_offset;
		if (size < sizeof(offset)) {
			r = _EINVAL;
			break;
		}
		memcpy(buffer, &offset, sizeof(offset));
		r = 0;
		break;
	}
	case CS_OPS_CDHASH: {
		uint8_t hash[CS_CDHASH_LEN];
		if (size < sizeof(hash)) {
			r = _ERANGE;
			break;
		}
		code_directory_hash(&signature, hash);
		memcpy(buffer, hash, sizeof(hash));
		r = 0;
		break;
	}
	default:
		r = 0;
		break;
	}
	free(signature.bytes);
	return r;
}

static bool
signature_load(int32_t pid, struct signature *signature)
{
	char path[PATH_MAX];
	if (!process_executable_path(pid == 0 ? getpid() : pid, path)) {
		return false;
	}
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return false;
	}
	uint64_t offset;
	bool ok = read_slice(fd, &offset)
			&& read_signature(fd, offset, signature);
	close(fd);
	signature->slice_offset = offset;
	if (ok) {
		index_blobs(signature);
		ok = signature->code_directory != NULL;
		if (!ok) {
			free(signature->bytes);
		}
	}
	return ok;
}

static bool
read_slice(int fd, uint64_t *offset)
{
	uint32_t header[2];
	if (pread(fd, header, sizeof(header), 0) != sizeof(header)) {
		return false;
	}
	uint32_t magic = ntohl(header[0]);
	if (magic != FAT_MAGIC && magic != FAT_MAGIC_64) {
		*offset = 0;
		return true;
	}

	uint32_t count = ntohl(header[1]);
	size_t entry_size = (magic == FAT_MAGIC) ? 20 : 32;
	bool found = false;
	for (uint32_t i = 0; i < count && i < 32; i++) {
		uint8_t entry[32];
		if (pread(fd, entry, entry_size, 8 + i * entry_size)
				!= (ssize_t)entry_size) {
			return false;
		}
		uint32_t cputype = big(entry);
		uint32_t subtype = big(entry + 4) & 0xffffff;
		uint64_t slice = (magic == FAT_MAGIC)
				? big(entry + 8)
				: (uint64_t)big(entry + 8) << 32
						| big(entry + 12);
		if (cputype == CPU_TYPE_ARM64
				&& (!found || subtype == CPU_SUBTYPE_ARM64E)) {
			*offset = slice;
			found = true;
		}
	}
	return found;
}

static bool
read_signature(int fd, uint64_t offset, struct signature *signature)
{
	uint32_t header[8];
	if (pread(fd, header, sizeof(header), offset) != sizeof(header)
			|| header[0] != MH_MAGIC_64) {
		return false;
	}
	uint32_t ncmds = header[4];
	uint32_t sizeofcmds = header[5];
	uint8_t *commands = malloc(sizeofcmds);
	if (pread(fd, commands, sizeofcmds, offset + sizeof(header))
			!= (ssize_t)sizeofcmds) {
		free(commands);
		return false;
	}

	uint32_t dataoff = 0, datasize = 0;
	for (uint32_t i = 0, at = 0; i < ncmds && at + 8 <= sizeofcmds; i++) {
		uint32_t cmd, cmdsize;
		memcpy(&cmd, commands + at, 4);
		memcpy(&cmdsize, commands + at + 4, 4);
		if (cmd == LC_CODE_SIGNATURE && at + 16 <= sizeofcmds) {
			memcpy(&dataoff, commands + at + 8, 4);
			memcpy(&datasize, commands + at + 12, 4);
		}
		if (cmdsize < 8) {
			break;
		}
		at += cmdsize;
	}
	free(commands);
	if (datasize < 12 || datasize > (64 << 20)) {
		return false;
	}

	signature->bytes = malloc(datasize);
	signature->size = datasize;
	if (pread(fd, signature->bytes, datasize, offset + dataoff)
					!= (ssize_t)datasize
			|| big(signature->bytes)
					!= CSMAGIC_EMBEDDED_SIGNATURE) {
		free(signature->bytes);
		return false;
	}
	return true;
}

static void
index_blobs(struct signature *signature)
{
	signature->code_directory = NULL;
	signature->entitlements = NULL;
	signature->der_entitlements = NULL;
	uint32_t count = big(signature->bytes + 8);
	for (uint32_t i = 0; i < count && 12 + (i + 1) * 8 <= signature->size;
			i++) {
		const uint8_t *index = signature->bytes + 12 + i * 8;
		uint32_t type = big(index);
		uint32_t offset = big(index + 4);
		if (offset + 8 > signature->size
				|| big(signature->bytes + offset + 4)
						> signature->size - offset) {
			continue;
		}
		const uint8_t *blob = signature->bytes + offset;
		if ((type == CSSLOT_CODEDIRECTORY
				    && signature->code_directory == NULL)
				|| type == CSSLOT_ALTERNATE_FIRST) {
			if (big(blob) == CSMAGIC_CODEDIRECTORY) {
				signature->code_directory = blob;
			}
		} else if (type == CSSLOT_ENTITLEMENTS) {
			signature->entitlements = blob;
		} else if (type == CSSLOT_DER_ENTITLEMENTS) {
			signature->der_entitlements = blob;
		}
	}
}

static void
code_directory_hash(
		const struct signature *signature, uint8_t hash[CS_CDHASH_LEN])
{
	const uint8_t *directory = signature->code_directory;
	uint32_t length = big(directory + 4);
	uint8_t hash_type = directory[37];
	if (hash_type == CS_HASHTYPE_SHA1) {
		sha1(directory, length, hash);
		return;
	}
	uint8_t digest[SHA256_DIGEST_LENGTH];
	sha256(directory, length, digest);
	memcpy(hash, digest, CS_CDHASH_LEN);
}

static uint32_t
status_flags(const struct signature *signature)
{
	const uint8_t *directory = signature->code_directory;
	uint32_t directory_flags = big(directory + 12);
	uint8_t platform = directory[38];

	uint32_t flags = CS_VALID | CS_SIGNED | CS_HARD | CS_KILL
			| CS_ENFORCEMENT
			| (directory_flags
					& (CS_ADHOC | CS_RUNTIME
							| CS_LINKER_SIGNED));
	if (platform != 0) {
		flags |= CS_PLATFORM_BINARY | CS_DYLD_PLATFORM | CS_RESTRICT
				| CS_REQUIRE_LV | CS_RUNTIME;
	}
	if (signature->entitlements != NULL
			|| signature->der_entitlements != NULL) {
		flags |= CS_ENTITLEMENTS_VALIDATED;
	}
	return flags;
}

static const char *
code_directory_string(const struct signature *signature, uint32_t field,
		uint32_t version)
{
	const uint8_t *directory = signature->code_directory;
	uint32_t length = big(directory + 4);
	if (big(directory + 8) < version || field + 4 > length) {
		return NULL;
	}
	uint32_t offset = big(directory + field);
	if (offset == 0 || offset >= length
			|| memchr(directory + offset, '\0', length - offset)
					== NULL) {
		return NULL;
	}
	return (const char *)directory + offset;
}

static int
reply_blob(const uint8_t *blob, void *buffer, size_t size)
{
	if (blob == NULL) {
		return _ENOENT;
	}
	uint32_t length = big(blob + 4);
	if (size < length) {
		if (size >= 8) {
			uint32_t header[2] = {0, htonl(length)};
			memcpy(buffer, header, sizeof(header));
		}
		return _ERANGE;
	}
	memcpy(buffer, blob, length);
	return 0;
}

static int
reply_string(const char *string, void *buffer, size_t size)
{
	if (string == NULL) {
		return _ENOENT;
	}
	uint32_t length = 8 + (uint32_t)strlen(string) + 1;
	uint32_t header[2] = {0, htonl(length)};
	if (size < length) {
		if (size >= 8) {
			memcpy(buffer, header, 8);
		}
		return _ERANGE;
	}
	memcpy(buffer, header, 8);
	memcpy((uint8_t *)buffer + 8, string, length - 8);
	return 0;
}

static uint32_t
big(const uint8_t *bytes)
{
	uint32_t value;
	memcpy(&value, bytes, sizeof(value));
	return ntohl(value);
}
