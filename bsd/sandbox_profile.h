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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum sandbox_operation {
	SANDBOX_FILE_WRITE_ALL = 34,
	SANDBOX_FILE_WRITE_ACL,
	SANDBOX_FILE_WRITE_CREATE,
	SANDBOX_FILE_WRITE_DATA,
	SANDBOX_FILE_WRITE_FINDERINFO,
	SANDBOX_FILE_WRITE_FLAGS,
	SANDBOX_FILE_WRITE_MODE,
	SANDBOX_FILE_WRITE_OWNER,
	SANDBOX_FILE_WRITE_SETUGID,
	SANDBOX_FILE_WRITE_TIMES,
	SANDBOX_FILE_WRITE_UNLINK,
	SANDBOX_FILE_WRITE_XATTR,
};

#define SANDBOX_ENFORCED(operation)                                            \
	(1u << ((operation) - SANDBOX_FILE_WRITE_ALL))
#define SANDBOX_ENFORCED_ALL                                                   \
	(2 * SANDBOX_ENFORCED(SANDBOX_FILE_WRITE_XATTR) - 1)

struct sandbox_profile {
	uint8_t *data;
	size_t size;
	uint16_t node_count;
	uint16_t operation_count;
	uint32_t enforced;
	uint16_t file_write_index;
};

enum sandbox_decision {
	SANDBOX_ALLOW,
	SANDBOX_DENY,
	SANDBOX_UNENFORCED,
};

bool sandbox_profile_parse(
		struct sandbox_profile *profile, const void *data, size_t size);
void sandbox_profile_free(struct sandbox_profile *profile);
enum sandbox_decision sandbox_profile_decide(
		const struct sandbox_profile *profile, int operation,
		const char *path);
