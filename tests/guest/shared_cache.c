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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "check.h"

extern const void *_dyld_get_shared_cache_range(size_t *length);

enum {
	HEADER_MAPPING_OFFSET = 16,
	HEADER_DYNAMIC_DATA_OFFSET = 496,
};

struct dynamic_data {
	char magic[16];
	uint64_t fsId;
	uint64_t fsObjId;
	uint32_t osCryptexPathOffset;
	uint32_t cachePathOffset;
};

int
main(void)
{
	size_t length;
	const uint8_t *cache = _dyld_get_shared_cache_range(&length);
	CHECK(cache != NULL);
	uint32_t header_size;
	memcpy(&header_size, cache + HEADER_MAPPING_OFFSET,
			sizeof(header_size));
	if (header_size <= HEADER_DYNAMIC_DATA_OFFSET + sizeof(uint64_t)) {
		printf("shared_cache: skipped (a cache without dynamic "
		       "data)\n");
		return 77;
	}
	uint64_t offset;
	memcpy(&offset, cache + HEADER_DYNAMIC_DATA_OFFSET, sizeof(offset));
	const struct dynamic_data *data = (const void *)(cache + offset);
	CHECK(strncmp(data->magic, "dyld_data    v", 14) == 0);
	struct stat st;
	CHECK(stat((const char *)data + data->cachePathOffset, &st) == 0);
	CHECK(data->fsObjId == st.st_ino);
	CHECK(data->fsId == (uint32_t)st.st_dev);
	printf("shared_cache: ok\n");
	return 0;
}
