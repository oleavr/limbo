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

#include "bsd/sandbox_profile.h"
#include <stdlib.h>
#include <string.h>

#define HEADER_SIZE            16
#define HEADER_NODE_COUNT      2
#define HEADER_OPERATION_COUNT 4
#define INDEX_SIZE             2
#define NODE_SIZE              8
#define DATA_UNIT              8
#define DATA_LENGTH_SIZE       2

#define OPERATION_COUNT_27 204
#define OPERATION_COUNT_26 200
#define FILE_WRITE_ALL_26  32

#define KIND_FILTER   0
#define KIND_DECISION 1
#define FILTER_PATH   1
#define DECISION_DENY 0x01

#define OP_END           0x00
#define OP_SKIP_PAST     0x03
#define OP_LONG_LITERAL  0x04
#define OP_RESTORE       0x05
#define OP_KEEP          0x06
#define OP_DROP          0x07
#define OP_FAIL_FAR      0x08
#define OP_MATCH         0x0a
#define OP_RANGES        0x0b
#define OP_FAIL_NO_MATCH 0x0f
#define OP_LITERAL       0x40
#define OP_FAIL_NEAR     0x80

#define LONG_LITERAL_MIN 65
#define RANGES_REPEAT    0x80
#define FAIL_FAR_MIN     129
#define SKIP_PAST_MAX    16
#define NO_MATCH         SIZE_MAX

struct node {
	uint8_t kind;
	uint8_t value;
	uint16_t argument;
	uint16_t match;
	uint16_t unmatch;
};

static uint16_t read16(const uint8_t *p);
static uint16_t start_node(
		const struct sandbox_profile *profile, int operation);
static bool graph_valid(const struct sandbox_profile *profile, uint16_t start,
		uint8_t *seen, uint16_t *stack);
static size_t nodes_offset(const struct sandbox_profile *profile);
static struct node node_at(
		const struct sandbox_profile *profile, uint16_t index);
static const uint8_t *blob_at(const struct sandbox_profile *profile,
		uint16_t argument, size_t *length);
static bool pattern_valid(const uint8_t *p, size_t length);
static bool instruction(const uint8_t *p, size_t length, size_t pc,
		size_t *size, bool *can_fail);
static bool failure_target(const uint8_t *p, size_t length, size_t pc,
		size_t *size, size_t *target);

bool
sandbox_profile_parse(
		struct sandbox_profile *profile, const void *data, size_t size)
{
	memset(profile, 0, sizeof(*profile));
	if (size < HEADER_SIZE) {
		return false;
	}
	const uint8_t *bytes = data;
	uint16_t node_count = read16(bytes + HEADER_NODE_COUNT);
	uint16_t operation_count = read16(bytes + HEADER_OPERATION_COUNT);
	if (HEADER_SIZE + INDEX_SIZE * (size_t)operation_count
					+ NODE_SIZE * (size_t)node_count
			> size) {
		return false;
	}
	profile->data = malloc(size);
	if (profile->data == NULL) {
		return false;
	}
	memcpy(profile->data, data, size);
	profile->size = size;
	profile->node_count = node_count;
	profile->operation_count = operation_count;
	if (operation_count == OPERATION_COUNT_27) {
		profile->file_write_index = SANDBOX_FILE_WRITE_ALL;
	} else if (operation_count == OPERATION_COUNT_26) {
		profile->file_write_index = FILE_WRITE_ALL_26;
	} else {
		return true;
	}
	for (int at = 0; at != HEADER_SIZE; at += sizeof(uint16_t)) {
		if (at != HEADER_NODE_COUNT && at != HEADER_OPERATION_COUNT
				&& read16(bytes + at) != 0) {
			return true;
		}
	}
	uint8_t *seen = malloc((size_t)node_count + 1);
	uint16_t *stack = calloc(2 * (size_t)node_count + 1, sizeof(*stack));
	for (int op = SANDBOX_FILE_WRITE_ALL; op <= SANDBOX_FILE_WRITE_XATTR;
			op++) {
		memset(seen, 0, node_count);
		if (graph_valid(profile, start_node(profile, op), seen,
				    stack)) {
			profile->enforced |= SANDBOX_ENFORCED(op);
		}
	}
	free(stack);
	free(seen);
	return true;
}

static uint16_t
read16(const uint8_t *p)
{
	return (uint16_t)(p[0] | p[1] << 8);
}

static uint16_t
start_node(const struct sandbox_profile *profile, int operation)
{
	size_t index = profile->file_write_index
			+ (operation - SANDBOX_FILE_WRITE_ALL);
	return read16(profile->data + HEADER_SIZE + INDEX_SIZE * index);
}

static bool
graph_valid(const struct sandbox_profile *profile, uint16_t start,
		uint8_t *seen, uint16_t *stack)
{
	size_t depth = 0;
	stack[depth++] = start;
	while (depth != 0) {
		uint16_t index = stack[--depth];
		if (index >= profile->node_count) {
			return false;
		}
		if (seen[index]) {
			continue;
		}
		seen[index] = 1;
		struct node node = node_at(profile, index);
		if (node.kind == KIND_DECISION) {
			continue;
		}
		if (node.kind != KIND_FILTER || node.value != FILTER_PATH) {
			return false;
		}
		size_t length;
		const uint8_t *pattern
				= blob_at(profile, node.argument, &length);
		if (pattern == NULL || !pattern_valid(pattern, length)) {
			return false;
		}
		stack[depth++] = node.match;
		stack[depth++] = node.unmatch;
	}
	return true;
}

static size_t
nodes_offset(const struct sandbox_profile *profile)
{
	return HEADER_SIZE + INDEX_SIZE * (size_t)profile->operation_count;
}

static struct node
node_at(const struct sandbox_profile *profile, uint16_t index)
{
	const uint8_t *p = profile->data + nodes_offset(profile)
			+ NODE_SIZE * index;
	return (struct node){p[0], p[1], read16(p + 2), read16(p + 4),
			read16(p + 6)};
}

static const uint8_t *
blob_at(const struct sandbox_profile *profile, uint16_t argument,
		size_t *length)
{
	size_t offset = nodes_offset(profile)
			+ NODE_SIZE * (size_t)profile->node_count
			+ DATA_UNIT * (size_t)argument;
	if (offset + DATA_LENGTH_SIZE > profile->size) {
		return NULL;
	}
	*length = read16(profile->data + offset);
	if (offset + DATA_LENGTH_SIZE + *length > profile->size) {
		return NULL;
	}
	return profile->data + offset + DATA_LENGTH_SIZE;
}

static bool
pattern_valid(const uint8_t *p, size_t length)
{
	size_t pc = 0;
	int skips = 0;
	while (pc < length) {
		size_t size, target;
		bool can_fail;
		if (!instruction(p, length, pc, &size, &can_fail)) {
			return false;
		}
		skips += p[pc] == OP_SKIP_PAST;
		pc += size;
		if (can_fail) {
			if (!failure_target(p, length, pc, &size, &target)) {
				return false;
			}
			pc += size;
		}
	}
	return skips <= SKIP_PAST_MAX;
}

static bool
instruction(const uint8_t *p, size_t length, size_t pc, size_t *size,
		bool *can_fail)
{
	uint8_t op = p[pc];
	bool has_operand = op == OP_LONG_LITERAL || op == OP_RANGES
			|| op == OP_SKIP_PAST;
	if (has_operand && pc + 1 >= length) {
		return false;
	}
	*can_fail = true;
	if (op >= OP_LITERAL && op < OP_FAIL_NEAR) {
		*size = 1 + (op - OP_LITERAL) + 1;
	} else if (op == OP_LONG_LITERAL) {
		*size = 2 + (size_t)p[pc + 1] + LONG_LITERAL_MIN;
	} else if (op == OP_RANGES) {
		*size = 2 + 2 * ((size_t)(p[pc + 1] & ~RANGES_REPEAT) + 1);
		*can_fail = !(p[pc + 1] & RANGES_REPEAT);
	} else if (op == OP_END) {
		*size = 1;
	} else if (op == OP_SKIP_PAST) {
		*size = 2;
	} else if (op == OP_MATCH || op == OP_RESTORE || op == OP_KEEP
			|| op == OP_DROP) {
		*size = 1;
		*can_fail = false;
	} else {
		return false;
	}
	return pc + *size <= length;
}

static bool
failure_target(const uint8_t *p, size_t length, size_t pc, size_t *size,
		size_t *target)
{
	if (pc >= length) {
		return false;
	}
	uint8_t op = p[pc];
	if (op == OP_FAIL_NO_MATCH) {
		*size = 1;
		*target = NO_MATCH;
	} else if (op >= OP_FAIL_NEAR) {
		*size = 1;
		*target = pc + 1 + (op - OP_FAIL_NEAR) + 1;
	} else if (op == OP_FAIL_FAR) {
		if (pc + 3 > length) {
			return false;
		}
		*size = 3;
		*target = pc + 3 + read16(p + pc + 1) + FAIL_FAR_MIN;
	} else {
		return false;
	}
	return *target == NO_MATCH || *target <= length;
}

void
sandbox_profile_free(struct sandbox_profile *profile)
{
	free(profile->data);
	memset(profile, 0, sizeof(*profile));
}
