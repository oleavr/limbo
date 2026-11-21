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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bsd/boot_state.h"
#include "bsd/codesign.h"
#include "bsd/persona.h"
#include "bsd/xnu-errno.h"

#define PERSONA_OP_ALLOC              1
#define PERSONA_OP_PALLOC             2
#define PERSONA_OP_DEALLOC            3
#define PERSONA_OP_GET                4
#define PERSONA_OP_INFO               5
#define PERSONA_OP_PIDINFO            6
#define PERSONA_OP_FIND               7
#define PERSONA_OP_GETPATH            8
#define PERSONA_OP_FIND_BY_TYPE       9
#define PERSONA_OP_PIDINFO_AUDIT_TOKEN 10

#define PERSONA_INFO_V1 1
#define PERSONA_INFO_V2 2
#define PERSONA_ID_NONE ((uint32_t)-1)

#define PERSONA_FIRST_ID 1000

#define PERSONA_NAME_MAX 256
#define PERSONAS_MAX 64
#define PERSONAS_PATH "/private/var/run/limbo-personas"
#define PERSONAS_MAGIC 0x4e535250

struct kpersona_info {
	uint32_t persona_info_version;
	uint32_t persona_id;
	int32_t persona_type;
	uint32_t persona_gid;
	uint32_t persona_ngroups;
	uint32_t persona_groups[16];
	uint32_t persona_gmuid;
	char persona_name[PERSONA_NAME_MAX];
	uint32_t persona_uid;
} __attribute__((packed));

#define PERSONA_INFO_V1_SIZE offsetof(struct kpersona_info, persona_uid)

struct persona {
	bool used;
	uint32_t id;
	int32_t type;
	uint32_t gid;
	uint32_t uid;
	char name[PERSONA_NAME_MAX];
};

struct personas {
	struct boot_state_header header;
	struct persona entries[PERSONAS_MAX];
};

static struct personas personas;
static struct boot_state personas_state
		= BOOT_STATE_INIT(PERSONAS_PATH, PERSONAS_MAGIC, &personas);

static bool
may_manage(void)
{
	return geteuid() == 0
			|| codesign_entitled(getpid(),
					"com.apple.private.persona-mgmt");
}

static bool
may_read(void)
{
	return geteuid() == 0
			|| codesign_entitled(getpid(),
					"com.apple.private.persona-read-all")
			|| codesign_entitled(getpid(),
					"com.apple.private.persona-proc-info");
}

static struct persona *
persona_by_id(struct personas *table, uint32_t id)
{
	for (int i = 0; i != PERSONAS_MAX; i++) {
		if (table->entries[i].used && table->entries[i].id == id) {
			return &table->entries[i];
		}
	}
	return NULL;
}

static size_t
info_size(uint32_t version)
{
	return version >= PERSONA_INFO_V2 ? sizeof(struct kpersona_info)
					  : PERSONA_INFO_V1_SIZE;
}

static void
describe(const struct persona *persona, struct kpersona_info *out)
{
	uint32_t version = out->persona_info_version;
	struct kpersona_info info = {
			.persona_info_version = version,
			.persona_id = persona->id,
			.persona_type = persona->type,
			.persona_gid = persona->gid,
			.persona_gmuid = PERSONA_ID_NONE,
			.persona_uid = persona->uid,
	};
	memcpy(info.persona_name, persona->name, sizeof(info.persona_name));
	memcpy(out, &info, info_size(version));
}

static int
allocate(struct personas *table, const struct kpersona_info *info,
		uint32_t *id)
{
	struct kpersona_info request = {0};
	if (info->persona_info_version != PERSONA_INFO_V1
			&& info->persona_info_version != PERSONA_INFO_V2) {
		return _EINVAL;
	}
	memcpy(&request, info, info_size(info->persona_info_version));
	request.persona_name[PERSONA_NAME_MAX - 1] = '\0';
	for (int i = 0; i != PERSONAS_MAX; i++) {
		const struct persona *other = &table->entries[i];
		if (other->used && (other->id == request.persona_id
						   || (request.persona_name[0] != '\0'
								   && strcmp(other->name,
										   request.persona_name)
										   == 0))) {
			return _EEXIST;
		}
	}
	uint32_t chosen = request.persona_id;
	if (chosen == PERSONA_ID_NONE) {
		for (chosen = PERSONA_FIRST_ID; persona_by_id(table, chosen);
				chosen++) {
		}
	}
	for (int i = 0; i != PERSONAS_MAX; i++) {
		struct persona *persona = &table->entries[i];
		if (!persona->used) {
			*persona = (struct persona){
					.used = true,
					.id = chosen,
					.type = request.persona_type,
					.gid = request.persona_gid,
					.uid = request.persona_info_version
									>= PERSONA_INFO_V2
							? request.persona_uid
							: PERSONA_ID_NONE,
			};
			memcpy(persona->name, request.persona_name,
					sizeof(persona->name));
			*id = chosen;
			return 0;
		}
	}
	return _ENOMEM;
}

static int
find(struct personas *table, const struct kpersona_info *query, bool by_type,
		uint32_t *ids, size_t *idlen)
{
	size_t found = 0;
	for (int i = 0; i != PERSONAS_MAX; i++) {
		const struct persona *persona = &table->entries[i];
		if (!persona->used) {
			continue;
		}
		if (by_type ? persona->type != query->persona_type
			    : ((query->persona_name[0] != '\0'
					       && strncmp(persona->name,
							       query->persona_name,
							       PERSONA_NAME_MAX)
							       != 0)
					      || (query->persona_id != PERSONA_ID_NONE
							      && persona->id
									      != query->persona_id))) {
			continue;
		}
		if (found < *idlen) {
			ids[found] = persona->id;
		}
		found++;
	}
	*idlen = found;
	return found == 0 ? _ESRCH : 0;
}

int
persona_syscall(uint32_t operation, uint32_t flags, void *info, void *id,
		size_t *idlen, char *path)
{
	(void)flags;
	switch (operation) {
	case PERSONA_OP_GET:
		return _ESRCH;
	case PERSONA_OP_PIDINFO:
		if (*(int32_t *)id != getpid() && !may_read()) {
			return _EPERM;
		}
		return _ESRCH;
	case PERSONA_OP_PIDINFO_AUDIT_TOKEN:
		if (!may_read()) {
			return _EPERM;
		}
		return _ESRCH;
	case PERSONA_OP_ALLOC:
	case PERSONA_OP_PALLOC:
	case PERSONA_OP_DEALLOC:
		if (!may_manage()) {
			return _EPERM;
		}
		break;
	case PERSONA_OP_INFO:
	case PERSONA_OP_GETPATH:
		if (!may_read()) {
			return _EPERM;
		}
		break;
	case PERSONA_OP_FIND:
	case PERSONA_OP_FIND_BY_TYPE:
		break;
	default:
		return _EINVAL;
	}

	struct personas *table = boot_state_begin(&personas_state);
	if (table == NULL) {
		return _ESRCH;
	}
	bool changed = false;
	int result = 0;
	switch (operation) {
	case PERSONA_OP_ALLOC:
	case PERSONA_OP_PALLOC:
		result = allocate(table, info, id);
		changed = result == 0;
		break;
	case PERSONA_OP_DEALLOC: {
		struct persona *persona = persona_by_id(table, *(uint32_t *)id);
		if (persona == NULL) {
			result = _ESRCH;
		} else {
			persona->used = false;
			changed = true;
		}
		break;
	}
	case PERSONA_OP_INFO: {
		const struct persona *persona
				= persona_by_id(table, *(uint32_t *)id);
		if (persona == NULL) {
			result = _ESRCH;
		} else {
			describe(persona, info);
		}
		break;
	}
	case PERSONA_OP_GETPATH: {

		if (persona_by_id(table, *(uint32_t *)id) == NULL) {
			result = _ESRCH;
		} else if (path != NULL) {
			path[0] = '\0';
		}
		break;
	}
	case PERSONA_OP_FIND:
	case PERSONA_OP_FIND_BY_TYPE:
		result = find(table, info, operation == PERSONA_OP_FIND_BY_TYPE,
				id, idlen);
		break;
	}
	boot_state_end(&personas_state, changed);
	return result;
}
