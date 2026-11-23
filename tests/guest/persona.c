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

#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

struct kpersona_info {
	uint32_t persona_info_version;
	uint32_t persona_id;
	int persona_type;
	uint32_t persona_gid;
	uint32_t persona_ngroups;
	uint32_t persona_groups[16];
	uint32_t persona_gmuid;
	char persona_name[256];
	uint32_t persona_uid;
} __attribute__((packed));

int kpersona_alloc(struct kpersona_info *info, uint32_t *id);
int kpersona_dealloc(uint32_t id);
int kpersona_get(uint32_t *id);
int kpersona_info(uint32_t id, struct kpersona_info *info);
int kpersona_find(const char *name, uint32_t uid, uint32_t *ids, size_t *count);
int kpersona_find_by_type(int type, uint32_t *ids, size_t *count);
int kpersona_pidinfo(pid_t pid, struct kpersona_info *info);
int posix_spawnattr_set_persona_np(
		posix_spawnattr_t *attr, uint32_t id, uint32_t flags);

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1

#define TEST_ID   4242
#define TEST_TYPE 7
#define USER      501
#define SKIP      77

static void check_not_root(void);

static int
child(void)
{
	uint32_t id = 0;
	CHECK(kpersona_get(&id) == 0 && id == TEST_ID);
	pid_t pid = fork();
	CHECK(pid != -1);
	if (pid == 0) {
		uint32_t inherited = 0;
		_exit(kpersona_get(&inherited) == 0 && inherited == TEST_ID
						? 0
						: 1);
	}
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	return 0;
}

static void
spawn_into_persona(const char *self)
{
	posix_spawnattr_t attr;
	CHECK(posix_spawnattr_init(&attr) == 0);
	CHECK(posix_spawnattr_set_persona_np(&attr, TEST_ID,
			      POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE)
			== 0);
	char *argv[] = {(char *)self, "child", NULL};
	extern char **environ;
	pid_t pid;
	CHECK(posix_spawn(&pid, self, NULL, &attr, argv, environ) == 0);
	posix_spawnattr_destroy(&attr);
	struct kpersona_info read = {.persona_info_version = 2};
	CHECK(kpersona_pidinfo(pid, &read) == 0 && read.persona_id == TEST_ID);
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	CHECK(posix_spawnattr_init(&attr) == 0);
	CHECK(posix_spawnattr_set_persona_np(&attr, TEST_ID + 1,
			      POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE)
			== 0);
	CHECK(posix_spawn(&pid, self, NULL, &attr, argv, environ) == ESRCH);
	posix_spawnattr_destroy(&attr);
}

int
main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "child") == 0) {
		return child();
	}

	uint32_t id = 0;
	CHECK(kpersona_get(&id) == -1 && errno == ESRCH);

	if (geteuid() != 0) {
		check_not_root();
		printf("persona: ok (not root)\n");
		return 0;
	}
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		if (setgid(USER) != 0 || setuid(USER) != 0) {
			_exit(SKIP);
		}
		check_not_root();
		_exit(0);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
	if (WEXITSTATUS(status) == SKIP) {
		printf("skipping what a user is refused: no user %d\n", USER);
	} else {
		CHECK(WEXITSTATUS(status) == 0);
	}

	struct kpersona_info info = {
			.persona_info_version = 2,
			.persona_id = TEST_ID,
			.persona_type = TEST_TYPE,
			.persona_uid = 501,
	};
	strcpy(info.persona_name, "limbo-test-persona");
	kpersona_dealloc(TEST_ID);
	CHECK(kpersona_alloc(&info, &id) == 0 && id == TEST_ID);
	CHECK(kpersona_alloc(&info, &id) == -1 && errno == EEXIST);

	struct kpersona_info read = {.persona_info_version = 2};
	CHECK(kpersona_info(TEST_ID, &read) == 0);
	CHECK(read.persona_id == TEST_ID && read.persona_type == TEST_TYPE);
	CHECK(read.persona_uid == 501);
	CHECK(strcmp(read.persona_name, "limbo-test-persona") == 0);

	uint32_t ids[8];
	size_t count = 8;
	CHECK(kpersona_find("limbo-test-persona", (uint32_t)-1, ids, &count) == 1);
	CHECK(ids[0] == TEST_ID);
	count = 8;
	CHECK(kpersona_find_by_type(TEST_TYPE, ids, &count) >= 1);

	spawn_into_persona(argv[0]);

	CHECK(kpersona_dealloc(TEST_ID) == 0);
	CHECK(kpersona_info(TEST_ID, &read) == -1 && errno == ESRCH);
	printf("persona: ok\n");
	return 0;
}

static void
check_not_root(void)
{
	struct kpersona_info info = {.persona_info_version = 2};
	CHECK(kpersona_info(99, &info) == -1 && errno == EPERM);
	CHECK(kpersona_pidinfo(getpid(), &info) == -1 && errno == ESRCH);
	CHECK(kpersona_pidinfo(1, &info) == -1 && errno == EPERM);
}
