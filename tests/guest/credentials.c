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
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"

#define USER     501
#define GROUP    20
#define STAFF    12
#define UNMAPPED 4000000000u

extern int __settid(uid_t uid, gid_t gid);
extern int __gettid(uid_t *uid, gid_t *gid);
extern int __settid_with_pid(pid_t pid, int assume);

static atomic_int step;
static int pipe_fds[2];

static void check_thread_identity(void);
static void check_unmapped_identity(void);
static void *report_identity(void *arg);
static void *widen_groups(void *arg);
static uid_t owner_of_new_file(void);
static int group_count(void);

static void *
wait_and_look(void *arg)
{
	(void)arg;
	char byte;
	atomic_store(&step, 1);
	CHECK(read(pipe_fds[0], &byte, 1) == 1);
	CHECK(geteuid() == USER && getuid() == 0);
	CHECK(getegid() == GROUP);
	atomic_store(&step, 2);
	return NULL;
}

static void
check_thread_identity(void)
{
	uid_t uid;
	gid_t gid;
	CHECK(__gettid(&uid, &gid) == -1 && errno == ESRCH);
	CHECK(__settid(KAUTH_UID_NONE, KAUTH_GID_NONE) == -1);
	CHECK(errno == EPERM);
	CHECK(__settid(USER, STAFF) == 0);
	CHECK(__gettid(&uid, &gid) == 0);
	CHECK(uid == USER && gid == STAFF);
	CHECK(getuid() == USER && geteuid() == USER);
	CHECK(getgid() == STAFF && getegid() == STAFF);
	gid_t groups[4];
	CHECK(getgroups(4, groups) == 1 && groups[0] == STAFF);
	CHECK(__settid(USER, STAFF) == -1 && errno == EPERM);
	CHECK(owner_of_new_file() == USER);

	pthread_t thread;
	uintptr_t reported;
	CHECK(pthread_create(&thread, NULL, report_identity, NULL) == 0);
	CHECK(pthread_join(thread, (void **)&reported) == 0);
	CHECK(reported == 0);
	CHECK(pthread_create(&thread, NULL, widen_groups, NULL) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(geteuid() == USER && getegid() == STAFF);
	CHECK(group_count() == 1);
	CHECK(owner_of_new_file() == USER);

	CHECK(__settid(KAUTH_UID_NONE, KAUTH_GID_NONE) == 0);
	CHECK(__gettid(&uid, &gid) == -1 && errno == ESRCH);
	CHECK(getuid() == 0 && geteuid() == 0);
	CHECK(group_count() == 2);
	CHECK(owner_of_new_file() == 0);

	CHECK(__settid_with_pid(0, 1) == -1 && errno == ESRCH);
	CHECK(__settid_with_pid(getpid(), 1) == 0);
	CHECK(__gettid(&uid, &gid) == 0);
	CHECK(uid == 0 && gid == getegid());
	CHECK(__settid_with_pid(getpid(), 0) == 0);
	CHECK(__gettid(&uid, &gid) == -1 && errno == ESRCH);
}

static void
check_unmapped_identity(void)
{
	uid_t uid;
	gid_t gid;
	if (__settid(UNMAPPED, UNMAPPED) == 0) {
		CHECK(__gettid(&uid, &gid) == 0 && uid == UNMAPPED);
		CHECK(geteuid() == UNMAPPED);
		CHECK(__settid(KAUTH_UID_NONE, KAUTH_GID_NONE) == 0);
	} else {
		CHECK(errno == EPERM);
		CHECK(__gettid(&uid, &gid) == -1 && errno == ESRCH);
	}
	CHECK(geteuid() == 0 && owner_of_new_file() == 0);
}

static void *
report_identity(void *arg)
{
	(void)arg;
	uid_t uid;
	gid_t gid;
	bool inherited = __gettid(&uid, &gid) == 0 || geteuid() != 0
			|| owner_of_new_file() != 0;
	return (void *)(uintptr_t)inherited;
}

static void *
widen_groups(void *arg)
{
	(void)arg;
	CHECK(setgroups(2, (gid_t[]){GROUP, STAFF}) == 0);
	return NULL;
}

static uid_t
owner_of_new_file(void)
{
	char path[] = "/tmp/credentials.XXXXXX";
	int fd = mkstemp(path);
	CHECK(fd != -1);
	struct stat st;
	CHECK(fstat(fd, &st) == 0);
	CHECK(close(fd) == 0 && unlink(path) == 0);
	return st.st_uid;
}

static int
group_count(void)
{
	gid_t groups[16];
	return getgroups(16, groups);
}

int
main(void)
{
	if (getuid() != 0) {
		uid_t uid = getuid();
		CHECK(setuid(uid) == 0 && seteuid(uid) == 0);
		CHECK(getuid() == uid && geteuid() == uid);
		printf("credentials: ok (not root)\n");
		return 0;
	}

	CHECK(pipe(pipe_fds) == 0);
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, wait_and_look, NULL) == 0);
	while (atomic_load(&step) != 1) {
		usleep(1000);
	}
	usleep(50000);
	CHECK(setegid(GROUP) == 0);
	CHECK(setreuid(0, USER) == 0);
	CHECK(geteuid() == USER && getuid() == 0);
	CHECK(write(pipe_fds[1], "x", 1) == 1);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(atomic_load(&step) == 2);

	const char *path = "/tmp/credentials-test";
	unlink(path);
	int fd = open(path, O_CREAT | O_WRONLY, 0600);
	CHECK(fd != -1);
	struct stat st;
	CHECK(fstat(fd, &st) == 0 && st.st_uid == USER);
	close(fd);

	CHECK(seteuid(0) == 0 && geteuid() == 0);
	CHECK(unlink(path) == 0);
	CHECK(setgroups(1, (gid_t[]){GROUP}) == 0);
	gid_t groups[4];
	CHECK(getgroups(4, groups) == 1 && groups[0] == GROUP);
	check_thread_identity();
	check_unmapped_identity();
	printf("credentials: ok\n");
	return 0;
}
