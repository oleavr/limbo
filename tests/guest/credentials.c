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

#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"

#define USER  501
#define GROUP 20

static atomic_int step;
static int pipe_fds[2];

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
	printf("credentials: ok\n");
	return 0;
}
