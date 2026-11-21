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

#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

extern int sandbox_init(const char *profile, uint64_t flags, char **error);
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

#define LOCK      "/tmp/limbo-sandbox.lock"
#define STARTED   "/tmp/limbo-sandbox-kept-started"
#define ALLOW_ALL "(version 1) (allow default)"
#define PROFILE                                                                \
	ALLOW_ALL " (deny file-write* (subpath \"/private/tmp/limbo-kept\"))"
#define KEPT_IN     "/private/var/run/limbo-sandbox"
#define SKIP        77
#define UNSANDBOXED 3

struct compiled {
	char *builtin;
	unsigned char *data;
	size_t size;
};

static const struct compiled *compile(const char *profile);
static void name_kept(void);
static void clean_up(void);
static int started(void);
static void replace_kept(void);
static void make_kept_a_fifo(void);
static void keep_over_other_bytes(void);
static void keep_over_a_folder(void);
static int start_self(void);
static void write_kept(const void *data, size_t size);
static int exit_status_of(void (*body)(void));

static char kept[PATH_MAX];
static pid_t owner;

int
main(int argc, char *argv[])
{
	if (argc == 2) {
		return started();
	}
	int lock = open(LOCK, O_RDONLY | O_CREAT, 0644);
	CHECK(lock >= 0);
	CHECK(flock(lock, LOCK_EX) == 0);
	name_kept();
	owner = getpid();
	CHECK(atexit(clean_up) == 0);
	clean_up();

	int status = exit_status_of(replace_kept);
	if (status == SKIP) {
		printf("skipping: no profile is kept here\n");
		return SKIP;
	}
	CHECK(status == 0);
	CHECK(exit_status_of(make_kept_a_fifo) == 0);
	CHECK(exit_status_of(keep_over_other_bytes) == 0);
	CHECK(exit_status_of(keep_over_a_folder) == 0);
	return 0;
}

static const struct compiled *
compile(const char *profile)
{
	void *library = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_NOW);
	CHECK(library != NULL);
	const struct compiled *(*compile_string)(const char *, void *, char **)
			= dlsym(library, "sandbox_compile_string");
	CHECK(compile_string != NULL);
	char *error = NULL;
	const struct compiled *result = compile_string(profile, NULL, &error);
	CHECK(result != NULL);
	return result;
}

static void
name_kept(void)
{
	const struct compiled *profile = compile(PROFILE);
	unsigned char digest[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256(profile->data, (CC_LONG)profile->size, digest);
	int length = snprintf(kept, sizeof(kept), KEPT_IN "/");
	for (int i = 0; i != CC_SHA256_DIGEST_LENGTH; i++) {
		length += snprintf(kept + length, sizeof(kept) - length, "%02x",
				digest[i]);
	}
	snprintf(kept + length, sizeof(kept) - length, ".sb");
}

static void
clean_up(void)
{
	if (getpid() == owner) {
		unlink(kept);
		rmdir(kept);
		unlink(STARTED);
	}
}

static int
started(void)
{
	int fd = open(STARTED, O_WRONLY | O_CREAT, 0644);
	CHECK(fd >= 0);
	return sandbox_check(getpid(), NULL, 0) == 1 ? 0 : UNSANDBOXED;
}

static void
replace_kept(void)
{
	char *error = NULL;
	CHECK(sandbox_init(PROFILE, 0, &error) == 0);
	if (access(kept, F_OK) == -1) {
		_exit(SKIP);
	}
	CHECK(start_self() == 0);
	CHECK(unlink(STARTED) == 0);

	const struct compiled *other = compile(ALLOW_ALL);
	write_kept(other->data, other->size);
	CHECK(start_self() != 0);
	CHECK(access(STARTED, F_OK) == -1);
}

static void
make_kept_a_fifo(void)
{
	char *error = NULL;
	CHECK(sandbox_init(PROFILE, 0, &error) == 0);
	CHECK(unlink(kept) == 0);
	CHECK(mkfifo(kept, 0644) == 0);
	CHECK(start_self() != 0);
	CHECK(access(STARTED, F_OK) == -1);
	CHECK(unlink(kept) == 0);
}

static void
keep_over_other_bytes(void)
{
	char *error = NULL;
	write_kept("other", 5);
	CHECK(sandbox_init(PROFILE, 0, &error) == 0);
	CHECK(start_self() == 0);
	CHECK(unlink(STARTED) == 0);
	CHECK(unlink(kept) == 0);
}

static void
keep_over_a_folder(void)
{
	char *error = NULL;
	CHECK(mkdir(kept, 0755) == 0);
	CHECK(sandbox_init(PROFILE, 0, &error) == -1);
	CHECK(sandbox_check(getpid(), NULL, 0) == 0);
	CHECK(rmdir(kept) == 0);
}

static int
start_self(void)
{
	extern char **environ;
	char self[PATH_MAX];
	uint32_t size = sizeof(self);
	CHECK(_NSGetExecutablePath(self, &size) == 0);
	char *argv[] = {self, "started", NULL};
	pid_t pid;
	CHECK(posix_spawn(&pid, self, NULL, NULL, argv, environ) == 0);
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status));
	return WEXITSTATUS(status);
}

static void
write_kept(const void *data, size_t size)
{
	int fd = open(kept, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	CHECK(write(fd, data, size) == (ssize_t)size);
	CHECK(close(fd) == 0);
}

static int
exit_status_of(void (*body)(void))
{
	pid_t child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		body();
		_exit(0);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status));
	return WEXITSTATUS(status);
}
