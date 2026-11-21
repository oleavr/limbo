/*
 * Copyright © 2026 Ole André Vadla Ravnås
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

extern const char *const APP_SANDBOX_READ_WRITE;
extern char *sandbox_extension_issue_file(
		const char *extension_class, const char *path, uint32_t flags);
extern char *sandbox_extension_issue_mach(
		const char *extension_class, const char *name, uint32_t flags);
extern int64_t sandbox_extension_consume(const char *token);
extern int sandbox_extension_release(int64_t handle);
extern int __mac_syscall(const char *policy, int call, void *arg);
extern int sandbox_init(const char *profile, uint64_t flags, char **error);
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

#define AMFI_QUERY_BOOTARG_STATE 96

#define SANDBOX_FILTER_PATH     1
#define SANDBOX_CHECK_NO_REPORT 0x40000000

#define LOCK    "/tmp/limbo-sandbox.lock"
#define MISSING "/private/tmp/limbo-sandbox-missing"
#define DENIED  "/tmp/limbo-sandbox-denied"
#define ALLOWED "/tmp/limbo-sandbox-allowed"

#define ALLOW_ALL "(version 1) (allow default)"
#define DENY_FOLDER                                                            \
	ALLOW_ALL " (deny file-write* (subpath \"/private" DENIED "\"))"

static void check_entered(void);
static void enter(void);
static void check_missing(void);
static void check_profile(void);
static void ask_profile(void);
static void make_file(const char *path);
static int exit_status_of(void (*body)(void));

int
main(void)
{
	int lock = open(LOCK, O_RDONLY | O_CREAT, 0644);
	CHECK(lock >= 0);
	CHECK(flock(lock, LOCK_EX) == 0);

	check_entered();
	check_missing();
	check_profile();

	char *token = sandbox_extension_issue_file(
			APP_SANDBOX_READ_WRITE, "/tmp", 0);
	CHECK(token != NULL);
	CHECK(strstr(token, ";com.apple.app-sandbox.read-write;") != NULL);
	size_t length = strlen(token);
	CHECK(length > 4 && strcmp(token + length - 4, "/tmp") == 0);
	int64_t handle = sandbox_extension_consume(token);
	CHECK(handle >= 0);
	CHECK(sandbox_extension_release(handle) == 0);
	free(token);

	token = sandbox_extension_issue_mach(
			"com.apple.app-sandbox.mach", "com.apple.lsd.mapdb", 0);
	CHECK(token != NULL);
	CHECK(strstr(token, ";com.apple.lsd.mapdb") != NULL);
	free(token);

	unlink("/tmp/limbo-unmade");
	token = sandbox_extension_issue_file(
			APP_SANDBOX_READ_WRITE, "/tmp/limbo-unmade", 0);
	CHECK(token != NULL);
	CHECK(strstr(token, ";com.apple.app-sandbox.read-write;00;") != NULL);
	free(token);

	CHECK(sandbox_extension_issue_file(APP_SANDBOX_READ_WRITE,
			      "/nonexistent/limbo", 0)
			== NULL);

	uint64_t bootarg_state = UINT64_MAX;
	CHECK(__mac_syscall("AMFI", AMFI_QUERY_BOOTARG_STATE, &bootarg_state)
			== 0);
	CHECK(bootarg_state == 0);
	return 0;
}

static void
check_entered(void)
{
	CHECK(exit_status_of(enter) == 0);
	CHECK(sandbox_check(getpid(), NULL, 0) == 0);
}

static void
enter(void)
{
	CHECK(sandbox_check(getpid(), NULL, 0) == 0);
	char *error = NULL;
	CHECK(sandbox_init(ALLOW_ALL, 0, &error) == 0);
	CHECK(sandbox_check(getpid(), NULL, 0) == 1);
	CHECK(sandbox_check(getpid(), "file-read-data", 0) == 0);
	pid_t child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		_exit(sandbox_check(getpid(), NULL, 0) == 1 ? 0 : 1);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void
check_missing(void)
{
	unlink(MISSING);
	CHECK(sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH,
			      MISSING)
			== 1);
	CHECK(sandbox_check(getpid(), "file-write-create", SANDBOX_FILTER_PATH,
			      MISSING)
			== 1);
	CHECK(sandbox_check(getpid(), "file-write-create",
			      SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
			      MISSING)
			== 1);
	CHECK(sandbox_check(getppid(), "file-read-data", SANDBOX_FILTER_PATH,
			      MISSING)
			== 1);
	CHECK(sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH,
			      "/private/tmp")
			== 0);
	CHECK(sandbox_check(getpid(), "file-write-data",
			      SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
			      "/private/tmp")
			== 0);
	CHECK(sandbox_check(getpid(), "file-read-data", 0) == 0);
	CHECK(sandbox_check(getpid(), NULL, SANDBOX_FILTER_PATH, MISSING) == 0);
}

static void
check_profile(void)
{
	unlink(DENIED "/existing");
	rmdir(DENIED);
	CHECK(mkdir(DENIED, 0755) == 0);
	make_file(DENIED "/existing");
	make_file(ALLOWED);
	CHECK(exit_status_of(ask_profile) == 0);
	CHECK(unlink(ALLOWED) == 0);
	CHECK(unlink(DENIED "/existing") == 0);
	CHECK(rmdir(DENIED) == 0);
}

static void
ask_profile(void)
{
	char *error = NULL;
	CHECK(sandbox_init(DENY_FOLDER, 0, &error) == 0);
	CHECK(sandbox_check(getpid(), "file-write-data", SANDBOX_FILTER_PATH,
			      "/private" DENIED "/existing")
			== 1);
	CHECK(sandbox_check(getpid(), "file-write-unlink", SANDBOX_FILTER_PATH,
			      DENIED "/existing")
			== 1);
	CHECK(sandbox_check(getpid(), "file-write-create", SANDBOX_FILTER_PATH,
			      "/private" DENIED)
			== 1);
	CHECK(sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH,
			      "/private" DENIED "/existing")
			== 0);
	CHECK(sandbox_check(getpid(), "file-write-data", SANDBOX_FILTER_PATH,
			      "/private" ALLOWED)
			== 0);
	CHECK(sandbox_check(getpid(), "file-write-create", SANDBOX_FILTER_PATH,
			      "/private/tmp")
			== 0);

	CHECK(sandbox_init(DENY_FOLDER, 0, &error) == 0);
	CHECK(sandbox_init(ALLOW_ALL, 0, &error) == -1);
	CHECK(strcmp(error, strerror(EPERM)) == 0);
	CHECK(sandbox_check(getpid(), "file-write-data", SANDBOX_FILTER_PATH,
			      "/private" DENIED "/existing")
			== 1);
}

static void
make_file(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT, 0644);
	CHECK(fd >= 0);
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
