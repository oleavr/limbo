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
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

#define USER 501
#define SKIP 77

static int run_as_user(
		const char *program, const char *mode, int fd, int *status);

int
main(int argc, char *argv[])
{
	if (argc == 4 && strcmp(argv[1], "report") == 0) {
		char cwd[PATH_MAX];
		CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
		dprintf(atoi(argv[3]), "%d %d %d %s", (int)getuid(),
				(int)geteuid(), issetugid(), cwd);
		if (strcmp(argv[2], "signal") == 0) {
			kill(getpid(), SIGTERM);
		}
		return 3;
	}

	if (geteuid() != 0) {
		printf("skipping: not root\n");
		return SKIP;
	}
	CHECK(issetugid() == 0);
	char self[PATH_MAX];
	uint32_t size = sizeof(self);
	CHECK(_NSGetExecutablePath(self, &size) == 0);
	char program[] = "/tmp/limbo-setid-XXXXXX";
	int out = mkstemp(program);
	int in = open(self, O_RDONLY);
	CHECK(in != -1 && out != -1);
	char buffer[65536];
	ssize_t n;
	while ((n = read(in, buffer, sizeof(buffer))) > 0) {
		CHECK(write(out, buffer, n) == n);
	}
	CHECK(close(in) == 0 && close(out) == 0);
	CHECK(chown(program, 0, 0) == 0 && chmod(program, 04755) == 0);
	struct statvfs vfs;
	CHECK(statvfs(program, &vfs) == 0);
	if (vfs.f_flag & ST_NOSUID) {
		printf("skipping: the build is on a nosuid mount\n");
		return SKIP;
	}

	int pipes[2];
	CHECK(pipe(pipes) == 0);
	int status;
	int result = run_as_user(program, "exit", pipes[1], &status);
	if (result == SKIP) {
		printf("skipping: no user %d in this namespace\n", USER);
		return SKIP;
	}
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 3);
	char report[PATH_MAX + 32];
	n = read(pipes[0], report, sizeof(report) - 1);
	CHECK(n > 0);
	report[n] = '\0';
	char expected[64];
	snprintf(expected, sizeof(expected), "%d 0 1 /usr/lib", USER);
	if (strcmp(report, expected) != 0) {
		fprintf(stderr, "report: %s, expected %s\n", report, expected);
	}
	CHECK(strcmp(report, expected) == 0);

	CHECK(run_as_user(program, "signal", pipes[1], &status) == 0);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
	CHECK(unlink(program) == 0);
	return 0;
}

static int
run_as_user(const char *program, const char *mode, int fd, int *status)
{
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		if (setuid(USER) != 0 || getuid() != USER) {
			_exit(SKIP);
		}
		CHECK(issetugid() == 1);
		int null = open("/dev/null", O_RDWR);
		CHECK(null != -1 && dup2(null, 999) == 999);
		for (int i = 0; i < 40; i++) {
			CHECK(dup(null) != -1);
		}
		char number[16];
		snprintf(number, sizeof(number), "%d", fd);
		CHECK(chdir("/usr/lib") == 0);
		execl(program, "setid-program", "report", mode, number, NULL);
		_exit(errno == ENOENT ? 127 : 126);
	}
	CHECK(waitpid(child, status, 0) == child);
	return (WIFEXITED(*status) && WEXITSTATUS(*status) == SKIP) ? SKIP : 0;
}
