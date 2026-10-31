/*
 * Copyright © 2026 Ole André Vadla Ravnås
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
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

extern char **environ;

static char self[PATH_MAX];

static int run_child(const char *mode);
static pid_t spawn_child(const char *mode, posix_spawn_file_actions_t *actions,
		posix_spawnattr_t *attr);
static int wait_child(pid_t pid);
static void read_all(int fd, char *buffer, size_t size);

int
main(int argc, char *argv[])
{
	if (argc == 2) {
		return run_child(argv[1]);
	}

	uint32_t size = sizeof(self);
	CHECK(_NSGetExecutablePath(self, &size) == 0);

	int fds[2];
	CHECK(pipe(fds) == 0);
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
	posix_spawn_file_actions_addclose(&actions, fds[0]);
	posix_spawn_file_actions_addchdir(&actions, "/tmp");
	pid_t pid = spawn_child("pwd", &actions, NULL);
	close(fds[1]);
	char output[PATH_MAX] = {0};
	read_all(fds[0], output, sizeof(output));
	close(fds[0]);
	CHECK(strcmp(output, "/private/tmp\n") == 0);
	CHECK(wait_child(pid) == 0);
	posix_spawn_file_actions_destroy(&actions);

	int status = wait_child(spawn_child("exit", NULL, NULL));
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 3);

	status = wait_child(spawn_child("signal", NULL, NULL));
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGUSR1);

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR2);
	posix_spawnattr_setsigmask(&attr, &mask);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
	status = wait_child(spawn_child("blocked", NULL, &attr));
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	posix_spawnattr_destroy(&attr);

	CHECK(pipe(fds) == 0);
	pid = fork();
	CHECK(pid != -1);
	if (pid == 0) {
		dup2(fds[1], STDOUT_FILENO);
		close(fds[0]);
		execl(self, self, "echo", NULL);
		_exit(127);
	}
	close(fds[1]);
	memset(output, 0, sizeof(output));
	read_all(fds[0], output, sizeof(output));
	CHECK(strcmp(output, "echo\n") == 0);
	CHECK(wait_child(pid) == 0);

	CHECK(pipe(fds) == 0);
	pid = fork();
	CHECK(pid != -1);
	if (pid == 0) {
		posix_spawn_file_actions_init(&actions);
		posix_spawn_file_actions_adddup2(
				&actions, fds[1], STDOUT_FILENO);
		posix_spawn_file_actions_addclose(&actions, fds[0]);
		posix_spawn_file_actions_addchdir(&actions, "/tmp");
		posix_spawnattr_init(&attr);
		posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
		char *argv[] = {self, "pwd", NULL};
		posix_spawn(NULL, self, &actions, &attr, argv, environ);
		_exit(127);
	}
	close(fds[1]);
	memset(output, 0, sizeof(output));
	read_all(fds[0], output, sizeof(output));
	CHECK(strcmp(output, "/private/tmp\n") == 0);
	CHECK(wait_child(pid) == 0);
	return 0;
}

static int
run_child(const char *mode)
{
	if (strcmp(mode, "pwd") == 0) {
		char cwd[PATH_MAX];
		CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
		printf("%s\n", cwd);
		return 0;
	}
	if (strcmp(mode, "exit") == 0) {
		return 3;
	}
	if (strcmp(mode, "signal") == 0) {
		raise(SIGUSR1);
		return 1;
	}
	if (strcmp(mode, "blocked") == 0) {
		sigset_t current;
		CHECK(sigprocmask(SIG_BLOCK, NULL, &current) == 0);
		return sigismember(&current, SIGUSR2) ? 0 : 1;
	}
	printf("%s\n", mode);
	return 0;
}

static pid_t
spawn_child(const char *mode, posix_spawn_file_actions_t *actions,
		posix_spawnattr_t *attr)
{
	char *argv[] = {self, (char *)mode, NULL};
	pid_t pid;
	CHECK(posix_spawn(&pid, self, actions, attr, argv, environ) == 0);
	return pid;
}

static int
wait_child(pid_t pid)
{
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	return status;
}

static void
read_all(int fd, char *buffer, size_t size)
{
	size_t used = 0;
	ssize_t n;
	while ((n = read(fd, buffer + used, size - used - 1)) > 0) {
		used += n;
	}
	CHECK(n == 0);
}
