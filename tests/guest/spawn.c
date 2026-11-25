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
#include <libproc.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

extern char **environ;

pid_t responsibility_get_pid_responsible_for_pid(pid_t pid);

typedef struct responsibility_identity *responsibility_identity_t;

responsibility_identity_t responsibility_get_attribution_for_audittoken(
		audit_token_t *token, int flags);
const char *responsibility_identity_get_binary_path(
		responsibility_identity_t identity);
const void *responsibility_identity_get_binary_entitlement_data(
		responsibility_identity_t identity, size_t *length);
void responsibility_identity_release(responsibility_identity_t identity);
int responsibility_identity_open_binary_fd(
		responsibility_identity_t identity, int flags);

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

#ifdef __arm64__
	audit_token_t token;
	mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
	CHECK(task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token,
			      &count)
			== KERN_SUCCESS);
	responsibility_identity_t identity
			= responsibility_get_attribution_for_audittoken(
					&token, 0);
	CHECK(identity != NULL);
	pid_t responsible_pid
			= responsibility_get_pid_responsible_for_pid(getpid());
	char responsible[PROC_PIDPATHINFO_MAXSIZE];
	CHECK(proc_pidpath(responsible_pid, responsible, sizeof(responsible))
			> 0);
	const char *binary = responsibility_identity_get_binary_path(identity);
	CHECK(binary != NULL && strcmp(binary, responsible) == 0);
	size_t entitlements_length = 1;
	responsibility_identity_get_binary_entitlement_data(
			identity, &entitlements_length);
	CHECK(responsible_pid != getpid() || entitlements_length == 0);
	errno = 0;
	int binary_fd = responsibility_identity_open_binary_fd(
			identity, O_RDONLY);
	CHECK(binary_fd >= 0 || errno != ENOTSUP);
	if (binary_fd >= 0) {
		struct stat by_id, by_path;
		CHECK(fstat(binary_fd, &by_id) == 0
				&& stat(self, &by_path) == 0);
		CHECK(by_id.st_ino == by_path.st_ino
				&& by_id.st_dev == by_path.st_dev);
		close(binary_fd);
	}
	responsibility_identity_release(identity);
#endif

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

	static const char link[] = "/tmp/limbo-spawn-link";
	unlink(link);
	CHECK(symlink(self, link) == 0);
	CHECK(pipe(fds) == 0);
	posix_spawn_file_actions_init(&actions);
	posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
	posix_spawn_file_actions_addclose(&actions, fds[0]);
	char *link_argv[] = {(char *)link, "exe", NULL};
	CHECK(posix_spawn(&pid, link, &actions, NULL, link_argv, environ) == 0);
	close(fds[1]);
	memset(output, 0, sizeof(output));
	read_all(fds[0], output, sizeof(output));
	close(fds[0]);
	CHECK(strcmp(output, "/tmp/limbo-spawn-link\n") == 0);
	CHECK(wait_child(pid) == 0);
	CHECK(unlink(link) == 0);
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
	if (strcmp(mode, "exe") == 0) {
		char path[PATH_MAX];
		uint32_t length = sizeof(path);
		CHECK(_NSGetExecutablePath(path, &length) == 0);
		CHECK(getenv("LIMBO_EXEC_PATH") == NULL);
		printf("%s\n", path);
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
