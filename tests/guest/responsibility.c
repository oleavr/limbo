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
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

extern char **environ;
pid_t responsibility_get_pid_responsible_for_pid(pid_t pid);
int __mac_syscall(const char *policy, int call, void *arg);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int size);

#define RESPONSIBLE_FOR_PID    180
#define PROC_PIDT_SHORTBSDINFO 13
#define USER                   501
#define SKIP                   77
#define DEADLINE               60
#define UNTOUCHED              0x5a5a5a5a
#define FILLERS                8
#define FILLER_SIZE            16384

struct responsible_for_pid_args {
	uint64_t pid;
	uint64_t *responsible;
	uint64_t *responsible_uniqueid;
	uint64_t reserved[2];
};

struct proc_bsdshortinfo {
	uint32_t pbsi_pid;
	uint32_t pbsi_ppid;
	uint32_t pbsi_pgid;
	uint32_t pbsi_status;
	char pbsi_comm[16];
	uint32_t pbsi_flags;
	uint32_t pbsi_uid;
	uint32_t pbsi_gid;
	uint32_t pbsi_ruid;
	uint32_t pbsi_rgid;
	uint32_t pbsi_svuid;
	uint32_t pbsi_svgid;
	uint32_t pbsi_rfu;
};

static int run_child(char *argv[]);
static void check_answered(void);
static void check_missing(void);
static void check_faults(void);
static void check_another_user(void);
static int ask_as_another(void);
static void check_forked(void);
static int inherits(void);
static void check_spawned(void);
static void check_environment(void);
static void check_large_environment(void);
static void check_held(char **envp);
static pid_t spawn_self(const char *mode, int number, char **envp);
static int exit_status_of(pid_t child);
static int exit_status_of_fork(int (*body)(void));

static char self[PATH_MAX];
static pid_t responsible;

int
main(int argc, char *argv[])
{
	alarm(DEADLINE);
	uint32_t size = sizeof(self);
	CHECK(_NSGetExecutablePath(self, &size) == 0);
	if (argc > 1) {
		return run_child(argv);
	}

	check_answered();
	check_missing();
	check_faults();
	check_another_user();
	check_forked();
	check_spawned();
	check_environment();
	check_large_environment();
	return 0;
}

static int
run_child(char *argv[])
{
	int number = atoi(argv[2]);
	if (strcmp(argv[1], "held") == 0) {
		char byte;
		return read(number, &byte, 1) == 1 ? 0 : 1;
	}
	return responsibility_get_pid_responsible_for_pid(getpid()) == number
			? 0
			: 1;
}

static void
check_answered(void)
{
	uint64_t pid = 0;
	uint64_t uniqueid = 0;
	struct responsible_for_pid_args args = {
			.pid = (uint64_t)getpid(),
			.responsible = &pid,
			.responsible_uniqueid = &uniqueid,
	};
	CHECK(__mac_syscall("Quarantine", RESPONSIBLE_FOR_PID, &args) == 0);
	CHECK(pid > 0 && uniqueid != 0);
	responsible = responsibility_get_pid_responsible_for_pid(getpid());
	CHECK((uint64_t)responsible == pid);
}

static void
check_missing(void)
{
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		_exit(0);
	}
	while (responsibility_get_pid_responsible_for_pid(child) != -1) {
		usleep(1000);
	}
	CHECK(errno == ESRCH);
	CHECK(exit_status_of(child) == 0);
	CHECK(responsibility_get_pid_responsible_for_pid(child) == -1);
	CHECK(errno == ESRCH);
	CHECK(responsibility_get_pid_responsible_for_pid(-1) == -1);
	CHECK(errno == ESRCH);

	uint64_t pid = UNTOUCHED;
	uint64_t uniqueid = UNTOUCHED;
	struct responsible_for_pid_args args = {
			.pid = (uint64_t)getpid() | (1ull << 32),
			.responsible = &pid,
			.responsible_uniqueid = &uniqueid,
	};
	CHECK(__mac_syscall("Quarantine", RESPONSIBLE_FOR_PID, &args) == -1);
	CHECK(errno == ESRCH && pid == UNTOUCHED && uniqueid == UNTOUCHED);
}

static void
check_faults(void)
{
	uint64_t pid = UNTOUCHED;
	uint64_t uniqueid = UNTOUCHED;
	struct responsible_for_pid_args args = {
			.pid = (uint64_t)getpid(),
			.responsible = &pid,
	};
	CHECK(__mac_syscall("Quarantine", RESPONSIBLE_FOR_PID, &args) == -1);
	CHECK(errno == EFAULT && pid == (uint64_t)responsible);

	args.responsible = NULL;
	args.responsible_uniqueid = &uniqueid;
	CHECK(__mac_syscall("Quarantine", RESPONSIBLE_FOR_PID, &args) == -1);
	CHECK(errno == EFAULT && uniqueid == UNTOUCHED);

	CHECK(__mac_syscall("Quarantine", RESPONSIBLE_FOR_PID, NULL) == -1);
	CHECK(errno == EFAULT);
}

static void
check_another_user(void)
{
	if (geteuid() == 0) {
		int status = exit_status_of_fork(ask_as_another);
		if (status == SKIP) {
			printf("skipping what another user is refused: no "
			       "user %d\n",
					USER);
		} else {
			CHECK(status == 0);
		}
		return;
	}
	struct proc_bsdshortinfo first;
	CHECK(proc_pidinfo(1, PROC_PIDT_SHORTBSDINFO, 0, &first, sizeof(first))
			== sizeof(first));
	if (first.pbsi_uid == geteuid()) {
		printf("skipping what another user is refused: process 1 is "
		       "this user's\n");
		return;
	}
	CHECK(responsibility_get_pid_responsible_for_pid(1) == -1);
	CHECK(errno == EPERM);
}

static int
ask_as_another(void)
{
	if (setgid(USER) != 0 || setuid(USER) != 0) {
		return SKIP;
	}
	return responsibility_get_pid_responsible_for_pid(getppid()) == -1
					&& errno == EPERM
			? 0
			: 1;
}

static void
check_forked(void)
{
	int held[2];
	CHECK(pipe(held) == 0);
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		char byte;
		close(held[1]);
		_exit(read(held[0], &byte, 1) == 0 ? inherits() : 1);
	}
	CHECK(responsibility_get_pid_responsible_for_pid(child) == responsible);
	close(held[1]);
	close(held[0]);
	CHECK(exit_status_of(child) == 0);
}

static int
inherits(void)
{
	return responsibility_get_pid_responsible_for_pid(getpid())
					== responsible
			? 0
			: 1;
}

static void
check_spawned(void)
{
	CHECK(exit_status_of(spawn_self("is", responsible, environ)) == 0);
	check_held(environ);
}

static void
check_environment(void)
{
	char *none[] = {NULL};
	char *another[] = {"LIMBO_RESPONSIBLE=1:1", NULL};
	CHECK(exit_status_of(spawn_self("is", responsible, none)) == 0);
	CHECK(exit_status_of(spawn_self("is", responsible, another)) == 0);
	check_held(another);
}

static void
check_large_environment(void)
{
	static char fillers[FILLERS][FILLER_SIZE];
	char *large[FILLERS + 1] = {NULL};
	for (int i = 0; i != FILLERS; i++) {
		memset(fillers[i], 'x', FILLER_SIZE - 1);
		memcpy(fillers[i], "FILLER=", 7);
		fillers[i][6] = (char)('0' + i);
		fillers[i][7] = '=';
		large[i] = fillers[i];
	}
	check_held(large);
}

static void
check_held(char **envp)
{
	int held[2];
	CHECK(pipe(held) == 0);
	CHECK(fcntl(held[1], F_SETFD, FD_CLOEXEC) == 0);
	pid_t child = spawn_self("held", held[0], envp);
	CHECK(responsibility_get_pid_responsible_for_pid(child) == responsible);
	CHECK(write(held[1], "", 1) == 1);
	CHECK(exit_status_of(child) == 0);
	close(held[0]);
	close(held[1]);
}

static pid_t
spawn_self(const char *mode, int number, char **envp)
{
	char text[16];
	snprintf(text, sizeof(text), "%d", number);
	char *argv[] = {self, (char *)mode, text, NULL};
	pid_t child;
	CHECK(posix_spawn(&child, self, NULL, NULL, argv, envp) == 0);
	return child;
}

static int
exit_status_of(pid_t child)
{
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status));
	return WEXITSTATUS(status);
}

static int
exit_status_of_fork(int (*body)(void))
{
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		_exit(body());
	}
	return exit_status_of(child);
}
