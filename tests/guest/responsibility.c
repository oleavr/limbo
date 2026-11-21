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
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

extern char **environ;
pid_t responsibility_get_pid_responsible_for_pid(pid_t pid);
int responsibility_spawnattrs_setdisclaim(
		posix_spawnattr_t *attrs, int disclaim);
int posix_spawnattr_getmacpolicyinfo_np(const posix_spawnattr_t *attr,
		const char *policy, void **data, size_t *length);
int posix_spawnattr_setmacpolicyinfo_np(posix_spawnattr_t *attr,
		const char *policy, void *data, size_t length);
int __mac_syscall(const char *policy, int call, void *arg);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int size);

struct mac_extension {
	char policyname[128];
	uint64_t data;
	uint64_t datalen;
};

struct mac_extensions {
	int32_t alloc;
	int32_t count;
	struct mac_extension extensions[2];
};

struct spawn_args {
	size_t attr_size;
	void *attrp;
	size_t file_actions_size;
	void *file_actions;
	size_t port_actions_size;
	void *port_actions;
	size_t mac_extensions_size;
	struct mac_extensions *mac_extensions;
	uint64_t others[16];
};

int __posix_spawn(pid_t *pid, const char *path, struct spawn_args *args,
		char *const argv[], char *const envp[]);

#define RESPONSIBLE_FOR_PID        180
#define VARIABLE                   "LIMBO_RESPONSIBLE"
#define PROC_PIDT_SHORTBSDINFO     13
#define PROC_PIDUNIQIDENTIFIERINFO 17
#define DISCLAIM_SIZE              24
#define USER                       501
#define SKIP                       77
#define DEADLINE                   60
#define UNTOUCHED                  0x5a5a5a5a
#define NO_ATTRIBUTE               INT_MIN
#define DONE                       'd'
#define FILLERS                    8
#define FILLER_SIZE                16384

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

struct proc_uniqidentifierinfo {
	uint8_t p_uuid[16];
	uint64_t p_uniqueid;
	uint64_t p_puniqueid;
	int32_t p_idversion;
	uint32_t p_orig_ppidversion;
	uint64_t p_reserve2;
	uint64_t p_reserve3;
};

static int run_child(char *argv[]);
static void check_heads(void);
static int led_by_parent(void);
static int lead(int done);
static int outlive(pid_t leader, int ready, int done);
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
static void check_disclaimed(void);
static void check_attribute(void);
static int disclaimed_by(
		uint32_t version, uint32_t size, uint32_t flags, size_t length);
static int disclaimed_with(void *data, size_t length);
static int disclaimed_by_first(uint32_t first, uint32_t second);
static void check_outlived(void);
static void check_held(int disclaim, char **envp, bool own);
static pid_t spawn_self(const char *mode, int number, int disclaim, short flags,
		char **envp);
static int answers_for_itself(void);
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
	check_disclaimed();
	check_attribute();
	check_outlived();
	return 0;
}

static int
run_child(char *argv[])
{
	int number = argv[2] != NULL ? atoi(argv[2]) : getpid();
	if (strcmp(argv[1], "held") == 0) {
		char byte;
		return read(number, &byte, 1) == 1 ? 0 : 1;
	}
	if (strcmp(argv[1], "leads") == 0) {
		return lead(number);
	}
	if (responsibility_get_pid_responsible_for_pid(getpid()) != number) {
		return 1;
	}
	if (strcmp(argv[1], "heads") == 0) {
		check_heads();
	}
	if (strcmp(argv[1], "executes") == 0) {
		char own[16];
		snprintf(own, sizeof(own), "%d", getpid());
		execl(self, self, "is", own, NULL);
		return 1;
	}
	if (strcmp(argv[1], "replaces") == 0) {
		posix_spawnattr_t attr;
		char *missing[] = {"/limbo-responsibility-missing", NULL};
		CHECK(posix_spawnattr_init(&attr) == 0);
		CHECK(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC)
				== 0);
		CHECK(responsibility_spawnattrs_setdisclaim(&attr, 1) == 0);
		CHECK(posix_spawn(NULL, missing[0], NULL, &attr, missing,
				      environ)
				== ENOENT);
		CHECK(responsibility_get_pid_responsible_for_pid(getpid())
				== number);
		spawn_self("is", getpid(), 1, POSIX_SPAWN_SETEXEC, environ);
		return 1;
	}
	return 0;
}

static void
check_heads(void)
{
	struct proc_uniqidentifierinfo info;
	uint64_t pid;
	uint64_t uniqueid;
	struct responsible_for_pid_args args = {
			.pid = (uint64_t)getpid(),
			.responsible = &pid,
			.responsible_uniqueid = &uniqueid,
	};
	CHECK(proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0, &info,
			      sizeof(info))
			== sizeof(info));
	CHECK(__mac_syscall("Quarantine", RESPONSIBLE_FOR_PID, &args) == 0);
	CHECK(pid == (uint64_t)getpid() && uniqueid == info.p_uniqueid);
	CHECK(exit_status_of(spawn_self(
			      "is", getpid(), NO_ATTRIBUTE, 0, environ))
			== 0);
	CHECK(exit_status_of_fork(led_by_parent) == 0);
}

static int
led_by_parent(void)
{
	pid_t parent = getppid();
	pid_t own = responsibility_get_pid_responsible_for_pid(getpid());
	pid_t its = responsibility_get_pid_responsible_for_pid(parent);
	return own == parent && its == parent ? 0 : 1;
}

static int
lead(int done)
{
	pid_t leader = getpid();
	int ready[2];
	CHECK(pipe(ready) == 0);
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		close(ready[0]);
		CHECK(fork() != -1);
		_exit(outlive(leader, ready[1], done));
	}
	char bytes[2];
	close(ready[1]);
	CHECK(read(ready[0], &bytes[0], 1) == 1);
	CHECK(read(ready[0], &bytes[1], 1) == 1);
	return 0;
}

static int
outlive(pid_t leader, int ready, int done)
{
	alarm(DEADLINE);
	bool led = responsibility_get_pid_responsible_for_pid(getpid())
			== leader;
	CHECK(write(ready, "", 1) == 1);
	while (kill(leader, 0) == 0) {
		usleep(1000);
	}
	bool own = answers_for_itself() == 0
			&& exit_status_of_fork(answers_for_itself) == 0
			&& exit_status_of(spawn_self(
					   "is", 0, NO_ATTRIBUTE, 0, environ))
					== 0;
	char byte = led && own ? DONE : 0;
	CHECK(write(done, &byte, 1) == 1);
	return 0;
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
	CHECK(exit_status_of(spawn_self(
			      "is", responsible, NO_ATTRIBUTE, 0, environ))
			== 0);
	check_held(NO_ATTRIBUTE, environ, false);
}

static void
check_environment(void)
{
	char *none[] = {NULL};
	char *another[] = {VARIABLE "=1:1", NULL};
	char own[64];
	const char *value = getenv(VARIABLE);
	if (value != NULL) {
		snprintf(own, sizeof(own), VARIABLE "=%s", value);
	} else {
		snprintf(own, sizeof(own), VARIABLE "=%d:0", getpid());
	}
	char *named[] = {own, NULL};
	CHECK(exit_status_of(spawn_self(
			      "is", responsible, NO_ATTRIBUTE, 0, none))
			== 0);
	CHECK(exit_status_of(spawn_self(
			      "is", responsible, NO_ATTRIBUTE, 0, another))
			== 0);
	check_held(NO_ATTRIBUTE, another, false);
	check_held(1, named, true);
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
	check_held(NO_ATTRIBUTE, large, false);
}

static void
check_disclaimed(void)
{
	void *data = NULL;
	size_t length = 0;
	posix_spawnattr_t attr;
	CHECK(posix_spawnattr_init(&attr) == 0);
	CHECK(responsibility_spawnattrs_setdisclaim(&attr, 1) == 0);
	CHECK(posix_spawnattr_getmacpolicyinfo_np(
			      &attr, "Quarantine", &data, &length)
			== 0);
	CHECK(length == DISCLAIM_SIZE);
	const uint32_t *words = data;
	CHECK(words[0] == 1 && words[1] == DISCLAIM_SIZE && words[2] == 1);
	CHECK(posix_spawnattr_destroy(&attr) == 0);

	CHECK(exit_status_of(spawn_self("heads", 0, 1, 0, environ)) == 0);
	CHECK(exit_status_of(spawn_self("heads", 0, -1, 0, environ)) == 0);
	CHECK(exit_status_of(spawn_self("is", responsible, 0, 0, environ))
			== 0);
	CHECK(exit_status_of(spawn_self("is", responsible, 2, 0, environ))
			== 0);
	check_held(1, environ, true);
	CHECK(exit_status_of(spawn_self("executes", 0, 1, 0, environ)) == 0);
	CHECK(exit_status_of(spawn_self("replaces", responsible, NO_ATTRIBUTE,
			      0, environ))
			== 0);
}

static void
check_attribute(void)
{
	CHECK(disclaimed_by(1, DISCLAIM_SIZE, 1, DISCLAIM_SIZE) == 1);
	CHECK(disclaimed_by(2, DISCLAIM_SIZE, 1, DISCLAIM_SIZE) == 1);
	CHECK(disclaimed_by(1, DISCLAIM_SIZE / 2, 1, DISCLAIM_SIZE) == 1);
	CHECK(disclaimed_by(1, DISCLAIM_SIZE, 1, DISCLAIM_SIZE + 8) == 1);
	CHECK(disclaimed_by(1, DISCLAIM_SIZE, 2, DISCLAIM_SIZE) == 0);
	CHECK(disclaimed_by(1, DISCLAIM_SIZE, 1, 0) == -EINVAL);
	CHECK(disclaimed_by(1, DISCLAIM_SIZE, 1, 20000) == -EINVAL);
	CHECK(disclaimed_with(NULL, DISCLAIM_SIZE) == -ENOMEM);
	CHECK(disclaimed_by_first(0, 1) == 0);
	CHECK(disclaimed_by_first(1, 0) == 1);
}

static int
disclaimed_by(uint32_t version, uint32_t size, uint32_t flags, size_t length)
{
	static uint32_t words[5000];
	words[0] = version;
	words[1] = size;
	words[2] = flags;
	return disclaimed_with(words, length);
}

static int
disclaimed_with(void *data, size_t length)
{
	char *argv[] = {self, "is", NULL};
	posix_spawnattr_t attr;
	CHECK(posix_spawnattr_init(&attr) == 0);
	CHECK(posix_spawnattr_setmacpolicyinfo_np(
			      &attr, "Quarantine", data, length)
			== 0);
	pid_t child;
	int error = posix_spawn(&child, self, NULL, &attr, argv, environ);
	CHECK(posix_spawnattr_destroy(&attr) == 0);
	return error != 0 ? -error : exit_status_of(child) == 0;
}

static int
disclaimed_by_first(uint32_t first, uint32_t second)
{
	uint32_t words[2][DISCLAIM_SIZE / sizeof(uint32_t)] = {
			{1, DISCLAIM_SIZE, first}, {1, DISCLAIM_SIZE, second}};
	struct mac_extensions list = {.alloc = 2, .count = 2};
	for (int i = 0; i != 2; i++) {
		strcpy(list.extensions[i].policyname, "Quarantine");
		list.extensions[i].data = (uint64_t)(uintptr_t)words[i];
		list.extensions[i].datalen = DISCLAIM_SIZE;
	}
	struct spawn_args args = {
			.mac_extensions_size = sizeof(list),
			.mac_extensions = &list,
	};
	char *argv[] = {self, "is", NULL};
	pid_t child;
	CHECK(__posix_spawn(&child, self, &args, argv, environ) == 0);
	return exit_status_of(child) == 0;
}

static void
check_outlived(void)
{
	int done[2];
	CHECK(pipe(done) == 0);
	CHECK(exit_status_of(spawn_self("leads", done[1], 1, 0, environ)) == 0);
	close(done[1]);
	char bytes[2];
	CHECK(read(done[0], &bytes[0], 1) == 1 && bytes[0] == DONE);
	CHECK(read(done[0], &bytes[1], 1) == 1 && bytes[1] == DONE);
	close(done[0]);
}

static void
check_held(int disclaim, char **envp, bool own)
{
	int held[2];
	CHECK(pipe(held) == 0);
	CHECK(fcntl(held[1], F_SETFD, FD_CLOEXEC) == 0);
	pid_t child = spawn_self("held", held[0], disclaim, 0, envp);
	CHECK(responsibility_get_pid_responsible_for_pid(child)
			== (own ? child : responsible));
	CHECK(write(held[1], "", 1) == 1);
	CHECK(exit_status_of(child) == 0);
	close(held[0]);
	close(held[1]);
}

static pid_t
spawn_self(const char *mode, int number, int disclaim, short flags, char **envp)
{
	char text[16];
	snprintf(text, sizeof(text), "%d", number);
	char *argv[] = {self, (char *)mode, number != 0 ? text : NULL, NULL};
	posix_spawnattr_t attr;
	CHECK(posix_spawnattr_init(&attr) == 0);
	CHECK(posix_spawnattr_setflags(&attr, flags) == 0);
	if (disclaim != NO_ATTRIBUTE) {
		CHECK(responsibility_spawnattrs_setdisclaim(&attr, disclaim)
				== 0);
	}
	pid_t child;
	CHECK(posix_spawn(&child, self, NULL, &attr, argv, envp) == 0);
	CHECK(posix_spawnattr_destroy(&attr) == 0);
	return child;
}

static int
answers_for_itself(void)
{
	return responsibility_get_pid_responsible_for_pid(getpid()) == getpid()
			? 0
			: 1;
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
