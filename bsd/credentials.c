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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "bsd/credentials.h"
#include "bsd/xnu-errno.h"

#define GROUPS_MAX 1024
#define WAIT_STEPS 2000

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long change_number;
static long change_arguments[3];
static gid_t change_groups[GROUPS_MAX];
static int changed;
static bool sugid;

#ifndef __x86_64__
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif
void limbo_rt_sigreturn(void);
#endif

enum change_kind {
	CHANGE_USERS,
	CHANGE_GROUP_IDS,
	CHANGE_GROUPS,
};

static void handle_change(int sig, siginfo_t *info, void *context);
static long raw_syscall(long number, long a, long b, long c);
static int change(enum change_kind kind, long number, long a, long b, long c);
static bool privileged(void);
static void broadcast(void);
static bool blocks(pid_t tid);

int
credentials_signal(void)
{
	return SIGRTMIN + 5;
}

void
credentials_init(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = handle_change;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
#ifndef __x86_64__
	act.sa_flags |= SA_RESTORER;
	act.sa_restorer = limbo_rt_sigreturn;
#endif
	sigaction(credentials_signal(), &act, NULL);
}

static void
handle_change(int sig, siginfo_t *info, void *context)
{
	(void)sig;
	(void)info;
	(void)context;
	raw_syscall(__atomic_load_n(&change_number, __ATOMIC_ACQUIRE),
			change_arguments[0], change_arguments[1],
			change_arguments[2]);
	__atomic_add_fetch(&changed, 1, __ATOMIC_RELEASE);
}

static long
raw_syscall(long number, long a, long b, long c)
{
#ifdef __x86_64__
	long result;
	__asm__ volatile("syscall"
			: "=a"(result)
			: "a"(number), "D"(a), "S"(b), "d"(c)
			: "rcx", "r11", "memory");
	return result;
#else
	register long x8 __asm__("x8") = number;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	__asm__ volatile("svc #0"
			: "+r"(x0)
			: "r"(x8), "r"(x1), "r"(x2)
			: "memory");
	return x0;
#endif
}

int
credentials_setuid(uid_t uid)
{
	return change(CHANGE_USERS, SYS_setuid, uid, 0, 0);
}

static int
change(enum change_kind kind, long number, long a, long b, long c)
{
	if (!privileged()) {
		return 0;
	}
	pthread_mutex_lock(&lock);
	uid_t users[3];
	gid_t group_ids[3];
	gid_t groups[GROUPS_MAX];
	getresuid(&users[0], &users[1], &users[2]);
	getresgid(&group_ids[0], &group_ids[1], &group_ids[2]);
	int group_count = getgroups(GROUPS_MAX, groups);
	if (syscall(number, a, b, c) != 0) {
		int error = errno;
		pthread_mutex_unlock(&lock);
		errno = error;
		return errno_map(-1);
	}
	switch (kind) {
	case CHANGE_USERS: {
		uid_t real, effective, saved;
		getresuid(&real, &effective, &saved);
		if (real != users[0] || effective != users[1]
				|| saved != users[2]) {
			sugid = true;
		}
		change_arguments[0] = real;
		change_arguments[1] = effective;
		change_arguments[2] = saved;
		__atomic_store_n(&change_number, SYS_setresuid,
				__ATOMIC_RELEASE);
		break;
	}
	case CHANGE_GROUP_IDS: {
		gid_t real, effective, saved;
		getresgid(&real, &effective, &saved);
		if (real != group_ids[0] || effective != group_ids[1]
				|| saved != group_ids[2]) {
			sugid = true;
		}
		change_arguments[0] = real;
		change_arguments[1] = effective;
		change_arguments[2] = saved;
		__atomic_store_n(&change_number, SYS_setresgid,
				__ATOMIC_RELEASE);
		break;
	}
	case CHANGE_GROUPS: {
		int count = getgroups(GROUPS_MAX, change_groups);
		if (count != group_count
				|| (count > 0
						&& memcmp(change_groups, groups,
								   count * sizeof(gid_t))
								!= 0)) {
			sugid = true;
		}
		change_arguments[0] = count < 0 ? 0 : count;
		change_arguments[1] = (long)change_groups;
		change_arguments[2] = 0;
		__atomic_store_n(&change_number, SYS_setgroups,
				__ATOMIC_RELEASE);
		break;
	}
	}
	broadcast();
	pthread_mutex_unlock(&lock);
	return 0;
}

static bool
privileged(void)
{
	uid_t real, effective, saved;
	return getresuid(&real, &effective, &saved) == 0
			&& (real == 0 || effective == 0 || saved == 0);
}

static void
broadcast(void)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/task", getpid());
	DIR *dir = opendir(path);
	if (dir == NULL) {
		return;
	}
	__atomic_store_n(&changed, 0, __ATOMIC_RELEASE);
	pid_t self = gettid();
	int sent = 0;
	for (struct dirent *entry; (entry = readdir(dir)) != NULL;) {
		pid_t tid = (pid_t)atoi(entry->d_name);
		if (tid <= 0 || tid == self || blocks(tid)) {
			continue;
		}
		if (syscall(SYS_tgkill, getpid(), tid, credentials_signal())
				== 0) {
			sent++;
		}
	}
	closedir(dir);
	for (int i = 0; i != WAIT_STEPS
			&& __atomic_load_n(&changed, __ATOMIC_ACQUIRE) < sent;
			i++) {
		usleep(500);
	}
#ifdef ENABLE_STRACE
	if (__atomic_load_n(&changed, __ATOMIC_ACQUIRE) < sent) {
		fprintf(stderr, "credentials: %d of %d threads changed\n",
				__atomic_load_n(&changed, __ATOMIC_ACQUIRE),
				sent);
	}
#endif
}

static bool
blocks(pid_t tid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/task/%d/status", getpid(), tid);
	FILE *file = fopen(path, "re");
	if (file == NULL) {
		return true;
	}
	char line[256];
	char state = 'R';
	unsigned long long blocked = 0;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (sscanf(line, "State: %c", &state) == 1) {
			continue;
		}
		if (sscanf(line, "SigBlk: %llx", &blocked) == 1) {
			break;
		}
	}
	fclose(file);
	return state == 'Z' || state == 'X'
			|| ((blocked >> (credentials_signal() - 1)) & 1);
}

int
credentials_seteuid(uid_t euid)
{
	return change(CHANGE_USERS, SYS_setresuid, -1, euid, -1);
}

int
credentials_setreuid(uid_t ruid, uid_t euid)
{
	return change(CHANGE_USERS, SYS_setreuid, (int32_t)ruid, (int32_t)euid,
			0);
}

int
credentials_setgid(gid_t gid)
{
	return change(CHANGE_GROUP_IDS, SYS_setgid, gid, 0, 0);
}

int
credentials_setegid(gid_t egid)
{
	return change(CHANGE_GROUP_IDS, SYS_setresgid, -1, egid, -1);
}

int
credentials_setregid(gid_t rgid, gid_t egid)
{
	return change(CHANGE_GROUP_IDS, SYS_setregid, (int32_t)rgid,
			(int32_t)egid, 0);
}

int
credentials_setgroups(uint32_t count, const uint32_t *groups)
{
	if (count > GROUPS_MAX) {
		return _EINVAL;
	}
	gid_t list[GROUPS_MAX];
	for (uint32_t i = 0; i != count; i++) {
		list[i] = groups[i];
	}
	return change(CHANGE_GROUPS, SYS_setgroups, count, (long)list, 0);
}

bool
credentials_issetugid(void)
{
	return sugid;
}

void
credentials_set_sugid(void)
{
	sugid = true;
}
