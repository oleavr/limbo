/*
 * Copyright © 2021 Keegan Saunders
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

#include <dirent.h>
#include <limits.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "handler.h"
#include "osfmk/task.h"
#include "process.h"
#include "sysroot.h"
#include "xnu-errno.h"

#define PROC_INFO_CALL_LISTPIDS        0x1
#define PROC_INFO_CALL_PIDINFO         0x2
#define PROC_INFO_CALL_SETCONTROL      0x5
#define PROC_INFO_CALL_DIRTYCONTROL    0x8
#define PROC_INFO_CALL_SET_DYLD_IMAGES 0xf

#define PROC_SELFSET_THREADNAME 2

#define PROC_ALL_PIDS  1
#define PROC_UID_ONLY  4
#define PROC_RUID_ONLY 5
#define PROC_PPID_ONLY 6

#define PROC_PIDTBSDINFO           3
#define PROC_PIDT_SHORTBSDINFO     13
#define PROC_PIDUNIQIDENTIFIERINFO 17
#define PROC_PIDCOALITIONINFO      20

#define SRUN           2
#define PROC_FLAG_LP64 0x10

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
	uint32_t p_reserve2;
	uint64_t p_reserve3;
	uint64_t p_reserve4;
};

struct proc_bsdinfo {
	uint32_t pbi_flags;
	uint32_t pbi_status;
	uint32_t pbi_xstatus;
	uint32_t pbi_pid;
	uint32_t pbi_ppid;
	uint32_t pbi_uid;
	uint32_t pbi_gid;
	uint32_t pbi_ruid;
	uint32_t pbi_rgid;
	uint32_t pbi_svuid;
	uint32_t pbi_svgid;
	uint32_t rfu_1;
	char pbi_comm[16];
	char pbi_name[32];
	uint32_t pbi_nfiles;
	uint32_t pbi_pgid;
	uint32_t pbi_pjobc;
	uint32_t e_tdev;
	uint32_t e_tpgid;
	int32_t pbi_nice;
	uint64_t pbi_start_tvsec;
	uint64_t pbi_start_tvusec;
};

struct proc_taskinfo {
	uint64_t pti_virtual_size;
	uint64_t pti_resident_size;
	uint64_t pti_total_user;
	uint64_t pti_total_system;
	uint64_t pti_threads_user;
	uint64_t pti_threads_system;
	int32_t pti_policy;
	int32_t pti_faults;
	int32_t pti_pageins;
	int32_t pti_cow_faults;
	int32_t pti_messages_sent;
	int32_t pti_messages_received;
	int32_t pti_syscalls_mach;
	int32_t pti_syscalls_unix;
	int32_t pti_csw;
	int32_t pti_threadnum;
	int32_t pti_numrunning;
	int32_t pti_priority;
};

struct proc_taskallinfo {
	struct proc_bsdinfo pbsd;
	struct proc_taskinfo ptinfo;
};

#define PROC_PIDTASKALLINFO 2
#define PROC_PIDTASKINFO    4

#define PROC_PIDPATHINFO 11

#define PROC_PIDPLATFORMINFO 30
#define PLATFORM_MACOS 1

static int pidinfo(int32_t pid, uint32_t flavor, user_addr_t buffer,
		int32_t buffersize);
static void bsdinfo(const struct process *process, struct proc_bsdinfo *info);
static void taskinfo(struct proc_taskinfo *info);
static int setcontrol(uint32_t flavor, user_addr_t buffer, int32_t buffersize);
static int listpids(uint32_t type, uint32_t typeinfo, user_addr_t buffer,
		int32_t buffersize);
static bool status_field(pid_t pid, const char *field, int index,
		unsigned long *value);

int
sys_proc_info(int32_t callnum, int32_t pid, uint32_t flavor, uint64_t arg,
		user_addr_t buffer, int32_t buffersize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "proc_info(%p, %p, %p, %p, %p, %p)\n", (void *)callnum,
			(void *)pid, (void *)flavor, (void *)arg,
			(void *)buffer, (void *)buffersize);
#endif
	switch (callnum) {
	case PROC_INFO_CALL_LISTPIDS:
		return listpids(pid, flavor, buffer, buffersize);
	case PROC_INFO_CALL_PIDINFO:
		return pidinfo(pid, flavor, buffer, buffersize);
	case PROC_INFO_CALL_SETCONTROL:
		return setcontrol(flavor, buffer, buffersize);
	case PROC_INFO_CALL_SET_DYLD_IMAGES:
		task_set_dyld_all_image_info(
				(mach_vm_address_t)buffer, buffersize);
		return 0;
	case PROC_INFO_CALL_DIRTYCONTROL:
		return 0;
	default:
		unimplemented();
	}
}

static int
pidinfo(int32_t pid, uint32_t flavor, user_addr_t buffer, int32_t buffersize)
{
	struct process process;
	if (process_lookup(pid, &process)) {
		return _ESRCH;
	}

	switch (flavor) {
	case PROC_PIDTBSDINFO: {
		struct proc_bsdinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		bsdinfo(&process, info);
		return sizeof(*info);
	}
	case PROC_PIDTASKINFO: {
		struct proc_taskinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		taskinfo(info);
		return sizeof(*info);
	}
	case PROC_PIDTASKALLINFO: {
		struct proc_taskallinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		bsdinfo(&process, &info->pbsd);
		taskinfo(&info->ptinfo);
		return sizeof(*info);
	}
	case PROC_PIDT_SHORTBSDINFO: {
		struct proc_bsdshortinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		memset(info, 0, sizeof(*info));
		info->pbsi_pid = process.pid;
		info->pbsi_ppid = process.ppid;
		info->pbsi_pgid = process.pgid;
		info->pbsi_status = SRUN;
		memcpy(info->pbsi_comm, process.comm, sizeof(process.comm));
		info->pbsi_flags = PROC_FLAG_LP64;
		info->pbsi_uid = process.uid[1];
		info->pbsi_gid = process.gid[1];
		info->pbsi_ruid = process.uid[0];
		info->pbsi_rgid = process.gid[0];
		info->pbsi_svuid = process.uid[2];
		info->pbsi_svgid = process.gid[2];
		return sizeof(*info);
	}
	case PROC_PIDUNIQIDENTIFIERINFO: {
		struct proc_uniqidentifierinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		memset(info, 0, sizeof(*info));
		info->p_uniqueid = process.pid;
		info->p_puniqueid = process.ppid;
		return sizeof(*info);
	}
	case PROC_PIDPATHINFO: {
		char path[PATH_MAX];
		if (!process_executable_path(pid, path)) {
			return _ESRCH;
		}
		const char *guest = sysroot_guest_path(path);
		int32_t length = (int32_t)strlen(guest) + 1;
		if (buffersize < length) {
			return _ENOMEM;
		}
		memcpy(buffer, guest, length);
		return length;
	}
	case PROC_PIDPLATFORMINFO: {
		uint32_t platform = PLATFORM_MACOS;
		if (buffersize < (int32_t)sizeof(platform)) {
			return _ENOMEM;
		}
		memcpy(buffer, &platform, sizeof(platform));
		return sizeof(platform);
	}
	case PROC_PIDCOALITIONINFO: {
		uint64_t info[5] = {0};
		if (buffersize < (int32_t)sizeof(info)) {
			return _ENOMEM;
		}
		memcpy(buffer, info, sizeof(info));
		return sizeof(info);
	}
	default:
		unimplemented();
	}
}

static void
bsdinfo(const struct process *process, struct proc_bsdinfo *info)
{
	memset(info, 0, sizeof(*info));
	info->pbi_flags = PROC_FLAG_LP64;
	info->pbi_status = SRUN;
	info->pbi_pid = process->pid;
	info->pbi_ppid = process->ppid;
	info->pbi_uid = process->uid[1];
	info->pbi_gid = process->gid[1];
	info->pbi_ruid = process->uid[0];
	info->pbi_rgid = process->gid[0];
	info->pbi_svuid = process->uid[2];
	info->pbi_svgid = process->gid[2];
	memcpy(info->pbi_comm, process->comm, sizeof(process->comm));
	memcpy(info->pbi_name, process->comm, sizeof(process->comm));
	info->pbi_pgid = process->pgid;
	info->e_tpgid = process->tpgid;
	info->pbi_nice = process->nice;
	process_start_time(process, &info->pbi_start_tvsec,
			&info->pbi_start_tvusec);
}

static void
taskinfo(struct proc_taskinfo *info)
{
	memset(info, 0, sizeof(*info));
	info->pti_threadnum = 1;
	info->pti_numrunning = 1;
	info->pti_priority = 31;
	info->pti_policy = POLICY_TIMESHARE;
}

static int
setcontrol(uint32_t flavor, user_addr_t buffer, int32_t buffersize)
{
	if (flavor != PROC_SELFSET_THREADNAME) {
		return 0;
	}

	char name[16];
	snprintf(name, sizeof(name), "%.*s", buffersize, (char *)buffer);
	prctl(PR_SET_NAME, name);
	return 0;
}

static int
listpids(uint32_t type, uint32_t typeinfo, user_addr_t buffer,
		int32_t buffersize)
{
	DIR *proc = opendir("/proc");
	int32_t size = 0;
	int *pids = buffer;
	struct dirent *entry;
	while ((entry = readdir(proc)) != NULL) {
		char *end;
		long pid = strtol(entry->d_name, &end, 10);
		if (*end != '\0') {
			continue;
		}
		unsigned long value;
		bool match;
		switch (type) {
		case PROC_ALL_PIDS:
			match = true;
			break;
		case PROC_UID_ONLY:
			match = status_field(pid, "Uid:", 1, &value)
					&& value == typeinfo;
			break;
		case PROC_RUID_ONLY:
			match = status_field(pid, "Uid:", 0, &value)
					&& value == typeinfo;
			break;
		case PROC_PPID_ONLY:
			match = status_field(pid, "PPid:", 0, &value)
					&& value == typeinfo;
			break;
		default:
			match = false;
			break;
		}
		if (!match) {
			continue;
		}
		if (buffer != NULL) {
			if (size + (int32_t)sizeof(int) > buffersize) {
				break;
			}
			pids[size / sizeof(int)] = (int)pid;
		}
		size += sizeof(int);
	}
	closedir(proc);
	return size;
}

static bool
status_field(pid_t pid, const char *field, int index, unsigned long *value)
{
	char path[64], line[256];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	FILE *status = fopen(path, "r");
	if (status == NULL) {
		return false;
	}
	bool found = false;
	size_t length = strlen(field);
	while (fgets(line, sizeof(line), status) != NULL) {
		if (strncmp(line, field, length) != 0) {
			continue;
		}
		char *cursor = line + length;
		for (int i = 0; i <= index; i++) {
			*value = strtoul(cursor, &cursor, 10);
		}
		found = true;
		break;
	}
	fclose(status);
	return found;
}
