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
#include <sys/stat.h>
#include <unistd.h>

#include "codesign.h"
#include "commpage.h"
#include "fs/device.h"
#include "handler.h"
#include "kevent.h"
#include "osfmk/task.h"
#include "process.h"
#include "sysroot.h"
#include "xnu-errno.h"

#define PROC_INFO_CALL_LISTPIDS        0x1
#define PROC_INFO_CALL_PIDINFO         0x2
#define PROC_INFO_CALL_PIDFDINFO       0x3
#define PROC_INFO_CALL_SETCONTROL      0x5
#define PROC_INFO_CALL_DIRTYCONTROL    0x8
#define PROC_INFO_CALL_PIDRUSAGE       0x9
#define PROC_INFO_CALL_SET_DYLD_IMAGES 0xf

#define PROC_SELFSET_THREADNAME 2

#define PROC_ALL_PIDS  1
#define PROC_UID_ONLY  4
#define PROC_RUID_ONLY 5
#define PROC_PPID_ONLY 6

#define PROC_PIDLISTFDS            1
#define PROC_PIDTBSDINFO           3
#define PROC_PIDT_SHORTBSDINFO     13
#define PROC_PIDUNIQIDENTIFIERINFO 17
#define PROC_PIDT_BSDINFOWITHUNIQID 18
#define PROC_PIDCOALITIONINFO      20
#define PROC_PIDLISTDYNKQUEUES     27

#define PROC_PIDDYNKQUEUES_MAX 1024

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

struct proc_bsdinfowithuniqid {
	struct proc_bsdinfo pbsd;
	struct proc_uniqidentifierinfo p_uniqidentifier;
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

#ifndef PROC_PIDPLATFORMINFO
#define PROC_PIDPLATFORMINFO 30
#endif

static int pidinfo(int32_t pid, uint32_t flavor, user_addr_t buffer,
		int32_t buffersize);
static void uniqidentifierinfo(const struct process *process,
		struct proc_uniqidentifierinfo *info);
static void bsdinfo(const struct process *process, struct proc_bsdinfo *info);
static int listfds(int32_t pid, void *buffer, int32_t buffersize);
static int fdinfo(int32_t pid, uint32_t flavor, int32_t fd, void *buffer,
		int32_t buffersize);
static void taskinfo(const struct process *process, struct proc_taskinfo *info);
static int pidrusage(int32_t pid, uint32_t flavor, user_addr_t buffer);
static uint64_t nanoseconds_to_absolute(uint64_t nanoseconds);
static int setcontrol(uint32_t flavor, user_addr_t buffer, int32_t buffersize);
static int listpids(uint32_t type, uint32_t typeinfo, user_addr_t buffer,
		int32_t buffersize);
static bool status_field(pid_t pid, const char *field, int index,
		unsigned long *value);
static uint64_t wakeups(int32_t pid);

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
	case PROC_INFO_CALL_PIDFDINFO:
		return fdinfo(pid, flavor, (int32_t)arg, (void *)buffer,
				buffersize);
	case PROC_INFO_CALL_SETCONTROL:
		return setcontrol(flavor, buffer, buffersize);
	case PROC_INFO_CALL_SET_DYLD_IMAGES:
		task_set_dyld_all_image_info(
				(mach_vm_address_t)buffer, buffersize);
		return 0;
	case PROC_INFO_CALL_DIRTYCONTROL:
		return 0;
	case PROC_INFO_CALL_PIDRUSAGE:
		return pidrusage(pid, flavor, buffer);
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
	case PROC_PIDLISTFDS:
		return listfds(pid, buffer, buffersize);
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
		taskinfo(&process, info);
		return sizeof(*info);
	}
	case PROC_PIDTASKALLINFO: {
		struct proc_taskallinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		bsdinfo(&process, &info->pbsd);
		taskinfo(&process, &info->ptinfo);
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
		uniqidentifierinfo(&process, info);
		return sizeof(*info);
	}
	/* As sysmond reads each process, for Activity Monitor */
	case PROC_PIDT_BSDINFOWITHUNIQID: {
		struct proc_bsdinfowithuniqid *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		bsdinfo(&process, &info->pbsd);
		uniqidentifierinfo(&process, &info->p_uniqidentifier);
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
		uint32_t platform = codesign_platform(pid);
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

	case PROC_PIDLISTDYNKQUEUES: {
		if (pid != getpid()) {
			unimplemented();
		}
		if (buffer == NULL && buffersize != 0) {
			return _EINVAL;
		}
		size_t capacity = (buffersize > 0)
				? (size_t)buffersize / sizeof(uint64_t)
				: 0;
		if (capacity > PROC_PIDDYNKQUEUES_MAX) {
			capacity = PROC_PIDDYNKQUEUES_MAX;
		}
		size_t count = kevent_dynamic_ids(buffer, capacity);
		return (int)((count < PROC_PIDDYNKQUEUES_MAX)
						? count
						: PROC_PIDDYNKQUEUES_MAX);
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
	info->e_tdev = process_terminal(process);
	info->e_tpgid = process->tpgid;
	info->pbi_nice = process->nice;
	process_start_time(process, &info->pbi_start_tvsec,
			&info->pbi_start_tvusec);
}

static void
uniqidentifierinfo(const struct process *process,
		struct proc_uniqidentifierinfo *info)
{
	memset(info, 0, sizeof(*info));
	info->p_uniqueid = process->pid;
	info->p_puniqueid = process->ppid;
}

/* Its threads, time and memory, as Linux counts them; times are absolute */
static void
taskinfo(const struct process *process, struct proc_taskinfo *info)
{
	memset(info, 0, sizeof(*info));
	info->pti_virtual_size = process->virtual_size;
	info->pti_resident_size
			= process->resident_pages * (uint64_t)getpagesize();
	info->pti_total_user = nanoseconds_to_absolute(
			process_ticks_to_nanoseconds(process->user_ticks));
	info->pti_total_system = nanoseconds_to_absolute(
			process_ticks_to_nanoseconds(process->system_ticks));
	info->pti_threadnum = process->threads > 0 ? process->threads : 1;
	info->pti_numrunning = 1;
	info->pti_priority = 31;
	info->pti_policy = POLICY_TIMESHARE;
}

/*
 * The rusage_info of a version, as proc_pid_rusage asks, as sysmond does of
 * each process: times, wakeups, the start time and memory as Linux counts
 * them, and disk I/O where /proc lets it be read. Every version begins as
 * the first, and the second adds disk I/O at 144
 */
#define RUSAGE_INFO_V6 6
static int
pidrusage(int32_t pid, uint32_t flavor, user_addr_t buffer)
{
	static const size_t sizes[] = {96, 144, 160, 232, 296, 304, 464};
	if (flavor > RUSAGE_INFO_V6) {
		return _EINVAL;
	}
	struct process process;
	if (process_lookup(pid, &process)) {
		return _ESRCH;
	}
	uint8_t *info = buffer;
	memset(info, 0, sizes[flavor]);
	uint64_t fields[] = {
		/* ri_user_time, at 16, ri_system_time */
		nanoseconds_to_absolute(
				process_ticks_to_nanoseconds(process.user_ticks)),
		nanoseconds_to_absolute(process_ticks_to_nanoseconds(
				process.system_ticks)),
	};
	memcpy(info + 16, fields, sizeof(fields));
	uint64_t woken = wakeups(pid);
	memcpy(info + 40, &woken, sizeof(woken));
	/* ri_resident_size, at 64, and ri_phys_footprint */
	uint64_t resident = process.resident_pages * (uint64_t)getpagesize();
	memcpy(info + 64, &resident, sizeof(resident));
	memcpy(info + 72, &resident, sizeof(resident));
	uint64_t started = process_ticks_to_nanoseconds(process.start_ticks);
	uint64_t boot = commpage_boot_nanoseconds();
	uint64_t start = nanoseconds_to_absolute(
			started > boot ? started - boot : 0);
	memcpy(info + 80, &start, sizeof(start));
	if (flavor >= 2) {
		char path[64];
		snprintf(path, sizeof(path), "/proc/%d/io", pid);
		FILE *io = fopen(path, "r");
		uint64_t read_bytes = 0, write_bytes = 0;
		if (io != NULL) {
			char line[128];
			while (fgets(line, sizeof(line), io) != NULL) {
				sscanf(line, "read_bytes: %lu", &read_bytes);
				sscanf(line, "write_bytes: %lu", &write_bytes);
			}
			fclose(io);
		}
		memcpy(info + 144, &read_bytes, sizeof(read_bytes));
		memcpy(info + 152, &write_bytes, sizeof(write_bytes));
	}
	return 0;
}

static uint64_t
wakeups(int32_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	DIR *tasks = opendir(path);
	if (tasks == NULL) {
		return 0;
	}
	uint64_t count = 0;
	struct dirent *task;
	while ((task = readdir(tasks)) != NULL) {
		if (task->d_name[0] == '.') {
			continue;
		}
		char status_path[PATH_MAX];
		snprintf(status_path, sizeof(status_path), "%s/%s/status", path,
				task->d_name);
		FILE *status = fopen(status_path, "r");
		if (status == NULL) {
			continue;
		}
		char line[128];
		uint64_t switches;
		while (fgets(line, sizeof(line), status) != NULL) {
			if (sscanf(line, "voluntary_ctxt_switches: %lu",
					    &switches)
					== 1) {
				count += switches;
				break;
			}
		}
		fclose(status);
	}
	closedir(tasks);
	return count;
}

static uint64_t
nanoseconds_to_absolute(uint64_t nanoseconds)
{
	uint32_t numer, denom;
	commpage_timebase(&numer, &denom);
	return (uint64_t)((unsigned __int128)nanoseconds * denom / numer);
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
	if (proc == NULL) {
		return 0;
	}
	int32_t size = 0;
	int *pids = buffer;
	struct dirent *entry;
	while ((entry = readdir(proc)) != NULL) {
		char *end;
		long pid = strtol(entry->d_name, &end, 10);
		if (*end != '\0' || pid <= 0) {
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

static int
fdinfo(int32_t pid, uint32_t flavor, int32_t fd, void *buffer,
		int32_t buffersize)
{
	enum {
		PROC_PIDFDVNODEPATHINFO = 2,
	};
	enum {
		VREG = 1,
		VDIR = 2,
		VBLK = 3,
		VCHR = 4,
		VLNK = 5,
		VSOCK = 6,
		VFIFO = 7,
	};
	struct vinfo_stat {
		uint32_t vst_dev;
		uint16_t vst_mode;
		uint16_t vst_nlink;
		uint64_t vst_ino;
		uint32_t vst_uid;
		uint32_t vst_gid;
		int64_t vst_atime;
		int64_t vst_atimensec;
		int64_t vst_mtime;
		int64_t vst_mtimensec;
		int64_t vst_ctime;
		int64_t vst_ctimensec;
		int64_t vst_birthtime;
		int64_t vst_birthtimensec;
		int64_t vst_size;
		int64_t vst_blocks;
		int32_t vst_blksize;
		uint32_t vst_flags;
		uint32_t vst_gen;
		uint32_t vst_rdev;
		int64_t vst_qspare[2];
	};
	struct vnode_fdinfowithpath {
		struct {
			uint32_t fi_openflags;
			uint32_t fi_status;
			int64_t fi_offset;
			int32_t fi_type;
			uint32_t fi_guardflags;
		} pfi;
		struct {
			struct vinfo_stat vi_stat;
			int32_t vi_type;
			int32_t vi_pad;
			int32_t vi_fsid[2];
			char vip_path[1024];
		} pvip;
	};
	_Static_assert(sizeof(struct vnode_fdinfowithpath) == 1200,
			"vnode_fdinfowithpath");

	if (flavor != PROC_PIDFDVNODEPATHINFO) {
		return _ENOTSUP;
	}
	struct vnode_fdinfowithpath *info = buffer;
	if (buffersize < (int32_t)sizeof(*info)) {
		return _ENOMEM;
	}
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
	char link[PATH_MAX];
	ssize_t length = readlink(path, link, sizeof(link) - 1);
	struct stat st;
	if (length <= 0 || stat(path, &st) == -1) {
		return _EBADF;
	}
	link[length] = '\0';
	/* Only files have vnodes: a socket or a pipe has none */
	if (link[0] != '/') {
		return _EBADF;
	}
	memset(info, 0, sizeof(*info));
	char flags_path[64];
	snprintf(flags_path, sizeof(flags_path), "/proc/%d/fdinfo/%d", pid, fd);
	FILE *file = fopen(flags_path, "r");
	if (file != NULL) {
		char line[128];
		while (fgets(line, sizeof(line), file) != NULL) {
			long long value;
			unsigned int flags;
			if (sscanf(line, "pos: %lld", &value) == 1) {
				info->pfi.fi_offset = value;
			} else if (sscanf(line, "flags: %o", &flags) == 1) {
				/* FREAD and FWRITE, from O_ACCMODE */
				info->pfi.fi_openflags = (flags & 3) + 1;
			}
		}
		fclose(file);
	}
	info->pfi.fi_type = 1; /* PROX_FDTYPE_VNODE */
	struct vinfo_stat *vst = &info->pvip.vi_stat;
	vst->vst_dev = darwin_device(st.st_dev);
	vst->vst_mode = st.st_mode;
	vst->vst_nlink = st.st_nlink;
	vst->vst_ino = sysroot_file_id(st.st_dev, st.st_ino);
	vst->vst_uid = st.st_uid;
	vst->vst_gid = st.st_gid;
	vst->vst_atime = st.st_atim.tv_sec;
	vst->vst_atimensec = st.st_atim.tv_nsec;
	vst->vst_mtime = st.st_mtim.tv_sec;
	vst->vst_mtimensec = st.st_mtim.tv_nsec;
	vst->vst_ctime = st.st_ctim.tv_sec;
	vst->vst_ctimensec = st.st_ctim.tv_nsec;
	vst->vst_size = st.st_size;
	vst->vst_blocks = st.st_blocks;
	vst->vst_blksize = st.st_blksize;
	vst->vst_rdev = (major(st.st_rdev) << 24) | minor(st.st_rdev);
	info->pvip.vi_type = S_ISREG(st.st_mode) ? VREG
			: S_ISDIR(st.st_mode)    ? VDIR
			: S_ISBLK(st.st_mode)    ? VBLK
			: S_ISCHR(st.st_mode)    ? VCHR
			: S_ISLNK(st.st_mode)    ? VLNK
			: S_ISSOCK(st.st_mode)   ? VSOCK
						 : VFIFO;
	info->pvip.vi_fsid[0] = (int32_t)vst->vst_dev;
	snprintf(info->pvip.vip_path, sizeof(info->pvip.vip_path), "%s",
			sysroot_guest_path(link));
	return sizeof(*info);
}

static int
listfds(int32_t pid, void *buffer, int32_t buffersize)
{
	enum {
		PROX_FDTYPE_VNODE = 1,
		PROX_FDTYPE_SOCKET = 2,
		PROX_FDTYPE_KQUEUE = 5,
		PROX_FDTYPE_PIPE = 6,
	};
	struct proc_fdinfo_entry {
		int32_t proc_fd;
		uint32_t proc_fdtype;
	};

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	DIR *dir = opendir(path);
	if (dir == NULL) {
		return _ESRCH;
	}
	struct proc_fdinfo_entry *out = buffer;
	int32_t count = 0;
	int32_t room = (buffer != NULL) ? buffersize / (int32_t)sizeof(*out)
					: INT32_MAX;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL && count < room) {
		if (entry->d_name[0] == '.') {
			continue;
		}
		if (buffer != NULL) {
			char link[PATH_MAX];
			snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid,
					entry->d_name);
			ssize_t length = readlink(path, link, sizeof(link) - 1);
			link[length > 0 ? length : 0] = '\0';
			uint32_t type = PROX_FDTYPE_VNODE;
			if (strncmp(link, "socket:", 7) == 0) {
				type = PROX_FDTYPE_SOCKET;
			} else if (strncmp(link, "pipe:", 5) == 0) {
				type = PROX_FDTYPE_PIPE;
			} else if (strncmp(link, "anon_inode:", 11) == 0) {
				type = PROX_FDTYPE_KQUEUE;
			}
			out[count] = (struct proc_fdinfo_entry){
					.proc_fd = atoi(entry->d_name),
					.proc_fdtype = type,
			};
		}
		count++;
	}
	closedir(dir);
	if (buffer == NULL) {
		count += 20;
	}
	return count * (int32_t)sizeof(*out);
}
