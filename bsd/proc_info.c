/*
 * Copyright © 2021 Keegan Saunders
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

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "codesign.h"
#include "commpage.h"
#include "credentials.h"
#include "fs/device.h"
#include "gid.h"
#include "handler.h"
#include "kevent.h"
#include "kmsg.h"
#include "osfmk/broker_client.h"
#include "osfmk/task.h"
#include "process.h"
#include "responsibility.h"
#include "sysroot.h"
#include "thread.h"
#include "xnu-errno.h"

#define PROC_INFO_CALL_LISTPIDS        0x1
#define PROC_INFO_CALL_PIDINFO         0x2
#define PROC_INFO_CALL_PIDFDINFO       0x3
#define PROC_INFO_CALL_KERNMSGBUF      0x4
#define PROC_INFO_CALL_SETCONTROL      0x5
#define PROC_INFO_CALL_DIRTYCONTROL    0x8
#define PROC_INFO_CALL_PIDRUSAGE       0x9
#define PROC_INFO_CALL_PIDORIGINATORINFO 0xa
#define PROC_INFO_CALL_CANUSEFGHW        0xc
#define PROC_INFO_CALL_SET_DYLD_IMAGES 0xf

#define PROC_SELFSET_THREADNAME 2

#define PROC_PIDORIGINATOR_UUID     0x1
#define PROC_PIDORIGINATOR_BGSTATE  0x2
#define PROC_PIDORIGINATOR_PID_UUID 0x3

#define PROC_PIDORIGINATOR_UUID_SIZE     16
#define PROC_PIDORIGINATOR_BGSTATE_SIZE  4
#define PROC_PIDORIGINATOR_PID_UUID_SIZE 48

#define PROC_FGHW_DAEMON_NO_VOUCHER 13
#define PROC_FGHW_ERROR             99

#define PROC_ALL_PIDS  1
#define PROC_UID_ONLY  4
#define PROC_RUID_ONLY 5
#define PROC_PPID_ONLY 6

#define PROC_PIDLISTFDS            1
#define PROC_PIDTBSDINFO           3
#define PROC_PIDWORKQUEUEINFO      12
#define PROC_PIDT_SHORTBSDINFO     13
#define PROC_PIDUNIQIDENTIFIERINFO 17
#define PROC_PIDT_BSDINFOWITHUNIQID 18
#define PROC_PIDCOALITIONINFO      20
#define PROC_PIDLISTDYNKQUEUES     27
#define PROC_PIDVMRTFAULTINFO      29

#define PROC_PIDDYNKQUEUES_MAX 1024

#define FREAD  0x1
#define FWRITE 0x2

#define KEVENT_SIZE 32
#define PIPE_SIZE   16384

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

struct proc_workqueueinfo {
	uint32_t pwq_nthreads;
	uint32_t pwq_runthreads;
	uint32_t pwq_blockedthreads;
	uint32_t pwq_state;
};

#define PROC_PIDTASKALLINFO 2
#define PROC_PIDTASKINFO    4

#define PROC_PIDTHREADINFO     5
#define PROC_PIDLISTTHREADS    6
#define PROC_PIDTHREADID64INFO 15
#define PROC_PIDLISTTHREADIDS  28

struct proc_threadinfo {
	uint64_t pth_user_time;
	uint64_t pth_system_time;
	int32_t pth_cpu_usage;
	int32_t pth_policy;
	int32_t pth_run_state;
	int32_t pth_flags;
	int32_t pth_sleep_time;
	int32_t pth_curpri;
	int32_t pth_priority;
	int32_t pth_maxpriority;
	char pth_name[THREAD_NAME_SIZE];
};

#define PROC_PIDPATHINFO 11
#define PROC_PIDREGIONINFO      7
#define PROC_PIDVNODEPATHINFO   9
#define PROC_PIDREGIONPATHINFO2 22
#define PROC_PIDLISTFILEPORTS   14

#ifndef PROC_PIDPLATFORMINFO
#define PROC_PIDPLATFORMINFO 30
#endif

enum {
	PROX_FDTYPE_VNODE = 1,
	PROX_FDTYPE_SOCKET = 2,
	PROX_FDTYPE_KQUEUE = 5,
	PROX_FDTYPE_PIPE = 6,
};

struct proc_fileinfo {
	uint32_t fi_openflags;
	uint32_t fi_status;
	int64_t fi_offset;
	int32_t fi_type;
	uint32_t fi_guardflags;
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

struct vnode_info_path {
	struct vinfo_stat vi_stat;
	int32_t vi_type;
	int32_t vi_pad;
	int32_t vi_fsid[2];
	char vip_path[1024];
};
_Static_assert(sizeof(struct vnode_info_path) == 1176, "vnode_info_path");

struct kqueue_fdinfo {
	struct proc_fileinfo pfi;
	struct {
		struct vinfo_stat kq_stat;
		uint32_t kq_state;
		uint32_t rfu_1;
	} kqueueinfo;
};
_Static_assert(sizeof(struct kqueue_fdinfo) == 168, "kqueue_fdinfo");

struct pipe_fdinfo {
	struct proc_fileinfo pfi;
	struct {
		struct vinfo_stat pipe_stat;
		uint64_t pipe_handle;
		uint64_t pipe_peerhandle;
		int32_t pipe_status;
		int32_t rfu_1;
	} pipeinfo;
};
_Static_assert(sizeof(struct pipe_fdinfo) == 184, "pipe_fdinfo");

struct sockbuf_info {
	uint32_t sbi_cc;
	uint32_t sbi_hiwat;
	uint32_t sbi_mbcnt;
	uint32_t sbi_mbmax;
	uint32_t sbi_lowat;
	int16_t sbi_flags;
	int16_t sbi_timeo;
};

struct in_sockinfo {
	int32_t insi_fport;
	int32_t insi_lport;
	uint64_t insi_gencnt;
	uint32_t insi_flags;
	uint32_t insi_flow;
	uint8_t insi_vflag;
	uint8_t insi_ip_ttl;
	uint32_t rfu_1;
	uint32_t insi_faddr[4];
	uint32_t insi_laddr[4];
	uint8_t insi_v4_tos;
	struct {
		uint8_t in6_hlim;
		int32_t in6_cksum;
		uint16_t in6_ifindex;
		int16_t in6_hops;
	} insi_v6;
};

struct tcp_sockinfo {
	struct in_sockinfo tcpsi_ini;
	int32_t tcpsi_state;
	int32_t tcpsi_timer[4];
	int32_t tcpsi_mss;
	uint32_t tcpsi_flags;
	uint32_t rfu_1;
	uint64_t tcpsi_tp;
};

struct darwin_sockaddr_un {
	uint8_t sun_len;
	uint8_t sun_family;
	char sun_path[104];
};

struct un_sockinfo {
	uint64_t unsi_conn_so;
	uint64_t unsi_conn_pcb;
	union {
		struct darwin_sockaddr_un ua_sun;
		char ua_dummy[255];
	} unsi_addr;
	union {
		struct darwin_sockaddr_un ua_sun;
		char ua_dummy[255];
	} unsi_caddr;
};

struct socket_fdinfo {
	struct proc_fileinfo pfi;
	struct socket_info {
		struct vinfo_stat soi_stat;
		uint64_t soi_so;
		uint64_t soi_pcb;
		int32_t soi_type;
		int32_t soi_protocol;
		int32_t soi_family;
		int16_t soi_options;
		int16_t soi_linger;
		int16_t soi_state;
		int16_t soi_qlen;
		int16_t soi_incqlen;
		int16_t soi_qlimit;
		int16_t soi_timeo;
		uint16_t soi_error;
		uint32_t soi_oobmark;
		struct sockbuf_info soi_rcv;
		struct sockbuf_info soi_snd;
		int32_t soi_kind;
		uint32_t rfu_1;
		union {
			struct in_sockinfo pri_in;
			struct tcp_sockinfo pri_tcp;
			struct un_sockinfo pri_un;
		} soi_proto;
	} psi;
};
_Static_assert(sizeof(struct in_sockinfo) == 80, "in_sockinfo");
_Static_assert(sizeof(struct tcp_sockinfo) == 120, "tcp_sockinfo");
_Static_assert(sizeof(struct un_sockinfo) == 528, "un_sockinfo");
_Static_assert(sizeof(struct socket_fdinfo) == 792, "socket_fdinfo");
_Static_assert(offsetof(struct socket_fdinfo, psi.soi_proto) == 264,
		"socket_info's protocol part");

enum {
	SOCKINFO_GENERIC,
	SOCKINFO_IN,
	SOCKINFO_TCP,
	SOCKINFO_UN,
};

enum {
	TSI_S_CLOSED,
	TSI_S_LISTEN,
	TSI_S_SYN_SENT,
	TSI_S_SYN_RECEIVED,
	TSI_S_ESTABLISHED,
	TSI_S_CLOSE_WAIT,
	TSI_S_FIN_WAIT_1,
	TSI_S_CLOSING,
	TSI_S_LAST_ACK,
	TSI_S_FIN_WAIT_2,
	TSI_S_TIME_WAIT,
};

#define INI_IPV4             0x1
#define INI_IPV6             0x2
#define SOI_S_ISCONNECTED    0x2
#define DARWIN_SO_ACCEPTCONN 0x2
#define DARWIN_AF_UNIX       1
#define DARWIN_AF_INET       2
#define DARWIN_AF_INET6      30
#define DARWIN_SOCK_STREAM   1
#define DARWIN_SOCK_DGRAM    2

struct proc_regioninfo {
	uint32_t pri_protection;
	uint32_t pri_max_protection;
	uint32_t pri_inheritance;
	uint32_t pri_flags;
	uint64_t pri_offset;
	uint32_t pri_behavior;
	uint32_t pri_user_wired_count;
	uint32_t pri_user_tag;
	uint32_t pri_pages_resident;
	uint32_t pri_pages_shared_now_private;
	uint32_t pri_pages_swapped_out;
	uint32_t pri_pages_dirtied;
	uint32_t pri_ref_count;
	uint32_t pri_shadow_depth;
	uint32_t pri_share_mode;
	uint32_t pri_private_pages_resident;
	uint32_t pri_shared_pages_resident;
	uint32_t pri_obj_id;
	uint32_t pri_depth;
	uint64_t pri_address;
	uint64_t pri_size;
};
_Static_assert(sizeof(struct proc_regioninfo) == 96, "proc_regioninfo");

struct proc_regionwithpathinfo {
	struct proc_regioninfo prp_prinfo;
	struct vnode_info_path prp_vip;
};

static int pidinfo(int32_t pid, uint32_t flavor, uint64_t arg,
		user_addr_t buffer, int32_t buffersize);
static int list_linux_threads(const struct process *process, user_addr_t buffer,
		int32_t buffersize);
static int threadinfo_of_linux(const struct process *process, uint64_t id,
		user_addr_t buffer, int32_t buffersize);
static bool same_user(const struct process *process);
static int coalition_ids(int32_t pid, uint64_t ids[2]);
static size_t coalition_members(
		uint64_t id, int32_t leader, int32_t *pids, size_t max);
static bool linux_thread_is_guest(int32_t pid, int32_t tid);
static int threadinfo(uint64_t value, bool id, user_addr_t buffer,
		int32_t buffersize);
static void proc_threadinfo_of(const thread_extended_info_data_t *extended,
		struct proc_threadinfo *info);
static bool vnode_info_path(
		const char *proc_link, struct vnode_info_path *info);
static void fill_vnode_info(const char *file, const struct stat *st,
		struct vnode_info_path *info);
static bool region_with_path(int32_t pid, uint64_t address, bool files_only,
		struct proc_regionwithpathinfo *info);
static void fill_region_info(struct proc_regioninfo *region,
		unsigned long start, unsigned long end, const char *perms,
		unsigned long offset);
static void uniqidentifierinfo(const struct process *process,
		struct proc_uniqidentifierinfo *info);
static void bsdinfo(const struct process *process, struct proc_bsdinfo *info);
static uint32_t file_table_size(int32_t pid);
static int listfds(int32_t pid, void *buffer, int32_t buffersize);
static int fdinfo(int32_t pid, uint32_t flavor, int32_t fd, void *buffer,
		int32_t buffersize);
static int socket_fdinfo(
		int32_t pid, int32_t fd, void *buffer, int32_t buffersize);
static bool inet_socket_info(const char *proc_dir, unsigned long inode,
		struct socket_info *info);
static void put_address(uint32_t address[4], const char *hex, bool v6);
static bool unix_socket_info(const char *proc_dir, unsigned long inode,
		struct socket_info *info);
static int pipe_fdinfo(
		int32_t pid, int32_t fd, void *buffer, int32_t buffersize);
static int kqueue_fdinfo(
		int32_t pid, int32_t fd, void *buffer, int32_t buffersize);
static void taskinfo(const struct process *process, struct proc_taskinfo *info);
static int pidrusage(int32_t pid, uint32_t flavor, user_addr_t buffer);
static uint64_t nanoseconds_to_absolute(uint64_t nanoseconds);
static int setcontrol(uint32_t flavor, user_addr_t buffer, int32_t buffersize);
static int pidoriginatorinfo(int32_t pid, uint32_t flavor, user_addr_t buffer,
		int32_t buffersize);
static int listpids(uint32_t type, uint32_t typeinfo, user_addr_t buffer,
		int32_t buffersize);
static bool status_field(pid_t pid, const char *field, int index,
		unsigned long *value);
static uint64_t wakeups(int32_t pid);
static int can_use_foreground_hw(
		int32_t pid, user_addr_t reason, int32_t reasonsize);

int
sys_proc_info(int32_t callnum, int32_t pid, uint32_t flavor, uint64_t arg,
		user_addr_t buffer, int32_t buffersize)
{
	switch (callnum) {
	case PROC_INFO_CALL_LISTPIDS:
		return listpids(pid, flavor, buffer, buffersize);
	case PROC_INFO_CALL_PIDINFO:
		return pidinfo(pid, flavor, arg, buffer, buffersize);
	case PROC_INFO_CALL_PIDFDINFO:
		if (limbo_fd_is_own((int32_t)arg)) {
			return _EBADF;
		}
		return fdinfo(pid, flavor, (int32_t)arg, (void *)buffer,
				buffersize);
	case PROC_INFO_CALL_KERNMSGBUF:
		if (geteuid() != 0) {
			return _EPERM;
		}
		return kmsg_read((char *)buffer, (uint32_t)buffersize);
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
	case PROC_INFO_CALL_PIDORIGINATORINFO:
		return pidoriginatorinfo(pid, flavor, buffer, buffersize);
	case PROC_INFO_CALL_CANUSEFGHW:
		return can_use_foreground_hw(pid, buffer, buffersize);
	default:
		unimplemented();
	}
}

static int
pidinfo(int32_t pid, uint32_t flavor, uint64_t arg, user_addr_t buffer,
		int32_t buffersize)
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
	case PROC_PIDTHREADINFO:
	case PROC_PIDTHREADID64INFO:
		if (pid != getpid()) {
			return flavor == PROC_PIDTHREADID64INFO
					? threadinfo_of_linux(&process, arg,
							  buffer, buffersize)
					: _ESRCH;
		}
		return threadinfo(arg, flavor == PROC_PIDTHREADID64INFO, buffer,
				buffersize);
	case PROC_PIDLISTTHREADS:
	case PROC_PIDLISTTHREADIDS: {
		if (buffersize < (int32_t)sizeof(uint64_t)) {
			return _ENOMEM;
		}
		if (pid != getpid()) {
			return flavor == PROC_PIDLISTTHREADIDS
					? list_linux_threads(&process, buffer,
							  buffersize)
					: _ESRCH;
		}
		size_t count = thread_guest_handles(buffer,
				(size_t)buffersize / sizeof(uint64_t),
				flavor == PROC_PIDLISTTHREADIDS);
		return (int)(count * sizeof(uint64_t));
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
	case PROC_PIDVNODEPATHINFO: {
		struct proc_vnodepathinfo {
			struct vnode_info_path pvi_cdir;
			struct vnode_info_path pvi_rdir;
		} *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		char dir[64 + NAME_MAX], cwd[80 + NAME_MAX];
		process_proc_dir(pid, dir, sizeof(dir));
		snprintf(cwd, sizeof(cwd), "%s/cwd", dir);
		memset(info, 0, sizeof(*info));
		if (!vnode_info_path(cwd, &info->pvi_cdir)) {
			return _EPERM;
		}
		return sizeof(*info);
	}
	case PROC_PIDREGIONPATHINFO2: {
		struct proc_regionwithpathinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		return region_with_path(pid, arg, true, info)
				? (int)sizeof(*info)
				: _EINVAL;
	}
	case PROC_PIDREGIONINFO: {
		struct proc_regionwithpathinfo region;
		if (buffersize < (int32_t)sizeof(region.prp_prinfo)) {
			return _ENOMEM;
		}
		if (!region_with_path(pid, arg, false, &region)) {
			return _EINVAL;
		}
		memcpy(buffer, &region.prp_prinfo, sizeof(region.prp_prinfo));
		return sizeof(region.prp_prinfo);
	}
	case PROC_PIDLISTFILEPORTS:
		return 0;
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
		int error = coalition_ids(pid, info);
		if (error != 0) {
			return error;
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
	case PROC_PIDVMRTFAULTINFO:
		if (pid != getpid()) {
			return _EINVAL;
		}
		return 0;
	case PROC_PIDWORKQUEUEINFO: {
		struct proc_workqueueinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		if (pid != getpid()) {
			return _ESRCH;
		}
		info->pwq_state = 0;
		workq_counts(&info->pwq_nthreads, &info->pwq_runthreads,
				&info->pwq_blockedthreads);
		return sizeof(*info);
	}
	default:
		unimplemented();
	}
}

static int
list_linux_threads(const struct process *process, user_addr_t buffer,
		int32_t buffersize)
{
	if (!same_user(process)) {
		return _EPERM;
	}
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/task", process->pid);
	DIR *dir = opendir(path);
	if (dir == NULL) {
		return _ESRCH;
	}
	uint64_t *ids = buffer;
	size_t max = (size_t)buffersize / sizeof(ids[0]);
	size_t count = 0;
	struct dirent *entry;
	while (count < max && (entry = readdir(dir)) != NULL) {
		int32_t tid = (int32_t)strtol(entry->d_name, NULL, 10);
		if (tid != 0 && linux_thread_is_guest(process->pid, tid)) {
			ids[count++] = (uint64_t)tid;
		}
	}
	closedir(dir);
	return (int)(count * sizeof(ids[0]));
}

static int
threadinfo_of_linux(const struct process *process, uint64_t id,
		user_addr_t buffer, int32_t buffersize)
{
	struct proc_threadinfo *info = buffer;
	if (buffersize < (int32_t)sizeof(*info)) {
		return _ENOMEM;
	}
	if (!same_user(process)) {
		return _EPERM;
	}
	thread_extended_info_data_t extended;
	if (id > INT32_MAX || !linux_thread_is_guest(process->pid, (int32_t)id)
			|| !thread_linux_extended_info(
					process->pid, (pid_t)id, &extended)) {
		return _ESRCH;
	}
	proc_threadinfo_of(&extended, info);
	return sizeof(*info);
}

static bool
same_user(const struct process *process)
{
	return geteuid() == 0 || process->uid[1] == geteuid();
}

static bool
linux_thread_is_guest(int32_t pid, int32_t tid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/task/%d/status", pid, tid);
	FILE *status = fopen(path, "re");
	if (status == NULL) {
		return false;
	}
	char line[256];
	unsigned long long blocked = 0;
	while (fgets(line, sizeof(line), status) != NULL
			&& sscanf(line, "SigBlk: %llx", &blocked) != 1) {
	}
	fclose(status);
	return !((blocked >> (credentials_signal() - 1)) & 1);
}

static int
threadinfo(uint64_t value, bool id, user_addr_t buffer, int32_t buffersize)
{
	struct proc_threadinfo *info = buffer;
	if (buffersize < (int32_t)sizeof(*info)) {
		return _ENOMEM;
	}
	thread_extended_info_data_t extended;
	mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
	if (thread_info(thread_guest_port_of(value, id), THREAD_EXTENDED_INFO,
			    (thread_info_t)&extended, &count)
			!= KERN_SUCCESS) {
		return _ESRCH;
	}
	proc_threadinfo_of(&extended, info);
	return sizeof(*info);
}

static void
proc_threadinfo_of(const thread_extended_info_data_t *extended,
		struct proc_threadinfo *info)
{
	*info = (struct proc_threadinfo){
			.pth_user_time = extended->pth_user_time,
			.pth_system_time = extended->pth_system_time,
			.pth_cpu_usage = extended->pth_cpu_usage,
			.pth_policy = extended->pth_policy,
			.pth_run_state = extended->pth_run_state,
			.pth_flags = extended->pth_flags,
			.pth_sleep_time = extended->pth_sleep_time,
			.pth_curpri = extended->pth_curpri,
			.pth_priority = extended->pth_priority,
			.pth_maxpriority = extended->pth_maxpriority,
	};
	memcpy(info->pth_name, extended->pth_name, sizeof(info->pth_name));
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
	memcpy(info->pbi_name, process->name, sizeof(info->pbi_name));
	info->pbi_pgid = process->pgid;
	info->e_tdev = process_terminal(process);
	info->e_tpgid = process->tpgid;
	info->pbi_nice = process->nice;
	info->pbi_nfiles = file_table_size(process->pid);
	process_start_time(process, &info->pbi_start_tvsec,
			&info->pbi_start_tvusec);
}

static uint32_t
file_table_size(int32_t pid)
{
	char proc_dir[64 + NAME_MAX], path[80 + NAME_MAX];
	process_proc_dir(pid, proc_dir, sizeof(proc_dir));
	snprintf(path, sizeof(path), "%s/fd", proc_dir);
	DIR *dir = opendir(path);
	if (dir == NULL) {
		return 0;
	}
	uint32_t size = 0;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] != '.') {
			uint32_t fd = (uint32_t)atoi(entry->d_name);
			size = fd + 1 > size ? fd + 1 : size;
		}
	}
	closedir(dir);
	return size;
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
	if (buffersize < 0 || buffersize >= THREAD_NAME_SIZE) {
		return _ENAMETOOLONG;
	}
	struct thread *thread = thread_current();
	memset(thread->name, 0, sizeof(thread->name));
	memcpy(thread->name, buffer, buffersize);
	if (thread->tid == getpid()) {
		return 0;
	}

	char name[16];
	snprintf(name, sizeof(name), "%.*s", buffersize, (char *)buffer);
	prctl(PR_SET_NAME, name);
	return 0;
}

static int
pidoriginatorinfo(int32_t pid, uint32_t flavor, user_addr_t buffer,
		int32_t buffersize)
{
	int32_t size;
	switch (flavor) {
	case PROC_PIDORIGINATOR_UUID:
		size = PROC_PIDORIGINATOR_UUID_SIZE;
		break;
	case PROC_PIDORIGINATOR_BGSTATE:
		size = PROC_PIDORIGINATOR_BGSTATE_SIZE;
		break;
	case PROC_PIDORIGINATOR_PID_UUID:
		size = PROC_PIDORIGINATOR_PID_UUID_SIZE;
		break;
	default:
		return _EINVAL;
	}
	if (buffersize < size) {
		return _ENOMEM;
	}
	if ((pid != 0 && pid != getpid())
			|| flavor != PROC_PIDORIGINATOR_BGSTATE) {
		return _EINVAL;
	}
	uint32_t backgrounded = 0;
	memcpy(buffer, &backgrounded, sizeof(backgrounded));
	return size;
}

static int
can_use_foreground_hw(int32_t pid, user_addr_t reason, int32_t reasonsize)
{
	uint32_t answer = PROC_FGHW_ERROR;
	int error = 0;
	struct process process;
	if (pid <= 0) {
		error = _EINVAL;
	} else if (process_lookup(pid, &process)) {
		error = _ESRCH;
	} else if (pid != getpid()) {
		error = geteuid() == 0 ? _EINVAL : _EPERM;
	} else {
		answer = PROC_FGHW_DAEMON_NO_VOUCHER;
	}
	if (reason != NULL && reasonsize >= (int32_t)sizeof(answer)) {
		memcpy(reason, &answer, sizeof(answer));
	}
	return error;
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
					&& (uint32_t)process_guest_parent(
							   (int32_t)value)
							== typeinfo;
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
	char dir[64 + NAME_MAX], path[80 + NAME_MAX], line[256];
	process_proc_dir(pid, dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/status", dir);
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
		PROC_PIDFDSOCKETINFO = 3,
		PROC_PIDFDPIPEINFO = 6,
		PROC_PIDFDKQUEUEINFO = 7,
	};
	struct vnode_fdinfowithpath {
		struct proc_fileinfo pfi;
		struct vnode_info_path pvip;
	};
	_Static_assert(sizeof(struct vnode_fdinfowithpath) == 1200,
			"vnode_fdinfowithpath");

	if (flavor == PROC_PIDFDSOCKETINFO) {
		return socket_fdinfo(pid, fd, buffer, buffersize);
	}
	if (flavor == PROC_PIDFDPIPEINFO) {
		return pipe_fdinfo(pid, fd, buffer, buffersize);
	}
	if (flavor == PROC_PIDFDKQUEUEINFO) {
		return kqueue_fdinfo(pid, fd, buffer, buffersize);
	}
	if (flavor != PROC_PIDFDVNODEPATHINFO) {
		return _ENOTSUP;
	}
	struct vnode_fdinfowithpath *info = buffer;
	if (buffersize < (int32_t)sizeof(*info)) {
		return _ENOMEM;
	}
	char proc_dir[64 + NAME_MAX], path[80 + NAME_MAX];
	process_proc_dir(pid, proc_dir, sizeof(proc_dir));
	snprintf(path, sizeof(path), "%s/fd/%d", proc_dir, fd);
	struct vnode_info_path vnode;
	if (!vnode_info_path(path, &vnode)) {
		return _EBADF;
	}
	memset(info, 0, sizeof(*info));
	info->pvip = vnode;
	char flags_path[80 + NAME_MAX];
	snprintf(flags_path, sizeof(flags_path), "%s/fdinfo/%d", proc_dir, fd);
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
	info->pfi.fi_type = PROX_FDTYPE_VNODE;
	return sizeof(*info);
}

static int
socket_fdinfo(int32_t pid, int32_t fd, void *buffer, int32_t buffersize)
{
	struct socket_fdinfo *info = buffer;
	if (buffersize < (int32_t)sizeof(*info)) {
		return _ENOMEM;
	}
	char proc_dir[64 + NAME_MAX], path[80 + NAME_MAX], link[64];
	process_proc_dir(pid, proc_dir, sizeof(proc_dir));
	snprintf(path, sizeof(path), "%s/fd/%d", proc_dir, fd);
	ssize_t length = readlink(path, link, sizeof(link) - 1);
	if (length == -1) {
		return _EBADF;
	}
	link[length] = '\0';
	unsigned long inode;
	if (sscanf(link, "socket:[%lu]", &inode) != 1) {
		return _ENOTSOCK;
	}
	memset(info, 0, sizeof(*info));
	info->pfi.fi_openflags = FREAD | FWRITE;
	info->pfi.fi_type = PROX_FDTYPE_SOCKET;
	info->psi.soi_so = inode;
	info->psi.soi_pcb = inode;
	if (!inet_socket_info(proc_dir, inode, &info->psi)) {
		unix_socket_info(proc_dir, inode, &info->psi);
	}
	return sizeof(*info);
}

static bool
inet_socket_info(const char *proc_dir, unsigned long inode,
		struct socket_info *info)
{
	static const struct {
		const char *name;
		bool tcp;
		bool v6;
	} tables[] = {
			{"tcp", true, false},
			{"tcp6", true, true},
			{"udp", false, false},
			{"udp6", false, true},
	};
	static const int32_t tcp_states[] = {
			[TCP_ESTABLISHED] = TSI_S_ESTABLISHED,
			[TCP_SYN_SENT] = TSI_S_SYN_SENT,
			[TCP_SYN_RECV] = TSI_S_SYN_RECEIVED,
			[TCP_FIN_WAIT1] = TSI_S_FIN_WAIT_1,
			[TCP_FIN_WAIT2] = TSI_S_FIN_WAIT_2,
			[TCP_TIME_WAIT] = TSI_S_TIME_WAIT,
			[TCP_CLOSE] = TSI_S_CLOSED,
			[TCP_CLOSE_WAIT] = TSI_S_CLOSE_WAIT,
			[TCP_LAST_ACK] = TSI_S_LAST_ACK,
			[TCP_LISTEN] = TSI_S_LISTEN,
			[TCP_CLOSING] = TSI_S_CLOSING,
	};
	for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
		bool tcp = tables[i].tcp, v6 = tables[i].v6;
		char path[96 + NAME_MAX];
		snprintf(path, sizeof(path), "%s/net/%s", proc_dir,
				tables[i].name);
		FILE *file = fopen(path, "re");
		if (file == NULL) {
			continue;
		}
		char line[512], local[33], remote[33];
		unsigned int local_port, remote_port, state;
		unsigned long sending, receiving, found = 0;
		while (found != inode
				&& fgets(line, sizeof(line), file) != NULL) {
			if (sscanf(line,
					    " %*d: %32[0-9A-Fa-f]:%x "
					    "%32[0-9A-Fa-f]:%x %x %lx:%lx "
					    "%*x:%*x %*x %*u %*u %lu",
					    local, &local_port, remote,
					    &remote_port, &state, &sending,
					    &receiving, &found)
					!= 8) {
				found = 0;
			}
		}
		fclose(file);
		if (found != inode) {
			continue;
		}
		bool listening = tcp && state == TCP_LISTEN;
		info->soi_type = tcp ? DARWIN_SOCK_STREAM : DARWIN_SOCK_DGRAM;
		info->soi_protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP;
		info->soi_family = v6 ? DARWIN_AF_INET6 : DARWIN_AF_INET;
		info->soi_kind = tcp ? SOCKINFO_TCP : SOCKINFO_IN;
		struct in_sockinfo *in = &info->soi_proto.pri_in;
		in->insi_fport = htons(remote_port);
		in->insi_lport = htons(local_port);
		in->insi_vflag = v6 ? INI_IPV6 : INI_IPV4;
		put_address(in->insi_faddr, remote, v6);
		put_address(in->insi_laddr, local, v6);
		if (!tcp) {
			return true;
		}
		if (listening) {
			info->soi_options = DARWIN_SO_ACCEPTCONN;
			info->soi_qlen = (int16_t)receiving;
		} else {
			info->soi_rcv.sbi_cc = (uint32_t)receiving;
			info->soi_snd.sbi_cc = (uint32_t)sending;
		}
		if (state == TCP_ESTABLISHED) {
			info->soi_state = SOI_S_ISCONNECTED;
		}
		info->soi_proto.pri_tcp.tcpsi_state = state <= TCP_CLOSING
				? tcp_states[state]
				: TSI_S_CLOSED;
		return true;
	}
	return false;
}

static void
put_address(uint32_t address[4], const char *hex, bool v6)
{
	if (v6) {
		sscanf(hex, "%8x%8x%8x%8x", &address[0], &address[1],
				&address[2], &address[3]);
	} else {
		sscanf(hex, "%8x", &address[3]);
	}
}

#define LINUX_UNIX_ACCEPTCON 0x10000
#define LINUX_SS_CONNECTED   3

static bool
unix_socket_info(const char *proc_dir, unsigned long inode,
		struct socket_info *info)
{
	char path[96 + NAME_MAX];
	snprintf(path, sizeof(path), "%s/net/unix", proc_dir);
	FILE *file = fopen(path, "re");
	if (file == NULL) {
		return false;
	}
	char line[PATH_MAX + 128];
	unsigned int flags, type, state;
	unsigned long found = 0;
	int name;
	while (found != inode && fgets(line, sizeof(line), file) != NULL) {
		name = 0;
		if (sscanf(line, "%*x: %*x %*x %x %x %x %lu %n", &flags, &type,
				    &state, &found, &name)
				< 4) {
			found = 0;
		}
	}
	fclose(file);
	if (found != inode) {
		return false;
	}
	info->soi_type = (int32_t)type;
	info->soi_family = DARWIN_AF_UNIX;
	info->soi_kind = SOCKINFO_UN;
	if (flags & LINUX_UNIX_ACCEPTCON) {
		info->soi_options = DARWIN_SO_ACCEPTCONN;
	}
	if (state == LINUX_SS_CONNECTED) {
		info->soi_state = SOI_S_ISCONNECTED;
	}
	line[strcspn(line, "\n")] = '\0';
	struct darwin_sockaddr_un *bound
			= &info->soi_proto.pri_un.unsi_addr.ua_sun;
	if (name != 0 && line[name] != '\0'
			&& !unix_bound_address(inode, bound, sizeof(*bound))
			&& line[name] == '/') {
		bound->sun_family = DARWIN_AF_UNIX;
		snprintf(bound->sun_path, sizeof(bound->sun_path), "%s",
				sysroot_guest_path(line + name));
		bound->sun_len = (uint8_t)(offsetof(struct darwin_sockaddr_un,
							   sun_path)
				+ strlen(bound->sun_path));
	}
	return true;
}

static int
pipe_fdinfo(int32_t pid, int32_t fd, void *buffer, int32_t buffersize)
{
	struct pipe_fdinfo *info = buffer;
	if (buffersize < (int32_t)sizeof(*info)) {
		return _ENOMEM;
	}
	char proc_dir[64 + NAME_MAX], path[80 + NAME_MAX], link[64];
	process_proc_dir(pid, proc_dir, sizeof(proc_dir));
	snprintf(path, sizeof(path), "%s/fd/%d", proc_dir, fd);
	ssize_t length = readlink(path, link, sizeof(link) - 1);
	link[length > 0 ? length : 0] = '\0';
	unsigned long inode;
	if (sscanf(link, "pipe:[%lu]", &inode) != 1) {
		return _EBADF;
	}
	snprintf(path, sizeof(path), "%s/fdinfo/%d", proc_dir, fd);
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		return _EBADF;
	}
	unsigned int flags;
	fscanf(file, "pos: %*d flags: %o", &flags);
	fclose(file);
	bool writes = (flags & O_ACCMODE) == O_WRONLY;
	memset(info, 0, sizeof(*info));
	info->pfi.fi_openflags = writes ? FWRITE : FREAD;
	info->pfi.fi_type = PROX_FDTYPE_PIPE;
	info->pipeinfo.pipe_stat.vst_mode = S_IFIFO | 0660;
	info->pipeinfo.pipe_stat.vst_nlink = 1;
	info->pipeinfo.pipe_stat.vst_blksize = PIPE_SIZE;
	info->pipeinfo.pipe_handle = inode * 2 + writes;
	info->pipeinfo.pipe_peerhandle = inode * 2 + !writes;
	return sizeof(*info);
}

static int
kqueue_fdinfo(int32_t pid, int32_t fd, void *buffer, int32_t buffersize)
{
	struct kqueue_fdinfo *info = buffer;
	if (buffersize < (int32_t)sizeof(*info)) {
		return _ENOMEM;
	}
	char proc_dir[64 + NAME_MAX], path[80 + NAME_MAX], link[64];
	process_proc_dir(pid, proc_dir, sizeof(proc_dir));
	snprintf(path, sizeof(path), "%s/fd/%d", proc_dir, fd);
	ssize_t length = readlink(path, link, sizeof(link) - 1);
	link[length > 0 ? length : 0] = '\0';
	if (strncmp(link, "anon_inode:", 11) != 0) {
		return _EBADF;
	}
	memset(info, 0, sizeof(*info));
	info->pfi.fi_openflags = FREAD | FWRITE;
	info->pfi.fi_type = PROX_FDTYPE_KQUEUE;
	info->kqueueinfo.kq_stat.vst_mode = S_IFIFO;
	info->kqueueinfo.kq_stat.vst_blksize = KEVENT_SIZE;
	return sizeof(*info);
}

static int
listfds(int32_t pid, void *buffer, int32_t buffersize)
{
	struct proc_fdinfo_entry {
		int32_t proc_fd;
		uint32_t proc_fdtype;
	};

	char proc_dir[64 + NAME_MAX], path[80 + NAME_MAX];
	process_proc_dir(pid, proc_dir, sizeof(proc_dir));
	snprintf(path, sizeof(path), "%s/fd", proc_dir);
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
			snprintf(path, sizeof(path), "%s/fd/%s", proc_dir,
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

static bool
vnode_info_path(const char *proc_link, struct vnode_info_path *info)
{
	char file[PATH_MAX];
	ssize_t length = readlink(proc_link, file, sizeof(file) - 1);
	struct stat st;
	if (length <= 0 || stat(proc_link, &st) == -1) {
		return false;
	}
	file[length] = '\0';
	/* Only files have vnodes: a socket or a pipe has none */
	if (file[0] != '/') {
		return false;
	}
	fill_vnode_info(file, &st, info);
	return true;
}

static void
fill_vnode_info(const char *file, const struct stat *st,
		struct vnode_info_path *info)
{
	memset(info, 0, sizeof(*info));
	struct vinfo_stat *vst = &info->vi_stat;
	vst->vst_dev = darwin_device(sysroot_device(st->st_dev));
	vst->vst_mode = st->st_mode;
	vst->vst_nlink = st->st_nlink;
	vst->vst_ino = sysroot_file_id(st->st_dev, st->st_ino);
	vst->vst_uid = st->st_uid;
	vst->vst_gid = gid_from_linux(st->st_gid);
	vst->vst_atime = st->st_atim.tv_sec;
	vst->vst_atimensec = st->st_atim.tv_nsec;
	vst->vst_mtime = st->st_mtim.tv_sec;
	vst->vst_mtimensec = st->st_mtim.tv_nsec;
	vst->vst_ctime = st->st_ctim.tv_sec;
	vst->vst_ctimensec = st->st_ctim.tv_nsec;
	vst->vst_size = st->st_size;
	vst->vst_blocks = st->st_blocks;
	vst->vst_blksize = st->st_blksize;
	vst->vst_rdev = (major(st->st_rdev) << 24) | minor(st->st_rdev);
	info->vi_type = S_ISREG(st->st_mode)    ? VREG
			: S_ISDIR(st->st_mode)  ? VDIR
			: S_ISBLK(st->st_mode)  ? VBLK
			: S_ISCHR(st->st_mode)  ? VCHR
			: S_ISLNK(st->st_mode)  ? VLNK
			: S_ISSOCK(st->st_mode) ? VSOCK
						: VFIFO;
	info->vi_fsid[0] = (int32_t)vst->vst_dev;
	snprintf(info->vip_path, sizeof(info->vip_path), "%s",
			sysroot_guest_path(file));
}

static bool
region_with_path(int32_t pid, uint64_t address, bool files_only,
		struct proc_regionwithpathinfo *info)
{
	char dir[64 + NAME_MAX], maps_path[80 + NAME_MAX];
	process_proc_dir(pid, dir, sizeof(dir));
	snprintf(maps_path, sizeof(maps_path), "%s/maps", dir);
	FILE *maps = fopen(maps_path, "re");
	if (maps == NULL) {
		return false;
	}
	char line[PATH_MAX + 128];
	bool found = false;
	while (!found && fgets(line, sizeof(line), maps) != NULL) {
		unsigned long start, end, offset;
		char perms[5];
		int name = 0;
		sscanf(line, "%lx-%lx %4s %lx %*s %*s %n", &start, &end, perms,
				&offset, &name);
		line[strcspn(line, "\n")] = '\0';
		const char *file = line + name;
		struct stat st;
		if (name == 0 || end <= address) {
			continue;
		}
		memset(info, 0, sizeof(*info));
		if (files_only) {
			if (file[0] != '/' || strstr(file, " (deleted)") != NULL
					|| stat(file, &st) != 0) {
				continue;
			}
			fill_vnode_info(file, &st, &info->prp_vip);
		}
		fill_region_info(&info->prp_prinfo, start, end, perms, offset);
		found = true;
	}
	fclose(maps);
	return found;
}

static void
fill_region_info(struct proc_regioninfo *region, unsigned long start,
		unsigned long end, const char *perms, unsigned long offset)
{
	region->pri_protection = (perms[0] == 'r' ? 1 : 0)
			| (perms[1] == 'w' ? 2 : 0) | (perms[2] == 'x' ? 4 : 0);
	region->pri_max_protection = 7;
	region->pri_offset = offset;
	region->pri_share_mode = perms[3] == 's' ? SM_SHARED : SM_PRIVATE;
	region->pri_address = start;
	region->pri_size = end - start;
}

#define COALITION_KERNEL_RESOURCE 1
#define COALITION_KERNEL_JETSAM   3
#define COALITION_PID_BITS        22

static bool
kernel_coalition_member(int32_t pid)
{
	return pid == 0 || pid == 1 || broker_client_is_launchd(pid)
			|| !process_is_guest(pid);
}

static int
coalition_ids(int32_t pid, uint64_t ids[2])
{
	if (kernel_coalition_member(pid)) {
		ids[0] = COALITION_KERNEL_RESOURCE;
		ids[1] = COALITION_KERNEL_JETSAM;
		return 0;
	}
	struct process process;
	if (process_lookup(pid, &process) != 0) {
		return _ESRCH;
	}
	int32_t leader = responsibility_of(&process);
	if (leader != pid && process_lookup(leader, &process) != 0) {
		leader = pid;
		if (process_lookup(leader, &process) != 0) {
			return _ESRCH;
		}
	}
	uint64_t id = ((process.start_ticks & 0xffffff) << COALITION_PID_BITS
				      | (uint64_t)leader)
			<< 1;
	ids[0] = id;
	ids[1] = id | 1;
	return 0;
}

int
proc_coalition_leader(uint64_t id, int32_t *leader)
{
	if (id == COALITION_KERNEL_RESOURCE || id == COALITION_KERNEL_JETSAM) {
		*leader = 0;
		return 0;
	}
	int32_t pid = (int32_t)((id >> 1) & ((1u << COALITION_PID_BITS) - 1));
	struct process process;
	if (kernel_coalition_member(pid) || process_lookup(pid, &process) != 0
			|| (process.start_ticks & 0xffffff)
					!= id >> (COALITION_PID_BITS + 1)
			|| responsibility_of(&process) != pid) {
		return _ESRCH;
	}
	*leader = pid;
	return 0;
}

int
proc_coalition_info(uint32_t flavor, uint64_t id, void *buffer, size_t *size)
{
	int32_t leader;
	int error = proc_coalition_leader(id, &leader);
	if (error != 0) {
		return error;
	}
	switch (flavor) {
	case 1: {
		uint64_t usage[45] = {0};
		int32_t pids[512];
		size_t count = coalition_members(id, leader, pids, 512);
		for (size_t i = 0; i != count && i < 512; i++) {
			uint64_t info[58] = {0};
			if (pidrusage(pids[i], 2, info) != 0) {
				continue;
			}
			usage[0]++;
			usage[3] += info[2] + info[3];
			usage[9] += info[2] + info[3];
			usage[4] += info[5];
			usage[6] += info[18];
			usage[7] += info[19];
			usage[40] += info[9];
		}
		usage[23] = 7;
		memcpy(buffer, usage,
				*size < sizeof(usage) ? *size : sizeof(usage));
		return 0;
	}
	case 5: {
		size_t max = *size / sizeof(int32_t);
		size_t count = coalition_members(id, leader, buffer, max);
		*size = (count < max ? count : max) * sizeof(int32_t);
		return 0;
	}
	default:
		unimplemented();
	}
}

static size_t
coalition_members(uint64_t id, int32_t leader, int32_t *pids, size_t max)
{
	if (leader == 0) {
		int32_t kernel[] = {0, 1, broker_client_pid(),
				broker_client_launchd_pid()};
		size_t count = kernel[2] <= 1            ? 2
				: kernel[3] == kernel[2] ? 3
							 : 4;
		for (size_t i = 0; i != count && i < max; i++) {
			pids[i] = kernel[i];
		}
		return count;
	}
	DIR *dir = opendir("/proc");
	if (dir == NULL) {
		return 0;
	}
	size_t count = 0;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		char *end;
		long pid = strtol(entry->d_name, &end, 10);
		uint64_t ids[2];
		if (*end != '\0' || pid <= 0
				|| coalition_ids((int32_t)pid, ids) != 0
				|| (ids[0] != id && ids[1] != id)) {
			continue;
		}
		if (count < max) {
			pids[count] = (int32_t)pid;
		}
		count++;
	}
	closedir(dir);
	return count;
}
