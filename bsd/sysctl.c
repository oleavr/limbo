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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <mach/mach.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "commpage.h"
#include "cpuinfo.h"
#include "handler.h"
#include "kmsg.h"
#include "memorystatus.h"
#include "net.h"
#include "process.h"
#include "route.h"
#include "shared_cache.h"
#include "sysroot.h"
#include "trace.h"
#include "xnu-errno.h"

#ifdef __arm64__
#define HOST_CPU_TYPE CPU_TYPE_ARM64
#define HOST_MACHINE  "arm64"
#define HOST_MODEL    "Mac17,2"
#define HOST_KERNEL_VERSION                                                    \
	"Darwin Kernel Version 27.0.0: Tue Aug 11 21:05:48 PDT 2026; "         \
	"root:xnu-13432.1.9~1/RELEASE_ARM64_T6041"
#else
#define HOST_CPU_TYPE CPU_TYPE_X86_64
#define HOST_MACHINE  "x86_64"
#define HOST_MODEL    "MacPro7,1"
#define HOST_KERNEL_VERSION                                                    \
	"Darwin Kernel Version 27.0.0: Tue Aug 11 21:02:59 PDT 2026; "         \
	"root:xnu-13432.1.9~1/RELEASE_X86_64"
#endif

#define CTL_UNSPEC 0
#define CTL_KERN   1
#define CTL_NET        4
#define xnu_PF_ROUTE   17
#define NET_RT_IFLIST  3
#define NET_RT_IFLIST2 6
#define CTL_VM     2
#define CTL_HW     6

#define xnu_PF_INET    2
#define xnu_IPPROTO_IP 0
#define IPCTL_DEFTTL   3

#define VM_LOADAVG   2
#define VM_SWAPUSAGE 5

#define FSCALE 2048

#define CTL_SYSCTL_NAME     1
#define CTL_SYSCTL_NEXT     2
#define CTL_SYSCTL_NAME2OID 3
#define CTL_SYSCTL_OIDFMT   4

#define CTLTYPE_INT    2
#define CTLTYPE_STRING 3
#define CTLTYPE_QUAD   4
#define CTLTYPE_OPAQUE 5
#define CTLFLAG_RD     0x80000000

#define KERN_OSTYPE     1
#define KERN_OSRELEASE  2
#define KERN_OSREV      3
#define KERN_VERSION    4
#define KERN_MAXPROC    6
#define KERN_MAXFILES   7
#define KERN_ARGMAX     8
#define KERN_SECURELVL  9
#define KERN_HOSTNAME   10
#define KERN_HOSTID     11
#define KERN_PROC       14
#define KERN_NGROUPS    18
#define KERN_BOOTTIME   21
#define KERN_MAXFILESPERPROC 29
#define KERN_USRSTACK64 59
#define KERN_OSVERSION  65
#define KERN_PROCARGS2  49

#define xnu_NGROUPS_MAX 16

#define EXCLAVES_STATUS_NOT_SUPPORTED 0xff

#define KERN_PROC_ALL     0
#define KERN_PROC_PID     1
#define KERN_PROC_PGRP    2
#define KERN_PROC_SESSION 3
#define KERN_PROC_TTY     4
#define KERN_PROC_UID     5
#define KERN_PROC_RUID    6

#define SRUN   2
#define P_CONTROLT 0x2
#define P_LP64     0x4

#define HW_MACHINE   1
#define HW_MODEL     2
#define HW_NCPU      3
#define HW_BYTEORDER 4
#define HW_PAGESIZE  7
#define HW_MEMSIZE   24
#define HW_AVAILCPU  25

#define SYSCTL_AUTO_OID 1000

typedef enum {
	SYSCTL_STRING,
	SYSCTL_INT,
	SYSCTL_QUAD,
	SYSCTL_READER,
	SYSCTL_QUERY,
} sysctl_kind_t;

typedef int (*sysctl_reader_t)(void *old, size_t *oldlenp);

typedef int (*sysctl_query_t)(
		const void *new, size_t newlen, void *old, size_t *oldlenp);

struct sysctl_node {
	const char *name;
	int oid[2];
	sysctl_kind_t kind;
	union {
		const char *string;
		int64_t number;
		sysctl_reader_t reader;
		sysctl_query_t query;
	};
};

struct __darwin_timeval {
	int64_t tv_sec;
	int32_t tv_usec;
};

struct __darwin_kinfo_proc {
	struct __darwin_timeval p_starttime;
	uint8_t reserved1[16];
	int32_t p_flag;
	char p_stat;
	uint8_t reserved2[3];
	int32_t p_pid;
	int32_t p_oppid;
	uint8_t reserved3[194];
	char p_nice;
	char p_comm[17];
	uint8_t reserved4[132];
	uint32_t p_ruid;
	uint32_t p_svuid;
	uint32_t p_rgid;
	uint32_t p_svgid;
	uint8_t reserved5[12];
	uint32_t cr_uid;
	int16_t cr_ngroups;
	uint8_t reserved6[2];
	uint32_t cr_groups[16];
	uint8_t reserved7[68];
	int32_t e_ppid;
	int32_t e_pgid;
	uint8_t reserved8[4];
	int32_t e_tdev;
	int32_t e_tpgid;
	uint8_t reserved9[68];
};

static int read_hostname(void *old, size_t *oldlenp);
static int read_boottime(void *old, size_t *oldlenp);
static int read_bootsessionuuid(void *old, size_t *oldlenp);
static int read_sandbox_sentinel(void *old, size_t *oldlenp);
static int read_ncpu(void *old, size_t *oldlenp);
static int read_msgbuf(void *old, size_t *oldlenp);
static int read_memsize(void *old, size_t *oldlenp);
#ifdef __x86_64__
static int read_cpu_brand(void *old, size_t *oldlenp);
static int read_cpu_cores(void *old, size_t *oldlenp);
static int read_cpu_packages(void *old, size_t *oldlenp);
static int read_cpu_frequency(void *old, size_t *oldlenp);
#endif
static int read_cpusubtype(void *old, size_t *oldlenp);
static int read_loadavg(void *old, size_t *oldlenp);
static int read_swapusage(void *old, size_t *oldlenp);
static int read_osversion(void *old, size_t *oldlenp);
static int read_osproductversion(void *old, size_t *oldlenp);
static const char *system_version(const char *key, const char *otherwise,
		char *value, size_t size);
static int read_tcp_pcblist(void *old, size_t *oldlenp);
static int read_udp_pcblist(void *old, size_t *oldlenp);
static int read_tcp_stats(void *old, size_t *oldlenp);
static int read_udp_stats(void *old, size_t *oldlenp);
static int read_ip_stats(void *old, size_t *oldlenp);
static int read_ip_ttl(void *old, size_t *oldlenp);
static int read_pressure_level(void *old, size_t *oldlenp);
static int query_grade_cputype(
		const void *new, size_t newlen, void *old, size_t *oldlenp);

static const struct sysctl_node nodes[] = {
		{"kern.ostype", {CTL_KERN, KERN_OSTYPE}, SYSCTL_STRING,
				.string = "Darwin"},
		{"kern.osrelease", {CTL_KERN, KERN_OSRELEASE}, SYSCTL_STRING,
				.string = "27.0.0"},
		{"kern.osrevision", {CTL_KERN, KERN_OSREV}, SYSCTL_INT,
				.number = 199506},
		{"kern.version", {CTL_KERN, KERN_VERSION}, SYSCTL_STRING,
				.string = HOST_KERNEL_VERSION},
		{"kern.argmax", {CTL_KERN, KERN_ARGMAX}, SYSCTL_INT,
				.number = 1048576},

		{"kern.maxproc", {CTL_KERN, KERN_MAXPROC}, SYSCTL_INT,
				.number = 12000},
		{"kern.maxfiles", {CTL_KERN, KERN_MAXFILES}, SYSCTL_INT,
				.number = 368640},
		{"kern.maxfilesperproc", {CTL_KERN, KERN_MAXFILESPERPROC},
				SYSCTL_INT, .number = 184320},
		{"kern.maxprocperuid", {0, 0}, SYSCTL_INT, .number = 8000},
		{"kern.ngroups", {CTL_KERN, KERN_NGROUPS}, SYSCTL_INT,
				.number = xnu_NGROUPS_MAX},
		{"kern.securelevel", {CTL_KERN, KERN_SECURELVL}, SYSCTL_INT,
				.number = 0},
		{"kern.hostname", {CTL_KERN, KERN_HOSTNAME}, SYSCTL_READER,
				.reader = read_hostname},
		{"kern.hostid", {CTL_KERN, KERN_HOSTID}, SYSCTL_INT,
				.number = 0},
		{"kern.boottime", {CTL_KERN, KERN_BOOTTIME}, SYSCTL_READER,
				.reader = read_boottime},
		{"kern.usrstack64", {CTL_KERN, KERN_USRSTACK64}, SYSCTL_QUAD,
				.number = (int64_t)VM_USRSTACK64},
		{"kern.osversion", {CTL_KERN, KERN_OSVERSION}, SYSCTL_READER,
				.reader = read_osversion},
		{"kern.bootargs", {0, 0}, SYSCTL_STRING, .string = ""},
		{"kern.msgbuf", {0, 0}, SYSCTL_READER, .reader = read_msgbuf},
		{"kern.bootsessionuuid", {0, 0}, SYSCTL_READER,
				.reader = read_bootsessionuuid},
		{"kern.grade_cputype", {0, 0}, SYSCTL_QUERY,
				.query = query_grade_cputype},
		{"kern.osproductversion", {0, 0}, SYSCTL_READER,
				.reader = read_osproductversion},
		{"kern.secure_kernel", {0, 0}, SYSCTL_INT, .number = 0},

		{"kern.iossupportversion", {0, 0}, SYSCTL_STRING,
				.string = "27.0"},

		{"kern.osvariant_status", {0, 0}, SYSCTL_QUAD,
				.number = (int64_t)8070732011310449290ULL},
		{"kern.willshutdown", {0, 0}, SYSCTL_INT, .number = 0},

		{"kern.exclaves_status", {0, 0}, SYSCTL_INT,
				.number = EXCLAVES_STATUS_NOT_SUPPORTED},
		{"kern.check_openevt", {0, 0}, SYSCTL_INT, .number = 0},

		{"kern.wq_max_threads", {0, 0}, SYSCTL_INT, .number = 512},
		{"kern.wq_max_constrained_threads", {0, 0}, SYSCTL_INT,
				.number = 70},

		{"kern.memorystatus_vm_pressure_level", {0, 0}, SYSCTL_READER,
				.reader = read_pressure_level},
		{"vm.loadavg", {CTL_VM, VM_LOADAVG}, SYSCTL_READER,
				.reader = read_loadavg},
		{"vm.swapusage", {CTL_VM, VM_SWAPUSAGE}, SYSCTL_READER,
				.reader = read_swapusage},
		{"vm.self_region_footprint", {0, 0}, SYSCTL_INT, .number = 0},
		{"vm.self_region_info_flags", {0, 0}, SYSCTL_INT, .number = 0},
		{"net.inet.tcp.pcblist_n", {0, 0}, SYSCTL_READER,
				.reader = read_tcp_pcblist},
		{"net.inet.udp.pcblist_n", {0, 0}, SYSCTL_READER,
				.reader = read_udp_pcblist},
		{"net.inet.tcp.stats", {0, 0}, SYSCTL_READER,
				.reader = read_tcp_stats},
		{"net.inet.udp.stats", {0, 0}, SYSCTL_READER,
				.reader = read_udp_stats},
		{"net.inet.ip.stats", {0, 0}, SYSCTL_READER,
				.reader = read_ip_stats},
		{"net.inet.ip.ttl", {0, 0}, SYSCTL_READER,
				.reader = read_ip_ttl},

		{"sysctl.proc_cputype", {0, 0}, SYSCTL_INT,
				.number = HOST_CPU_TYPE},
		{"hw.machine", {CTL_HW, HW_MACHINE}, SYSCTL_STRING,
				.string = HOST_MACHINE},
		{"hw.model", {CTL_HW, HW_MODEL}, SYSCTL_STRING,
				.string = HOST_MODEL},
		{"hw.product", {0, 0}, SYSCTL_STRING, .string = HOST_MODEL},
#ifdef __arm64__
		{"hw.target", {0, 0}, SYSCTL_STRING, .string = "J704AP"},
#else
		{"hw.target", {0, 0}, SYSCTL_STRING, .string = ""},
#endif
		{"hw.ncpu", {CTL_HW, HW_NCPU}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.byteorder", {CTL_HW, HW_BYTEORDER}, SYSCTL_INT,
				.number = 1234},
		{"hw.pagesize", {CTL_HW, HW_PAGESIZE}, SYSCTL_QUAD,
				.number = PAGE_SIZE},
		{"hw.memsize", {CTL_HW, HW_MEMSIZE}, SYSCTL_READER,
				.reader = read_memsize},
		{"hw.availcpu", {CTL_HW, HW_AVAILCPU}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.activecpu", {0, 0}, SYSCTL_READER, .reader = read_ncpu},
		{"hw.logicalcpu", {0, 0}, SYSCTL_READER, .reader = read_ncpu},
		{"hw.logicalcpu_max", {0, 0}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.physicalcpu", {0, 0}, SYSCTL_READER, .reader = read_ncpu},
		{"hw.physicalcpu_max", {0, 0}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.cachelinesize", {0, 0}, SYSCTL_QUAD, .number = 64},
#ifdef __x86_64__
		{"machdep.cpu.brand_string", {0, 0}, SYSCTL_READER,
				.reader = read_cpu_brand},
		{"machdep.cpu.core_count", {0, 0}, SYSCTL_READER,
				.reader = read_cpu_cores},
		{"hw.packages", {0, 0}, SYSCTL_READER,
				.reader = read_cpu_packages},
		{"hw.cpufrequency", {0, 0}, SYSCTL_READER,
				.reader = read_cpu_frequency},
		{"hw.cpufrequency_max", {0, 0}, SYSCTL_READER,
				.reader = read_cpu_frequency},
#endif
		{"hw.cputype", {0, 0}, SYSCTL_INT, .number = HOST_CPU_TYPE},
		{"hw.cpusubtype", {0, 0}, SYSCTL_READER,
				.reader = read_cpusubtype},
		{"hw.cpu64bit_capable", {0, 0}, SYSCTL_INT, .number = 1},
		{"hw.ephemeral_storage", {0, 0}, SYSCTL_INT, .number = 0},

		{"hw.use_kernelmanagerd", {0, 0}, SYSCTL_INT, .number = 1},

		{"hw.nperflevels", {0, 0}, SYSCTL_INT, .number = 1},
		{"hw.perflevel0.physicalcpu", {0, 0}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.perflevel0.physicalcpu_max", {0, 0}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.perflevel0.logicalcpu", {0, 0}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.perflevel0.logicalcpu_max", {0, 0}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.perflevel0.cpusperl2", {0, 0}, SYSCTL_READER,
				.reader = read_ncpu},
		{"hw.perflevel0.l1icachesize", {0, 0}, SYSCTL_INT,
				.number = 196608},
		{"hw.perflevel0.l1dcachesize", {0, 0}, SYSCTL_INT,
				.number = 131072},
		{"hw.perflevel0.l2cachesize", {0, 0}, SYSCTL_INT,
				.number = 16777216},
		{"hw.perflevel0.name", {0, 0}, SYSCTL_STRING,
				.string = "Performance"},
		{"security.mac.lockdown_mode_state", {0, 0}, SYSCTL_INT,
				.number = 0},
		{"vfs.generic.noremotehang", {0, 0}, SYSCTL_INT, .number = 0},
		{"security.mac.amfi.qa_root_certs_allowed", {0, 0}, SYSCTL_INT,
				.number = 0},
		{"kern.safeboot", {0, 0}, SYSCTL_INT, .number = 0},
		{"vfs.generic.root_unmounted_cleanly", {0, 0}, SYSCTL_INT,
				.number = 1},

		{"security.mac.sandbox.sentinel", {0, 0}, SYSCTL_READER,
				.reader = read_sandbox_sentinel},
};

static int read_kinfo_proc(int32_t pid, void *old, size_t *oldlenp);
static int list_kinfo_proc(
		int32_t what, int32_t arg, void *old, size_t *oldlenp);
static bool kinfo_proc_matches(
		const struct process *process, int32_t what, int32_t arg);
static void fill_kinfo_proc(const struct process *process,
		struct __darwin_kinfo_proc *info);
static int read_procargs2(int32_t pid, void *old, size_t *oldlenp);
static const struct sysctl_node *lookup_oid(const int *name, uint32_t namelen);
static int name2oid(
		const char *name, size_t namelen, void *old, size_t *oldlenp);
static int next_oid(
		const int *name, uint32_t namelen, void *old, size_t *oldlenp);
static bool oid_before(const int *a, uint32_t a_length, const int *b,
		uint32_t b_length);
static int oid_format(const int *oid, void *old, size_t *oldlenp);
static const struct sysctl_node *lookup_name(const char *name, size_t namelen);
static void node_oid(const struct sysctl_node *node, int oid[2]);
static int read_node(
		const struct sysctl_node *node, void *old, size_t *oldlenp);
static int read_bytes(
		const void *value, size_t size, void *old, size_t *oldlenp);
static int read_number(int64_t value, size_t size, void *old, size_t *oldlenp);

int
sys_sysctl(int *name, uint32_t namelen, void *old, size_t *oldlenp, void *new,
		size_t newlen)
{
	if (namelen == 2 && name[0] == CTL_UNSPEC
			&& name[1] == CTL_SYSCTL_NAME2OID) {
		return name2oid(new, newlen, old, oldlenp);
	}
	if (namelen >= 2 && name[0] == CTL_UNSPEC
			&& name[1] == CTL_SYSCTL_NEXT) {
		return next_oid(name + 2, namelen - 2, old, oldlenp);
	}
	if (namelen == 4 && name[0] == CTL_UNSPEC
			&& name[1] == CTL_SYSCTL_OIDFMT) {
		return oid_format(name + 2, old, oldlenp);
	}
	if (namelen == 4 && name[0] == CTL_UNSPEC
			&& name[1] == CTL_SYSCTL_NAME) {
		const struct sysctl_node *node = lookup_oid(name + 2, 2);
		if (node == NULL) {
			return _ENOENT;
		}
		return read_bytes(node->name, strlen(node->name) + 1, old,
				oldlenp);
	}

	const struct sysctl_node *question = lookup_oid(name, namelen);
	if (question != NULL && question->kind == SYSCTL_QUERY) {
		return question->query(new, newlen, old, oldlenp);
	}

	if (new != NULL) {
		if (old == NULL) {
			return 0;
		}
	}

	if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC
			&& name[2] == KERN_PROC_PID) {
		return read_kinfo_proc(name[3], old, oldlenp);
	}
	if (name[0] == CTL_KERN && name[1] == KERN_PROC
			&& ((namelen == 3 && name[2] == KERN_PROC_ALL)
					|| (namelen == 4
							&& name[2] >= KERN_PROC_ALL
							&& name[2] <= KERN_PROC_RUID))) {
		return list_kinfo_proc(name[2], namelen == 4 ? name[3] : 0, old,
				oldlenp);
	}
	if (namelen == 3 && name[0] == CTL_KERN && name[1] == KERN_PROCARGS2) {
		return read_procargs2(name[2], old, oldlenp);
	}

	if (namelen == 6 && name[0] == CTL_NET && name[1] == xnu_PF_ROUTE
			&& (name[4] == NET_RT_IFLIST
					|| name[4] == NET_RT_IFLIST2)) {
		return net_interface_list(
				name[4], name[3], name[5], old, oldlenp);
	}
	if (namelen == 6 && name[0] == CTL_NET && name[1] == xnu_PF_ROUTE
			&& name[2] == 0 && name[4] != NET_RT_IFLIST
			&& name[4] != NET_RT_IFLIST2) {
		return route_dump(name[4], name[3], name[5], old, oldlenp);
	}

	if (namelen == 4 && name[0] == CTL_NET && name[1] == xnu_PF_INET
			&& name[2] == xnu_IPPROTO_IP
			&& name[3] == IPCTL_DEFTTL) {
		return read_node(lookup_name("net.inet.ip.ttl", 15), old,
				oldlenp);
	}

	const struct sysctl_node *node = lookup_oid(name, namelen);
	if (node == NULL && namelen == 3) {

		const struct sysctl_node *parent = lookup_oid(name, 2);
		if (parent != NULL
				&& strcmp(parent->name, "sysctl.proc_cputype")
						== 0) {
			struct process process;
			if (process_lookup(name[2], &process) != 0) {
				return _ESRCH;
			}
			node = parent;
		}
	}
	if (node == NULL) {
		return _ENOENT;
	}
	trace_string(node->name);
	return read_node(node, old, oldlenp);
}

static int
read_procargs2(int32_t pid, void *old, size_t *oldlenp)
{
	char cmdline[16 * 1024];
	ssize_t length = process_cmdline(pid, cmdline, sizeof(cmdline) - 1);
	if (length <= 0) {
		return _EINVAL;
	}
	cmdline[length] = '\0';
	const char *arguments = cmdline;
	const char *end = cmdline + length;
	char path[PATH_MAX];
	const char *first = cmdline;
	const char *base = strrchr(first, '/');
	if (strcmp(base != NULL ? base + 1 : first, "limbo") == 0
			&& first + strlen(first) + 1 < end) {
		const char *host = first + strlen(first) + 1;
		snprintf(path, sizeof(path), "%s", sysroot_guest_path(host));
		arguments = host + strlen(host) + 1;
	} else {
		char link[64];
		snprintf(link, sizeof(link), "/proc/%d/exe", (int)pid);
		ssize_t n = readlink(link, path, sizeof(path) - 1);
		if (n <= 0) {
			snprintf(path, sizeof(path), "%s", first);
		} else {
			path[n] = '\0';
		}
	}

	int32_t argc = 0;
	for (const char *a = arguments; a < end; a += strlen(a) + 1) {
		argc++;
	}
	size_t path_size = (strlen(path) + 1 + 7) & ~(size_t)7;
	size_t size = sizeof(argc) + path_size
			+ (size_t)(end - arguments) + 1;
	if (old == NULL) {
		*oldlenp = size;
		return 0;
	}
	if (*oldlenp < size) {
		return _ENOMEM;
	}
	uint8_t *out = old;
	memset(out, 0, size);
	memcpy(out, &argc, sizeof(argc));
	memcpy(out + sizeof(argc), path, strlen(path));
	memcpy(out + sizeof(argc) + path_size, arguments, end - arguments);
	*oldlenp = size;
	return 0;
}

static int
read_kinfo_proc(int32_t pid, void *old, size_t *oldlenp)
{
	struct process process;
	if (process_lookup(pid, &process)) {
		*oldlenp = 0;
		return 0;
	}

	struct __darwin_kinfo_proc info;
	fill_kinfo_proc(&process, &info);
	return read_bytes(&info, sizeof(info), old, oldlenp);
}

static int
list_kinfo_proc(int32_t what, int32_t arg, void *old, size_t *oldlenp)
{
	DIR *proc = opendir("/proc");
	size_t size = 0;
	bool full = false;
	struct dirent *entry;
	while ((entry = readdir(proc)) != NULL) {
		char *end;
		long pid = strtol(entry->d_name, &end, 10);
		struct process process;
		if (*end != '\0' || pid <= 0
				|| process_lookup((int32_t)pid, &process) != 0
				|| !kinfo_proc_matches(&process, what, arg)) {
			continue;
		}
		if (old != NULL) {
			if (size + sizeof(struct __darwin_kinfo_proc)
					> *oldlenp) {
				full = true;
				break;
			}
			struct __darwin_kinfo_proc info;
			fill_kinfo_proc(&process, &info);
			memcpy((uint8_t *)old + size, &info, sizeof(info));
		}
		size += sizeof(struct __darwin_kinfo_proc);
	}
	closedir(proc);
	*oldlenp = old != NULL ? size
			       : size + 5 * sizeof(struct __darwin_kinfo_proc);
	return full ? _ENOMEM : 0;
}

static bool
kinfo_proc_matches(const struct process *process, int32_t what, int32_t arg)
{
	switch (what) {
	case KERN_PROC_ALL:
		return true;
	case KERN_PROC_PID:
		return process->pid == arg;
	case KERN_PROC_PGRP:
		return process->pgid == arg;
	case KERN_PROC_SESSION:
		return process->session == arg;
	case KERN_PROC_TTY:
		return process_terminal(process) == arg;
	case KERN_PROC_UID:
		return process->uid[1] == (uint32_t)arg;
	case KERN_PROC_RUID:
		return process->uid[0] == (uint32_t)arg;
	default:
		return false;
	}
}

static void
fill_kinfo_proc(const struct process *process, struct __darwin_kinfo_proc *info)
{
	*info = (struct __darwin_kinfo_proc){
			.p_flag = P_LP64,
			.p_stat = SRUN,
			.p_pid = process->pid,
			.p_nice = process->nice,
			.p_ruid = process->uid[0],
			.p_svuid = process->uid[2],
			.p_rgid = process->gid[0],
			.p_svgid = process->gid[2],
			.cr_uid = process->uid[1],
			.cr_ngroups = 1,
			.cr_groups = {process->gid[1]},
			.e_ppid = process->ppid,
			.e_pgid = process->pgid,
			.e_tdev = process_terminal(process),
			.e_tpgid = process->tpgid,
	};
	uint64_t sec, usec;
	process_start_time(process, &sec, &usec);
	info->p_starttime.tv_sec = sec;
	info->p_starttime.tv_usec = usec;
	memcpy(info->p_comm, process->comm, sizeof(process->comm));
	if (info->e_tdev != -1) {
		info->p_flag |= P_CONTROLT;
	}
}

static const struct sysctl_node *
lookup_oid(const int *name, uint32_t namelen)
{
	if (namelen != 2) {
		return NULL;
	}

	for (uint32_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		int oid[2];
		node_oid(&nodes[i], oid);
		if (oid[0] == name[0] && oid[1] == name[1]) {
			return &nodes[i];
		}
	}
	return NULL;
}

static int
name2oid(const char *name, size_t namelen, void *old, size_t *oldlenp)
{
	const struct sysctl_node *node = lookup_name(name, namelen);
	if (node == NULL) {
		return _ENOENT;
	}

	int oid[2];
	node_oid(node, oid);
	return read_bytes(oid, sizeof(oid), old, oldlenp);
}

static int
next_oid(const int *name, uint32_t namelen, void *old, size_t *oldlenp)
{
	int best[2];
	bool found = false;
	for (uint32_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		int oid[2];
		node_oid(&nodes[i], oid);
		if (oid_before(name, namelen, oid, 2)
				&& (!found || oid_before(oid, 2, best, 2))) {
			best[0] = oid[0];
			best[1] = oid[1];
			found = true;
		}
	}
	if (!found) {
		return _ENOENT;
	}
	return read_bytes(best, sizeof(best), old, oldlenp);
}

static bool
oid_before(const int *a, uint32_t a_length, const int *b, uint32_t b_length)
{
	for (uint32_t i = 0; i < a_length && i < b_length; i++) {
		if (a[i] != b[i]) {
			return (unsigned)a[i] < (unsigned)b[i];
		}
	}
	return a_length < b_length;
}

static int
oid_format(const int *oid, void *old, size_t *oldlenp)
{
	const struct sysctl_node *node = lookup_oid(oid, 2);
	if (node == NULL) {
		return _ENOENT;
	}
	uint32_t kind;
	const char *format;
	switch (node->kind) {
	case SYSCTL_STRING:
		kind = CTLTYPE_STRING;
		format = "A";
		break;
	case SYSCTL_QUAD:
		kind = CTLTYPE_QUAD;
		format = "Q";
		break;
	case SYSCTL_READER:
		if (node->reader == read_boottime) {
			kind = CTLTYPE_OPAQUE;
			format = "S,timeval";
		} else if (node->reader == read_loadavg) {
			kind = CTLTYPE_OPAQUE;
			format = "S,loadavg";
		} else if (node->reader == read_swapusage) {
			kind = CTLTYPE_OPAQUE;
			format = "S,xsw_usage";
		} else if (node->reader == read_tcp_pcblist) {
			kind = CTLTYPE_OPAQUE;
			format = "S,xtcpcb_n";
		} else if (node->reader == read_udp_pcblist) {
			kind = CTLTYPE_OPAQUE;
			format = "S,xinpcb_n";
		} else if (node->reader == read_tcp_stats) {
			kind = CTLTYPE_OPAQUE;
			format = "S,tcpstat";
		} else if (node->reader == read_udp_stats) {
			kind = CTLTYPE_OPAQUE;
			format = "S,udpstat";
		} else if (node->reader == read_ip_stats) {
			kind = CTLTYPE_OPAQUE;
			format = "S,ipstat";
		} else if (node->reader == read_hostname
				|| node->reader == read_bootsessionuuid
				|| node->reader == read_sandbox_sentinel
				|| node->reader == read_osversion
				|| node->reader == read_osproductversion) {
			kind = CTLTYPE_STRING;
			format = "A";
		} else if (node->reader == read_memsize) {
			kind = CTLTYPE_QUAD;
			format = "Q";
		} else {
			kind = CTLTYPE_INT;
			format = "I";
		}
		break;
	case SYSCTL_QUERY:
		kind = CTLTYPE_OPAQUE;
		format = "S";
		break;
	default:
		kind = CTLTYPE_INT;
		format = "I";
		break;
	}
	uint8_t buffer[16] = {0};
	uint32_t value = kind | CTLFLAG_RD;
	memcpy(buffer, &value, sizeof(value));
	memcpy(buffer + sizeof(value), format, strlen(format) + 1);
	return read_bytes(buffer, sizeof(value) + strlen(format) + 1, old,
			oldlenp);
}

int
sys_sys_sysctlbyname(const char *name, size_t namelen, void *old,
		size_t *oldlenp, void *new, size_t newlen)
{
	trace_string(name);
	const struct sysctl_node *node = lookup_name(name, namelen);
	if (node != NULL && node->kind == SYSCTL_QUERY) {
		return node->query(new, newlen, old, oldlenp);
	}
	if (new != NULL) {
		if (old == NULL) {
			return 0;
		}
	}
	if (node == NULL) {
		return _ENOENT;
	}
	return read_node(node, old, oldlenp);
}

static const struct sysctl_node *
lookup_name(const char *name, size_t namelen)
{
	for (uint32_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		const char *candidate = nodes[i].name;
		if (strlen(candidate) == namelen
				&& memcmp(candidate, name, namelen) == 0) {
			return &nodes[i];
		}
	}
	return NULL;
}

static void
node_oid(const struct sysctl_node *node, int oid[2])
{
	if (node->oid[0] != 0) {
		oid[0] = node->oid[0];
		oid[1] = node->oid[1];
	} else {
		oid[0] = SYSCTL_AUTO_OID;
		oid[1] = node - nodes;
	}
}

static int
read_node(const struct sysctl_node *node, void *old, size_t *oldlenp)
{
	switch (node->kind) {
	case SYSCTL_STRING:
		return read_bytes(node->string, strlen(node->string) + 1, old,
				oldlenp);
	case SYSCTL_INT:
		return read_number(node->number, sizeof(int32_t), old, oldlenp);
	case SYSCTL_QUAD:
		return read_number(node->number, sizeof(int64_t), old, oldlenp);
	case SYSCTL_READER:
		return node->reader(old, oldlenp);
	case SYSCTL_QUERY:
		return _EINVAL;
	}
	unimplemented();
}

static int
query_grade_cputype(const void *new, size_t newlen, void *old, size_t *oldlenp)
{
	if (new == NULL || newlen != 2 * sizeof(int32_t) || old == NULL
			|| oldlenp == NULL || *oldlenp < sizeof(int32_t)) {
		return _EINVAL;
	}
	int32_t asked[2];
	memcpy(asked, new, sizeof(asked));
	cpu_subtype_t subtype = asked[1] & ~CPU_SUBTYPE_MASK;
	int32_t grade = 0;
#ifdef __x86_64__
	if (asked[0] == CPU_TYPE_X86_64) {
		if (subtype == CPU_SUBTYPE_X86_64_H) {
			grade = shared_cache_cpu_subtype == CPU_SUBTYPE_X86_64_H
					? 2
					: 0;
		} else if (subtype == CPU_SUBTYPE_X86_64_ALL) {
			grade = 1;
		}
	}
#else
	if (asked[0] == CPU_TYPE_ARM64) {
		if (subtype == CPU_SUBTYPE_ARM64E) {
			grade = shared_cache_cpu_subtype == CPU_SUBTYPE_ARM64E
					? 3
					: 0;
		} else if (subtype == CPU_SUBTYPE_ARM64_V8) {
			grade = 2;
		} else if (subtype == CPU_SUBTYPE_ARM64_ALL) {
			grade = 1;
		}
	}
#endif
	memcpy(old, &grade, sizeof(grade));
	*oldlenp = sizeof(grade);
	return 0;
}

static int
read_hostname(void *old, size_t *oldlenp)
{
	char hostname[256];
	gethostname(hostname, sizeof(hostname));
	return read_bytes(hostname, strlen(hostname) + 1, old, oldlenp);
}

static int
read_bootsessionuuid(void *old, size_t *oldlenp)
{
	char uuid[40] = "00000000-0000-0000-0000-000000000000";
	FILE *boot_id = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (boot_id != NULL) {
		if (fgets(uuid, sizeof(uuid), boot_id) != NULL) {
			uuid[strcspn(uuid, "\n")] = '\0';
		}
		fclose(boot_id);
	}
	for (char *c = uuid; *c != '\0'; c++) {
		*c = (char)toupper((unsigned char)*c);
	}
	return read_bytes(uuid, strlen(uuid) + 1, old, oldlenp);
}

static int
read_sandbox_sentinel(void *old, size_t *oldlenp)
{
	char boot[40] = "00000000";
	FILE *boot_id = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (boot_id != NULL) {
		if (fgets(boot, sizeof(boot), boot_id) == NULL) {
			boot[0] = '\0';
		}
		fclose(boot_id);
	}
	char sentinel[16];
	snprintf(sentinel, sizeof(sentinel), ".sb-%.8s", boot);
	return read_bytes(sentinel, strlen(sentinel) + 1, old, oldlenp);
}

static int
read_boottime(void *old, size_t *oldlenp)
{
	struct timespec now, monotonic;
	clock_gettime(CLOCK_REALTIME, &now);
	clock_gettime(CLOCK_MONOTONIC, &monotonic);

	int64_t uptime_ns = monotonic.tv_sec * 1000000000LL + monotonic.tv_nsec
			- (int64_t)commpage_boot_nanoseconds();
	int64_t boot_ns = now.tv_sec * 1000000000LL + now.tv_nsec - uptime_ns;
	struct __darwin_timeval tv = {
			.tv_sec = boot_ns / 1000000000LL,
			.tv_usec = (boot_ns % 1000000000LL) / 1000,
	};
	return read_bytes(&tv, sizeof(tv), old, oldlenp);
}

static int
read_osversion(void *old, size_t *oldlenp)
{
	char value[64];
	const char *version = system_version(
			"ProductBuildVersion", "26A434", value, sizeof(value));
	return read_bytes(version, strlen(version) + 1, old, oldlenp);
}

static int
read_osproductversion(void *old, size_t *oldlenp)
{
	char value[64];
	const char *version = system_version(
			"ProductVersion", "27.0.1", value, sizeof(value));
	return read_bytes(version, strlen(version) + 1, old, oldlenp);
}

#define SYSTEM_VERSION_PATH "/System/Library/CoreServices/SystemVersion.plist"

static const char *
system_version(const char *key, const char *otherwise, char *value, size_t size)
{
	char buffer[PATH_MAX];
	FILE *file = fopen(sysroot_host_path(SYSTEM_VERSION_PATH, 0, buffer),
			"re");
	if (file == NULL) {
		return otherwise;
	}
	char text[8192];
	size_t length = fread(text, 1, sizeof(text) - 1, file);
	fclose(file);
	text[length] = '\0';
	char wanted[64];
	snprintf(wanted, sizeof(wanted), "<key>%s</key>", key);
	const char *at = strstr(text, wanted);
	const char *start = at != NULL ? strstr(at, "<string>") : NULL;
	const char *end = start != NULL ? strstr(start, "</string>") : NULL;
	if (end == NULL) {
		return otherwise;
	}
	start += strlen("<string>");
	snprintf(value, size, "%.*s", (int)(end - start), start);
	return value;
}

static int
read_ncpu(void *old, size_t *oldlenp)
{
	return read_number(sysconf(_SC_NPROCESSORS_ONLN), sizeof(int32_t), old,
			oldlenp);
}

static int
read_msgbuf(void *old, size_t *oldlenp)
{
	return read_number(KMSG_SIZE, sizeof(int32_t), old, oldlenp);
}

#ifdef __x86_64__
static int
read_cpu_brand(void *old, size_t *oldlenp)
{
	const char *brand = host_cpu()->brand;
	return read_bytes(brand, strlen(brand) + 1, old, oldlenp);
}

static int
read_cpu_cores(void *old, size_t *oldlenp)
{
	uint32_t cores = host_cpu()->cores;
	return read_number(cores != 0 ? cores : sysconf(_SC_NPROCESSORS_ONLN),
			sizeof(int32_t), old, oldlenp);
}

static int
read_cpu_packages(void *old, size_t *oldlenp)
{
	uint32_t packages = host_cpu()->packages;
	return read_number(packages != 0 ? packages : 1, sizeof(int32_t), old,
			oldlenp);
}

static int
read_cpu_frequency(void *old, size_t *oldlenp)
{
	return read_number((int64_t)host_cpu()->frequency, sizeof(int64_t), old,
			oldlenp);
}
#endif

static int
read_memsize(void *old, size_t *oldlenp)
{
	int64_t memsize = (int64_t)sysconf(_SC_PHYS_PAGES) * getpagesize();
	return read_number(memsize, sizeof(int64_t), old, oldlenp);
}

static int
read_loadavg(void *old, size_t *oldlenp)
{
	struct {
		uint32_t ldavg[3];
		int64_t fscale;
	} load = {.fscale = FSCALE};
	double averages[3];
	FILE *file = fopen("/proc/loadavg", "re");
	fscanf(file, "%lf %lf %lf", &averages[0], &averages[1], &averages[2]);
	fclose(file);
	for (int i = 0; i < 3; i++) {
		load.ldavg[i] = (uint32_t)(averages[i] * FSCALE + 0.5);
	}
	return read_bytes(&load, sizeof(load), old, oldlenp);
}

static int
read_swapusage(void *old, size_t *oldlenp)
{
	struct {
		uint64_t total;
		uint64_t avail;
		uint64_t used;
		uint32_t pagesize;
		uint32_t encrypted;
	} usage = {.pagesize = 16384, .encrypted = 1};
	FILE *meminfo = fopen("/proc/meminfo", "r");
	if (meminfo != NULL) {
		char line[128];
		unsigned long long kilobytes;
		while (fgets(line, sizeof(line), meminfo) != NULL) {
			if (sscanf(line, "SwapTotal: %llu kB", &kilobytes) == 1) {
				usage.total = kilobytes * 1024;
			} else if (sscanf(line, "SwapFree: %llu kB", &kilobytes)
					== 1) {
				usage.avail = kilobytes * 1024;
			}
		}
		fclose(meminfo);
	}
	usage.used = usage.total - usage.avail;
	return read_bytes(&usage, sizeof(usage), old, oldlenp);
}

#pragma pack(push, 4)
struct xnu_xinpgen {
	uint32_t xig_len;
	uint32_t xig_count;
	uint64_t xig_gen;
	uint64_t xig_sogen;
};

struct xnu_xinpcb_n {
	uint32_t xi_len;
	uint32_t xi_kind;
	uint64_t xi_inpp;
	uint16_t inp_fport;
	uint16_t inp_lport;
	uint64_t inp_ppcb;
	uint64_t inp_gencnt;
	int32_t inp_flags;
	uint32_t inp_flow;
	uint8_t inp_vflag;
	uint8_t inp_ip_ttl;
	uint8_t inp_ip_p;
	uint32_t inp_faddr[4];
	uint32_t inp_laddr[4];
	uint8_t inp4_ip_tos;
	struct {
		uint8_t inp6_hlim;
		int32_t inp6_cksum;
		uint16_t inp6_ifindex;
		int16_t inp6_hops;
	} inp_depend6;
	uint32_t inp_flowhash;
	uint32_t inp_flags2;
};

struct xnu_xsocket_n {
	uint32_t xso_len;
	uint32_t xso_kind;
	uint64_t xso_so;
	int16_t so_type;
	uint32_t so_options;
	int16_t so_linger;
	int16_t so_state;
	uint64_t so_pcb;
	int32_t xso_protocol;
	int32_t xso_family;
	int16_t so_qlen;
	int16_t so_incqlen;
	int16_t so_qlimit;
	int16_t so_timeo;
	uint16_t so_error;
	int32_t so_pgid;
	uint32_t so_oobmark;
	uint32_t so_uid;
	int32_t so_last_pid;
	int32_t so_e_pid;
	uint64_t so_gencnt;
	uint32_t so_flags;
	uint32_t so_flags1;
	int32_t so_usecount;
	int32_t so_retaincnt;
	uint32_t xso_filter_flags;
};

struct xnu_xsockbuf_n {
	uint32_t xsb_len;
	uint32_t xsb_kind;
	uint32_t sb_cc;
	uint32_t sb_hiwat;
	uint32_t sb_mbcnt;
	uint32_t sb_mbmax;
	int32_t sb_lowat;
	int16_t sb_flags;
	int16_t sb_timeo;
};

struct xnu_xsockstat_n {
	uint32_t xst_len;
	uint32_t xst_kind;
	uint64_t xst_tc_stats[4][4];
};

struct xnu_xtcpcb_n {
	uint32_t xt_len;
	uint32_t xt_kind;
	uint64_t t_segq;
	int32_t t_dupacks;
	int32_t t_timer[4];
	int32_t t_state;
	uint32_t t_rest[41];
};

struct pcblist_item {
	struct xnu_xinpcb_n inpcb;
	struct xnu_xsocket_n socket;
	struct xnu_xsockbuf_n receive;
	struct xnu_xsockbuf_n send;
	struct xnu_xsockstat_n stats;
	struct xnu_xtcpcb_n tcpcb;
	uint32_t padding;
};
#pragma pack(pop)
_Static_assert(sizeof(struct xnu_xinpgen) == 24, "xinpgen");
_Static_assert(sizeof(struct xnu_xinpcb_n) == 104, "xinpcb_n");
_Static_assert(sizeof(struct xnu_xsocket_n) == 104, "xsocket_n");
_Static_assert(sizeof(struct xnu_xsockbuf_n) == 32, "xsockbuf_n");
_Static_assert(sizeof(struct xnu_xsockstat_n) == 136, "xsockstat_n");
_Static_assert(sizeof(struct xnu_xtcpcb_n) == 204, "xtcpcb_n");
_Static_assert(sizeof(struct pcblist_item) == 616, "a TCP socket's records");

#define XSO_SOCKET 0x001
#define XSO_RCVBUF 0x002
#define XSO_SNDBUF 0x004
#define XSO_STATS  0x008
#define XSO_INPCB  0x010
#define XSO_TCPCB  0x020

#define DARWIN_INP_IPV4      0x1
#define DARWIN_INP_IPV6      0x2
#define DARWIN_AF_INET       2
#define DARWIN_AF_INET6      30
#define DARWIN_SOCK_STREAM   1
#define DARWIN_SOCK_DGRAM    2
#define DARWIN_SO_ACCEPTCONN 0x2

enum {
	DARWIN_TCPS_CLOSED,
	DARWIN_TCPS_LISTEN,
	DARWIN_TCPS_SYN_SENT,
	DARWIN_TCPS_SYN_RECEIVED,
	DARWIN_TCPS_ESTABLISHED,
	DARWIN_TCPS_CLOSE_WAIT,
	DARWIN_TCPS_FIN_WAIT_1,
	DARWIN_TCPS_CLOSING,
	DARWIN_TCPS_LAST_ACK,
	DARWIN_TCPS_FIN_WAIT_2,
	DARWIN_TCPS_TIME_WAIT,
};

struct pcblist {
	bool tcp;
	uint8_t ttl;
	struct pcblist_item *items;
	size_t count, capacity;
};

static int pcblist_answer(bool tcp, void *old, size_t *oldlenp);
static bool pcblist_table(struct pcblist *list, const char *table, bool v6);
static void pcblist_address(uint32_t address[4], const char *hex, bool v6);
static int default_ttl(void);

static int
read_tcp_pcblist(void *old, size_t *oldlenp)
{
	return pcblist_answer(true, old, oldlenp);
}

static int
read_udp_pcblist(void *old, size_t *oldlenp)
{
	return pcblist_answer(false, old, oldlenp);
}

static int
pcblist_answer(bool tcp, void *old, size_t *oldlenp)
{
	struct pcblist list = {.tcp = tcp, .ttl = (uint8_t)default_ttl()};
	if (!pcblist_table(&list, tcp ? "tcp" : "udp", false)
			|| !pcblist_table(&list, tcp ? "tcp6" : "udp6", true)) {
		free(list.items);
		return _ENOMEM;
	}
	size_t item_size = tcp ? sizeof(struct pcblist_item)
			       : offsetof(struct pcblist_item, tcpcb);
	struct xnu_xinpgen header = {
			.xig_len = sizeof(header),
			.xig_count = (uint32_t)list.count,
	};
	if (old == NULL) {
		*oldlenp = 2 * sizeof(header)
				+ (list.count + list.count / 8 + 1) * item_size;
		free(list.items);
		return 0;
	}
	uint8_t *out = old;
	size_t room = *oldlenp, length = 0, copied = 0;
	bool complete = false;
	if (room >= sizeof(header)) {
		memcpy(out, &header, sizeof(header));
		length = sizeof(header);
		while (copied < list.count && length + item_size <= room) {
			memcpy(out + length, &list.items[copied++], item_size);
			length += item_size;
		}
		complete = list.count == 0;
		if (!complete && copied == list.count
				&& length + sizeof(header) <= room) {
			memcpy(out + length, &header, sizeof(header));
			length += sizeof(header);
			complete = true;
		}
	}
	*oldlenp = length;
	free(list.items);
	return complete ? 0 : _ENOMEM;
}

static bool
pcblist_table(struct pcblist *list, const char *table, bool v6)
{
	static const int32_t tcp_states[] = {
			[TCP_ESTABLISHED] = DARWIN_TCPS_ESTABLISHED,
			[TCP_SYN_SENT] = DARWIN_TCPS_SYN_SENT,
			[TCP_SYN_RECV] = DARWIN_TCPS_SYN_RECEIVED,
			[TCP_FIN_WAIT1] = DARWIN_TCPS_FIN_WAIT_1,
			[TCP_FIN_WAIT2] = DARWIN_TCPS_FIN_WAIT_2,
			[TCP_TIME_WAIT] = DARWIN_TCPS_TIME_WAIT,
			[TCP_CLOSE] = DARWIN_TCPS_CLOSED,
			[TCP_CLOSE_WAIT] = DARWIN_TCPS_CLOSE_WAIT,
			[TCP_LAST_ACK] = DARWIN_TCPS_LAST_ACK,
			[TCP_LISTEN] = DARWIN_TCPS_LISTEN,
			[TCP_CLOSING] = DARWIN_TCPS_CLOSING,
	};
	char path[32];
	snprintf(path, sizeof(path), "/proc/net/%s", table);
	FILE *file = fopen(path, "re");
	if (file == NULL) {
		return true;
	}
	bool tcp = list->tcp;
	char line[512];
	while (fgets(line, sizeof(line), file) != NULL) {
		char local[33], remote[33];
		unsigned int local_port, remote_port, state, uid;
		unsigned long sending, receiving, inode;
		if (sscanf(line,
				    " %*d: %32[0-9A-Fa-f]:%x %32[0-9A-Fa-f]:%x "
				    "%x "
				    "%lx:%lx %*x:%*x %*x %u %*u %lu",
				    local, &local_port, remote, &remote_port,
				    &state, &sending, &receiving, &uid, &inode)
				!= 9) {
			continue;
		}
		if (list->count == list->capacity) {
			size_t capacity = list->capacity == 0
					? 64
					: list->capacity * 2;
			struct pcblist_item *grown = realloc(
					list->items, capacity * sizeof(*grown));
			if (grown == NULL) {
				fclose(file);
				return false;
			}
			list->items = grown;
			list->capacity = capacity;
		}
		bool listening = tcp && state == TCP_LISTEN;
		struct pcblist_item *item = &list->items[list->count++];
		memset(item, 0, sizeof(*item));
		item->inpcb = (struct xnu_xinpcb_n){
				.xi_len = sizeof(item->inpcb),
				.xi_kind = XSO_INPCB,
				.xi_inpp = inode,
				.inp_fport = htons(remote_port),
				.inp_lport = htons(local_port),
				.inp_ppcb = tcp ? inode : 0,
				.inp_vflag
				= v6 ? DARWIN_INP_IPV6 : DARWIN_INP_IPV4,
				.inp_ip_ttl = list->ttl,
		};
		item->socket = (struct xnu_xsocket_n){
				.xso_len = sizeof(item->socket),
				.xso_kind = XSO_SOCKET,
				.xso_so = inode,
				.so_type
				= tcp ? DARWIN_SOCK_STREAM : DARWIN_SOCK_DGRAM,
				.so_options
				= listening ? DARWIN_SO_ACCEPTCONN : 0,
				.so_pcb = inode,
				.xso_protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP,
				.xso_family
				= v6 ? DARWIN_AF_INET6 : DARWIN_AF_INET,
				.so_qlen = listening ? (int16_t)receiving : 0,
				.so_uid = uid,
		};
		item->receive = (struct xnu_xsockbuf_n){
				.xsb_len = sizeof(item->receive),
				.xsb_kind = XSO_RCVBUF,
				.sb_cc
				= tcp && !listening ? (uint32_t)receiving : 0,
		};
		item->send = (struct xnu_xsockbuf_n){
				.xsb_len = sizeof(item->send),
				.xsb_kind = XSO_SNDBUF,
				.sb_cc = tcp ? (uint32_t)sending : 0,
		};
		item->stats.xst_len = sizeof(item->stats);
		item->stats.xst_kind = XSO_STATS;
		item->tcpcb.xt_len = sizeof(item->tcpcb);
		item->tcpcb.xt_kind = XSO_TCPCB;
		item->tcpcb.t_state = state <= TCP_CLOSING ? tcp_states[state]
							   : DARWIN_TCPS_CLOSED;
		pcblist_address(item->inpcb.inp_faddr, remote, v6);
		pcblist_address(item->inpcb.inp_laddr, local, v6);
	}
	fclose(file);
	return true;
}

static void
pcblist_address(uint32_t address[4], const char *hex, bool v6)
{
	if (v6) {
		sscanf(hex, "%8x%8x%8x%8x", &address[0], &address[1],
				&address[2], &address[3]);
	} else {
		sscanf(hex, "%8x", &address[3]);
	}
}

enum {
	TCPSTAT_SIZE = 912,
	TCPS_CONNATTEMPT = 0,
	TCPS_ACCEPTS = 4,
	TCPS_DROPS = 12,
	TCPS_CONNDROPS = 16,
	TCPS_SNDTOTAL = 60,
	TCPS_SNDREXMITPACK = 72,
	TCPS_RCVTOTAL = 100,
	TCPS_RCVBADSUM = 112,
};

enum {
	UDPSTAT_SIZE = 104,
	UDPS_IPACKETS = 0,
	UDPS_BADSUM = 8,
	UDPS_NOPORT = 16,
	UDPS_FULLSOCK = 24,
	UDPS_OPACKETS = 36,
};

enum {
	IPSTAT_SIZE = 196,
	IPS_TOTAL = 0,
	IPS_FRAGMENTS = 24,
	IPS_FRAGTIMEOUT = 32,
	IPS_FORWARD = 36,
	IPS_NOPROTO = 52,
	IPS_DELIVERED = 56,
	IPS_LOCALOUT = 60,
	IPS_ODROPPED = 64,
	IPS_REASSEMBLED = 68,
	IPS_FRAGMENTED = 72,
	IPS_OFRAGMENTS = 76,
	IPS_CANTFRAG = 80,
	IPS_NOROUTE = 88,
	IPS_BADADDR = 112,
};

struct snmp_counter {
	const char *name;
	size_t offset;
};

static void snmp_counters(const char *protocol,
		const struct snmp_counter *counters, size_t count,
		uint8_t *stats);
static int read_truncated(
		const void *value, size_t size, void *old, size_t *oldlenp);

static int
read_tcp_stats(void *old, size_t *oldlenp)
{
	static const struct snmp_counter counters[] = {
			{"ActiveOpens", TCPS_CONNATTEMPT},
			{"PassiveOpens", TCPS_ACCEPTS},
			{"EstabResets", TCPS_DROPS},
			{"AttemptFails", TCPS_CONNDROPS},
			{"OutSegs", TCPS_SNDTOTAL},
			{"RetransSegs", TCPS_SNDTOTAL},
			{"RetransSegs", TCPS_SNDREXMITPACK},
			{"InSegs", TCPS_RCVTOTAL},
			{"InCsumErrors", TCPS_RCVBADSUM},
	};
	uint8_t stats[TCPSTAT_SIZE] = {0};
	if (geteuid() == 0) {
		snmp_counters("Tcp", counters,
				sizeof(counters) / sizeof(counters[0]), stats);
	}
	return read_truncated(stats, sizeof(stats), old, oldlenp);
}

static int
read_udp_stats(void *old, size_t *oldlenp)
{
	static const struct snmp_counter counters[] = {
			{"InDatagrams", UDPS_IPACKETS},
			{"NoPorts", UDPS_IPACKETS},
			{"InErrors", UDPS_IPACKETS},
			{"InCsumErrors", UDPS_BADSUM},
			{"NoPorts", UDPS_NOPORT},
			{"RcvbufErrors", UDPS_FULLSOCK},
			{"OutDatagrams", UDPS_OPACKETS},
	};
	uint8_t stats[UDPSTAT_SIZE] = {0};
	snmp_counters("Udp", counters, sizeof(counters) / sizeof(counters[0]),
			stats);
	return read_truncated(stats, sizeof(stats), old, oldlenp);
}

static int
read_ip_stats(void *old, size_t *oldlenp)
{
	static const struct snmp_counter counters[] = {
			{"InReceives", IPS_TOTAL},
			{"ReasmReqds", IPS_FRAGMENTS},
			{"ReasmTimeout", IPS_FRAGTIMEOUT},
			{"ForwDatagrams", IPS_FORWARD},
			{"InUnknownProtos", IPS_NOPROTO},
			{"InDelivers", IPS_DELIVERED},
			{"OutRequests", IPS_LOCALOUT},
			{"OutDiscards", IPS_ODROPPED},
			{"ReasmOKs", IPS_REASSEMBLED},
			{"FragOKs", IPS_FRAGMENTED},
			{"FragCreates", IPS_OFRAGMENTS},
			{"FragFails", IPS_CANTFRAG},
			{"OutNoRoutes", IPS_NOROUTE},
			{"InAddrErrors", IPS_BADADDR},
	};
	uint8_t stats[IPSTAT_SIZE] = {0};
	snmp_counters("Ip", counters, sizeof(counters) / sizeof(counters[0]),
			stats);
	return read_truncated(stats, sizeof(stats), old, oldlenp);
}

static void
snmp_counters(const char *protocol, const struct snmp_counter *counters,
		size_t count, uint8_t *stats)
{
	FILE *file = fopen("/proc/net/snmp", "re");
	if (file == NULL) {
		return;
	}
	char names[2048], values[2048];
	size_t prefix = strlen(protocol);
	while (fgets(names, sizeof(names), file) != NULL
			&& fgets(values, sizeof(values), file) != NULL) {
		if (strncmp(names, protocol, prefix) != 0
				|| names[prefix] != ':') {
			continue;
		}
		char *next_name, *next_value;
		char *name = strtok_r(names + prefix + 1, " \n", &next_name);
		char *value = strtok_r(values + prefix + 1, " \n", &next_value);
		while (name != NULL && value != NULL) {
			for (size_t i = 0; i < count; i++) {
				if (strcmp(name, counters[i].name) != 0) {
					continue;
				}
				uint32_t sum;
				uint8_t *counter = stats + counters[i].offset;
				memcpy(&sum, counter, sizeof(sum));
				sum += (uint32_t)strtoull(value, NULL, 10);
				memcpy(counter, &sum, sizeof(sum));
			}
			name = strtok_r(NULL, " \n", &next_name);
			value = strtok_r(NULL, " \n", &next_value);
		}
		break;
	}
	fclose(file);
}

static int
read_truncated(const void *value, size_t size, void *old, size_t *oldlenp)
{
	if (old != NULL) {
		size = size < *oldlenp ? size : *oldlenp;
		memcpy(old, value, size);
	}
	*oldlenp = size;
	return 0;
}

static int
read_ip_ttl(void *old, size_t *oldlenp)
{
	return read_number(default_ttl(), sizeof(int32_t), old, oldlenp);
}

static int
default_ttl(void)
{
	int ttl = IPDEFTTL;
	FILE *file = fopen("/proc/sys/net/ipv4/ip_default_ttl", "re");
	if (file != NULL) {
		fscanf(file, "%d", &ttl);
		fclose(file);
	}
	return ttl;
}

static int
read_pressure_level(void *old, size_t *oldlenp)
{
	return read_number(memorystatus_level(), sizeof(int32_t), old, oldlenp);
}

static int
read_cpusubtype(void *old, size_t *oldlenp)
{
	return read_number(shared_cache_cpu_subtype, sizeof(int32_t), old,
			oldlenp);
}

static int
read_bytes(const void *value, size_t size, void *old, size_t *oldlenp)
{
	if (old == NULL) {
		*oldlenp = size;
		return 0;
	}

	if (*oldlenp < size) {
		memcpy(old, value, *oldlenp);
		return _ENOMEM;
	}

	memcpy(old, value, size);
	*oldlenp = size;
	return 0;
}

static int
read_number(int64_t value, size_t size, void *old, size_t *oldlenp)
{
	if (size == sizeof(int64_t) && old != NULL
			&& *oldlenp == sizeof(int32_t)) {
		int32_t narrowed = value;
		return read_bytes(&narrowed, sizeof(narrowed), old, oldlenp);
	}

	if (size == sizeof(int32_t)) {
		int32_t narrowed = value;
		return read_bytes(&narrowed, sizeof(narrowed), old, oldlenp);
	}
	return read_bytes(&value, sizeof(value), old, oldlenp);
}
