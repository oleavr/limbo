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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <limits.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "commpage.h"
#include "cpuinfo.h"
#include "handler.h"
#include "net.h"
#include "process.h"
#include "route.h"
#include "shared_cache.h"
#include "sysroot.h"
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

#define VM_SWAPUSAGE 5

#define CTL_SYSCTL_NAME     1
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
#define KERN_BOOTTIME   21
#define KERN_MAXFILESPERPROC 29
#define KERN_USRSTACK64 59
#define KERN_OSVERSION  65
#define KERN_PROCARGS2  49

#define KERN_PROC_PID 1

#define SRUN   2
#define P_LP64 0x4

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
} sysctl_kind_t;

typedef int (*sysctl_reader_t)(void *old, size_t *oldlenp);

struct sysctl_node {
	const char *name;
	int oid[2];
	sysctl_kind_t kind;
	union {
		const char *string;
		int64_t number;
		sysctl_reader_t reader;
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
static int read_memsize(void *old, size_t *oldlenp);
#ifdef __x86_64__
static int read_cpu_brand(void *old, size_t *oldlenp);
static int read_cpu_cores(void *old, size_t *oldlenp);
static int read_cpu_packages(void *old, size_t *oldlenp);
static int read_cpu_frequency(void *old, size_t *oldlenp);
#endif
static int read_cpusubtype(void *old, size_t *oldlenp);
static int read_swapusage(void *old, size_t *oldlenp);

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
		{"kern.osversion", {CTL_KERN, KERN_OSVERSION}, SYSCTL_STRING,
				.string = "26A434"},
		{"kern.bootargs", {0, 0}, SYSCTL_STRING, .string = ""},
		{"kern.bootsessionuuid", {0, 0}, SYSCTL_READER,
				.reader = read_bootsessionuuid},
		{"kern.osproductversion", {0, 0}, SYSCTL_STRING,
				.string = "27.0.1"},
		{"kern.secure_kernel", {0, 0}, SYSCTL_INT, .number = 0},

		{"kern.iossupportversion", {0, 0}, SYSCTL_STRING,
				.string = "27.0"},

		{"kern.osvariant_status", {0, 0}, SYSCTL_QUAD,
				.number = (int64_t)8070732011310449290ULL},
		{"kern.willshutdown", {0, 0}, SYSCTL_INT, .number = 0},

		{"kern.wq_max_threads", {0, 0}, SYSCTL_INT, .number = 512},
		{"kern.wq_max_constrained_threads", {0, 0}, SYSCTL_INT,
				.number = 70},

		{"kern.memorystatus_vm_pressure_level", {0, 0}, SYSCTL_INT,
				.number = 1},
		{"vm.swapusage", {CTL_VM, VM_SWAPUSAGE}, SYSCTL_READER,
				.reader = read_swapusage},

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

		{"security.mac.sandbox.sentinel", {0, 0}, SYSCTL_READER,
				.reader = read_sandbox_sentinel},
};

static int read_kinfo_proc(int32_t pid, void *old, size_t *oldlenp);
static int read_procargs2(int32_t pid, void *old, size_t *oldlenp);
static const struct sysctl_node *lookup_oid(const int *name, uint32_t namelen);
static int name2oid(
		const char *name, size_t namelen, void *old, size_t *oldlenp);
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
#ifdef ENABLE_STRACE
	fprintf(stderr, "sysctl(%p, %p, %p, %p, %p, %p)\n", (void *)name,
			(void *)namelen, (void *)old, (void *)oldlenp,
			(void *)new, (void *)newlen);
#endif
	if (namelen == 2 && name[0] == CTL_UNSPEC
			&& name[1] == CTL_SYSCTL_NAME2OID) {
		return name2oid(new, newlen, old, oldlenp);
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

	if (new != NULL) {
#ifdef ENABLE_STRACE
		fprintf(stderr, "  sysctl: setting {%d, %d} ignored\n", name[0],
				namelen > 1 ? name[1] : 0);
#endif
		if (old == NULL) {
			return 0;
		}
	}

	if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC
			&& name[2] == KERN_PROC_PID) {
		return read_kinfo_proc(name[3], old, oldlenp);
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
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> Unknown sysctl:");
		for (uint32_t i = 0; i < namelen; i++) {
			fprintf(stderr, " %d", name[i]);
		}
		fprintf(stderr, "\n");
#endif
		return _ENOENT;
	}
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

	struct __darwin_kinfo_proc info = {
			.p_flag = P_LP64,
			.p_stat = SRUN,
			.p_pid = process.pid,
			.p_nice = process.nice,
			.p_ruid = process.uid[0],
			.p_svuid = process.uid[2],
			.p_rgid = process.gid[0],
			.p_svgid = process.gid[2],
			.cr_uid = process.uid[1],
			.cr_ngroups = 1,
			.cr_groups = {process.gid[1]},
			.e_ppid = process.ppid,
			.e_pgid = process.pgid,
			.e_tdev = process_terminal(&process),
			.e_tpgid = process.tpgid,
	};
	uint64_t sec, usec;
	process_start_time(&process, &sec, &usec);
	info.p_starttime.tv_sec = sec;
	info.p_starttime.tv_usec = usec;
	memcpy(info.p_comm, process.comm, sizeof(process.comm));
	return read_bytes(&info, sizeof(info), old, oldlenp);
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
		} else if (node->reader == read_hostname
				|| node->reader == read_bootsessionuuid
				|| node->reader == read_sandbox_sentinel) {
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
#ifdef ENABLE_STRACE
	fprintf(stderr, "sysctlbyname(\"%.*s\", %p, %p, %p, %p, %p)\n",
			(int)namelen, name, (void *)namelen, (void *)old,
			(void *)oldlenp, (void *)new, (void *)newlen);
#endif
	if (new != NULL) {
#ifdef ENABLE_STRACE
		fprintf(stderr, "  sysctl: setting {%d, %d} ignored\n", name[0],
				namelen > 1 ? name[1] : 0);
#endif
		if (old == NULL) {
			return 0;
		}
	}

	const struct sysctl_node *node = lookup_name(name, namelen);
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
#ifdef ENABLE_STRACE
	fprintf(stderr, ">> Unknown sysctl: %.*s\n", (int)namelen, name);
#endif
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
#ifdef ENABLE_STRACE
	fprintf(stderr, "  sysctl: %s\n", node->name);
#endif
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
	}
	unimplemented();
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
read_ncpu(void *old, size_t *oldlenp)
{
	return read_number(sysconf(_SC_NPROCESSORS_ONLN), sizeof(int32_t), old,
			oldlenp);
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
