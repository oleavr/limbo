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
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "handler.h"
#include "process.h"
#include "shared_cache.h"
#include "xnu-errno.h"

#ifdef __arm64__
#define HOST_CPU_TYPE CPU_TYPE_ARM64
#define HOST_MACHINE  "arm64"
#define HOST_MODEL    "Mac17,2"
#else
#define HOST_CPU_TYPE CPU_TYPE_X86_64
#define HOST_MACHINE  "x86_64"
#define HOST_MODEL    "MacPro7,1"
#endif

#define CTL_UNSPEC 0
#define CTL_KERN   1
#define CTL_HW     6

#define CTL_SYSCTL_NAME2OID 3

#define KERN_OSTYPE     1
#define KERN_OSRELEASE  2
#define KERN_OSREV      3
#define KERN_VERSION    4
#define KERN_ARGMAX     8
#define KERN_SECURELVL  9
#define KERN_HOSTNAME   10
#define KERN_PROC       14
#define KERN_BOOTTIME   21
#define KERN_USRSTACK64 59
#define KERN_OSVERSION  65

#define KERN_PROC_PID 1

#define SRUN   2
#define P_LP64 0x4
#define NODEV  -1

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
static int read_ncpu(void *old, size_t *oldlenp);
static int read_memsize(void *old, size_t *oldlenp);
static int read_cpusubtype(void *old, size_t *oldlenp);

static const struct sysctl_node nodes[] = {
		{"kern.ostype", {CTL_KERN, KERN_OSTYPE}, SYSCTL_STRING,
				.string = "Darwin"},
		{"kern.osrelease", {CTL_KERN, KERN_OSRELEASE}, SYSCTL_STRING,
				.string = "27.0.0"},
		{"kern.osrevision", {CTL_KERN, KERN_OSREV}, SYSCTL_INT,
				.number = 199506},
		{"kern.version", {CTL_KERN, KERN_VERSION}, SYSCTL_STRING,
				.string
				= "Darwin Kernel Version 27.0.0: Tue Aug 11 "
				  "21:02:59 PDT 2026; "
				  "root:xnu-13432.1.9~1/RELEASE_X86_64"},
		{"kern.argmax", {CTL_KERN, KERN_ARGMAX}, SYSCTL_INT,
				.number = 1048576},
		{"kern.securelevel", {CTL_KERN, KERN_SECURELVL}, SYSCTL_INT,
				.number = 0},
		{"kern.hostname", {CTL_KERN, KERN_HOSTNAME}, SYSCTL_READER,
				.reader = read_hostname},
		{"kern.boottime", {CTL_KERN, KERN_BOOTTIME}, SYSCTL_READER,
				.reader = read_boottime},
		{"kern.usrstack64", {CTL_KERN, KERN_USRSTACK64}, SYSCTL_QUAD,
				.number = (int64_t)VM_USRSTACK64},
		{"kern.osversion", {CTL_KERN, KERN_OSVERSION}, SYSCTL_STRING,
				.string = "26A428"},
		{"kern.bootargs", {0, 0}, SYSCTL_STRING, .string = ""},
		{"kern.bootsessionuuid", {0, 0}, SYSCTL_READER,
				.reader = read_bootsessionuuid},
		{"kern.osproductversion", {0, 0}, SYSCTL_STRING,
				.string = "27.0"},
		{"kern.secure_kernel", {0, 0}, SYSCTL_INT, .number = 0},
		{"hw.machine", {CTL_HW, HW_MACHINE}, SYSCTL_STRING,
				.string = HOST_MACHINE},
		{"hw.model", {CTL_HW, HW_MODEL}, SYSCTL_STRING,
				.string = HOST_MODEL},
#ifdef __arm64__
		{"hw.product", {0, 0}, SYSCTL_STRING, .string = HOST_MODEL},
		{"hw.target", {0, 0}, SYSCTL_STRING, .string = "J704AP"},
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
		{"hw.cputype", {0, 0}, SYSCTL_INT, .number = HOST_CPU_TYPE},
		{"hw.cpusubtype", {0, 0}, SYSCTL_READER,
				.reader = read_cpusubtype},
		{"hw.cpu64bit_capable", {0, 0}, SYSCTL_INT, .number = 1},
		{"security.mac.lockdown_mode_state", {0, 0}, SYSCTL_INT,
				.number = 0},
};

static int read_kinfo_proc(int32_t pid, void *old, size_t *oldlenp);
static const struct sysctl_node *lookup_oid(const int *name, uint32_t namelen);
static int name2oid(
		const char *name, size_t namelen, void *old, size_t *oldlenp);
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

	const struct sysctl_node *node = lookup_oid(name, namelen);
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
			.e_tdev = NODEV,
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
		fprintf(stderr, "  sysctl: setting %.*s ignored\n", (int)namelen,
				name);
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
read_boottime(void *old, size_t *oldlenp)
{
	struct timespec now, uptime;
	clock_gettime(CLOCK_REALTIME, &now);
	clock_gettime(CLOCK_BOOTTIME, &uptime);

	int64_t boot_ns = (now.tv_sec - uptime.tv_sec) * 1000000000LL
			+ (now.tv_nsec - uptime.tv_nsec);
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

static int
read_memsize(void *old, size_t *oldlenp)
{
	int64_t memsize = (int64_t)sysconf(_SC_PHYS_PAGES) * PAGE_SIZE;
	return read_number(memsize, sizeof(int64_t), old, oldlenp);
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
