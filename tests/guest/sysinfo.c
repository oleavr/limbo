/*
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

#include <libproc.h>
#include <mach/mach.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "check.h"

#ifdef __arm64__
#define HOST_CPU_TYPE CPU_TYPE_ARM64
#define HOST_MACHINE  "arm64"
#else
#define HOST_CPU_TYPE CPU_TYPE_X86_64
#define HOST_MACHINE  "x86_64"
#endif

int
main(void)
{
	char ostype[16];
	size_t size = sizeof(ostype);
	CHECK(sysctlbyname("kern.ostype", ostype, &size, NULL, 0) == 0);
	CHECK(strcmp(ostype, "Darwin") == 0);

	int ncpu;
	size = sizeof(ncpu);
	CHECK(sysctlbyname("hw.ncpu", &ncpu, &size, NULL, 0) == 0 && ncpu > 0);
	int64_t memsize;
	size = sizeof(memsize);
	CHECK(sysctlbyname("hw.memsize", &memsize, &size, NULL, 0) == 0);
	CHECK(memsize > 0);
	cpu_type_t cputype;
	size = sizeof(cputype);
	CHECK(sysctlbyname("hw.cputype", &cputype, &size, NULL, 0) == 0);
	CHECK(cputype == HOST_CPU_TYPE);
	char machine[32];
	size = sizeof(machine);
	CHECK(sysctlbyname("hw.machine", machine, &size, NULL, 0) == 0);
	CHECK(strcmp(machine, HOST_MACHINE) == 0);
#ifdef __arm64__
	char target[32];
	size = sizeof(target);
	CHECK(sysctlbyname("hw.target", target, &size, NULL, 0) == 0);
#endif

	struct kinfo_proc info;
	size = sizeof(info);
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
	CHECK(sysctl(mib, 4, &info, &size, NULL, 0) == 0);
	CHECK(size == sizeof(info));
	CHECK(info.kp_proc.p_pid == getpid());
	CHECK(info.kp_eproc.e_ppid == getppid());
	CHECK(strcmp(info.kp_proc.p_comm, "sysinfo") == 0);

	struct proc_bsdinfo bsdinfo;
	CHECK(proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &bsdinfo,
			      sizeof(bsdinfo))
			== sizeof(bsdinfo));
	CHECK(bsdinfo.pbi_pid == (uint32_t)getpid());
	CHECK(bsdinfo.pbi_uid == geteuid());
	char name[64];
	CHECK(proc_name(getpid(), name, sizeof(name)) > 0);
	CHECK(strcmp(name, "sysinfo") == 0);

	struct utsname uts;
	CHECK(uname(&uts) == 0 && strcmp(uts.sysname, "Darwin") == 0);

	struct rlimit limit;
	CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur > 0);
	limit.rlim_cur = 64;
	CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
	CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur == 64);

	uuid_t uuid;
	struct timespec wait = {1, 0};
	CHECK(gethostuuid(uuid, &wait) == 0);
	CHECK(!uuid_is_null(uuid));

	host_basic_info_data_t basic;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
	CHECK(host_info(mach_host_self(), HOST_BASIC_INFO, (host_info_t)&basic,
			      &count)
			== KERN_SUCCESS);
	CHECK(basic.cpu_type == HOST_CPU_TYPE && basic.avail_cpus > 0);

	CHECK(labs(time(NULL) - info.kp_proc.p_starttime.tv_sec) < 60);
	return 0;
}
