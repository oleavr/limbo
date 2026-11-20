/*
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

#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
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

#define EXCLAVES_STATUS_NOT_SUPPORTED 0xff

#ifndef PROC_PIDREGIONPATHINFO2
#define PROC_PIDREGIONPATHINFO2 22
#endif
#ifndef PROC_PIDVMRTFAULTINFO
#define PROC_PIDVMRTFAULTINFO 29
#endif
#ifndef PROC_PIDORIGINATOR_UUID
#define PROC_PIDORIGINATOR_UUID    1
#define PROC_PIDORIGINATOR_BGSTATE 2
#endif

int proc_get_cpumon_params(pid_t pid, int *percentage, int *interval);
int proc_pidoriginatorinfo(int flavor, void *buffer, int buffersize);

static void check_main_thread_gone(void);
static void check_sysctl_walk(void);
static void check_structure(const char *name, const char *format);
static void check_pipe_info(void);
static void check_kqueue_info(void);
static void check_workqueue(void);
static void signal_done(void *done);

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
	CHECK(sysconf(_SC_NGROUPS_MAX) == NGROUPS_MAX);
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

	int ttl_mib[4] = {CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DEFTTL};
	int ttl = 0, named = 0;
	size = sizeof(ttl);
	CHECK(sysctl(ttl_mib, 4, &ttl, &size, NULL, 0) == 0 && ttl > 0);
	size = sizeof(named);
	CHECK(sysctlbyname("net.inet.ip.ttl", &named, &size, NULL, 0) == 0);
	CHECK(named == ttl);

	int pressure = 0;
	size = sizeof(pressure);
	CHECK(sysctlbyname("kern.memorystatus_vm_pressure_level", &pressure,
			      &size, NULL, 0)
			== 0);
	CHECK(pressure == 1 || pressure == 2 || pressure == 4);

	int exclaves = 0;
	size = sizeof(exclaves);
	CHECK(sysctlbyname("kern.exclaves_status", &exclaves, &size, NULL, 0)
			== 0);
	CHECK(exclaves == EXCLAVES_STATUS_NOT_SUPPORTED);

	int check_openevt = -1;
	size = sizeof(check_openevt);
	CHECK(sysctlbyname("kern.check_openevt", &check_openevt, &size, NULL, 0)
			== 0);
	CHECK(check_openevt == 0);

	int footprint = -1;
	size = sizeof(footprint);
	CHECK(sysctlbyname("vm.self_region_footprint", &footprint, &size, NULL,
			      0)
			== 0);
	CHECK(footprint == 0);

	struct proc_vnodepathinfo vnodes;
	CHECK(proc_pidinfo(getpid(), PROC_PIDVNODEPATHINFO, 0, &vnodes,
			      sizeof(vnodes))
			== sizeof(vnodes));
	char cwd[PATH_MAX];
	CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
	CHECK(strcmp(vnodes.pvi_cdir.vip_path, cwd) == 0);

	struct proc_regionwithpathinfo mapped;
	CHECK(proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO2, 0, &mapped,
			      sizeof(mapped))
			== sizeof(mapped));
	CHECK(mapped.prp_vip.vip_path[0] == '/');
	CHECK(proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO2, UINT64_MAX,
			      &mapped, sizeof(mapped))
			<= 0);

	struct proc_regioninfo region;
	uint64_t code = (uint64_t)(uintptr_t)main;
	CHECK(proc_pidinfo(getpid(), PROC_PIDREGIONINFO, code, &region,
			      sizeof(region))
			== sizeof(region));
	CHECK(region.pri_address <= code
			&& code < region.pri_address + region.pri_size);
	CHECK(region.pri_protection == (VM_PROT_READ | VM_PROT_EXECUTE));
	CHECK(proc_pidinfo(getpid(), PROC_PIDREGIONINFO, UINT64_MAX, &region,
			      sizeof(region))
			<= 0);

	check_main_thread_gone();
	check_sysctl_walk();
	check_structure("vm.loadavg", "S,loadavg");
	check_structure("vm.swapusage", "S,xsw_usage");
	check_pipe_info();
	check_kqueue_info();
	check_workqueue();

	int value = -1;
	size = sizeof(value);
	CHECK(sysctlbyname("kern.safeboot", &value, &size, NULL, 0) == 0
			&& value == 0);
	value = -1;
	CHECK(sysctlbyname("security.mac.amfi.qa_root_certs_allowed", &value,
			      &size, NULL,
			      0) == 0
			&& value == 0);
	value = -1;
	CHECK(sysctlbyname("vfs.generic.root_unmounted_cleanly", &value, &size,
			      NULL, 0) == 0
			&& value == 1);

	struct kinfo_proc info;
	size = sizeof(info);
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
	CHECK(sysctl(mib, 4, &info, &size, NULL, 0) == 0);
	CHECK(size == sizeof(info));
	CHECK(info.kp_proc.p_pid == getpid());
	CHECK(info.kp_eproc.e_ppid == getppid());
	CHECK(strcmp(info.kp_proc.p_comm, "sysinfo") == 0);
	CHECK(((info.kp_proc.p_flag & P_CONTROLT) != 0)
			== (info.kp_eproc.e_tdev != NODEV));

	int lists[][4] = {
			{CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0},
			{CTL_KERN, KERN_PROC, KERN_PROC_UID, (int)geteuid()},
			{CTL_KERN, KERN_PROC, KERN_PROC_RUID, (int)getuid()},
			{CTL_KERN, KERN_PROC, KERN_PROC_PGRP, getpgrp()},
	};
	static struct kinfo_proc procs[4096];
	for (size_t l = 0; l < sizeof(lists) / sizeof(lists[0]); l++) {
		u_int length = lists[l][2] == KERN_PROC_ALL ? 3 : 4;
		size = 0;
		CHECK(sysctl(lists[l], length, NULL, &size, NULL, 0) == 0);
		CHECK(size >= sizeof(procs[0]) && size % sizeof(procs[0]) == 0);
		size = sizeof(procs);
		CHECK(sysctl(lists[l], length, procs, &size, NULL, 0) == 0);
		CHECK(size >= sizeof(procs[0]) && size % sizeof(procs[0]) == 0);
		bool listed = false;
		for (size_t i = 0; i < size / sizeof(procs[0]); i++) {
			listed = listed || procs[i].kp_proc.p_pid == getpid();
		}
		CHECK(listed);
	}
	size = sizeof(procs[0]);
	CHECK(sysctl(lists[0], 3, procs, &size, NULL, 0) == -1
			&& errno == ENOMEM);
	CHECK(size == sizeof(procs[0]));

	struct proc_bsdinfo bsdinfo;
	CHECK(proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &bsdinfo,
			      sizeof(bsdinfo))
			== sizeof(bsdinfo));
	CHECK(bsdinfo.pbi_pid == (uint32_t)getpid());
	CHECK(bsdinfo.pbi_uid == geteuid());
	CHECK(bsdinfo.pbi_nfiles > (uint32_t)STDERR_FILENO);

	int fds_size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
	CHECK(fds_size > 0);
	struct proc_fdinfo fds[256];
	fds_size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
	CHECK(fds_size > 0 && fds_size % (int)sizeof(fds[0]) == 0);
	bool found = false;
	for (int i = 0; i < fds_size / (int)sizeof(fds[0]); i++) {
		found = found || fds[i].proc_fd == STDERR_FILENO;
	}
	CHECK(found);
	uint8_t faults[4096];
	CHECK(proc_pidinfo(getpid(), PROC_PIDVMRTFAULTINFO, 0, faults,
			      sizeof(faults))
			== 0);

	char name[64];
	CHECK(proc_name(getpid(), name, sizeof(name)) > 0);
	CHECK(strcmp(name, "sysinfo") == 0);
	CHECK(pthread_setname_np("main-thread") == 0);
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
	CHECK(host_set_multiuser_config_flags(mach_host_self(), 0)
			== KERN_NOT_SUPPORTED);

	int msgbuf_size = 0;
	size = sizeof(msgbuf_size);
	CHECK(sysctlbyname("kern.msgbuf", &msgbuf_size, &size, NULL, 0) == 0);
	CHECK(msgbuf_size > 0);
	static char messages[256 * 1024];
	errno = 0;
	int given = proc_kmsgbuf(messages, sizeof(messages));
	if (geteuid() != 0) {
		CHECK(given == 0 && errno == EPERM);
	} else {
		CHECK(given >= 2 && messages[given - 1] == '\0'
				&& messages[given - 2] == '\n');
	}

#ifdef __x86_64__
	uint64_t capabilities = *(volatile uint64_t *)0x7fffffe00010ULL;
	CHECK((capabilities & 0x204) == 0x204);
	CHECK((capabilities >> 16 & 0xff) > 0);
	CHECK(*(volatile uint32_t *)0x7fffffe00020ULL
			== (uint32_t)capabilities);
#endif

	int mib_hang[CTL_MAXNAME];
	size_t hang_length = CTL_MAXNAME;
	CHECK(sysctlnametomib("vfs.generic.noremotehang", mib_hang,
			      &hang_length)
			== 0);
	int pid = getpid();
	CHECK(sysctl(mib_hang, (u_int)hang_length, NULL, NULL, &pid,
			      sizeof(pid))
			== 0);

	int percentage = -1, interval = -1;
	CHECK(proc_get_cpumon_params(getpid(), &percentage, &interval) == 0);
	CHECK(percentage == 0 && interval == 0);
	errno = 0;
	CHECK(proc_get_cpumon_params(99998, &percentage, &interval) == -1
			&& errno == ESRCH);

	uint32_t backgrounded = 1;
	CHECK(proc_pidoriginatorinfo(PROC_PIDORIGINATOR_BGSTATE, &backgrounded,
			      sizeof(backgrounded))
			== sizeof(backgrounded));
	CHECK(backgrounded == 0);
	uuid_t originator;
	errno = 0;
	CHECK(proc_pidoriginatorinfo(PROC_PIDORIGINATOR_UUID, originator,
			      sizeof(originator))
					== 0
			&& errno == EINVAL);

	CHECK(labs(time(NULL) - info.kp_proc.p_starttime.tv_sec) < 60);

	double loads[3] = {-1, -1, -1};
	CHECK(getloadavg(loads, 3) == 3);
	CHECK(loads[0] >= 0 && loads[1] >= 0 && loads[2] >= 0);
	host_load_info_data_t load;
	mach_msg_type_number_t load_count = HOST_LOAD_INFO_COUNT;
	CHECK(host_statistics(mach_host_self(), HOST_LOAD_INFO,
			      (host_info_t)&load, &load_count)
			== KERN_SUCCESS);
	CHECK(load.avenrun[0] >= 0 && load.mach_factor[0] >= 0);

	vm_statistics64_data_t vm;
	mach_msg_type_number_t vm_count = HOST_VM_INFO64_COUNT;
	CHECK(host_statistics64(mach_host_self(), HOST_VM_INFO64,
			      (host_info64_t)&vm, &vm_count)
			== KERN_SUCCESS);
	uint64_t pages = (uint64_t)vm.free_count + vm.active_count
			+ vm.inactive_count + vm.wire_count;
	CHECK(pages > 0);
	CHECK(pages * (uint64_t)getpagesize() <= (uint64_t)memsize);
	CHECK(vm.wire_count > 0);
	CHECK(vm.internal_page_count + vm.external_page_count > 0);

	processor_set_t set;
	CHECK(host_processor_set_priv(mach_host_self(), MACH_PORT_NULL, &set)
			== KERN_INVALID_ARGUMENT);
	processor_set_name_array_t sets;
	mach_msg_type_number_t set_count;
	if (host_processor_sets(mach_host_self(), &sets, &set_count)
			== KERN_SUCCESS) {
		CHECK(host_processor_set_priv(mach_host_self(), sets[0], &set)
				== (geteuid() == 0 ? KERN_SUCCESS
						   : KERN_INVALID_ARGUMENT));
	}
	return 0;
}

static void *
linger(void *arg)
{
	for (;;) {
		pause();
	}
	return arg;
}

static void
check_main_thread_gone(void)
{
	int ready[2];
	CHECK(pipe(ready) == 0);
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		pthread_t thread;
		CHECK(pthread_create(&thread, NULL, linger, NULL) == 0);
		close(ready[1]);
		pthread_exit(NULL);
	}
	close(ready[1]);
	char byte;
	CHECK(read(ready[0], &byte, 1) == 0);
	close(ready[0]);
	usleep(200000);

	struct proc_fdinfo fds[256];
	int fds_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
	struct proc_vnodepathinfo paths;
	memset(&paths, 0, sizeof(paths));
	int paths_size = proc_pidinfo(
			pid, PROC_PIDVNODEPATHINFO, 0, &paths, sizeof(paths));
	CHECK(kill(pid, SIGKILL) == 0);

	CHECK(fds_size > 0);
	bool found = false;
	for (int i = 0; i < fds_size / (int)sizeof(fds[0]); i++) {
		found = found || fds[i].proc_fd == STDERR_FILENO;
	}
	CHECK(found);
	CHECK(paths_size == sizeof(paths));
	CHECK(paths.pvi_cdir.vip_path[0] == '/');

	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
}

static void
check_sysctl_walk(void)
{
	int walk[2 + CTL_MAXNAME] = {CTL_UNSPEC, 2, CTL_KERN};
	u_int walk_length = 3, visited = 0;
	bool saw_ostype = false;
	for (;;) {
		int next[CTL_MAXNAME];
		size_t size = sizeof(next);
		if (sysctl(walk, walk_length, next, &size, NULL, 0) != 0) {
			break;
		}
		u_int length = 2 + (u_int)(size / sizeof(int));
		int name_oid[2 + CTL_MAXNAME] = {CTL_UNSPEC, 1};
		memcpy(name_oid + 2, next, size);
		char name[128];
		size_t name_size = sizeof(name);
		CHECK(sysctl(name_oid, length, name, &name_size, NULL, 0) == 0);
		saw_ostype |= strcmp(name, "kern.ostype") == 0;
		memcpy(walk + 2, next, size);
		walk_length = length;
		CHECK(++visited < 10000);
	}
	CHECK(errno == ENOENT);
	CHECK(visited > 20 && saw_ostype);
}

static void
check_structure(const char *name, const char *format)
{
	int oid[2 + CTL_MAXNAME] = {CTL_UNSPEC, 4};
	size_t length = CTL_MAXNAME;
	CHECK(sysctlnametomib(name, oid + 2, &length) == 0);
	struct {
		uint32_t kind;
		char format[60];
	} description;
	size_t size = sizeof(description);
	CHECK(sysctl(oid, 2 + (u_int)length, &description, &size, NULL, 0)
			== 0);
	CHECK((description.kind & CTLTYPE) == CTLTYPE_STRUCT);
	CHECK(strcmp(description.format, format) == 0);
}

static void
check_pipe_info(void)
{
	int ends[2];
	CHECK(pipe(ends) == 0);
	struct pipe_fdinfo reader, writer;
	CHECK(proc_pidfdinfo(getpid(), ends[0], PROC_PIDFDPIPEINFO, &reader,
			      sizeof(reader))
			== sizeof(reader));
	CHECK(proc_pidfdinfo(getpid(), ends[1], PROC_PIDFDPIPEINFO, &writer,
			      sizeof(writer))
			== sizeof(writer));
	CHECK(reader.pfi.fi_type == PROX_FDTYPE_PIPE);
	CHECK(reader.pfi.fi_openflags == FREAD);
	CHECK(writer.pfi.fi_openflags == FWRITE);
	CHECK(S_ISFIFO(reader.pipeinfo.pipe_stat.vst_mode));
	CHECK(reader.pipeinfo.pipe_handle != writer.pipeinfo.pipe_handle);
	CHECK(reader.pipeinfo.pipe_peerhandle == writer.pipeinfo.pipe_handle);
	CHECK(writer.pipeinfo.pipe_peerhandle == reader.pipeinfo.pipe_handle);
	CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);

	int kq = kqueue();
	CHECK(kq >= 0);
	errno = 0;
	CHECK(proc_pidfdinfo(getpid(), kq, PROC_PIDFDPIPEINFO, &reader,
			      sizeof(reader))
			== 0);
	CHECK(errno == EBADF);
	CHECK(close(kq) == 0);
}

static void
check_kqueue_info(void)
{
	int kq = kqueue();
	CHECK(kq >= 0);
	struct kqueue_fdinfo info;
	CHECK(proc_pidfdinfo(getpid(), kq, PROC_PIDFDKQUEUEINFO, &info,
			      sizeof(info))
			== sizeof(info));
	CHECK(info.pfi.fi_type == PROX_FDTYPE_KQUEUE);
	CHECK(info.pfi.fi_openflags == (FREAD | FWRITE));
	CHECK(S_ISFIFO(info.kqueueinfo.kq_stat.vst_mode));
	CHECK(info.kqueueinfo.kq_stat.vst_blksize == sizeof(struct kevent));
	errno = 0;
	CHECK(proc_pidfdinfo(getpid(), STDERR_FILENO, PROC_PIDFDKQUEUEINFO,
			      &info, sizeof(info))
			== 0);
	CHECK(errno == EBADF);
	CHECK(close(kq) == 0);
}

static void
check_workqueue(void)
{
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	dispatch_async_f(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), done,
			signal_done);
	dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);

	struct proc_workqueueinfo info;
	CHECK(proc_pidinfo(getpid(), PROC_PIDWORKQUEUEINFO, 0, &info,
			      sizeof(info))
			== sizeof(info));
	CHECK(info.pwq_nthreads > 0);
	CHECK(info.pwq_runthreads + info.pwq_blockedthreads
			<= info.pwq_nthreads);
}

static void
signal_done(void *done)
{
	dispatch_semaphore_signal(done);
}
