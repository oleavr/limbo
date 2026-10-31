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

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/fsuid.h>
#include <sys/socket.h>
#ifdef __x86_64__
#include <asm/prctl.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/machine/thread_status.h>
#include <mach/mach.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/fs.h>
#include <sys/xattr.h>
#include <ucontext.h>
#include <unistd.h>

#include "bsd/credentials.h"
#include "bsd/hostuuid.h"
#include "commpage.h"
#include "fsevents.h"
#include "icmp.h"
#include "kctl.h"
#include "necp.h"
#include "net.h"
#include "persona.h"
#include "persona.h"
#include "route.h"
#include "signals.h"
#include "tty.h"
#include "fs/at.h"
#include "fs/bsd_flags.h"
#include "codesign.h"
#include "fs/fileid.h"
#include "handler.h"
#include "kevent.h"
#include "osfmk/broker_client.h"
#include "osfmk/ipc.h"
#include "osfmk/semaphore.h"
#include "shared_cache.h"
#include "signo.h"
#include "syscall.h"
#include "sysroot.h"
#include "thread.h"
#include "xnu-errno.h"

#define KAUTH_UID_NONE (~(uid_t)0 - 100)
#define KAUTH_GID_NONE (~(gid_t)0 - 100)

#define PT_DENY_ATTACH 31

#define _ACCESS_READ_MASK ((1 << 9) | (1 << 15) | (1 << 17) | (1 << 19))
#define _ACCESS_WRITE_MASK                                                     \
	((1 << 10) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 16) | (1 << 18) \
			| (1 << 20) | (1 << 21))
#define _ACCESS_EXECUTE_MASK (1 << 11)

static __thread unsigned long current_syscall;

static sem_t *semaphore(void *handle);
static uint32_t interface_of(const struct sockaddr_storage *address);
static int host_unix_address(const void *name, socklen_t length,
		struct sockaddr_un *linux_address, int *directory);

int
sys_nosys(void)
{
	fprintf(stderr, "limbo: system call %#lx is not implemented\n",
			current_syscall);
	unimplemented();
}

#define KAUTH_EXTLOOKUP_REGISTER 0
#define KAUTH_EXTLOOKUP_RESULT (1 << 0)
#define KAUTH_EXTLOOKUP_WORKER (1 << 1)
#define KAUTH_EXTLOOKUP_DEREGISTER (1 << 2)
#define KAUTH_GET_CACHE_SIZES (1 << 3)
#define KAUTH_SET_CACHE_SIZES (1 << 4)
#define KAUTH_CLEAR_CACHES (1 << 5)

int
sys_identitysvc(int opcode, void *message)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "identitysvc(%#x, %p)\n", opcode, message);
#endif
	switch (opcode) {
	case KAUTH_GET_CACHE_SIZES:

		if (message != NULL) {
			uint32_t sizes[2] = { 0, 0 };
			memcpy(message, sizes, sizeof(sizes));
		}
		return 0;
	case KAUTH_SET_CACHE_SIZES:
	case KAUTH_CLEAR_CACHES:
	case KAUTH_EXTLOOKUP_DEREGISTER:
		return 0;
	case KAUTH_EXTLOOKUP_REGISTER:
	case KAUTH_EXTLOOKUP_RESULT:
	case KAUTH_EXTLOOKUP_WORKER:
	default:

		if (select(0, NULL, NULL, NULL, NULL) < 0 && errno == EINTR) {
			return _EINTR;
		}
		return _EINTR;
	}
}

int
sys_necp_open(int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "necp_open(%p)\n", (void *)flags);
#endif
	return necp_open(flags);
}

int
sys_necp_session_open(int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "necp_session_open(%p)\n", (void *)flags);
#endif
	return necp_session_open(flags);
}

long
sys_necp_session_action(int fd, uint32_t action, uint8_t *in, size_t in_length,
		uint8_t *out, size_t out_length)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "necp_session_action(%p, %u, %p, %p, %p, %p)\n",
			(void *)fd, action, (void *)in, (void *)in_length,
			(void *)out, (void *)out_length);
#endif
	return necp_session_action(fd, action, in, in_length, out, out_length);
}

long
sys_necp_client_action(int fd, uint32_t action, uint8_t *client_id,
		size_t client_id_len, uint8_t *buffer, size_t buffer_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "necp_client_action(%p, %u, %p, %p, %p, %p)\n",
			(void *)fd, action, client_id, (void *)client_id_len,
			buffer, (void *)buffer_size);
#endif
	return necp_client_action(fd, action, client_id, client_id_len, buffer,
			buffer_size);
}

int
sys_enosys(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "enosys(%#lx)\n", current_syscall);
#endif
	return _ENOSYS;
}

int __attribute__((noreturn)) sys_exit(int rval)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "exit(%#x)\n", rval);
#endif
	_exit(rval);
}

int
sys_fork(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fork()\n");
#endif
	pid_t parent = getpid();
	pid_t pid = fork();
	if (pid == -1) {
		return err_map(errno);
	}
	if (pid == 0) {
		syscall_dispatch_enable();
		broker_client_reset();
		signals_fork_child();
	}
	syscall_set_rdx(pid == 0);
	return (pid == 0) ? parent : pid;
}

user_ssize_t
sys_read(int fd, user_addr_t cbuf, user_size_t nbyte)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "read(%p, %p, %p)\n", (void *)fd, (void *)cbuf,
			(void *)nbyte);
#endif
	if (net_is_bpf(fd)) {
		return net_bpf_read(fd, cbuf, nbyte);
	}
	if (fsevents_is_watcher(fd)) {
		return fsevents_read(fd, cbuf, nbyte);
	}
	return errno_map(read(fd, cbuf, nbyte));
}

user_ssize_t
sys_write(int fd, user_addr_t cbuf, user_size_t nbyte)
{
#ifdef ENABLE_STRACE
	/* Do not clutter output on stdout and stderr */
	if (fd != 1 && fd != 2) {
		fprintf(stderr, "write(%p, %p, %p)\n", (void *)fd, (void *)cbuf,
				(void *)nbyte);
	}
#endif
	if (route_is_socket(fd)) {
		return route_write(fd, cbuf, nbyte);
	}
	return errno_map(write(fd, cbuf, nbyte));
}

#define _O_RDONLY    0x0000
#define _O_WRONLY    0x0001
#define _O_RDWR      0x0002
#define _O_NONBLOCK  0x00000004
#define _O_APPEND    0x00000008
#define _O_SHLOCK    0x00000010
#define _O_EXLOCK    0x00000020
#define _O_ASYNC     0x00000040
#define _O_FSYNC     0x00000080
#define _O_NOFOLLOW  0x00000100
#define _O_CREAT     0x00000200
#define _O_TRUNC     0x00000400
#define _O_EXCL      0x00000800
#define _O_DIRECTORY 0x00100000
#define _O_SYMLINK   0x00200000
#define _O_CLOEXEC   0x01000000

static int open_follow(int flags);
static int fpathconf_value(int fd, int name);
static short poll_events_to_linux(short events);
static short poll_events_from_linux(short events);
static struct timeval *convert_timevals(
		const void *tptr, struct timeval *times);
static unsigned int rename_flags(uint32_t flags);
static int clone_file(int src_fd, int dst_dirfd, const char *dst_host,
		uint32_t flags);

#define _CLONE_NOFOLLOW     0x0001
#define _CLONE_NOOWNERCOPY  0x0002
static int rlimit_resource(uint32_t which);
static uint64_t rlimit_to_darwin(rlim_t value);
static rlim_t rlimit_from_darwin(uint64_t value);
static int wait_status(int status);
static int wait_options(int options);
static int translate_domain(int domain);
static socklen_t translate_to_host_sockaddr(const void *guest, socklen_t len,
		struct sockaddr_storage *host);
static void translate_to_guest_sockaddr(
		struct sockaddr_storage *addr, socklen_t len);
static int translate_msg_flags(int flags);
static bool translate_sockopt(
		int level, int name, int *host_level, int *host_name);
static int keep_bsd_flags(int fd, int flags);

int
sys_open(user_addr_t path, int flags, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "open(\"%s\", %p, %p)\n", (char *)path, (void *)flags,
			(void *)mode);
#endif
	if (path == NULL) {
		return _EFAULT;
	}
	if (net_is_bpf_path(path)) {
		return net_bpf_open(flags & _O_NONBLOCK, flags & _O_CLOEXEC);
	}
	if (fsevents_is_device_path(path)) {
		return fsevents_open(flags & _O_CLOEXEC);
	}
	char buffer[PATH_MAX];
	return errno_map(open(
			sysroot_host_path(path, open_follow(flags), buffer),
			open_flags(flags), mode));
}

static int
open_follow(int flags)
{
	return (flags & (_O_NOFOLLOW | _O_SYMLINK | _O_EXCL))
			? AT_SYMLINK_NOFOLLOW
			: 0;
}

int
open_flags(int flags)
{
	int cflags = O_NOCTTY;
	if (flags & _O_RDONLY)
		cflags |= O_RDONLY;
	if (flags & _O_WRONLY)
		cflags |= O_WRONLY;
	if (flags & _O_RDWR)
		cflags |= O_RDWR;
	if (flags & _O_NONBLOCK)
		cflags |= O_NONBLOCK;
	if (flags & _O_APPEND)
		cflags |= O_APPEND;
	/* TODO: Not supported */
	/* if (flags & _O_SHLOCK)
		cflags |= O_SHLOCK;
	if (flags & _O_EXLOCK)
		cflags |= O_EXLOCK; */
	if (flags & _O_ASYNC)
		cflags |= O_ASYNC;
	if (flags & _O_FSYNC)
		cflags |= O_FSYNC;
	if (flags & _O_NOFOLLOW)
		cflags |= O_NOFOLLOW;
	if (flags & _O_CREAT)
		cflags |= O_CREAT;
	if (flags & _O_TRUNC)
		cflags |= O_TRUNC;
	if (flags & _O_EXCL)
		cflags |= O_EXCL;
	if (flags & _O_DIRECTORY)
		cflags |= O_DIRECTORY;
	/* TODO: Not supported */
	/* if (flags & _O_SYMLINK)
		cflags |= O_SYMLINK; */
	if (flags & _O_CLOEXEC)
		cflags |= O_CLOEXEC;
	return cflags;
}

int
sys_sys_close(int fd)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_close(%p)\n", (void *)fd);
#endif
	kevent_close(fd);
	net_close(fd);
	route_close(fd);
	kctl_close(fd);
	icmp_close(fd);
	fsevents_close(fd);
	necp_close(fd);
	return errno_map(close(fd));
}

int
sys_wait4(int pid, user_addr_t status, int options, user_addr_t rusage)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "wait4(%p, %p, %p, %p)\n", (void *)pid, (void *)status,
			(void *)options, (void *)rusage);
#endif
	struct rusage usage;
	int result = wait4(pid, status, wait_options(options), &usage);
	if (result == -1) {
		return err_map(errno);
	}

	if (rusage != NULL) {
		usage.ru_maxrss *= 1024;
		memcpy(rusage, &usage, sizeof(usage));
	}
	if (status != NULL) {
		*(int *)status = wait_status(*(int *)status);
	}
	return result;
}

#define _WCONTINUED 0x10
#define _WNOWAIT    0x20

static int
wait_status(int status)
{
	if (WIFSIGNALED(status)) {
		return (status & ~0x7f) | signo_from_linux(WTERMSIG(status));
	}
	if (WIFSTOPPED(status)) {
		return (status & ~0xff00)
				| (signo_from_linux(WSTOPSIG(status)) << 8);
	}
	return status;
}

static int
wait_options(int options)
{
	int result = options & (WNOHANG | WUNTRACED);
	if (options & _WCONTINUED) {
		result |= WCONTINUED;
	}
	if (options & _WNOWAIT) {
		result |= WNOWAIT;
	}
	return result;
}

int
sys_link(user_addr_t oldpath, user_addr_t newpath)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "link(%p, %p)\n", (void *)oldpath, (void *)newpath);
#endif
	char old_buffer[PATH_MAX], new_buffer[PATH_MAX];
	return errno_map(link(sysroot_host_path(oldpath, AT_SYMLINK_NOFOLLOW,
					      old_buffer),
			sysroot_host_path(newpath, AT_SYMLINK_NOFOLLOW,
					new_buffer)));
}

int
sys_unlink(user_addr_t path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "unlink(\"%s\")\n", (char *)path);
#endif
	char buffer[PATH_MAX];
	return errno_map(unlink(
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer)));
}

int
sys_chdir(user_addr_t path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "chdir(\"%s\")\n", (char *)path);
#endif
	char buffer[PATH_MAX];
	return errno_map(chdir(sysroot_host_path(path, 0, buffer)));
}

int
sys_fchdir(int fd)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fchdir(%p)\n", (void *)fd);
#endif
	return errno_map(fchdir(fd));
}

int
sys_mknod(user_addr_t path, int mode, int dev)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mknod(%p, %p, %p)\n", (void *)path, (void *)mode,
			(void *)dev);
#endif
	unimplemented();
}

int
sys_chmod(user_addr_t path, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "chmod(%p, %p)\n", (void *)path, (void *)mode);
#endif
	char buffer[PATH_MAX];
	return errno_map(chmod(sysroot_host_path(path, 0, buffer), mode));
}

int
sys_chown(user_addr_t path, int uid, int gid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "chown(%p, %p, %p)\n", (void *)path, (void *)uid,
			(void *)gid);
#endif
	char buffer[PATH_MAX];
	return errno_map(chown(sysroot_host_path(path, 0, buffer), uid, gid));
}

int
sys_getpid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getpid()\n");
#endif
	return getpid();
}

int
sys_setuid(void *uid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setuid(%p)\n", (void *)uid);
#endif
	return credentials_setuid((uid_t)(uintptr_t)uid);
}

int
sys_getuid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getuid()\n");
#endif
	return getuid();
}

int
sys_geteuid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "geteuid()\n");
#endif
	return geteuid();
}

int
sys_ptrace(int req, uint64_t pid, void *addr, int data)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "ptrace(%p, %p, %p, %p)\n", (void *)req, (void *)pid,
			(void *)addr, (void *)data);
#endif
	if (req == PT_DENY_ATTACH) {
		return 0;
	}
	unimplemented();
}

struct xnu_msghdr {
	void *msg_name;
	uint32_t msg_namelen;
	struct iovec *msg_iov;
	int32_t msg_iovlen;
	void *msg_control;
	uint32_t msg_controllen;
	int32_t msg_flags;
};

struct xnu_cmsghdr {
	uint32_t cmsg_len;
	int32_t cmsg_level;
	int32_t cmsg_type;
};

#define xnu_CMSG_ALIGN(n) (((n) + 3) & ~(size_t)3)
#define xnu_SOL_SOCKET 0xffff
#define xnu_SCM_RIGHTS 1
#define xnu_MSG_TRUNC 0x10
#define xnu_MSG_CTRUNC 0x20

static size_t
control_to_host(const struct xnu_msghdr *guest, void *host, size_t size)
{
	size_t used = 0;
	const uint8_t *position = guest->msg_control;
	const uint8_t *end = position + guest->msg_controllen;
	while (position + sizeof(struct xnu_cmsghdr) <= end) {
		const struct xnu_cmsghdr *cmsg = (const void *)position;
		if (cmsg->cmsg_len < sizeof(*cmsg)
				|| position + cmsg->cmsg_len > end) {
			break;
		}
		size_t length = cmsg->cmsg_len - sizeof(*cmsg);
		if (cmsg->cmsg_level == xnu_SOL_SOCKET
				&& cmsg->cmsg_type == xnu_SCM_RIGHTS
				&& used + CMSG_SPACE(length) <= size) {
			struct cmsghdr *out = (void *)((uint8_t *)host + used);
			out->cmsg_len = CMSG_LEN(length);
			out->cmsg_level = SOL_SOCKET;
			out->cmsg_type = SCM_RIGHTS;
			memcpy(CMSG_DATA(out), cmsg + 1, length);
			used += CMSG_SPACE(length);
		}
		position += xnu_CMSG_ALIGN(cmsg->cmsg_len);
	}
	return used;
}

static uint32_t
control_to_guest(struct msghdr *host, struct xnu_msghdr *guest)
{
	uint32_t used = 0;
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(host); cmsg != NULL;
			cmsg = CMSG_NXTHDR(host, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET
				|| cmsg->cmsg_type != SCM_RIGHTS) {
			continue;
		}
		size_t length = cmsg->cmsg_len - CMSG_LEN(0);
		size_t space = xnu_CMSG_ALIGN(sizeof(struct xnu_cmsghdr) + length);
		if (used + space > guest->msg_controllen) {

			for (size_t i = 0; i != length / sizeof(int); i++) {
				close(((int *)CMSG_DATA(cmsg))[i]);
			}
			guest->msg_flags |= xnu_MSG_CTRUNC;
			continue;
		}
		struct xnu_cmsghdr *out = (void *)((uint8_t *)guest->msg_control
				+ used);
		out->cmsg_len = sizeof(*out) + length;
		out->cmsg_level = xnu_SOL_SOCKET;
		out->cmsg_type = xnu_SCM_RIGHTS;
		memcpy(out + 1, CMSG_DATA(cmsg), length);
		used += space;
	}
	return used;
}

int
sys_recvmsg(int s, void *msg, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "recvmsg(%p, %p, %p)\n", (void *)s, (void *)msg,
			(void *)flags);
#endif
	struct xnu_msghdr *guest = msg;
	struct sockaddr_storage address;
	if (icmp_is_socket(s)) {
		bool truncated;
		ssize_t received = icmp_receive(s, guest->msg_iov,
				guest->msg_iovlen, translate_msg_flags(flags),
				(struct sockaddr_in *)&address, &truncated);
		if (received < 0) {
			return err_map(errno);
		}
		if (guest->msg_name != NULL) {
			translate_to_guest_sockaddr(
					&address, sizeof(struct sockaddr_in));
			uint32_t length = guest->msg_namelen < sizeof(
							  struct sockaddr_in)
					? guest->msg_namelen
					: sizeof(struct sockaddr_in);
			memcpy(guest->msg_name, &address, length);
			guest->msg_namelen = sizeof(struct sockaddr_in);
		}
		guest->msg_flags = truncated ? xnu_MSG_TRUNC : 0;
		guest->msg_controllen = 0;
		return (int)received;
	}
	uint8_t control[CMSG_SPACE(253 * sizeof(int))]
			__attribute__((aligned(8)));
	struct msghdr host = {
		.msg_name = guest->msg_name != NULL ? &address : NULL,
		.msg_namelen = guest->msg_name != NULL ? sizeof(address) : 0,
		.msg_iov = guest->msg_iov,
		.msg_iovlen = guest->msg_iovlen,
		.msg_control = guest->msg_control != NULL ? control : NULL,
		.msg_controllen = guest->msg_control != NULL ? sizeof(control)
				: 0,
	};
	ssize_t received = recvmsg(s, &host,
			translate_msg_flags(flags) | MSG_CMSG_CLOEXEC);
	if (received < 0) {
		return err_map(errno);
	}
	if (guest->msg_name != NULL) {
		translate_to_guest_sockaddr(&address, host.msg_namelen);
		uint32_t length = host.msg_namelen < guest->msg_namelen
				? host.msg_namelen
				: guest->msg_namelen;
		memcpy(guest->msg_name, &address, length);
		guest->msg_namelen = host.msg_namelen;
	}
	guest->msg_flags = 0;
	if (host.msg_flags & MSG_TRUNC) {
		guest->msg_flags |= xnu_MSG_TRUNC;
	}
	if (host.msg_flags & MSG_CTRUNC) {
		guest->msg_flags |= xnu_MSG_CTRUNC;
	}
	if (guest->msg_control != NULL) {
		guest->msg_controllen = control_to_guest(&host, guest);
	}
	return (int)received;
}

int
sys_sendmsg(int s, void *msg, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sendmsg(%p, %p, %p)\n", (void *)s, (void *)msg,
			(void *)flags);
#endif
	const struct xnu_msghdr *guest = msg;
	if (route_is_socket(s)) {
		return (int)route_writev(s, guest->msg_iov, guest->msg_iovlen);
	}
	if (icmp_is_socket(s)) {
		icmp_sending(s, guest->msg_iov, guest->msg_iovlen);
	}
	struct sockaddr_storage address;
	uint8_t control[CMSG_SPACE(253 * sizeof(int))]
			__attribute__((aligned(8)));
	struct msghdr host = {
		.msg_iov = guest->msg_iov,
		.msg_iovlen = guest->msg_iovlen,
	};
	if (guest->msg_name != NULL) {
		host.msg_name = &address;
		host.msg_namelen = translate_to_host_sockaddr(guest->msg_name,
				guest->msg_namelen, &address);
	}
	if (guest->msg_control != NULL) {
		host.msg_controllen = control_to_host(guest, control,
				sizeof(control));
		host.msg_control = host.msg_controllen != 0 ? control : NULL;
	}
	return errno_map(sendmsg(s, &host,
			translate_msg_flags(flags) | MSG_NOSIGNAL));
}

int
sys_recvfrom(int s, void *buf, size_t len, int flags, void *from,
		int *fromlenaddr)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "recvfrom(%p, %p, %p, %p, %p, %p)\n", (void *)s,
			(void *)buf, (void *)len, (void *)flags, (void *)from,
			(void *)fromlenaddr);
#endif
	struct sockaddr_storage host;
	socklen_t host_len = sizeof(host);
	ssize_t received;
	if (icmp_is_socket(s)) {
		struct iovec iov = {buf, len};
		bool truncated;
		received = icmp_receive(s, &iov, 1, translate_msg_flags(flags),
				(struct sockaddr_in *)&host, &truncated);
		host_len = sizeof(struct sockaddr_in);
	} else {
		received = recvfrom(s, buf, len, translate_msg_flags(flags),
				from != NULL ? (struct sockaddr *)&host : NULL,
				from != NULL ? &host_len : NULL);
	}
	if (received >= 0 && from != NULL && fromlenaddr != NULL) {
		translate_to_guest_sockaddr(&host, host_len);
		uint32_t guest_len = *(uint32_t *)fromlenaddr;
		if (host_len < guest_len) {
			guest_len = host_len;
		}
		memcpy(from, &host, guest_len);
		*(uint32_t *)fromlenaddr = host_len;
	}
	return errno_map(received);
}

int
sys_accept(int s, void *name, void *anamelen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "accept(%p, %p, %p)\n", (void *)s, (void *)name,
			(void *)anamelen);
#endif
	struct sockaddr_storage host;
	socklen_t host_len = sizeof(host);
	int result = accept4(s, name != NULL ? (struct sockaddr *)&host : NULL,
			name != NULL ? &host_len : NULL, 0);
	if (result >= 0 && name != NULL && anamelen != NULL) {
		translate_to_guest_sockaddr(&host, host_len);
		uint32_t guest_len = *(uint32_t *)anamelen;
		if (host_len < guest_len) {
			guest_len = host_len;
		}
		memcpy(name, &host, guest_len);
		*(uint32_t *)anamelen = host_len;
	}
	return errno_map(result);
}

int
sys_getpeername(int fdes, void *asa, void *alen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getpeername(%p, %p, %p)\n", (void *)fdes, (void *)asa,
			(void *)alen);
#endif
	struct sockaddr_storage host;
	socklen_t host_len = sizeof(host);
	int result = getpeername(fdes, (struct sockaddr *)&host, &host_len);
	if (result == 0) {
		translate_to_guest_sockaddr(&host, host_len);
		uint32_t guest_len = *(uint32_t *)alen;
		if (host_len < guest_len) {
			guest_len = host_len;
		}
		memcpy(asa, &host, guest_len);
		*(uint32_t *)alen = host_len;
	}
	return errno_map(result);
}

int
sys_getsockname(int fdes, void *asa, void *alen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getsockname(%p, %p, %p)\n", (void *)fdes, (void *)asa,
			(void *)alen);
#endif
	struct sockaddr_storage host;
	socklen_t host_len = sizeof(host);
	int result = getsockname(fdes, (struct sockaddr *)&host, &host_len);
	if (result == 0) {
		translate_to_guest_sockaddr(&host, host_len);
		uint32_t guest_len = *(uint32_t *)alen;
		if (host_len < guest_len) {
			guest_len = host_len;
		}
		memcpy(asa, &host, guest_len);
		*(uint32_t *)alen = host_len;
	}
	return errno_map(result);
}

#define _F_OK 0
#define _X_OK (1 << 0)
#define _W_OK (1 << 1)
#define _R_OK (1 << 2)

int
sys_access(user_addr_t path, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "access(\"%s\", %#x)\n", (char *)path, flags);
#endif
	int cflags = 0;
	if (flags & _F_OK)
		cflags |= F_OK;
	if (flags & _X_OK)
		cflags |= X_OK;
	if (flags & _W_OK)
		cflags |= W_OK;
	if (flags & _R_OK)
		cflags |= R_OK;

	char buffer[PATH_MAX];
	return errno_map(access(sysroot_host_path(path, 0, buffer), cflags));
}

int
sys_chflags(char *path, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "chflags(\"%s\", %p)\n", path, (void *)flags);
#endif
	char buffer[PATH_MAX];
	int fd = open(sysroot_host_path(path, 0, buffer), O_PATH | O_CLOEXEC);
	if (fd == -1) {
		return err_map(errno);
	}
	int result = keep_bsd_flags(fd, flags);
	close(fd);
	return result;
}

int
sys_fchflags(int fd, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fchflags(%p, %p)\n", (void *)fd, (void *)flags);
#endif
	return keep_bsd_flags(fd, flags);
}

static int
keep_bsd_flags(int fd, int flags)
{
	if (bsd_flags_set(fd, (uint32_t)flags) == -1 && errno != EOPNOTSUPP) {
		return err_map(errno);
	}
	return 0;
}

int
sys_sync(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sync()\n");
#endif
	sync();
	return 0;
}

int
sys_kill(int pid, int signum, int posix)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kill(%p, %p, %p)\n", (void *)pid, (void *)signum,
			(void *)posix);
#endif
	int linux_signum = signo_to_linux(signum);
	if (signum != 0 && linux_signum == 0) {
		return _EINVAL;
	}
	return errno_map(kill(pid, linux_signum));
}

int
sys_getppid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getppid()\n");
#endif
	return getppid();
}

int
sys_sys_dup(uint32_t fd)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_dup(%p)\n", (void *)fd);
#endif
	return errno_map(dup(fd));
}

int
sys_pipe(int pipefd[2])
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pipe()\n");
#endif
	int fds[2];
	if (pipe(fds) == -1) {
		return err_map(errno);
	}
	syscall_set_rdx(fds[1]);
	return fds[0];
}

#define _O_CLOFORK 0x08000000

int
sys_pipe2(int pipefd[2], int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pipe2(%p, %p)\n", (void *)pipefd, (void *)flags);
#endif
	if (flags & ~(_O_NONBLOCK | _O_CLOEXEC | _O_CLOFORK)) {
		return _EINVAL;
	}

	int linux_flags = 0;
	if (flags & _O_NONBLOCK) {
		linux_flags |= O_NONBLOCK;
	}
	if (flags & _O_CLOEXEC) {
		linux_flags |= O_CLOEXEC;
	}
	int fds[2];
	if (pipe2(fds, linux_flags) == -1) {
		return err_map(errno);
	}
	syscall_set_rdx(fds[1]);
	return fds[0];
}

int
sys_getegid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getegid()\n");
#endif
	return getegid();
}

int
sys_getgid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getgid()\n");
#endif
	return getgid();
}

int
sys_sigprocmask(int how, user_addr_t mask, user_addr_t omask)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigprocmask(%p, %p, %p)\n", (void *)how, (void *)mask,
			(void *)omask);
#endif
	return signals_mask(how, mask, omask);
}

int
sys_getlogin(char *namebuf, uint32_t namelen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getlogin(%p, %p)\n", (void *)namebuf, (void *)namelen);
#endif
	char *name = getlogin();
	if (name == NULL) {
#ifdef ENABLE_STRACE
		perror("getlogin");
#endif
		return err_map(errno);
	}

	if (strlen(name) + 1 > namelen) {
		return _ERANGE;
	}

	strcpy(namebuf, name);
	return 0;
}

int
sys_setlogin(char *namebuf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setlogin(%p)\n", (void *)namebuf);
#endif
	/* Not supported */
	return 0;
}

int
sys_acct(char *path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "acct(%p)\n", (void *)path);
#endif
	return errno_map(acct(path));
}

#define xnu_SIOCGCONNINFO 0xc0407398
#define CIF_CONNECTED     0x2
#define CIF_PREFERRED     0x80

struct xnu_so_cinforeq {
	uint32_t cid;
	uint32_t flags;
	uint32_t ifindex;
	int32_t error;
	uint64_t src;
	uint32_t src_len;
	uint32_t reserved1;
	uint64_t dst;
	uint32_t dst_len;
	uint32_t aux_type;
	uint64_t aux_data;
	uint32_t aux_len;
	uint32_t reserved2;
};

static int connection_info(int fd, struct xnu_so_cinforeq *request);

static void translate_to_guest_sockaddr(
		struct sockaddr_storage *addr, socklen_t len);

static void
copy_address(struct sockaddr_storage *address, socklen_t length, uint64_t to,
		uint32_t *to_length)
{
	translate_to_guest_sockaddr(address, length);
	if (to != 0 && *to_length != 0) {
		memcpy((void *)(uintptr_t)to, address,
				length < *to_length ? length : *to_length);
	}
	*to_length = length;
}

int
sys_ioctl(int fd, uint64_t com, void *data)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "ioctl(%p, %p, %p)\n", (void *)fd, (void *)com,
			(void *)data);
#endif
	if (com == xnu_SIOCGCONNINFO) {
		return connection_info(fd, data);
	}
	int result = route_ioctl(fd, com, data);
	if (result != 1) {
		return result;
	}
	result = kctl_ioctl(fd, com, data);
	if (result != 1) {
		return result;
	}
	result = fsevents_ioctl(fd, com, data);
	if (result != 1) {
		return result;
	}
	result = net_ioctl(fd, com, data);
	if (result != 1) {
		return result;
	}
	result = tty_ioctl(fd, com, data);
	if (result != 1) {
		return result;
	}
	/* TODO: ioctl(2) emulation layer */
	/* if (fd == 2 && com == 0x4004667a) {
		return 0;
	}
	if (fd == 0 && com == 0x4004667a) {
		return 0;
	}
	if (fd == 1 && com == 0x4004667a) {
		return 0;
	}
	if (fd == 0 && com == 0x40487413) {
		return 0;
	}
	unimplemented(); */
	if (fcntl(fd, F_GETFD) == -1) {
		return errno_map(-1);
	}
#ifdef ENABLE_STRACE
	fprintf(stderr, "  ioctl: %#llx not done\n", (unsigned long long)com);
#endif
	return 0;
}

static int
connection_info(int fd, struct xnu_so_cinforeq *request)
{
	struct sockaddr_storage local, peer;
	socklen_t local_len = sizeof(local), peer_len = sizeof(peer);
	if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0) {
		return errno_map(-1);
	}
	if (local.ss_family != AF_INET && local.ss_family != AF_INET6) {
		return _EINVAL;
	}
	bool connected = getpeername(fd, (struct sockaddr *)&peer, &peer_len)
			== 0;
	request->flags = connected ? CIF_CONNECTED | CIF_PREFERRED : 0;
	request->error = 0;
	request->ifindex = interface_of(&local);
	copy_address(&local, local_len, request->src, &request->src_len);
	if (connected) {
		copy_address(&peer, peer_len, request->dst, &request->dst_len);
	} else {
		request->dst_len = 0;
	}
	request->aux_type = 0;
	request->aux_len = 0;
	return 0;
}

static uint32_t
interface_of(const struct sockaddr_storage *address)
{
	struct ifaddrs *list;
	if (getifaddrs(&list) != 0) {
		return 0;
	}
	uint32_t index = 0;
	for (struct ifaddrs *a = list; a != NULL && index == 0;
			a = a->ifa_next) {
		if (a->ifa_addr == NULL
				|| a->ifa_addr->sa_family
						!= address->ss_family) {
			continue;
		}
		bool same = address->ss_family == AF_INET
				? ((const struct sockaddr_in *)a->ifa_addr)
								->sin_addr
								.s_addr
						== ((const struct sockaddr_in *)address)
								   ->sin_addr
								   .s_addr
				: memcmp(&((const struct sockaddr_in6 *)a->ifa_addr)
								  ->sin6_addr,
						  &((const struct sockaddr_in6 *)address)
								  ->sin6_addr,
						  16)
						== 0;
		if (same) {
			index = if_nametoindex(a->ifa_name);
		}
	}
	freeifaddrs(list);
	return index;
}

int
sys_reboot(int opt, char *msg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "reboot(%p, %p)\n", (void *)opt, (void *)msg);
#endif
	/* Not supported */
	return 0;
}

int
sys_revoke(char *path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "revoke(%p)\n", (void *)path);
#endif
	/* Not supported */
	return 0;
}

int
sys_symlink(char *path, char *link)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "symlink(%p, %p)\n", (void *)path, (void *)link);
#endif
	char buffer[PATH_MAX];
	return errno_map(symlink(path,
			sysroot_host_path(link, AT_SYMLINK_NOFOLLOW, buffer)));
}

int
sys_readlink(char *path, char *buf, int count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "readlink(%p, %p, %p)\n", (void *)path, (void *)buf,
			(void *)count);
#endif
	char buffer[PATH_MAX];
	return errno_map(readlink(
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer),
			buf, count));
}

int
sys_execve(char *fname, char **argp, char **envp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "execve(%s, %p, %p)\n", fname, (void *)argp,
			(void *)envp);
#endif
	char buffer[PATH_MAX];
	char **script_argv;
	const char *host = exec_path(fname, argp, buffer, &script_argv);
	int result = errno_map(execve(host,
			(script_argv != NULL) ? script_argv : argp, envp));
	free(script_argv);
	return result;
}

int
sys_umask(int newmask)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "umask(%p)\n", (void *)newmask);
#endif
	return errno_map(umask(newmask));
}

int
sys_chroot(user_addr_t path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "chroot(%p)\n", (void *)path);
#endif
	return errno_map(chroot((char *)path));
}

#define _MS_ASYNC      0x1
#define _MS_INVALIDATE 0x2
#define _MS_SYNC       0x10

int
sys_msync(void *addr, size_t len, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "msync(%p, %p, %p)\n", (void *)addr, (void *)len,
			(void *)flags);
#endif
	int linux_flags = ((flags & _MS_ASYNC) ? MS_ASYNC : 0)
			| ((flags & _MS_INVALIDATE) ? MS_INVALIDATE : 0)
			| ((flags & _MS_SYNC) ? MS_SYNC : 0);
	return errno_map(msync(addr, len, linux_flags));
}

int
sys_vfork(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "vfork()\n");
#endif
	unimplemented();
}

int
sys_munmap(void *addr, size_t len)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "munmap(%p, %p)\n", (void *)addr, (void *)len);
#endif
	return munmap(addr, len);
}

int
sys_mprotect(void *addr, size_t len, int prot)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mprotect(%p, %p, %p)\n", (void *)addr, (void *)len,
			(void *)prot);
#endif
	/* TODO: Be responsible and convert the protection properly */
	return errno_map(mprotect(addr, len, prot));
}

#define _MADV_NORMAL     0
#define _MADV_RANDOM     1
#define _MADV_SEQUENTIAL 2
#define _MADV_WILLNEED   3
#define _MADV_ZERO       11

int
sys_madvise(void *addr, size_t len, int behav)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "madvise(%p, %p, %p)\n", (void *)addr, (void *)len,
			(void *)behav);
#endif
	switch (behav) {
	case _MADV_NORMAL:
	case _MADV_RANDOM:
	case _MADV_SEQUENTIAL:
	case _MADV_WILLNEED:
		madvise(addr, len, behav);
		return 0;
	case _MADV_ZERO:
		memset(addr, 0, len);
		return 0;
	default:
		return 0;
	}
}

int
sys_mincore(user_addr_t addr, user_size_t len, user_addr_t vec)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mincore(%p, %p, %p)\n", (void *)addr, (void *)len,
			(void *)vec);
#endif
	unimplemented();
}

int
sys_getgroups(uint32_t gidsetsize, void *gidset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getgroups(%p, %p)\n", (void *)gidsetsize,
			(void *)gidset);
#endif
	gid_t groups[NGROUPS_MAX];
	int count = getgroups(gidsetsize > NGROUPS_MAX ? NGROUPS_MAX
						       : (int)gidsetsize,
			groups);
	if (count < 0) {
		return errno_map(count);
	}
	for (int i = 0; i != count && gidsetsize != 0; i++) {
		((uint32_t *)gidset)[i] = groups[i];
	}
	return count;
}

int
sys_setgroups(uint32_t gidsetsize, void *gidset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setgroups(%p, %p)\n", (void *)gidsetsize,
			(void *)gidset);
#endif
	return credentials_setgroups(gidsetsize, gidset);
}

int
sys_getpgrp(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getpgrp()\n");
#endif
	return getpgrp();
}

int
sys_setpgid(int pid, int pgid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setpgid(%p, %p)\n", (void *)pid, (void *)pgid);
#endif
	return errno_map(setpgid(pid, pgid));
}

struct __darwin_user64_timeval {
	int64_t tv_sec;
	int32_t tv_usec;
};

struct __darwin_user64_itimerval {
	struct __darwin_user64_timeval it_interval;
	struct __darwin_user64_timeval it_value;
};

static void itimerval_from_linux(const struct itimerval *from,
		struct __darwin_user64_itimerval *to);

int
sys_setitimer(uint32_t which, void *itv, void *oitv)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setitimer(%p, %p, %p)\n", (void *)which, (void *)itv,
			(void *)oitv);
#endif
	if (which > ITIMER_PROF) {
		return _EINVAL;
	}
	struct itimerval value = {0}, old;
	if (itv != NULL) {
		const struct __darwin_user64_itimerval *darwin = itv;
		value.it_interval.tv_sec = darwin->it_interval.tv_sec;
		value.it_interval.tv_usec = darwin->it_interval.tv_usec;
		value.it_value.tv_sec = darwin->it_value.tv_sec;
		value.it_value.tv_usec = darwin->it_value.tv_usec;
	}

	if (setitimer(which, &value, &old) == -1) {
		return err_map(errno);
	}
	if (oitv != NULL) {
		itimerval_from_linux(&old, oitv);
	}
	return 0;
}

int
sys_swapon(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "swapon()\n");
#endif
	/* Not supported */
	return 0;
}

int
sys_getitimer(uint32_t which, void *itv)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getitimer(%p, %p)\n", (void *)which, (void *)itv);
#endif
	if (which > ITIMER_PROF) {
		return _EINVAL;
	}
	struct itimerval value;
	if (getitimer(which, &value) == -1) {
		return err_map(errno);
	}
	itimerval_from_linux(&value, itv);
	return 0;
}

static void
itimerval_from_linux(const struct itimerval *from,
		struct __darwin_user64_itimerval *to)
{
	memset(to, 0, sizeof(*to));
	to->it_interval.tv_sec = from->it_interval.tv_sec;
	to->it_interval.tv_usec = from->it_interval.tv_usec;
	to->it_value.tv_sec = from->it_value.tv_sec;
	to->it_value.tv_usec = from->it_value.tv_usec;
}

int
sys_sys_getdtablesize(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_getdtablesize()\n");
#endif
	return getdtablesize();
}

int
sys_sys_dup2(uint32_t from, uint32_t to)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_dup2(%p, %p)\n", (void *)from, (void *)to);
#endif
	return errno_map(dup2(from, to));
}

int
sys_select(int nd, uint32_t *in, uint32_t *ou, uint32_t *ex, void *tv)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "select(%p, %p, %p, %p, %p)\n", (void *)nd, (void *)in,
			(void *)ou, (void *)ex, (void *)tv);
#endif
	if (nd < 0 || nd > FD_SETSIZE) {
		return _EINVAL;
	}
	size_t bytes = ((size_t)nd + 31) / 32 * 4;
	fd_set sets[3];
	uint32_t *guest_sets[3] = {in, ou, ex};
	for (int i = 0; i < 3; i++) {
		FD_ZERO(&sets[i]);
		if (guest_sets[i] != NULL) {
			memcpy(&sets[i], guest_sets[i], bytes);
		}
	}
	struct {
		int64_t tv_sec;
		int32_t tv_usec;
	} *guest_timeout = tv;
	struct timeval timeout;
	if (guest_timeout != NULL) {
		timeout.tv_sec = guest_timeout->tv_sec;
		timeout.tv_usec = guest_timeout->tv_usec;
	}
	int result = select(nd, in != NULL ? &sets[0] : NULL,
			ou != NULL ? &sets[1] : NULL, ex != NULL ? &sets[2] : NULL,
			guest_timeout != NULL ? &timeout : NULL);
	if (result == -1) {
		return err_map(errno);
	}
	for (int i = 0; i < 3; i++) {
		if (guest_sets[i] != NULL) {
			memcpy(guest_sets[i], &sets[i], bytes);
		}
	}
	return result;
}

int
sys_fsync(int fd)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fsync(%p)\n", (void *)fd);
#endif
	return errno_map(fsync(fd));
}

int
sys_setpriority(int which, void *who, int prio)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setpriority(%p, %p, %p)\n", (void *)which, (void *)who,
			(void *)prio);
#endif

	if (which <= PRIO_USER) {
		return errno_map(setpriority(which, (id_t)(uintptr_t)who, prio));
	}
	return 0;
}

#define xnu_PF_UNIX    1
#define xnu_AF_INET    2
#define xnu_PF_ROUTE   17
#define xnu_PF_SYSTEM  32
#define xnu_SYSPROTO_EVENT   1
#define xnu_SYSPROTO_CONTROL 2
#define xnu_AF_INET6   30
#define xnu_SOCK_STREAM 1
#define xnu_SOCK_DGRAM 2
#define xnu_SO_REUSEADDR 0x0004
#define xnu_SO_KEEPALIVE 0x0008
#define xnu_SO_DONTROUTE 0x0010
#define xnu_SO_BROADCAST 0x0020
#define xnu_SO_LINGER    0x0080
#define xnu_SO_OOBINLINE 0x0100
#define xnu_SO_REUSEPORT 0x0200
#define xnu_SO_SNDBUF    0x1001
#define xnu_SO_RCVBUF    0x1002
#define xnu_SO_SNDLOWAT  0x1003
#define xnu_SO_RCVLOWAT  0x1004
#define xnu_SO_ERROR     0x1007
#define xnu_SO_TYPE      0x1008
#define xnu_IPPROTO_TCP  6

static int
translate_domain(int domain)
{
	switch (domain) {
	case xnu_PF_UNIX:
		return AF_UNIX;
	case xnu_AF_INET:
		return AF_INET;
	case xnu_AF_INET6:
		return AF_INET6;
	default:
		return -1;
	}
}

static socklen_t
translate_to_host_sockaddr(const void *guest, socklen_t len,
		struct sockaddr_storage *host)
{
	if (len > sizeof(*host)) {
		len = sizeof(*host);
	}
	memcpy(host, guest, len);
	uint8_t family = ((const uint8_t *)guest)[1];
	host->ss_family = (family == xnu_AF_INET6) ? AF_INET6 : family;
	return len;
}

static void
translate_to_guest_sockaddr(struct sockaddr_storage *addr, socklen_t len)
{
	if (len < 2) {
		return;
	}
	sa_family_t family = addr->ss_family;
	uint8_t *bytes = (uint8_t *)addr;
	bytes[0] = (uint8_t)len;
	bytes[1] = (family == AF_INET6) ? xnu_AF_INET6 : (uint8_t)family;
}

#define xnu_MSG_OOB       0x1
#define xnu_MSG_PEEK      0x2
#define xnu_MSG_DONTROUTE 0x4
#define xnu_MSG_WAITALL   0x40
#define xnu_MSG_DONTWAIT  0x80

static int
translate_msg_flags(int flags)
{
	int host = 0;
	if (flags & xnu_MSG_OOB) {
		host |= MSG_OOB;
	}
	if (flags & xnu_MSG_PEEK) {
		host |= MSG_PEEK;
	}
	if (flags & xnu_MSG_DONTROUTE) {
		host |= MSG_DONTROUTE;
	}
	if (flags & xnu_MSG_WAITALL) {
		host |= MSG_WAITALL;
	}
	if (flags & xnu_MSG_DONTWAIT) {
		host |= MSG_DONTWAIT;
	}
	return host;
}

static bool
translate_sockopt(int level, int name, int *host_level, int *host_name)
{
	if (level == xnu_IPPROTO_TCP) {
		*host_level = IPPROTO_TCP;
		switch (name) {
		case 1:
			*host_name = TCP_NODELAY;
			return true;
		case 0x10:
			*host_name = TCP_KEEPIDLE;
			return true;
		case 0x101:
			*host_name = TCP_KEEPINTVL;
			return true;
		case 0x102:
			*host_name = TCP_KEEPCNT;
			return true;
		default:
			return false;
		}
	}
	if (level != xnu_SOL_SOCKET) {
		return false;
	}
	*host_level = SOL_SOCKET;
	switch (name) {
	case xnu_SO_REUSEADDR:
		*host_name = SO_REUSEADDR;
		return true;
	case xnu_SO_KEEPALIVE:
		*host_name = SO_KEEPALIVE;
		return true;
	case xnu_SO_DONTROUTE:
		*host_name = SO_DONTROUTE;
		return true;
	case xnu_SO_BROADCAST:
		*host_name = SO_BROADCAST;
		return true;
	case xnu_SO_OOBINLINE:
		*host_name = SO_OOBINLINE;
		return true;
	case xnu_SO_REUSEPORT:
		*host_name = SO_REUSEPORT;
		return true;
	case xnu_SO_SNDBUF:
		*host_name = SO_SNDBUF;
		return true;
	case xnu_SO_RCVBUF:
		*host_name = SO_RCVBUF;
		return true;
	case xnu_SO_SNDLOWAT:
		*host_name = SO_SNDLOWAT;
		return true;
	case xnu_SO_RCVLOWAT:
		*host_name = SO_RCVLOWAT;
		return true;
	case xnu_SO_LINGER:
		*host_name = SO_LINGER;
		return true;
	case xnu_SO_ERROR:
		*host_name = SO_ERROR;
		return true;
	case xnu_SO_TYPE:
		*host_name = SO_TYPE;
		return true;
	default:
		return false;
	}
}

int
sys_socket(int domain, int type, int protocol)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "socket(%p, %p, %p)\n", (void *)domain, (void *)type,
			(void *)protocol);
#endif
	if (domain == xnu_PF_SYSTEM && protocol == xnu_SYSPROTO_EVENT) {
		return route_socket(true, 0);
	}
	if (domain == xnu_PF_ROUTE) {
		return route_socket(false, protocol);
	}
	if (domain == xnu_PF_SYSTEM && protocol == xnu_SYSPROTO_CONTROL) {
		return kctl_socket(type);
	}
	if (domain == xnu_PF_SYSTEM) {
		return _EAFNOSUPPORT;
	}
	if (domain == AF_INET && type == SOCK_DGRAM
			&& protocol == IPPROTO_ICMP) {
		return icmp_socket();
	}
	int host_domain = translate_domain(domain);
	if (host_domain == -1) {
		unimplemented();
	}
	return errno_map(socket(host_domain, type, protocol));
}

struct xnu_sockaddr_un {
	uint8_t sun_len;
	uint8_t sun_family;
	char sun_path[104];
};

int
sys_connect(int s, void *name, void *namelen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "connect(%p, %p, %p)\n", (void *)s, (void *)name,
			(void *)namelen);
#endif
	socklen_t length = (socklen_t)(uintptr_t)namelen;
	if (kctl_is_socket(s)) {
		return kctl_connect(s, name, length);
	}
	if (length >= 2 && ((const uint8_t *)name)[1] == xnu_PF_UNIX) {
		struct sockaddr_un linux_address;
		int directory;
		int error = host_unix_address(
				name, length, &linux_address, &directory);
		if (error != 0) {
			return error;
		}
		int result = connect(s, (struct sockaddr *)&linux_address,
				sizeof(linux_address));
		error = errno;
		if (directory != -1) {
			close(directory);
		}
		return result == -1 ? err_map(error) : 0;
	}
	struct sockaddr_storage host;
	socklen_t len = translate_to_host_sockaddr(name, length, &host);
	return errno_map(connect(s, (struct sockaddr *)&host, len));
}

static int
host_unix_address(const void *name, socklen_t length,
		struct sockaddr_un *linux_address, int *directory)
{
	const struct xnu_sockaddr_un *address = name;
	char path[sizeof(address->sun_path) + 1] = {0};
	size_t path_length = length - 2;
	if (path_length > sizeof(address->sun_path)) {
		path_length = sizeof(address->sun_path);
	}
	memcpy(path, address->sun_path, path_length);

	char buffer[PATH_MAX];
	const char *host_path
			= sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer);
	*linux_address = (struct sockaddr_un){.sun_family = AF_UNIX};
	*directory = -1;
	if (strlen(host_path) < sizeof(linux_address->sun_path)) {
		strcpy(linux_address->sun_path, host_path);
		return 0;
	}
	char parent[PATH_MAX];
	snprintf(parent, sizeof(parent), "%s", host_path);
	char *slash = strrchr(parent, '/');
	if (slash == NULL) {
		return _ENAMETOOLONG;
	}
	*slash = '\0';
	*directory = open(parent[0] != '\0' ? parent : "/",
			O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (*directory == -1) {
		return err_map(errno);
	}
	if ((size_t)snprintf(linux_address->sun_path,
			    sizeof(linux_address->sun_path),
			    "/proc/thread-self/fd/%d/%s", *directory, slash + 1)
			>= sizeof(linux_address->sun_path)) {
		close(*directory);
		*directory = -1;
		return _ENAMETOOLONG;
	}
	return 0;
}

int
sys_getpriority(int which, void *who)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getpriority(%p, %p)\n", (void *)which, (void *)who);
#endif
	if (which > PRIO_USER) {
		return 0;
	}
	errno = 0;
	int priority = getpriority(which, (id_t)(uintptr_t)who);
	if (priority == -1 && errno != 0) {
		return errno_map(-1);
	}
	return priority;
}

int
sys_bind(int s, void *name, void *namelen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "bind(%p, %p, %p)\n", (void *)s, (void *)name,
			(void *)namelen);
#endif
	const struct xnu_sockaddr_un *address = name;
	socklen_t length = (socklen_t)(uintptr_t)namelen;
	if (length < 2) {
		return _EINVAL;
	}
	if (address->sun_family != xnu_PF_UNIX) {
		struct sockaddr_storage host;
		socklen_t host_length
				= translate_to_host_sockaddr(name, length, &host);
		return errno_map(
				bind(s, (struct sockaddr *)&host, host_length));
	}
	struct sockaddr_un linux_address;
	int directory;
	int error = host_unix_address(name, length, &linux_address, &directory);
	if (error != 0) {
		return error;
	}
	int result = bind(s, (struct sockaddr *)&linux_address,
			sizeof(linux_address));
	error = errno;
	if (directory != -1) {
		close(directory);
	}
	return result == -1 ? err_map(error) : 0;
}

int
sys_setsockopt(int s, int level, int name, void *val, void *valsize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setsockopt(%p, %p, %p, %p, %p)\n", (void *)s,
			(void *)level, (void *)name, (void *)val,
			(void *)valsize);
#endif
	int host_level, host_name;
	if (!translate_sockopt(level, name, &host_level, &host_name)) {
		return 0;
	}
	return errno_map(setsockopt(s, host_level, host_name, val,
			(socklen_t)(uintptr_t)valsize));
}

int
sys_listen(int s, int backlog)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "listen(%p, %p)\n", (void *)s, (void *)backlog);
#endif
	return errno_map(listen(s, backlog));
}

int
sys_sigsuspend(uint32_t mask)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigsuspend(%p)\n", (void *)(uintptr_t)mask);
#endif
	sigset_t set;
	sigset_to_linux(mask, &set);
	sigdelset(&set, SIGSYS);
	return errno_map(sigsuspend(&set));
}

int
sys_gettimeofday(void *tp, void *tzp, uint64_t *mach_absolute_time)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "gettimeofday(%p, %p, %p)\n", (void *)tp, (void *)tzp,
			(void *)mach_absolute_time);
#endif
	if (tp != NULL) {
		struct timeval now;
		gettimeofday(&now, NULL);
		struct __darwin_user64_timeval *result = tp;
		result->tv_sec = now.tv_sec;
		result->tv_usec = now.tv_usec;
	}
	if (tzp != NULL) {
		memset(tzp, 0, 2 * sizeof(int));
	}
	if (mach_absolute_time != NULL) {
		*mach_absolute_time = commpage_absolute_time();
	}
	return 0;
}

int
sys_getrusage(int who, void *rusage)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getrusage(%p, %p)\n", (void *)who, (void *)rusage);
#endif
	struct rusage usage;
	if (getrusage(who, &usage) == -1) {
		return err_map(errno);
	}
	usage.ru_maxrss *= 1024;
	memcpy(rusage, &usage, sizeof(usage));
	return 0;
}

int
sys_getsockopt(int s, int level, int name, void *val, void *avalsize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getsockopt(%p, %p, %p, %p, %p)\n", (void *)s,
			(void *)level, (void *)name, (void *)val,
			(void *)avalsize);
#endif
	uint32_t *size = avalsize;
	int host_level, host_name;
	if (translate_sockopt(level, name, &host_level, &host_name)) {
		socklen_t len = *size;
		int result = getsockopt(s, host_level, host_name, val, &len);
		*size = len;
		return errno_map(result);
	}
	if (*size > 0) {
		memset(val, 0, *size);
	}
	return 0;
}

user_ssize_t
sys_readv(int fd, void *iovp, uint32_t iovcnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "readv(%p, %p, %p)\n", (void *)fd, (void *)iovp,
			(void *)iovcnt);
#endif
	return errno_map(readv(fd, iovp, iovcnt));
}

user_ssize_t
sys_writev(int fd, void *iovp, uint32_t iovcnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "writev(%p, %p, %p)\n", (void *)fd, (void *)iovp,
			(void *)iovcnt);
#endif
	if (route_is_socket(fd)) {
		return route_writev(fd, iovp, iovcnt);
	}
	return errno_map(writev(fd, iovp, iovcnt));
}

int
sys_settimeofday(void *tv, void *tzp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "settimeofday(%p, %p)\n", (void *)tv, (void *)tzp);
#endif
	unimplemented();
}

int
sys_fchown(int fd, int uid, int gid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fchown(%p, %p, %p)\n", (void *)fd, (void *)uid,
			(void *)gid);
#endif
	return errno_map(fchown(fd, uid, gid));
}

int
sys_fchmod(int fd, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fchmod(%p, %p)\n", (void *)fd, (void *)mode);
#endif
	return errno_map(fchmod(fd, mode));
}

int
sys_setreuid(void *ruid, void *euid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setreuid(%p, %p)\n", (void *)ruid, (void *)euid);
#endif
	return credentials_setreuid(
			(uid_t)(uintptr_t)ruid, (uid_t)(uintptr_t)euid);
}

int
sys_setregid(void *rgid, void *egid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setregid(%p, %p)\n", (void *)rgid, (void *)egid);
#endif
	return credentials_setregid(
			(gid_t)(uintptr_t)rgid, (gid_t)(uintptr_t)egid);
}

int
sys_rename(char *from, char *to)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "rename(\"%s\", \"%s\")\n", from, to);
#endif
	char from_buffer[PATH_MAX], to_buffer[PATH_MAX];
	return errno_map(rename(sysroot_host_path(from, AT_SYMLINK_NOFOLLOW,
						from_buffer),
			sysroot_host_path(to, AT_SYMLINK_NOFOLLOW, to_buffer)));
}

int
sys_sys_flock(int fd, int how)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_flock(%p, %p)\n", (void *)fd, (void *)how);
#endif
	return errno_map(flock(fd, how));
}

int
sys_mkfifo(user_addr_t path, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mkfifo(%p, %p)\n", (void *)path, (void *)mode);
#endif
	char buffer[PATH_MAX];
	return errno_map(mkfifo(
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer),
			mode));
}

int
sys_sendto(int s, void *buf, size_t len, int flags, void *to, void *tolen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sendto(%p, %p, %p, %p, %p, %p)\n", (void *)s,
			(void *)buf, (void *)len, (void *)flags, (void *)to,
			(void *)tolen);
#endif
	if (route_is_socket(s)) {
		return route_write(s, buf, len);
	}
	if (icmp_is_socket(s)) {
		struct iovec iov = {buf, len};
		icmp_sending(s, &iov, 1);
	}
	struct sockaddr_storage host;
	struct sockaddr *dest = NULL;
	socklen_t dest_len = 0;
	if (to != NULL) {
		dest_len = translate_to_host_sockaddr(
				to, (socklen_t)(uintptr_t)tolen, &host);
		dest = (struct sockaddr *)&host;
	}
	return errno_map(sendto(s, buf, len, translate_msg_flags(flags) | MSG_NOSIGNAL,
			dest, dest_len));
}

int
sys_shutdown(int s, int how)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shutdown(%p, %p)\n", (void *)s, (void *)how);
#endif
	/* Not supported */
	return 0;
}

int
sys_socketpair(int domain, int type, int protocol, int *rsv)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "socketpair(%p, %p, %p, %p)\n", (void *)domain,
			(void *)type, (void *)protocol, (void *)rsv);
#endif
	if (domain != xnu_PF_UNIX || protocol != 0
			|| (type != xnu_SOCK_STREAM && type != xnu_SOCK_DGRAM)) {
		unimplemented();
	}
	return errno_map(socketpair(AF_UNIX,
			type == xnu_SOCK_STREAM ? SOCK_STREAM : SOCK_DGRAM, 0,
			rsv));
}

int
sys_mkdir(user_addr_t path, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mkdir(\"%s\", %p)\n", (char *)path, (void *)mode);
#endif
	char buffer[PATH_MAX];
	return errno_map(mkdir(
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer),
			mode));
}

static bool
last_component_is_dot(const char *path)
{
	size_t end = strlen(path);
	while (end > 1 && path[end - 1] == '/') {
		end--;
	}
	size_t start = end;
	while (start > 0 && path[start - 1] != '/') {
		start--;
	}
	return (end - start == 1 && path[start] == '.')
			|| (end - start == 2 && path[start] == '.'
					&& path[start + 1] == '.');
}

int
sys_rmdir(char *path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "rmdir(%p)\n", (void *)path);
#endif
	if (last_component_is_dot(path)) {
		return _EINVAL;
	}
	char buffer[PATH_MAX];
	return errno_map(rmdir(
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer)));
}

int
sys_utimes(char *path, void *tptr)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "utimes(%p, %p)\n", (void *)path, (void *)tptr);
#endif
	char buffer[PATH_MAX];
	struct timeval times[2];
	return errno_map(utimes(sysroot_host_path(path, 0, buffer),
			convert_timevals(tptr, times)));
}

static struct timeval *
convert_timevals(const void *tptr, struct timeval *times)
{
	if (tptr == NULL) {
		return NULL;
	}

	const struct __darwin_user64_timeval *darwin_times = tptr;
	for (int i = 0; i < 2; i++) {
		times[i].tv_sec = darwin_times[i].tv_sec;
		times[i].tv_usec = darwin_times[i].tv_usec;
	}
	return times;
}

int
sys_futimes(int fd, void *tptr)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "futimes(%p, %p)\n", (void *)fd, (void *)tptr);
#endif
	struct timeval times[2];
	return errno_map(futimes(fd, convert_timevals(tptr, times)));
}

int
sys_adjtime(void *delta, void *olddelta)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "adjtime(%p, %p)\n", (void *)delta, (void *)olddelta);
#endif
	unimplemented();
}

int
sys_gethostuuid(unsigned char *uuid_buf, void *timeoutp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "gethostuuid(%p, %p)\n", (void *)uuid_buf,
			(void *)timeoutp);
#endif
	if (!host_uuid(uuid_buf)) {
		return _EIO;
	}
#ifdef ENABLE_STRACE
	fprintf(stderr, "  host uuid: %s\n", host_uuid_string());
#endif
	return 0;
}

int
sys_setsid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setsid()\n");
#endif
	return errno_map(setsid());
}

int
sys_getpgid(uint64_t pid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getpgid(%p)\n", (void *)pid);
#endif
	return errno_map(getpgid(pid));
}

int
sys_setprivexec(int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setprivexec(%p)\n", (void *)flag);
#endif
	unimplemented();
}

user_ssize_t
sys_pread(int fd, user_addr_t buf, user_size_t nbyte, off_t offset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pread(%p, %p, %p, %p)\n", (void *)fd, (void *)buf,
			(void *)nbyte, (void *)offset);
#endif
	ssize_t n = pread(fd, buf, nbyte, offset);
	if (n < 0) {
#ifdef ENABLE_STRACE
		perror("pread");
#endif
		return err_map(errno);
	}
	return n;
}

user_ssize_t
sys_pwrite(int fd, user_addr_t buf, user_size_t nbyte, off_t offset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pwrite(%p, %p, %p, %p)\n", (void *)fd, (void *)buf,
			(void *)nbyte, (void *)offset);
#endif
	ssize_t n = pwrite(fd, buf, nbyte, offset);
	if (n < 0) {
#ifdef ENABLE_STRACE
		perror("pwrite");
#endif
		return err_map(errno);
	}
	return n;
}

int
sys_unmount(user_addr_t path, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "unmount(%p, %p)\n", (void *)path, (void *)flags);
#endif
	unimplemented();
}

int
sys_quotactl(const char *path, int cmd, int uid, void *arg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "quotactl(%p, %p, %p, %p)\n", (void *)path, (void *)cmd,
			(void *)uid, (void *)arg);
#endif
	return _ENOTSUP;
}

int
sys_mount(char *type, char *path, int flags, void *data)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mount(%p, %p, %p, %p)\n", (void *)type, (void *)path,
			(void *)flags, (void *)data);
#endif
	unimplemented();
}

int
sys_csops(uint64_t pid, uint32_t ops, user_addr_t useraddr,
		user_size_t usersize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "csops(%p, %p, %p, %p)\n", (void *)pid, (void *)ops,
			(void *)useraddr, (void *)usersize);
#endif
	return codesign_ops((int32_t)pid, ops, useraddr, usersize);
}

int
sys_csops_audittoken(uint64_t pid, uint32_t ops, user_addr_t useraddr,
		user_size_t usersize, user_addr_t uaudittoken)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "csops_audittoken(%p, %p, %p, %p, %p)\n", (void *)pid,
			(void *)ops, (void *)useraddr, (void *)usersize,
			(void *)uaudittoken);
#endif
	return codesign_ops((int32_t)pid, ops, useraddr, usersize);
}

int
sys_waitid(void *idtype, void *id, void *infop, int options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "waitid(%p, %p, %p, %p)\n", (void *)idtype, (void *)id,
			(void *)infop, (void *)options);
#endif
	unimplemented();
}

int
sys_kdebug_typefilter(void **addr, size_t *size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kdebug_typefilter(%p, %p)\n", (void *)addr,
			(void *)size);
#endif
	unimplemented();
}

uint64_t
sys_kdebug_trace_string(uint32_t debugid, uint64_t str_id, const char *str)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kdebug_trace_string(%p, %p, %p)\n", (void *)debugid,
			(void *)str_id, (void *)str);
#endif
	unimplemented();
}

int
sys_kdebug_trace64(uint32_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		uint64_t arg4)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kdebug_trace64(%p, %p, %p, %p, %p)\n", (void *)code,
			(void *)arg1, (void *)arg2, (void *)arg3, (void *)arg4);
#endif
	unimplemented();
}

int
sys_kdebug_trace(uint32_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		uint64_t arg4)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kdebug_trace(%p, %p, %p, %p, %p)\n", (void *)code,
			(void *)arg1, (void *)arg2, (void *)arg3, (void *)arg4);
#endif
	return 0;
}

int
sys_setgid(void *gid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setgid(%p)\n", (void *)gid);
#endif
	return credentials_setgid((gid_t)(uintptr_t)gid);
}

int
sys_setegid(void *egid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setegid(%p)\n", (void *)egid);
#endif
	return credentials_setegid((gid_t)(uintptr_t)egid);
}

int
sys_seteuid(void *euid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "seteuid(%p)\n", (void *)euid);
#endif
	return credentials_seteuid((uid_t)(uintptr_t)euid);
}

int
sys_thread_selfcounts(int type, user_addr_t buf, user_size_t nbytes)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_selfcounts(%p, %p, %p)\n", (void *)type,
			(void *)buf, (void *)nbytes);
#endif
	if (buf == NULL) {
		return _EINVAL;
	}
	memset(buf, 0, nbytes);
	return 0;
}

int
sys_fdatasync(int fd)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fdatasync(%p)\n", (void *)fd);
#endif
	unimplemented();
}

int
sys_pathconf(char *path, int name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pathconf(\"%s\", %d)\n", path, name);
#endif
	char buffer[PATH_MAX];
	int fd = open(sysroot_host_path(path, 0, buffer), O_PATH);
	if (fd == -1) {
		return err_map(errno);
	}
	int result = fpathconf_value(fd, name);
	close(fd);
	return result;
}

#define XNU_PC_CASE_SENSITIVE  11
#define XNU_PC_CASE_PRESERVING 12
#define XNU_PC_FILESIZEBITS    18
#define XNU_PC_SYMLINK_MAX     24
#define XNU_PC_XATTR_SIZE_BITS 26

static int
fpathconf_value(int fd, int name)
{
	switch (name) {
	case XNU_PC_CASE_SENSITIVE:
	case XNU_PC_CASE_PRESERVING:
		return 1;
	case XNU_PC_XATTR_SIZE_BITS:
		return 32;
	}

	int linux_name;
	if (name >= 1 && name <= 9) {
		linux_name = name - 1;
	} else if (name == XNU_PC_FILESIZEBITS) {
		linux_name = _PC_FILESIZEBITS;
	} else if (name == XNU_PC_SYMLINK_MAX) {
		linux_name = _PC_SYMLINK_MAX;
	} else {
		unimplemented();
	}

	errno = 0;
	long value = fpathconf(fd, linux_name);
	if (value == -1 && errno != 0) {
		return err_map(errno);
	}
	return value;
}

int
sys_sys_fpathconf(int fd, int name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fpathconf(%d, %d)\n", fd, name);
#endif
	return fpathconf_value(fd, name);
}

int
sys_getrlimit(uint32_t which, void *rlp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getrlimit(%p, %p)\n", (void *)which, (void *)rlp);
#endif
	int resource = rlimit_resource(which);
	if (resource == -1) {
		return _EINVAL;
	}

	struct rlimit limit;
	if (getrlimit(resource, &limit) == -1) {
		return err_map(errno);
	}
	uint64_t *darwin_limit = rlp;
	darwin_limit[0] = rlimit_to_darwin(limit.rlim_cur);
	darwin_limit[1] = rlimit_to_darwin(limit.rlim_max);
	return 0;
}

#define _RLIMIT_POSIX_FLAG 0x1000
#define _RLIM_INFINITY     0x7fffffffffffffffULL

static int
rlimit_resource(uint32_t which)
{
	static const int resources[] = {
			RLIMIT_CPU,
			RLIMIT_FSIZE,
			RLIMIT_DATA,
			RLIMIT_STACK,
			RLIMIT_CORE,
			RLIMIT_AS,
			RLIMIT_MEMLOCK,
			RLIMIT_NPROC,
			RLIMIT_NOFILE,
	};
	which &= ~_RLIMIT_POSIX_FLAG;
	return (which < sizeof(resources) / sizeof(resources[0]))
			? resources[which]
			: -1;
}

static uint64_t
rlimit_to_darwin(rlim_t value)
{
	return (value == RLIM_INFINITY) ? _RLIM_INFINITY : value;
}

static rlim_t
rlimit_from_darwin(uint64_t value)
{
	return (value >= _RLIM_INFINITY) ? RLIM_INFINITY : value;
}

int
sys_setrlimit(uint32_t which, void *rlp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setrlimit(%p, %p)\n", (void *)which, (void *)rlp);
#endif
	int resource = rlimit_resource(which);
	if (resource == -1) {
		return _EINVAL;
	}

	const uint64_t *darwin_limit = rlp;
	struct rlimit limit = {
			.rlim_cur = rlimit_from_darwin(darwin_limit[0]),
			.rlim_max = rlimit_from_darwin(darwin_limit[1]),
	};
	return errno_map(setrlimit(resource, &limit));
}

#ifndef __x86_64__
static void *
map_page_aligned(size_t len, int prot, int tflags, int fd, off_t pos)
{
	size_t span = ((len + PAGE_MASK) & ~(size_t)PAGE_MASK) + PAGE_SIZE;
	uint8_t *region = mmap(
			NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (region == MAP_FAILED) {
		return MAP_FAILED;
	}

	uint8_t *base = (uint8_t *)(((uintptr_t)region + PAGE_MASK)
			& ~(uintptr_t)PAGE_MASK);
	void *mapped = mmap(base, len, prot, tflags | MAP_FIXED, fd, pos);
	if (mapped == MAP_FAILED) {
		munmap(region, span);
		return MAP_FAILED;
	}

	if (base != region) {
		munmap(region, base - region);
	}
	uint8_t *tail = base + (span - PAGE_SIZE);
	munmap(tail, region + span - tail);
	return mapped;
}
#endif

user_addr_t
sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t pos)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mmap(%p, %p, %p, %p, %p, %p)\n", (void *)addr,
			(void *)len, (void *)prot, (void *)flags, (void *)fd,
			(void *)pos);
#endif
	int tflags = 0;
	if (flags & 1)
		tflags |= MAP_SHARED;
	if (flags & 2)
		tflags |= MAP_PRIVATE;
	if (flags & 0x10)
		tflags |= MAP_FIXED;
	if (flags & 0x1000)
		tflags |= MAP_ANON;

	if ((tflags & MAP_ANON) && (tflags & MAP_PRIVATE))
		tflags |= MAP_NORESERVE;

	/* TODO: Be responsible and convert the protection properly */
	void *r;
#ifdef __x86_64__
	r = mmap(addr, len, prot, tflags, fd, pos);
#else
	if (tflags & MAP_FIXED) {
		r = mmap(addr, len, prot, tflags, fd, pos);
	} else {
		r = map_page_aligned(len, prot, tflags, fd, pos);
	}
#endif
	if (r == MAP_FAILED) {
#ifdef ENABLE_STRACE
		perror("mmap");
#endif
		return (void *)err_map(errno);
	}
	return r;
}

#define _SEEK_SET 0
#define _SEEK_CUR 1
#define _SEEK_END 2

off_t
sys_lseek(int fd, off_t offset, int whence)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lseek(%p, %p, %p)\n", (void *)fd, (void *)offset,
			(void *)whence);
#endif
	int flags = 0;
	switch (whence) {
	case _SEEK_SET:
		flags = SEEK_SET;
		break;
	case _SEEK_CUR:
		flags = SEEK_CUR;
		break;
	case _SEEK_END:
		flags = SEEK_END;
		break;
	default:
		unimplemented();
	}

	return errno_map(lseek(fd, offset, flags));
}

int
sys_truncate(char *path, off_t length)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "truncate(%p, %p)\n", (void *)path, (void *)length);
#endif
	char buffer[PATH_MAX];
	return errno_map(truncate(sysroot_host_path(path, 0, buffer), length));
}

int
sys_ftruncate(int fd, off_t length)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "ftruncate(%p, %p)\n", (void *)fd, (void *)length);
#endif
	return errno_map(ftruncate(fd, length));
}

int
sys_mlock(void *addr, size_t len)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mlock(%p, %p)\n", (void *)addr, (void *)len);
#endif

	if (mlock(addr, len) == -1 && errno != ENOMEM && errno != EPERM) {
		return errno_map(-1);
	}
	return 0;
}

int
sys_munlock(void *addr, size_t len)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "munlock(%p, %p)\n", (void *)addr, (void *)len);
#endif
	return errno_map(munlock(addr, len));
}

int
sys_undelete(user_addr_t path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "undelete(%p)\n", (void *)path);
#endif
	unimplemented();
}

int
sys_open_dprotected_np(
		user_addr_t path, int flags, int class, int dpflags, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "open_dprotected_np(\"%s\", %p, %p, %p, %p)\n",
			(char *)path, (void *)flags, (void *)class,
			(void *)dpflags, (void *)mode);
#endif
	char buffer[PATH_MAX];
	return errno_map(open(
			sysroot_host_path(path, open_follow(flags), buffer),
			open_flags(flags), mode));
}

user_ssize_t
sys_fsgetpath_ext(user_addr_t buf, size_t bufsize, user_addr_t fsid,
		uint64_t objid, uint32_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fsgetpath_ext(%p, %p, %p, %p, %p)\n", (void *)buf,
			(void *)bufsize, (void *)fsid, (void *)objid,
			(void *)options);
#endif
	return fileid_path(objid, buf, bufsize);
}

int
sys_exchangedata(const char *path1, const char *path2, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "exchangedata(%p, %p, %p)\n", (void *)path1,
			(void *)path2, (void *)options);
#endif
	unimplemented();
}

int
sys_searchfs(const char *path, void *searchblock, uint32_t *nummatches,
		uint32_t scriptcode, uint32_t options, void *state)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "searchfs(%p, %p, %p, %p, %p, %p)\n", (void *)path,
			(void *)searchblock, (void *)nummatches,
			(void *)scriptcode, (void *)options, (void *)state);
#endif
	unimplemented();
}

int
sys_delete(user_addr_t path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "delete(%p)\n", (void *)path);
#endif
	unimplemented();
}

int
sys_copyfile(char *from, char *to, int mode, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "copyfile(%p, %p, %p, %p)\n", (void *)from, (void *)to,
			(void *)mode, (void *)flags);
#endif
	unimplemented();
}

int
sys_poll(void *fds, uint32_t nfds, int timeout)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "poll(%p, %p, %p)\n", (void *)fds, (void *)nfds,
			(void *)timeout);
#endif
	struct pollfd *guest = fds;
	struct pollfd *host = calloc((nfds > 0) ? nfds : 1, sizeof(*host));
	if (host == NULL) {
		return _ENOMEM;
	}
	for (uint32_t i = 0; i < nfds; i++) {
		host[i].fd = guest[i].fd;
		host[i].events = poll_events_to_linux(guest[i].events);
	}
	int result = poll(host, nfds, timeout);
	int err = errno;
	if (result != -1) {
		for (uint32_t i = 0; i < nfds; i++) {
			guest[i].revents = poll_events_from_linux(host[i].revents);
		}
	}
	free(host);
	return (result == -1) ? err_map(err) : result;
}

#define _POLLWRBAND 0x0100
#define POLL_COMMON (POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLRDBAND)

static short
poll_events_to_linux(short events)
{
	short result = events & POLL_COMMON;
	if (events & _POLLWRBAND) {
		result |= POLLWRBAND;
	}
	return result;
}

static short
poll_events_from_linux(short events)
{
	short result = events & (POLL_COMMON | POLLERR | POLLHUP | POLLNVAL);
	if (events & POLLWRNORM) {
		result |= POLLOUT;
	}
	if (events & POLLWRBAND) {
		result |= _POLLWRBAND;
	}
	return result;
}

int
sys_fsctl(const char *path, uint64_t cmd, void *data, uint32_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fsctl(\"%s\", %p, %p, %p)\n", path, (void *)cmd,
			(void *)data, (void *)options);
#endif
	return _ENOTTY;
}

int
sys_initgroups(uint32_t gidsetsize, void *gidset, int gmuid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "initgroups(%p, %p, %p)\n", (void *)gidsetsize,
			(void *)gidset, (void *)gmuid);
#endif
	return credentials_setgroups(gidsetsize, gidset);
}

int
sys_ffsctl(int fd, uint64_t cmd, void *data, uint32_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "ffsctl(%p, %p, %p, %p)\n", (void *)fd, (void *)cmd,
			(void *)data, (void *)options);
#endif
	return _ENOTTY;
}

int
sys_minherit(void *addr, size_t len, int inherit)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "minherit(%p, %p, %p)\n", (void *)addr, (void *)len,
			(void *)inherit);
#endif
	unimplemented();
}

int
sys_semsys(uint32_t which, int a2, int a3, int a4, int a5)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semsys(%p, %p, %p, %p, %p)\n", (void *)which,
			(void *)a2, (void *)a3, (void *)a4, (void *)a5);
#endif
	unimplemented();
}

int
sys_msgsys(uint32_t which, int a2, int a3, int a4, int a5)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "msgsys(%p, %p, %p, %p, %p)\n", (void *)which,
			(void *)a2, (void *)a3, (void *)a4, (void *)a5);
#endif
	unimplemented();
}

int
sys_shmsys(uint32_t which, int a2, int a3, int a4)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shmsys(%p, %p, %p, %p)\n", (void *)which, (void *)a2,
			(void *)a3, (void *)a4);
#endif
	unimplemented();
}

int
sys_semctl(int semid, int semnum, int cmd, void *arg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semctl(%p, %p, %p, %p)\n", (void *)semid,
			(void *)semnum, (void *)cmd, (void *)arg);
#endif
	unimplemented();
}

int
sys_semget(void *key, int nsems, int semflg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semget(%p, %p, %p)\n", (void *)key, (void *)nsems,
			(void *)semflg);
#endif
	unimplemented();
}

int
sys_semop(int semid, void *sops, int nsops)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semop(%p, %p, %p)\n", (void *)semid, (void *)sops,
			(void *)nsops);
#endif
	unimplemented();
}

int
sys_msgctl(int msqid, int cmd, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "msgctl(%p, %p, %p)\n", (void *)msqid, (void *)cmd,
			(void *)buf);
#endif
	unimplemented();
}

int
sys_msgget(void *key, int msgflg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "msgget(%p, %p)\n", (void *)key, (void *)msgflg);
#endif
	unimplemented();
}

int
sys_msgsnd(int msqid, void *msgp, size_t msgsz, int msgflg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "msgsnd(%p, %p, %p, %p)\n", (void *)msqid, (void *)msgp,
			(void *)msgsz, (void *)msgflg);
#endif
	unimplemented();
}

user_ssize_t
sys_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "msgrcv(%p, %p, %p, %p, %p)\n", (void *)msqid,
			(void *)msgp, (void *)msgsz, (void *)msgtyp,
			(void *)msgflg);
#endif
	unimplemented();
}

user_addr_t
sys_shmat(int shmid, void *shmaddr, int shmflg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shmat(%p, %p, %p)\n", (void *)shmid, (void *)shmaddr,
			(void *)shmflg);
#endif
	unimplemented();
}

int
sys_shmctl(int shmid, int cmd, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shmctl(%p, %p, %p)\n", (void *)shmid, (void *)cmd,
			(void *)buf);
#endif
	unimplemented();
}

int
sys_shmdt(void *shmaddr)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shmdt(%p)\n", (void *)shmaddr);
#endif
	unimplemented();
}

int
sys_shmget(void *key, size_t size, int shmflg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shmget(%p, %p, %p)\n", (void *)key, (void *)size,
			(void *)shmflg);
#endif
	unimplemented();
}

int
sys_shm_open(const char *name, int oflag, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shm_open(\"%s\", %p, %p)\n", name, (void *)oflag,
			(void *)mode);
#endif
	return errno_map(shm_open(name, open_flags(oflag), mode));
}

int
sys_shm_unlink(const char *name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shm_unlink(\"%s\")\n", name);
#endif
	return errno_map(shm_unlink(name));
}

#define SEMAPHORE_MAX 1024

static pthread_mutex_t semaphores_lock = PTHREAD_MUTEX_INITIALIZER;
static sem_t *semaphores[SEMAPHORE_MAX];

user_addr_t
sys_sem_open(const char *name, int oflag, int mode, int value)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sem_open(\"%s\", %p, %p, %p)\n", name,
			(void *)oflag, (void *)mode, (void *)value);
#endif
	sem_t *sem = sem_open(name, open_flags(oflag) & (O_CREAT | O_EXCL),
			(mode_t)mode, (unsigned int)value);
	if (sem == SEM_FAILED) {
		return (user_addr_t)(intptr_t)err_map(errno);
	}
	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd == -1 || fd >= SEMAPHORE_MAX) {
		if (fd != -1) {
			close(fd);
		}
		sem_close(sem);
		return (user_addr_t)(intptr_t)_EMFILE;
	}
	pthread_mutex_lock(&semaphores_lock);
	semaphores[fd] = sem;
	pthread_mutex_unlock(&semaphores_lock);
	return (user_addr_t)(intptr_t)fd;
}

int
sys_sem_close(void *handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sem_close(%p)\n", handle);
#endif
	uintptr_t fd = (uintptr_t)handle;
	if (fd >= SEMAPHORE_MAX) {
		return _EINVAL;
	}
	pthread_mutex_lock(&semaphores_lock);
	sem_t *sem = semaphores[fd];
	semaphores[fd] = NULL;
	pthread_mutex_unlock(&semaphores_lock);
	if (sem == NULL) {
		return _EINVAL;
	}
	sem_close(sem);
	close((int)fd);
	return 0;
}

int
sys_sem_unlink(const char *name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sem_unlink(\"%s\")\n", name);
#endif
	return errno_map(sem_unlink(name));
}

int
sys_sem_wait(void *handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sem_wait(%p)\n", handle);
#endif
	sem_t *sem = semaphore(handle);
	return sem != NULL ? errno_map(sem_wait(sem)) : _EINVAL;
}

int
sys_sem_trywait(void *handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sem_trywait(%p)\n", handle);
#endif
	sem_t *sem = semaphore(handle);
	return sem != NULL ? errno_map(sem_trywait(sem)) : _EINVAL;
}

int
sys_sem_post(void *handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sem_post(%p)\n", handle);
#endif
	sem_t *sem = semaphore(handle);
	return sem != NULL ? errno_map(sem_post(sem)) : _EINVAL;
}

static sem_t *
semaphore(void *handle)
{
	uintptr_t fd = (uintptr_t)handle;
	if (fd >= SEMAPHORE_MAX) {
		return NULL;
	}
	pthread_mutex_lock(&semaphores_lock);
	sem_t *sem = semaphores[fd];
	pthread_mutex_unlock(&semaphores_lock);
	return sem;
}

int
sys_open_extended(user_addr_t path, int flags, void *uid, void *gid, int mode,
		user_addr_t xsecurity)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "open_extended(%p, %p, %p, %p, %p, %p)\n", (void *)path,
			(void *)flags, (void *)uid, (void *)gid, (void *)mode,
			(void *)xsecurity);
#endif
	unimplemented();
}

int
sys_umask_extended(int newmask, user_addr_t xsecurity)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "umask_extended(%p, %p)\n", (void *)newmask,
			(void *)xsecurity);
#endif
	unimplemented();
}

int
sys_chmod_extended(user_addr_t path, void *uid, void *gid, int mode,
		user_addr_t xsecurity)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "chmod_extended(\"%s\", %p, %p, %p, %p)\n",
			(char *)path, (void *)uid, (void *)gid, (void *)mode,
			(void *)xsecurity);
#endif
	char buffer[PATH_MAX];
	const char *host_path = sysroot_host_path(path, 0, buffer);
	if (chown(host_path,
			    ((uid_t)(uintptr_t)uid == KAUTH_UID_NONE)
					    ? (uid_t)-1
					    : (uid_t)(uintptr_t)uid,
			    ((gid_t)(uintptr_t)gid == KAUTH_GID_NONE)
					    ? (gid_t)-1
					    : (gid_t)(uintptr_t)gid)
			== -1) {
		return err_map(errno);
	}
	if (mode == -1) {
		return 0;
	}
	return errno_map(chmod(host_path, mode & ALLPERMS));
}

int
sys_fchmod_extended(
		int fd, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fchmod_extended(%p, %p, %p, %p, %p)\n", (void *)fd,
			(void *)uid, (void *)gid, (void *)mode,
			(void *)xsecurity);
#endif
	if (fchown(fd, (uid == KAUTH_UID_NONE) ? (uid_t)-1 : uid,
			    (gid == KAUTH_GID_NONE) ? (gid_t)-1 : gid)
			== -1) {
		return err_map(errno);
	}
	if (mode == -1) {
		return 0;
	}
	return errno_map(fchmod(fd, mode & ALLPERMS));
}

int
sys_access_extended(user_addr_t entries, size_t size, user_addr_t results,
		void *uid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "access_extended(%p, %p, %p, %p)\n", (void *)entries,
			(void *)size, (void *)results, (void *)uid);
#endif
	struct accessx_descriptor {
		unsigned int ad_name_offset;
		int ad_flags;
		int ad_pad[2];
	};
	const struct accessx_descriptor *descriptors = entries;
	if (size < sizeof(*descriptors)
			|| descriptors[0].ad_name_offset < sizeof(*descriptors)
			|| descriptors[0].ad_name_offset >= size) {
		return _EINVAL;
	}
	size_t count = descriptors[0].ad_name_offset / sizeof(*descriptors);
	int *errors = results;
	const char *name = NULL;
	for (size_t i = 0; i < count; i++) {
		unsigned int offset = descriptors[i].ad_name_offset;
		if (offset != 0) {
			if (offset >= size) {
				return _EINVAL;
			}
			name = (const char *)entries + offset;
		}
		int flags = descriptors[i].ad_flags;
		int mode = F_OK;
		if (flags & (_R_OK | _ACCESS_READ_MASK)) {
			mode |= R_OK;
		}
		if (flags & (_W_OK | _ACCESS_WRITE_MASK)) {
			mode |= W_OK;
		}
		if (flags & (_X_OK | _ACCESS_EXECUTE_MASK)) {
			mode |= X_OK;
		}
		char buffer[PATH_MAX];
		int r = errno_map(access(
				sysroot_host_path(name, 0, buffer), mode));
		errors[i] = (r < 0) ? -r : 0;
	}
	return 0;
}

static __thread bool thread_identity;
static __thread uid_t thread_uid;
static __thread gid_t thread_gid;

int
sys_settid(void *uid, void *gid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "settid(%p, %p)\n", (void *)uid, (void *)gid);
#endif
	unimplemented();
}

int
sys_gettid(void *uidp, void *gidp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "gettid(%p, %p)\n", (void *)uidp, (void *)gidp);
#endif
	if (!thread_identity) {
		return _ESRCH;
	}
	*(uint32_t *)uidp = thread_uid;
	*(uint32_t *)gidp = thread_gid;
	return 0;
}

int
sys_setsgroups(int setlen, user_addr_t guidset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setsgroups(%p, %p)\n", (void *)setlen,
			(void *)guidset);
#endif
	unimplemented();
}

int
sys_getsgroups(user_addr_t setlen, user_addr_t guidset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getsgroups(%p, %p)\n", (void *)setlen,
			(void *)guidset);
#endif
	unimplemented();
}

int
sys_setwgroups(int setlen, user_addr_t guidset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setwgroups(%p, %p)\n", (void *)setlen,
			(void *)guidset);
#endif
	unimplemented();
}

int
sys_getwgroups(user_addr_t setlen, user_addr_t guidset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getwgroups(%p, %p)\n", (void *)setlen,
			(void *)guidset);
#endif
	unimplemented();
}

int
sys_mkfifo_extended(user_addr_t path, void *uid, void *gid, int mode,
		user_addr_t xsecurity)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mkfifo_extended(%p, %p, %p, %p, %p)\n", (void *)path,
			(void *)uid, (void *)gid, (void *)mode,
			(void *)xsecurity);
#endif
	unimplemented();
}

int
sys_mkdir_extended(user_addr_t path, void *uid, void *gid, int mode,
		user_addr_t xsecurity)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mkdir_extended(%p, %p, %p, %p, %p)\n", (void *)path,
			(void *)uid, (void *)gid, (void *)mode,
			(void *)xsecurity);
#endif
	unimplemented();
}

int
sys_shared_region_check_np(uint64_t *start_address)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shared_region_check_np(%p)\n", (void *)start_address);
#endif
	if (start_address == (uint64_t *)-1) {
		return 0;
	}

	*start_address = (uint64_t)shared_cache_start;
	return 0;
}

int
sys_vm_pressure_monitor(int wait_for_pressure, int nsecs_monitored,
		uint32_t *pages_reclaimed)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "vm_pressure_monitor(%p, %p, %p)\n",
			(void *)wait_for_pressure, (void *)nsecs_monitored,
			(void *)pages_reclaimed);
#endif
	unimplemented();
}

int
sys_getsid(uint64_t pid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getsid(%p)\n", (void *)pid);
#endif
	unimplemented();
}

int
sys_settid_with_pid(uint64_t pid, int assume)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "settid_with_pid(%p, %p)\n", (void *)pid,
			(void *)assume);
#endif
	unimplemented();
}

int
sys_aio_fsync(int op, user_addr_t aiocbp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "aio_fsync(%p, %p)\n", (void *)op, (void *)aiocbp);
#endif
	unimplemented();
}

user_ssize_t
sys_aio_return(user_addr_t aiocbp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "aio_return(%p)\n", (void *)aiocbp);
#endif
	unimplemented();
}

int
sys_aio_suspend(user_addr_t aiocblist, int nent, user_addr_t timeoutp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "aio_suspend(%p, %p, %p)\n", (void *)aiocblist,
			(void *)nent, (void *)timeoutp);
#endif
	unimplemented();
}

int
sys_aio_cancel(int fd, user_addr_t aiocbp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "aio_cancel(%p, %p)\n", (void *)fd, (void *)aiocbp);
#endif
	unimplemented();
}

int
sys_aio_error(user_addr_t aiocbp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "aio_error(%p)\n", (void *)aiocbp);
#endif
	unimplemented();
}

int
sys_aio_read(user_addr_t aiocbp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "aio_read(%p)\n", (void *)aiocbp);
#endif
	unimplemented();
}

int
sys_aio_write(user_addr_t aiocbp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "aio_write(%p)\n", (void *)aiocbp);
#endif
	unimplemented();
}

int
sys_lio_listio(int mode, user_addr_t aiocblist, int nent, user_addr_t sigp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lio_listio(%p, %p, %p, %p)\n", (void *)mode,
			(void *)aiocblist, (void *)nent, (void *)sigp);
#endif
	unimplemented();
}

int
sys_iopolicysys(int cmd, void *arg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "iopolicysys(%p, %p)\n", (void *)cmd, (void *)arg);
#endif
	struct {
		int32_t scope;
		int32_t type;
		int32_t policy;
	} *param = arg;
	if (cmd == 1) {
		param->policy = 0;
	}
	return 0;
}

int
sys_process_policy(int scope, int action, int policy, int policy_subtype,
		user_addr_t attrp, uint64_t target_pid,
		uint64_t target_threadid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "process_policy(%p, %p, %p, %p, %p, %p, %p)\n",
			(void *)scope, (void *)action, (void *)policy,
			(void *)policy_subtype, (void *)attrp,
			(void *)target_pid, (void *)target_threadid);
#endif

	enum {
		PROC_POLICY_ACTION_APPLY = 1,
		PROC_POLICY_ACTION_RESTORE = 2,
		PROC_POLICY_ACTION_ENABLE = 5,
		PROC_POLICY_ACTION_DISABLE = 6,
		PROC_POLICY_ACTION_SET = 10,
	};
	switch (action) {
	case PROC_POLICY_ACTION_APPLY:
	case PROC_POLICY_ACTION_RESTORE:
	case PROC_POLICY_ACTION_ENABLE:
	case PROC_POLICY_ACTION_DISABLE:
	case PROC_POLICY_ACTION_SET:
		return 0;
	default:
		unimplemented();
	}
}

int
sys_mlockall(int how)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mlockall(%p)\n", (void *)how);
#endif
	unimplemented();
}

int
sys_munlockall(int how)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "munlockall(%p)\n", (void *)how);
#endif
	unimplemented();
}

int
sys_issetugid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "issetugid()\n");
#endif
	return credentials_issetugid() ? 1 : 0;
}

int
sys___pthread_kill(int thread_port, int sig)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__pthread_kill(%p, %p)\n", (void *)thread_port,
			(void *)sig);
#endif
	struct thread *thread
			= ((mach_port_name_t)thread_port == thread_current()->port)
			? thread_current()
			: ipc_kobject_lookup(thread_port, IPC_KOBJECT_THREAD);
	if (thread == NULL || thread->tid == 0) {
		return _ESRCH;
	}
	int linux_sig = signo_to_linux(sig);
	if (sig != 0 && linux_sig == 0) {
		return _EINVAL;
	}
	return errno_map(tgkill(getpid(), thread->tid, linux_sig));
}

int
sys___pthread_sigmask(int how, user_addr_t set, user_addr_t oset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__pthread_sigmask(%p, %p, %p)\n", (void *)how,
			(void *)set, (void *)oset);
#endif
	return signals_mask(how, set, oset);
}

int
sys___sigwait(user_addr_t set, user_addr_t sig)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__sigwait(%p, %p)\n", (void *)set, (void *)sig);
#endif
	unimplemented();
}

int
sys___disable_threadsignal(int value)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__disable_threadsignal(%p)\n", (void *)value);
#endif
	sigset_t mask;
	sigfillset(&mask);
	sigdelset(&mask, SIGSYS);
	return -pthread_sigmask(SIG_BLOCK, &mask, NULL);
}

int
sys___pthread_markcancel(int thread_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__pthread_markcancel(%p)\n", (void *)thread_port);
#endif
	unimplemented();
}

int
sys___pthread_canceled(int action)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__pthread_canceled(%p)\n", (void *)action);
#endif

	switch (action) {
	case 1:
	case 2:
		return 0;
	default:
		return _EINVAL;
	}
}

int
sys___semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative,
		int64_t tv_sec, int32_t tv_nsec)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__semwait_signal(%p, %p, %p, %p, %p, %p)\n",
			(void *)cond_sem, (void *)mutex_sem, (void *)timeout,
			(void *)relative, (void *)tv_sec, (void *)tv_nsec);
#endif
	kern_return_t kr;
	if (timeout) {
		if (!relative) {
			struct timespec now;
			clock_gettime(CLOCK_REALTIME, &now);
			int64_t remaining = (tv_sec - now.tv_sec) * 1000000000LL
					+ (tv_nsec - now.tv_nsec);
			remaining = (remaining > 0) ? remaining : 0;
			tv_sec = remaining / 1000000000LL;
			tv_nsec = remaining % 1000000000LL;
		}
		mach_timespec_t interval
				= {.tv_sec = tv_sec, .tv_nsec = tv_nsec};
		kr = (mutex_sem != MACH_PORT_NULL)
				? semaphore_timedwait_signal(
						  cond_sem, mutex_sem, interval)
				: semaphore_timedwait(cond_sem, interval);
	} else {
		kr = (mutex_sem != MACH_PORT_NULL)
				? semaphore_wait_signal(cond_sem, mutex_sem)
				: semaphore_wait(cond_sem);
	}

	switch (kr) {
	case KERN_SUCCESS:
		return 0;
	case KERN_OPERATION_TIMED_OUT:
		return _ETIMEDOUT;
	case KERN_ABORTED:
		return _EINTR;
	default:
		return _EINVAL;
	}
}

int
sys_sendfile(int fd, int s, off_t offset, off_t *nbytes, void *hdtr, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sendfile(%p, %p, %p, %p, %p, %p)\n", (void *)fd,
			(void *)s, (void *)offset, (void *)nbytes, (void *)hdtr,
			(void *)flags);
#endif
	unimplemented();
}

static __thread bool thread_directory;

static int
thread_directory_change(int (*change)(const void *), const void *to)
{
	if (!thread_directory) {
		if (unshare(CLONE_FS) == -1) {
			return errno_map(-1);
		}
		thread_directory = true;
	}
	return errno_map(change(to));
}

static int
change_to_path(const void *path)
{
	return chdir(path);
}

static int
change_to_descriptor(const void *fd)
{
	return fchdir((int)(intptr_t)fd);
}

int
sys___pthread_chdir(user_addr_t path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__pthread_chdir(\"%s\")\n", (char *)path);
#endif
	char buffer[PATH_MAX];
	return thread_directory_change(change_to_path,
			sysroot_host_path(path, 0, buffer));
}

int
sys___pthread_fchdir(int fd)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__pthread_fchdir(%p)\n", (void *)fd);
#endif
	if (fd == -1) {
		if (!thread_directory) {
			return 0;
		}
		char path[64];
		snprintf(path, sizeof(path), "/proc/%d/cwd", getpid());
		return errno_map(chdir(path));
	}
	return thread_directory_change(change_to_descriptor,
			(const void *)(intptr_t)fd);
}

int
sys_audit(void *record, int length)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "audit(%p, %p)\n", (void *)record, (void *)length);
#endif
	unimplemented();
}

#define A_OLDGETCOND 20
#define A_GETCOND    37
#define AUC_NOAUDIT  2

int
sys_auditon(int cmd, void *data, int length)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "auditon(%p, %p, %p)\n", (void *)cmd, (void *)data,
			(void *)length);
#endif
	/* No audit daemon runs, so nothing is audited */
	switch (cmd) {
	case A_GETCOND:
		if (length != (int)sizeof(int32_t)) {
			return _EINVAL;
		}
		*(int32_t *)data = AUC_NOAUDIT;
		return 0;
	case A_OLDGETCOND:
		if (length != (int)sizeof(int64_t)) {
			return _EINVAL;
		}
		*(int64_t *)data = AUC_NOAUDIT;
		return 0;
	}
	unimplemented();
}

int
sys_getauid(void *auid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getauid(%p)\n", (void *)auid);
#endif
	unimplemented();
}

int
sys_setauid(void *auid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setauid(%p)\n", (void *)auid);
#endif
	unimplemented();
}

int
sys_getaudit_addr(void *auditinfo_addr, int length)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getaudit_addr(%p, %p)\n", (void *)auditinfo_addr,
			(void *)length);
#endif
	uint32_t *info = auditinfo_addr;
	memset(info, 0, length);
	info[0] = (uint32_t)-1;
	info[9] = 10;
	return 0;
}

int
sys_setaudit_addr(void *auditinfo_addr, int length)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setaudit_addr(%p, %p)\n", (void *)auditinfo_addr,
			(void *)length);
#endif
	unimplemented();
}

int
sys_auditctl(char *path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "auditctl(%p)\n", (void *)path);
#endif
	unimplemented();
}

int
sys_lchown(user_addr_t path, void *owner, void *group)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lchown(%p, %p, %p)\n", (void *)path, (void *)owner,
			(void *)group);
#endif
	char buffer[PATH_MAX];
	return errno_map(lchown(
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer),
			(uid_t)(uintptr_t)owner, (gid_t)(uintptr_t)group));
}

int
sys_ledger(int cmd, void *arg1, void *arg2, void *arg3)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "ledger(%p, %p, %p, %p)\n", (void *)cmd, (void *)arg1,
			(void *)arg2, (void *)arg3);
#endif
	unimplemented();
}

int
sys___mac_execve(char *fname, char **argp, char **envp, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_execve(%p, %p, %p, %p)\n", (void *)fname,
			(void *)argp, (void *)envp, (void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_get_file(char *path_p, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_get_file(%p, %p)\n", (void *)path_p,
			(void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_set_file(char *path_p, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_set_file(%p, %p)\n", (void *)path_p,
			(void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_get_link(char *path_p, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_get_link(%p, %p)\n", (void *)path_p,
			(void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_set_link(char *path_p, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_set_link(%p, %p)\n", (void *)path_p,
			(void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_get_proc(void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_get_proc(%p)\n", (void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_set_proc(void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_set_proc(%p)\n", (void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_get_fd(int fd, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_get_fd(%p, %p)\n", (void *)fd, (void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_set_fd(int fd, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_set_fd(%p, %p)\n", (void *)fd, (void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_get_pid(uint64_t pid, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_get_pid(%p, %p)\n", (void *)pid, (void *)mac_p);
#endif
	unimplemented();
}

int
sys_pselect(int nd, uint32_t *in, uint32_t *ou, uint32_t *ex, void *ts,
		void *mask)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pselect(%p, %p, %p, %p, %p, %p)\n", (void *)nd,
			(void *)in, (void *)ou, (void *)ex, (void *)ts,
			(void *)mask);
#endif
	/* TODO */
	return 0;
}

int
sys___mac_mount(char *type, char *path, int flags, void *data, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_mount(%p, %p, %p, %p, %p)\n", (void *)type,
			(void *)path, (void *)flags, (void *)data,
			(void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_get_mount(char *path, void *mac_p)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_get_mount(%p, %p)\n", (void *)path,
			(void *)mac_p);
#endif
	unimplemented();
}

int
sys___mac_getfsstat(user_addr_t buf, int bufsize, user_addr_t mac, int macsize,
		int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_getfsstat(%p, %p, %p, %p, %p)\n", (void *)buf,
			(void *)bufsize, (void *)mac, (void *)macsize,
			(void *)flags);
#endif
	unimplemented();
}

user_ssize_t
sys_fsgetpath(user_addr_t buf, size_t bufsize, user_addr_t fsid, uint64_t objid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fsgetpath(%p, %p, %p, %p)\n", (void *)buf,
			(void *)bufsize, (void *)fsid, (void *)objid);
#endif
	return fileid_path(objid, buf, bufsize);
}

mach_port_name_t
sys_audit_session_self(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "audit_session_self()\n");
#endif
	unimplemented();
}

int
sys_audit_session_join(mach_port_name_t port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "audit_session_join(%p)\n", (void *)port);
#endif
	unimplemented();
}

int
sys_sys_fileport_makeport(int fd, user_addr_t portnamep)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fileport_makeport(%p, %p)\n", (void *)fd,
			(void *)portnamep);
#endif
	int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (copy == -1) {
		return err_map(errno);
	}
	*(mach_port_name_t *)portnamep = ipc_fileport_alloc(copy);
	return 0;
}

int
sys_sys_fileport_makefd(mach_port_name_t port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fileport_makefd(%p)\n", (void *)port);
#endif
	int fd = ipc_fileport_fd(port);
	if (fd == -1) {
		return _EINVAL;
	}
	return errno_map(fcntl(fd, F_DUPFD, 0));
}

int
sys_audit_session_port(void *asid, user_addr_t portnamep)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "audit_session_port(%p, %p)\n", (void *)asid,
			(void *)portnamep);
#endif
	unimplemented();
}

int
sys_pid_suspend(int pid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pid_suspend(%p)\n", (void *)pid);
#endif
	return errno_map(kill(pid, SIGSTOP));
}

int
sys_pid_resume(int pid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pid_resume(%p)\n", (void *)pid);
#endif
	return errno_map(kill(pid, SIGCONT));
}

int
sys_pid_shutdown_sockets(int pid, int level)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pid_shutdown_sockets(%p, %p)\n", (void *)pid,
			(void *)level);
#endif

	return 0;
}

int
sys_shared_region_map_and_slide_np(int fd, uint32_t count, void *mappings,
		uint32_t slide, uint64_t *slide_start, uint32_t slide_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"shared_region_map_and_slide_np(%p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)fd, (void *)count, (void *)mappings,
			(void *)slide, (void *)slide_start, (void *)slide_size);
#endif
	/* Should never be called by dyld because we map the shared cache before
	 */
	unimplemented();
}

int
sys_kas_info(int selector, void *value, size_t *size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kas_info(%p, %p, %p)\n", (void *)selector,
			(void *)value, (void *)size);
#endif
	unimplemented();
}

int
sys_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags,
		user_addr_t buffer, size_t buffersize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "memorystatus_control(%p, %p, %p, %p, %p)\n",
			(void *)command, (void *)pid, (void *)flags,
			(void *)buffer, (void *)buffersize);
#endif
	if (buffer != NULL) {
		memset(buffer, 0, buffersize);
	}
	return 0;
}

int
sys_guarded_open_np(user_addr_t path, void *guard, uint32_t guardflags,
		int flags, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "guarded_open_np(%p, %p, %p, %p, %p)\n", (void *)path,
			(void *)guard, (void *)guardflags, (void *)flags,
			(void *)mode);
#endif
	return sys_open(path, flags, mode);
}

int
sys_guarded_close_np(int fd, void *guard)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "guarded_close_np(%p, %p)\n", (void *)fd,
			(void *)guard);
#endif
	return sys_sys_close(fd);
}

int
sys_guarded_kqueue_np(void *guard, uint32_t guardflags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "guarded_kqueue_np(%p, %p)\n", (void *)guard,
			(void *)guardflags);
#endif
	unimplemented();
}

int
sys_change_fdguard_np(int fd, void *guard, uint32_t guardflags, void *nguard,
		uint32_t nguardflags, int *fdflagsp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "change_fdguard_np(%p, %p, %p, %p, %p, %p)\n",
			(void *)fd, (void *)guard, (void *)guardflags,
			(void *)nguard, (void *)nguardflags, (void *)fdflagsp);
#endif

	int old = fcntl(fd, F_GETFD);
	if (old == -1) {
		return err_map(errno);
	}
	if (fdflagsp != NULL) {
		fcntl(fd, F_SETFD, (old & ~FD_CLOEXEC) | (*fdflagsp & FD_CLOEXEC));
		*fdflagsp = old & FD_CLOEXEC;
	}
	return 0;
}

int
sys_usrctl(uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "usrctl(%p)\n", (void *)flags);
#endif
	unimplemented();
}

int
sys_proc_rlimit_control(uint64_t pid, int flavor, void *arg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "proc_rlimit_control(%p, %p, %p)\n", (void *)pid,
			(void *)flavor, (void *)arg);
#endif

	return 0;
}

int
sys_coalition_policy_set(uint64_t cid, int flavor, uint32_t value)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "coalition_policy_set(%p, %p, %p)\n", (void *)cid,
			(void *)(intptr_t)flavor, (void *)(uintptr_t)value);
#endif
	return 0;
}

int
sys_connectx(int socket, void *endpoints, void *associd, void *flags, void *iov,
		void *iovcnt, size_t *len, void *connid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "connectx(%p, %p, %p, %p, %p, %p, %p, %p)\n",
			(void *)socket, (void *)endpoints, (void *)associd,
			(void *)flags, (void *)iov, (void *)iovcnt, (void *)len,
			(void *)connid);
#endif

	const struct {
		uint32_t source_interface;
		const void *source;
		uint32_t source_length;
		const void *destination;
		uint32_t destination_length;
	} *ends = endpoints;
	if (ends == NULL || ends->destination == NULL) {
		return _EINVAL;
	}
	if (ends->source != NULL && ends->source_length != 0) {
		int error = sys_bind(socket, (void *)ends->source,
				(void *)(uintptr_t)ends->source_length);
		if (error != 0) {
			return error;
		}
	}
	int result = sys_connect(socket, (void *)ends->destination,
			(void *)(uintptr_t)ends->destination_length);

	size_t sent = 0;
	unsigned int count = (unsigned int)(uintptr_t)iovcnt;
	if (result == 0 && iov != NULL && count != 0) {
		ssize_t written = writev(socket, iov, (int)count);
		if (written > 0) {
			sent = (size_t)written;
		}
	}
	if (len != NULL) {
		*len = sent;
	}
	if (connid != NULL) {
		*(uint32_t *)connid = 1;
	}
	return result;
}

int
sys_disconnectx(int s, void *aid, void *cid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "disconnectx(%p, %p, %p)\n", (void *)s, (void *)aid,
			(void *)cid);
#endif
	unimplemented();
}

int
sys_peeloff(int s, void *aid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "peeloff(%p, %p)\n", (void *)s, (void *)aid);
#endif
	unimplemented();
}

int
sys_socket_delegate(int domain, int type, int protocol, uint64_t epid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "socket_delegate(%p, %p, %p, %p)\n", (void *)domain,
			(void *)type, (void *)protocol, (void *)epid);
#endif
	unimplemented();
}

int
sys_telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval,
		uint64_t leeway, uint64_t arg4, uint64_t arg5)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "telemetry(%p, %p, %p, %p, %p, %p)\n", (void *)cmd,
			(void *)deadline, (void *)interval, (void *)leeway,
			(void *)arg4, (void *)arg5);
#endif
	unimplemented();
}

int
sys_proc_uuid_policy(
		uint32_t operation, void *uuid, size_t uuidlen, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "proc_uuid_policy(%p, %p, %p, %p)\n", (void *)operation,
			(void *)uuid, (void *)uuidlen, (void *)flags);
#endif
	unimplemented();
}

int
sys_memorystatus_get_level(user_addr_t level)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "memorystatus_get_level(%p)\n", (void *)level);
#endif

	unsigned long long total = 0, available = 0;
	FILE *meminfo = fopen("/proc/meminfo", "r");
	if (meminfo != NULL) {
		char line[256];
		while (fgets(line, sizeof(line), meminfo) != NULL) {
			sscanf(line, "MemTotal: %llu kB", &total);
			sscanf(line, "MemAvailable: %llu kB", &available);
		}
		fclose(meminfo);
	}
	*(int *)level = (total != 0) ? (int)(available * 100 / total) : 100;
	return 0;
}

int
sys_system_override(uint64_t timeout, uint64_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "system_override(%p, %p)\n", (void *)timeout,
			(void *)flags);
#endif

	return 0;
}

int
sys_vfs_purge(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "vfs_purge()\n");
#endif
	unimplemented();
}

int
sys_sfi_ctl(uint32_t operation, uint32_t sfi_class, uint64_t time,
		uint64_t *out_time)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sfi_ctl(%p, %p, %p, %p)\n", (void *)operation,
			(void *)sfi_class, (void *)time, (void *)out_time);
#endif
	unimplemented();
}

int
sys_sfi_pidctl(uint32_t operation, uint64_t pid, uint32_t sfi_flags,
		uint32_t *out_sfi_flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sfi_pidctl(%p, %p, %p, %p)\n", (void *)operation,
			(void *)pid, (void *)sfi_flags, (void *)out_sfi_flags);
#endif
	unimplemented();
}

int
sys_coalition(uint32_t operation, uint64_t *cid, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "coalition(%p, %p, %p)\n", (void *)operation,
			(void *)cid, (void *)flags);
#endif
	unimplemented();
}

int
sys_coalition_info(
		uint32_t flavor, uint64_t *cid, void *buffer, size_t *bufsize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "coalition_info(%p, %p, %p, %p)\n", (void *)flavor,
			(void *)cid, (void *)buffer, (void *)bufsize);
#endif
	unimplemented();
}

int
sys_clonefileat(int src_dirfd, user_addr_t src, int dst_dirfd, user_addr_t dst,
		uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "clonefileat(%p, %p, %p, %p, %p)\n", (void *)src_dirfd,
			(void *)src, (void *)dst_dirfd, (void *)dst,
			(void *)flags);
#endif
	char buffer[PATH_MAX];
	const char *host = sysroot_host_path(src,
			(flags & _CLONE_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0,
			buffer);
	struct stat st;
	if (fstatat(at_fd(src_dirfd), host, &st,
			    (flags & _CLONE_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0)
			== -1) {
		return err_map(errno);
	}
	char dst_buffer[PATH_MAX];
	const char *dst_host = sysroot_host_path(dst, 0, dst_buffer);
	if (S_ISLNK(st.st_mode)) {
		char target[PATH_MAX];
		ssize_t length = readlinkat(at_fd(src_dirfd), host, target,
				sizeof(target) - 1);
		if (length == -1) {
			return err_map(errno);
		}
		target[length] = '\0';
		return errno_map(symlinkat(target, at_fd(dst_dirfd), dst_host));
	}
	int fd = openat(at_fd(src_dirfd), host, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return err_map(errno);
	}
	int result = clone_file(fd, at_fd(dst_dirfd), dst_host, flags);
	close(fd);
	return result;
}

int
sys_openat(int fd, user_addr_t path, int flags, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "openat(%p, \"%s\", %p, %p)\n", (void *)fd,
			(char *)path, (void *)flags, (void *)mode);
#endif
	if (fsevents_is_device_path(path)) {
		return fsevents_open(flags & _O_CLOEXEC);
	}
	char buffer[PATH_MAX];
	return errno_map(openat(at_fd(fd),
			sysroot_host_path(path, open_follow(flags), buffer),
			open_flags(flags), mode));
}

int
sys_renameat(int fromfd, char *from, int tofd, char *to)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "renameat(%p, \"%s\", %p, \"%s\")\n", (void *)fromfd,
			from, (void *)tofd, to);
#endif
	return sys_renameatx_np(fromfd, from, tofd, to, 0);
}

int
sys_faccessat(int fd, user_addr_t path, int amode, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "faccessat(%p, %p, %p, %p)\n", (void *)fd, (void *)path,
			(void *)amode, (void *)flag);
#endif
	char buffer[PATH_MAX];
	int flags = at_flags(flag);
	return errno_map(faccessat(at_fd(fd),
			sysroot_host_path(path, flags, buffer), amode, flags));
}

int
sys_fchmodat(int fd, user_addr_t path, int mode, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fchmodat(%p, %p, %p, %p)\n", (void *)fd, (void *)path,
			(void *)mode, (void *)flag);
#endif
	char buffer[PATH_MAX];
	int flags = at_flags(flag);
	return errno_map(fchmodat(at_fd(fd),
			sysroot_host_path(path, flags, buffer), mode, flags));
}

int
sys_fchownat(int fd, user_addr_t path, void *uid, void *gid, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fchownat(%p, %p, %p, %p, %p)\n", (void *)fd,
			(void *)path, (void *)uid, (void *)gid, (void *)flag);
#endif
	char buffer[PATH_MAX];
	int flags = at_flags(flag);
	return errno_map(fchownat(at_fd(fd),
			sysroot_host_path(path, flags, buffer),
			(uid_t)(uintptr_t)uid, (gid_t)(uintptr_t)gid, flags));
}

int
sys_linkat(int fd1, user_addr_t path, int fd2, user_addr_t link, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "linkat(%p, %p, %p, %p, %p)\n", (void *)fd1,
			(void *)path, (void *)fd2, (void *)link, (void *)flag);
#endif
	char path_buffer[PATH_MAX], link_buffer[PATH_MAX];
	int flags = at_flags(flag);
	return errno_map(linkat(at_fd(fd1),
			sysroot_host_path(path,
					(flags & AT_SYMLINK_FOLLOW)
							? 0
							: AT_SYMLINK_NOFOLLOW,
					path_buffer),
			at_fd(fd2),
			sysroot_host_path(
					link, AT_SYMLINK_NOFOLLOW, link_buffer),
			flags));
}

int
sys_unlinkat(int fd, user_addr_t path, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "unlinkat(%p, %p, %p)\n", (void *)fd, (void *)path,
			(void *)flag);
#endif
	char buffer[PATH_MAX];
	return errno_map(unlinkat(at_fd(fd),
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer),
			at_flags(flag)));
}

int
sys_readlinkat(int fd, user_addr_t path, user_addr_t buf, size_t bufsize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "readlinkat(%p, %p, %p, %p)\n", (void *)fd,
			(void *)path, (void *)buf, (void *)bufsize);
#endif
	char buffer[PATH_MAX];
	return errno_map(readlinkat(at_fd(fd),
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer),
			buf, bufsize));
}

int
sys_symlinkat(user_addr_t *path1, int fd, user_addr_t path2)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "symlinkat(%p, %p, %p)\n", (void *)path1, (void *)fd,
			(void *)path2);
#endif
	char buffer[PATH_MAX];
	return errno_map(symlinkat((const char *)path1, at_fd(fd),
			sysroot_host_path(path2, AT_SYMLINK_NOFOLLOW, buffer)));
}

int
sys_mkdirat(int fd, user_addr_t path, int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mkdirat(%p, \"%s\", %p)\n", (void *)fd, (char *)path,
			(void *)mode);
#endif
	char buffer[PATH_MAX];
	return errno_map(mkdirat(at_fd(fd),
			sysroot_host_path(path, AT_SYMLINK_NOFOLLOW, buffer),
			mode));
}

int
sys_proc_trace_log(uint64_t pid, uint64_t uniqueid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "proc_trace_log(%p, %p)\n", (void *)pid,
			(void *)uniqueid);
#endif
	unimplemented();
}

int
sys_openbyid_np(user_addr_t fsid, user_addr_t objid, int oflags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "openbyid_np(%p, %p, %p)\n", (void *)fsid,
			(void *)objid, (void *)oflags);
#endif
	unimplemented();
}

user_ssize_t
sys_recvmsg_x(int s, void *msgp, uint32_t cnt, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "recvmsg_x(%p, %p, %p, %p)\n", (void *)s, (void *)msgp,
			(void *)cnt, (void *)flags);
#endif
	unimplemented();
}

user_ssize_t
sys_sendmsg_x(int s, void *msgp, uint32_t cnt, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sendmsg_x(%p, %p, %p, %p)\n", (void *)s, (void *)msgp,
			(void *)cnt, (void *)flags);
#endif
	unimplemented();
}

uint64_t
sys_thread_selfusage(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_selfusage()\n");
#endif

	struct timespec time;
	syscall(SYS_clock_gettime, CLOCK_THREAD_CPUTIME_ID, &time);
	return (uint64_t)time.tv_sec * 1000000000 + (uint64_t)time.tv_nsec;
}

int
sys_guarded_open_dprotected_np(user_addr_t path, void *guard,
		uint32_t guardflags, int flags, int dpclass, int dpflags,
		int mode)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"guarded_open_dprotected_np(%p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)path, (void *)guard, (void *)guardflags,
			(void *)flags, (void *)dpclass, (void *)dpflags,
			(void *)mode);
#endif
	unimplemented();
}

user_ssize_t
sys_guarded_write_np(int fd, void *guard, user_addr_t cbuf, user_size_t nbyte)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "guarded_write_np(%p, %p, %p, %p)\n", (void *)fd,
			(void *)guard, (void *)cbuf, (void *)nbyte);
#endif
	return sys_write(fd, cbuf, nbyte);
}

user_ssize_t
sys_guarded_pwrite_np(int fd, void *guard, user_addr_t buf, user_size_t nbyte,
		off_t offset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "guarded_pwrite_np(%p, %p, %p, %p, %p)\n", (void *)fd,
			(void *)guard, (void *)buf, (void *)nbyte,
			(void *)offset);
#endif
	return sys_pwrite(fd, buf, nbyte, offset);
}

user_ssize_t
sys_guarded_writev_np(int fd, void *guard, void *iovp, int iovcnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "guarded_writev_np(%p, %p, %p, %p)\n", (void *)fd,
			(void *)guard, (void *)iovp, (void *)iovcnt);
#endif
	return sys_writev(fd, iovp, iovcnt);
}

int
sys_renameatx_np(int fromfd, char *from, int tofd, char *to, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "renameatx_np(%p, %p, %p, %p, %p)\n", (void *)fromfd,
			(void *)from, (void *)tofd, (void *)to, (void *)flags);
#endif
	char from_buffer[PATH_MAX], to_buffer[PATH_MAX];
	return errno_map(renameat2(at_fd(fromfd),
			sysroot_host_path(
					from, AT_SYMLINK_NOFOLLOW, from_buffer),
			at_fd(tofd),
			sysroot_host_path(to, AT_SYMLINK_NOFOLLOW, to_buffer),
			rename_flags(flags)));
}

#define _RENAME_SWAP 0x00000002
#define _RENAME_EXCL 0x00000004

static unsigned int
rename_flags(uint32_t flags)
{
	unsigned int result = 0;
	if (flags & _RENAME_SWAP) {
		result |= RENAME_EXCHANGE;
	}
	if (flags & _RENAME_EXCL) {
		result |= RENAME_NOREPLACE;
	}
	return result;
}

int
sys_mremap_encrypted(void *addr, size_t len, uint32_t cryptid, uint32_t cputype,
		uint32_t cpusubtype)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mremap_encrypted(%p, %p, %p, %p, %p)\n", (void *)addr,
			(void *)len, (void *)cryptid, (void *)cputype,
			(void *)cpusubtype);
#endif
	unimplemented();
}

int
sys_netagent_trigger(void *agent_uuid, size_t agent_uuidlen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "netagent_trigger(%p, %p)\n", (void *)agent_uuid,
			(void *)agent_uuidlen);
#endif
	unimplemented();
}

int
sys_stack_snapshot_with_config(int stackshot_config_version,
		user_addr_t stackshot_config, size_t stackshot_config_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stack_snapshot_with_config(%p, %p, %p)\n",
			(void *)stackshot_config_version,
			(void *)stackshot_config,
			(void *)stackshot_config_size);
#endif
	unimplemented();
}

int
sys_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "microstackshot(%p, %p, %p)\n", (void *)tracebuf,
			(void *)tracebuf_size, (void *)flags);
#endif
	unimplemented();
}

int
sys_persona(uint32_t operation, uint32_t flags, void *info, void *id,
		size_t *idlen, char *path)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "persona(%p, %p, %p, %p, %p, %p)\n", (void *)operation,
			(void *)flags, (void *)info, (void *)id, (void *)idlen,
			(void *)path);
#endif
	return persona_syscall(operation, flags, info, id, idlen, path);
}

uint64_t
sys_mach_eventlink_signal(
		mach_port_name_t eventlink_port, uint64_t signal_count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_eventlink_signal(%p, %p)\n",
			(void *)eventlink_port, (void *)signal_count);
#endif
	unimplemented();
}

uint64_t
sys_mach_eventlink_wait_until(mach_port_name_t eventlink_port,
		uint64_t wait_count, uint64_t deadline, uint32_t clock_id,
		uint32_t option)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_eventlink_wait_until(%p, %p, %p, %p, %p)\n",
			(void *)eventlink_port, (void *)wait_count,
			(void *)deadline, (void *)clock_id, (void *)option);
#endif
	unimplemented();
}

uint64_t
sys_mach_eventlink_signal_wait_until(mach_port_name_t eventlink_port,
		uint64_t wait_count, uint64_t signal_count, uint64_t deadline,
		uint32_t clock_id, uint32_t option)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_eventlink_signal_wait_until(%p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)eventlink_port, (void *)wait_count,
			(void *)signal_count, (void *)deadline,
			(void *)clock_id, (void *)option);
#endif
	unimplemented();
}

int
sys_work_interval_ctl(uint32_t operation, uint64_t work_interval_id, void *arg,
		size_t len)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "work_interval_ctl(%p, %p, %p, %p)\n",
			(void *)operation, (void *)work_interval_id,
			(void *)arg, (void *)len);
#endif
	unimplemented();
}

int
sys_getentropy(void *buffer, size_t size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getentropy(%p, %p)\n", (void *)buffer, (void *)size);
#endif
	return getentropy(buffer, size);
}

int
sys_fclonefileat(int src_fd, int dst_dirfd, user_addr_t dst, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fclonefileat(%p, %p, %p, %p)\n", (void *)src_fd,
			(void *)dst_dirfd, (void *)dst, (void *)flags);
#endif
	char buffer[PATH_MAX];
	return clone_file(src_fd, at_fd(dst_dirfd),
			sysroot_host_path(dst, 0, buffer), flags);
}

static int
clone_file(int src_fd, int dst_dirfd, const char *dst_host, uint32_t flags)
{
	struct stat st;
	if (fstat(src_fd, &st) == -1) {
		return err_map(errno);
	}
	if (!S_ISREG(st.st_mode)) {
		return S_ISDIR(st.st_mode) ? _ENOTSUP : _EINVAL;
	}
	int dst_fd = openat(dst_dirfd, dst_host,
			O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
			st.st_mode & 07777);
	if (dst_fd == -1) {
		return err_map(errno);
	}
	int error = 0;
	if (ioctl(dst_fd, FICLONE, src_fd) == -1) {
		off_t in = 0, out = 0;
		while (in < st.st_size) {
			ssize_t copied = copy_file_range(src_fd, &in, dst_fd,
					&out, st.st_size - in, 0);
			if (copied <= 0) {
				char chunk[65536];
				ssize_t n = pread(
						src_fd, chunk, sizeof(chunk), in);
				if (n <= 0 || pwrite(dst_fd, chunk, n, out) != n) {
					error = (n < 0) ? errno : EIO;
					break;
				}
				in += n;
				out += n;
			}
		}
	}
	if (error == 0) {
		char names[4096];
		ssize_t length = flistxattr(src_fd, names, sizeof(names));
		for (ssize_t i = 0; i < length; i += strlen(names + i) + 1) {
			char value[65536];
			ssize_t size = fgetxattr(
					src_fd, names + i, value, sizeof(value));
			if (size >= 0) {
				fsetxattr(dst_fd, names + i, value, size, 0);
			}
		}
		if (!(flags & _CLONE_NOOWNERCOPY) && geteuid() == 0) {
			fchown(dst_fd, st.st_uid, st.st_gid);
		}
		struct timespec times[2] = {st.st_atim, st.st_mtim};
		futimens(dst_fd, times);
	}
	close(dst_fd);
	if (error != 0) {
		unlinkat(dst_dirfd, dst_host, 0);
		return err_map(error);
	}
	return 0;
}

int
sys_fs_snapshot(uint32_t op, int dirfd, user_addr_t name1, user_addr_t name2,
		user_addr_t data, uint32_t flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fs_snapshot(%p, %p, %p, %p, %p, %p)\n", (void *)op,
			(void *)dirfd, (void *)name1, (void *)name2,
			(void *)data, (void *)flags);
#endif
	unimplemented();
}

int
sys_terminate_with_payload(int pid, uint32_t reason_namespace,
		uint64_t reason_code, void *payload, uint32_t payload_size,
		const char *reason_string, uint64_t reason_flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "terminate_with_payload(%p, %p, %p, %p, %p, %p, %p)\n",
			(void *)pid, (void *)reason_namespace,
			(void *)reason_code, (void *)payload,
			(void *)payload_size, (void *)reason_string,
			(void *)reason_flags);
#endif
	if (pid == getpid()) {
		sys_abort_with_payload(reason_namespace, reason_code, payload,
				payload_size, reason_string, reason_flags);
	}

	return errno_map(kill(pid, SIGKILL));
}

int __attribute__((noreturn)) sys_abort_with_payload(uint32_t reason_namespace,
		uint64_t reason_code, void *payload, uint32_t payload_size,
		const char *reason_string, uint64_t reason_flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "abort_with_payload(%p, %p, %p, %p, %p, %p)\n",
			(void *)reason_namespace, (void *)reason_code,
			(void *)payload, (void *)payload_size,
			(void *)reason_string, (void *)reason_flags);
#endif
	unimplemented();
}

int
sys_net_qos_guideline(void *param, uint32_t param_len)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "net_qos_guideline(%p, %p)\n", (void *)param,
			(void *)param_len);
#endif
	unimplemented();
}

int
sys_fmount(const char *type, int fd, int flags, void *data)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fmount(%p, %p, %p, %p)\n", (void *)type, (void *)fd,
			(void *)flags, (void *)data);
#endif
	unimplemented();
}

int
sys_ntp_adjtime(void *tp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "ntp_adjtime(%p)\n", (void *)tp);
#endif
	unimplemented();
}

int
sys_ntp_gettime(void *ntvp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "ntp_gettime(%p)\n", (void *)ntvp);
#endif
	unimplemented();
}

int
sys_os_fault_with_payload(uint32_t reason_namespace, uint64_t reason_code,
		void *payload, uint32_t payload_size, const char *reason_string,
		uint64_t reason_flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "os_fault_with_payload(%p, %p, %p, %p, %p, %p)\n",
			(void *)reason_namespace, (void *)reason_code,
			(void *)payload, (void *)payload_size,
			(void *)reason_string, (void *)reason_flags);
#endif

	fprintf(stderr, "limbo: abort, namespace %u, code %#llx: %s\n",
			reason_namespace, (unsigned long long)reason_code,
			reason_string != NULL ? reason_string : "");
	signal(SIGABRT, SIG_DFL);
	sigset_t abort_set;
	sigemptyset(&abort_set);
	sigaddset(&abort_set, SIGABRT);
	pthread_sigmask(SIG_UNBLOCK, &abort_set, NULL);
	raise(SIGABRT);
	_exit(134);
}

uint64_t
sys___mach_bridge_remote_time(uint64_t local_timestamp)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mach_bridge_remote_time(%p)\n",
			(void *)local_timestamp);
#endif
	unimplemented();
}

int
sys_coalition_ledger(uint32_t operation, uint64_t *cid, void *buffer,
		size_t *bufsize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "coalition_ledger(%p, %p, %p, %p)\n", (void *)operation,
			(void *)cid, (void *)buffer, (void *)bufsize);
#endif
	unimplemented();
}

int
sys_log_data(void *tag, void *flags, void *buffer, void *size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "log_data(%p, %p, %p, %p)\n", (void *)tag,
			(void *)flags, (void *)buffer, (void *)size);
#endif
	unimplemented();
}

uint64_t
sys_memorystatus_available_memory(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "memorystatus_available_memory()\n");
#endif
	unimplemented();
}

int
sys_shared_region_map_and_slide_2_np(uint32_t files_count, void *files,
		uint32_t mappings_count, void *mappings)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "shared_region_map_and_slide_2_np(%p, %p, %p, %p)\n",
			(void *)files_count, (void *)files,
			(void *)mappings_count, (void *)mappings);
#endif
	unimplemented();
}

int
sys_pivot_root(const char *new_rootfs_path_before,
		const char *old_rootfs_path_after)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pivot_root(%p, %p)\n", (void *)new_rootfs_path_before,
			(void *)old_rootfs_path_after);
#endif
	unimplemented();
}

int
sys_task_inspect_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *t)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_inspect_for_pid(%p, %p, %p)\n",
			(void *)target_tport, (void *)pid, (void *)t);
#endif
	unimplemented();
}

int
sys_task_read_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *t)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_read_for_pid(%p, %p, %p)\n", (void *)target_tport,
			(void *)pid, (void *)t);
#endif

	if (pid == getpid()) {
		*t = ipc_task_self();
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

user_ssize_t
sys_sys_preadv(int fd, void *iovp, int iovcnt, off_t offset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_preadv(%p, %p, %p, %p)\n", (void *)fd,
			(void *)iovp, (void *)iovcnt, (void *)offset);
#endif
	unimplemented();
}

user_ssize_t
sys_sys_pwritev(int fd, void *iovp, int iovcnt, off_t offset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_pwritev(%p, %p, %p, %p)\n", (void *)fd,
			(void *)iovp, (void *)iovcnt, (void *)offset);
#endif
	unimplemented();
}

int
sys_proc_info_extended_id(int32_t callnum, int32_t pid, uint32_t flavor,
		uint32_t flags, uint64_t ext_id, uint64_t arg,
		user_addr_t buffer, int32_t buffersize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"proc_info_extended_id(%p, %p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)callnum, (void *)pid, (void *)flavor,
			(void *)flags, (void *)ext_id, (void *)arg,
			(void *)buffer, (void *)buffersize);
#endif
	return sys_proc_info(callnum, pid, flavor, arg, buffer, buffersize);
}

uint64_t
sys_bsd(unsigned long syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t *sp)
{
	current_syscall = syscall;
	switch (syscall) {
	case 0x0:
		return sys_bsd(arg1, arg2, arg3, arg4, arg5, arg6, sp[1],
				sp + 1);
	case 0x1:
		return sys_exit(arg1);
	case 0x2:
		return sys_fork();
	case 0x3:
	case 0x18c: /* $nocancel */
		return sys_read(arg1, (void *)arg2, arg3);
	case 0x4:
	case 0x18d: /* $nocancel */
		return sys_write(arg1, (void *)arg2, arg3);
	case 0x5:
	case 0x18e: /* $nocancel */
		return sys_open((void *)arg1, arg2, arg3);
	case 0x6:
	case 0x18f: /* $nocancel */
		return sys_sys_close(arg1);
	case 0x7:
	case 0x190: /* $nocancel */
		return sys_wait4(arg1, (void *)arg2, arg3, (void *)arg4);
	case 0x8:
		return sys_enosys();
	case 0x9:
		return sys_link((void *)arg1, (void *)arg2);
	case 0xa:
		return sys_unlink((void *)arg1);
	case 0xb:
		return sys_enosys();
	case 0xc:
		return sys_chdir((void *)arg1);
	case 0xd:
		return sys_fchdir(arg1);
	case 0xe:
		return sys_mknod((void *)arg1, arg2, arg3);
	case 0xf:
		return sys_chmod((void *)arg1, arg2);
	case 0x10:
		return sys_chown((void *)arg1, arg2, arg3);
	case 0x11:
		return sys_enosys();
	case 0x12:
		return sys_getfsstat((void *)arg1, arg2, arg3);
	case 0x13:
		return sys_enosys();
	case 0x14:
		return sys_getpid();
	case 0x15:
		return sys_enosys();
	case 0x16:
		return sys_enosys();
	case 0x17:
		return sys_setuid((void *)arg1);
	case 0x18:
		return sys_getuid();
	case 0x19:
		return sys_geteuid();
	case 0x1a:
		return sys_ptrace(arg1, arg2, (void *)arg3, arg4);
	case 0x1b:
	case 0x191: /* $nocancel */
		return sys_recvmsg(arg1, (void *)arg2, arg3);
	case 0x1c:
	case 0x192: /* $nocancel */
		return sys_sendmsg(arg1, (void *)arg2, arg3);
	case 0x1d:
	case 0x193: /* $nocancel */
		return sys_recvfrom(arg1, (void *)arg2, arg3, arg4,
				(void *)arg5, (void *)arg6);
	case 0x1e:
	case 0x194: /* $nocancel */
		return sys_accept(arg1, (void *)arg2, (void *)arg3);
	case 0x1f:
		return sys_getpeername(arg1, (void *)arg2, (void *)arg3);
	case 0x20:
		return sys_getsockname(arg1, (void *)arg2, (void *)arg3);
	case 0x21:
		return sys_access((void *)arg1, arg2);
	case 0x22:
		return sys_chflags((void *)arg1, arg2);
	case 0x23:
		return sys_fchflags(arg1, arg2);
	case 0x24:
		return sys_sync();
	case 0x25:
		return sys_kill(arg1, arg2, arg3);
	case 0x26:
		return _ENOSYS;
	case 0x27:
		return sys_getppid();
	case 0x28:
		return sys_nosys();
	case 0x29:
		return sys_sys_dup(arg1);
	case 0x2a:
		return sys_pipe((void *)arg1);
	case 0x2b:
		return sys_getegid();
	case 0x2c:
		return sys_nosys();
	case 0x2d:
		return sys_nosys();
	case 0x2e:
		return sys_sigaction(arg1, (void *)arg2, (void *)arg3);
	case 0x2f:
		return sys_getgid();
	case 0x30:
		return sys_sigprocmask(arg1, (void *)arg2, (void *)arg3);
	case 0x31:
		return sys_getlogin((void *)arg1, arg2);
	case 0x32:
		return sys_setlogin((void *)arg1);
	case 0x33:
		return sys_acct((void *)arg1);
	case 0x34:
		return sys_sigpending((void *)arg1);
	case 0x35:
		return sys_sigaltstack((void *)arg1, (void *)arg2);
	case 0x36:
		return sys_ioctl(arg1, arg2, (void *)arg3);
	case 0x37:
		return sys_reboot(arg1, (void *)arg2);
	case 0x38:
		return sys_revoke((void *)arg1);
	case 0x39:
		return sys_symlink((void *)arg1, (void *)arg2);
	case 0x3a:
		return sys_readlink((void *)arg1, (void *)arg2, arg3);
	case 0x3b:
		return sys_execve((void *)arg1, (void *)arg2, (void *)arg3);
	case 0x3c:
		return sys_umask(arg1);
	case 0x3d:
		return sys_chroot((void *)arg1);
	case 0x3e:
		return sys_nosys();
	case 0x3f:
		return sys_nosys();
	case 0x40:
		return sys_nosys();
	case 0x41:
	case 0x195: /* $nocancel */
		return sys_msync((void *)arg1, arg2, arg3);
	case 0x42:
		return sys_vfork();
	case 0x43:
		return sys_nosys();
	case 0x44:
		return sys_nosys();
	case 0x45:
		return sys_nosys();
	case 0x46:
		return sys_nosys();
	case 0x47:
		return sys_nosys();
	case 0x48:
		return sys_nosys();
	case 0x49:
		return sys_munmap((void *)arg1, arg2);
	case 0x4a:
		return sys_mprotect((void *)arg1, arg2, arg3);
	case 0x4b:
		return sys_madvise((void *)arg1, arg2, arg3);
	case 0x4c:
		return sys_nosys();
	case 0x4d:
		return sys_nosys();
	case 0x4e:
		return sys_mincore((void *)arg1, arg2, (void *)arg3);
	case 0x4f:
		return sys_getgroups(arg1, (void *)arg2);
	case 0x50:
		return sys_setgroups(arg1, (void *)arg2);
	case 0x51:
		return sys_getpgrp();
	case 0x52:
		return sys_setpgid(arg1, arg2);
	case 0x53:
		return sys_setitimer(arg1, (void *)arg2, (void *)arg3);
	case 0x54:
		return sys_nosys();
	case 0x55:
		return sys_swapon();
	case 0x56:
		return sys_getitimer(arg1, (void *)arg2);
	case 0x57:
		return sys_nosys();
	case 0x58:
		return sys_nosys();
	case 0x59:
		return sys_sys_getdtablesize();
	case 0x5a:
		return sys_sys_dup2(arg1, arg2);
	case 0x5b:
		return sys_nosys();
	case 0x5c:
	case 0x196: /* $nocancel */
		return sys_sys_fcntl(arg1, arg2, arg3);
	case 0x5d:
	case 0x197: /* $nocancel */
		return sys_select(arg1, (void *)arg2, (void *)arg3,
				(void *)arg4, (void *)arg5);
	case 0x5e:
		return sys_nosys();
	case 0x5f:
	case 0x198: /* $nocancel */
		return sys_fsync(arg1);
	case 0x60:
		return sys_setpriority(arg1, (void *)arg2, arg3);
	case 0x61:
		return sys_socket(arg1, arg2, arg3);
	case 0x62:
	case 0x199: /* $nocancel */
		return sys_connect(arg1, (void *)arg2, (void *)arg3);
	case 0x63:
		return sys_nosys();
	case 0x64:
		return sys_getpriority(arg1, (void *)arg2);
	case 0x65:
		return sys_nosys();
	case 0x66:
		return sys_nosys();
	case 0x67:
		return sys_nosys();
	case 0x68:
		return sys_bind(arg1, (void *)arg2, (void *)arg3);
	case 0x69:
		return sys_setsockopt(
				arg1, arg2, arg3, (void *)arg4, (void *)arg5);
	case 0x6a:
		return sys_listen(arg1, arg2);
	case 0x6b:
		return sys_nosys();
	case 0x6c:
		return sys_nosys();
	case 0x6d:
		return sys_nosys();
	case 0x6e:
		return sys_nosys();
	case 0x6f:
	case 0x19a: /* $nocancel */
		return sys_sigsuspend(arg1);
	case 0x70:
		return sys_nosys();
	case 0x71:
		return sys_nosys();
	case 0x72:
		return sys_nosys();
	case 0x73:
		return sys_nosys();
	case 0x74:
		return sys_gettimeofday(
				(void *)arg1, (void *)arg2, (void *)arg3);
	case 0x75:
		return sys_getrusage(arg1, (void *)arg2);
	case 0x76:
		return sys_getsockopt(
				arg1, arg2, arg3, (void *)arg4, (void *)arg5);
	case 0x77:
		return sys_nosys();
	case 0x78:
	case 0x19b: /* $nocancel */
		return sys_readv(arg1, (void *)arg2, arg3);
	case 0x79:
	case 0x19c: /* $nocancel */
		return sys_writev(arg1, (void *)arg2, arg3);
	case 0x7a:
		return sys_settimeofday((void *)arg1, (void *)arg2);
	case 0x7b:
		return sys_fchown(arg1, arg2, arg3);
	case 0x7c:
		return sys_fchmod(arg1, arg2);
	case 0x7d:
		return sys_nosys();
	case 0x7e:
		return sys_setreuid((void *)arg1, (void *)arg2);
	case 0x7f:
		return sys_setregid((void *)arg1, (void *)arg2);
	case 0x80:
		return sys_rename((void *)arg1, (void *)arg2);
	case 0x81:
		return sys_nosys();
	case 0x82:
		return sys_nosys();
	case 0x83:
		return sys_sys_flock(arg1, arg2);
	case 0x84:
		return sys_mkfifo((void *)arg1, arg2);
	case 0x85:
	case 0x19d: /* $nocancel */
		return sys_sendto(arg1, (void *)arg2, arg3, arg4, (void *)arg5,
				(void *)arg6);
	case 0x86:
		return sys_shutdown(arg1, arg2);
	case 0x87:
		return sys_socketpair(arg1, arg2, arg3, (void *)arg4);
	case 0x88:
		return sys_mkdir((void *)arg1, arg2);
	case 0x89:
		return sys_rmdir((void *)arg1);
	case 0x8a:
		return sys_utimes((void *)arg1, (void *)arg2);
	case 0x8b:
		return sys_futimes(arg1, (void *)arg2);
	case 0x8c:
		return sys_adjtime((void *)arg1, (void *)arg2);
	case 0x8d:
		return sys_nosys();
	case 0x8e:
		return sys_gethostuuid((void *)arg1, (void *)arg2);
	case 0x8f:
		return sys_nosys();
	case 0x90:
		return sys_nosys();
	case 0x91:
		return sys_nosys();
	case 0x92:
		return sys_nosys();
	case 0x93:
		return sys_setsid();
	case 0x94:
		return sys_pipe2((void *)arg1, arg2);
	case 0x95:
		return sys_nosys();
	case 0x96:
		return sys_nosys();
	case 0x97:
		return sys_getpgid(arg1);
	case 0x98:
		return sys_setprivexec(arg1);
	case 0x99:
	case 0x19e: /* $nocancel */
		return sys_pread(arg1, (void *)arg2, arg3, arg4);
	case 0x9a:
	case 0x19f: /* $nocancel */
		return sys_pwrite(arg1, (void *)arg2, arg3, arg4);
	case 0x9b:
		return sys_nosys();
	case 0x9c:
		return sys_nosys();
	case 0x9d:
		return sys_statfs((void *)arg1, (void *)arg2);
	case 0x9e:
		return sys_fstatfs(arg1, (void *)arg2);
	case 0x9f:
		return sys_unmount((void *)arg1, arg2);
	case 0xa0:
		return sys_nosys();
	case 0xa1:
		return sys_nosys();
	case 0xa2:
		return sys_nosys();
	case 0xa3:
		return sys_nosys();
	case 0xa4:
		return sys_nosys();
	case 0xa5:
		return sys_quotactl((void *)arg1, arg2, arg3, (void *)arg4);
	case 0xa6:
		return sys_nosys();
	case 0xa7:
		return sys_mount(
				(void *)arg1, (void *)arg2, arg3, (void *)arg4);
	case 0xa8:
		return sys_nosys();
	case 0xa9:
		return sys_csops(arg1, arg2, (void *)arg3, arg4);
	case 0xaa:
		return sys_csops_audittoken(
				arg1, arg2, (void *)arg3, arg4, (void *)arg5);
	case 0xab:
		return sys_nosys();
	case 0xac:
		return sys_nosys();
	case 0xad:
	case 0x1a0: /* $nocancel */
		return sys_waitid(
				(void *)arg1, (void *)arg2, (void *)arg3, arg4);
	case 0xae:
		return sys_nosys();
	case 0xaf:
		return sys_nosys();
	case 0xb0:
		return sys_nosys();
	case 0xb1:
		return sys_kdebug_typefilter((void *)arg1, (void *)arg2);
	case 0xb2:
		return sys_kdebug_trace_string(arg1, arg2, (void *)arg3);
	case 0xb3:
		return sys_kdebug_trace64(arg1, arg2, arg3, arg4, arg5);
	case 0xb4:
		return sys_kdebug_trace(arg1, arg2, arg3, arg4, arg5);
	case 0xb5:
		return sys_setgid((void *)arg1);
	case 0xb6:
		return sys_setegid((void *)arg1);
	case 0xb7:
		return sys_seteuid((void *)arg1);
	case 0xb8:
		return sys_sigreturn((void *)arg1, arg2, (void *)arg3);
	case 0xb9:
		return sys_enosys();
	case 0xba:
		return sys_thread_selfcounts(arg1, (void *)arg2, arg3);
	case 0xbb:
		return sys_fdatasync(arg1);
	case 0xbc:
		return sys_stat((void *)arg1, (void *)arg2);
	case 0xbd:
		return sys_sys_fstat(arg1, (void *)arg2);
	case 0xbe:
		return sys_lstat((void *)arg1, (void *)arg2);
	case 0xbf:
		return sys_pathconf((void *)arg1, arg2);
	case 0xc0:
		return sys_sys_fpathconf(arg1, arg2);
	case 0xc1:
		return sys_nosys();
	case 0xc2:
		return sys_getrlimit(arg1, (void *)arg2);
	case 0xc3:
		return sys_setrlimit(arg1, (void *)arg2);
	case 0xc4:
		return sys_getdirentries(
				arg1, (void *)arg2, arg3, (void *)arg4);
	case 0xc5:
		return (uint64_t)sys_mmap(
				(void *)arg1, arg2, arg3, arg4, arg5, arg6);
	case 0xc6:
		return sys_nosys();
	case 0xc7:
		return sys_lseek(arg1, arg2, arg3);
	case 0xc8:
		return sys_truncate((void *)arg1, arg2);
	case 0xc9:
		return sys_ftruncate(arg1, arg2);
	case 0xca:
		return sys_sysctl((void *)arg1, arg2, (void *)arg3,
				(void *)arg4, (void *)arg5, arg6);
	case 0xcb:
		return sys_mlock((void *)arg1, arg2);
	case 0xcc:
		return sys_munlock((void *)arg1, arg2);
	case 0xcd:
		return sys_undelete((void *)arg1);
	case 0xce:
		return sys_nosys();
	case 0xcf:
		return sys_nosys();
	case 0xd0:
		return sys_nosys();
	case 0xd1:
		return sys_nosys();
	case 0xd2:
		return sys_nosys();
	case 0xd3:
		return sys_nosys();
	case 0xd4:
		return sys_nosys();
	case 0xd5:
		return sys_nosys();
	case 0xd6:
		return sys_nosys();
	case 0xd7:
		return sys_nosys();
	case 0xd8:
		return sys_open_dprotected_np(
				(void *)arg1, arg2, arg3, arg4, arg5);
	case 0xd9:
		return sys_fsgetpath_ext(
				(void *)arg1, arg2, (void *)arg3, arg4, arg5);
	case 0xda:
		return sys_nosys();
	case 0xdb:
		return sys_nosys();
	case 0xdc:
		return sys_getattrlist((void *)arg1, (void *)arg2, (void *)arg3,
				arg4, arg5);
	case 0xdd:
		return sys_setattrlist((void *)arg1, (void *)arg2, (void *)arg3,
				arg4, arg5);
	case 0xde:
		return sys_getdirentriesattr(arg1, (void *)arg2, (void *)arg3,
				arg4, (void *)arg5, (void *)arg6, (void *)sp[1],
				sp[2]);
	case 0xdf:
		return sys_exchangedata((void *)arg1, (void *)arg2, arg3);
	case 0xe0:
		return sys_nosys();
	case 0xe1:
		return sys_searchfs((void *)arg1, (void *)arg2, (void *)arg3,
				arg4, arg5, (void *)arg6);
	case 0xe2:
		return sys_delete((void *)arg1);
	case 0xe3:
		return sys_copyfile((void *)arg1, (void *)arg2, arg3, arg4);
	case 0xe4:
		return sys_fgetattrlist(
				arg1, (void *)arg2, (void *)arg3, arg4, arg5);
	case 0xe5:
		return sys_fsetattrlist(
				arg1, (void *)arg2, (void *)arg3, arg4, arg5);
	case 0xe6:
	case 0x1a1: /* $nocancel */
		return sys_poll((void *)arg1, arg2, arg3);
	case 0xe7:
		return sys_nosys();
	case 0xe8:
		return sys_nosys();
	case 0xe9:
		return sys_nosys();
	case 0xea:
		return sys_getxattr((void *)arg1, (void *)arg2, (void *)arg3,
				arg4, arg5, arg6);
	case 0xeb:
		return sys_fgetxattr(arg1, (void *)arg2, (void *)arg3, arg4,
				arg5, arg6);
	case 0xec:
		return sys_setxattr((void *)arg1, (void *)arg2, (void *)arg3,
				arg4, arg5, arg6);
	case 0xed:
		return sys_fsetxattr(arg1, (void *)arg2, (void *)arg3, arg4,
				arg5, arg6);
	case 0xee:
		return sys_removexattr((void *)arg1, (void *)arg2, arg3);
	case 0xef:
		return sys_fremovexattr(arg1, (void *)arg2, arg3);
	case 0xf0:
		return sys_listxattr((void *)arg1, (void *)arg2, arg3, arg4);
	case 0xf1:
		return sys_flistxattr(arg1, (void *)arg2, arg3, arg4);
	case 0xf2:
		return sys_fsctl((void *)arg1, arg2, (void *)arg3, arg4);
	case 0xf3:
		return sys_initgroups(arg1, (void *)arg2, arg3);
	case 0xf4:
		return sys_posix_spawn((void *)arg1, (void *)arg2, (void *)arg3,
				(void *)arg4, (void *)arg5);
	case 0xf5:
		return sys_ffsctl(arg1, arg2, (void *)arg3, arg4);
	case 0xf6:
		return sys_nosys();
	case 0xf7:
		return sys_nosys();
	case 0xf8:
		return sys_nosys();
	case 0xf9:
		return sys_nosys();
	case 0xfa:
		return sys_minherit((void *)arg1, arg2, arg3);
	case 0xfb:
		return sys_semsys(arg1, arg2, arg3, arg4, arg5);
	case 0xfc:
		return sys_msgsys(arg1, arg2, arg3, arg4, arg5);
	case 0xfd:
		return sys_shmsys(arg1, arg2, arg3, arg4);
	case 0xfe:
		return sys_semctl(arg1, arg2, arg3, (void *)arg4);
	case 0xff:
		return sys_semget((void *)arg1, arg2, arg3);
	case 0x100:
		return sys_semop(arg1, (void *)arg2, arg3);
	case 0x101:
		return sys_nosys();
	case 0x102:
		return sys_msgctl(arg1, arg2, (void *)arg3);
	case 0x103:
		return sys_msgget((void *)arg1, arg2);
	case 0x104:
	case 0x1a2: /* $nocancel */
		return sys_msgsnd(arg1, (void *)arg2, arg3, arg4);
	case 0x105:
	case 0x1a3: /* $nocancel */
		return sys_msgrcv(arg1, (void *)arg2, arg3, arg4, arg5);
	case 0x106:
		return (uint64_t)sys_shmat(arg1, (void *)arg2, arg3);
	case 0x107:
		return sys_shmctl(arg1, arg2, (void *)arg3);
	case 0x108:
		return sys_shmdt((void *)arg1);
	case 0x109:
		return sys_shmget((void *)arg1, arg2, arg3);
	case 0x10a:
		return sys_shm_open((void *)arg1, arg2, arg3);
	case 0x10b:
		return sys_shm_unlink((void *)arg1);
	case 0x10c:
		return (uint64_t)sys_sem_open((void *)arg1, arg2, arg3, arg4);
	case 0x10d:
		return sys_sem_close((void *)arg1);
	case 0x10e:
		return sys_sem_unlink((void *)arg1);
	case 0x10f:
	case 0x1a4: /* $nocancel */
		return sys_sem_wait((void *)arg1);
	case 0x110:
		return sys_sem_trywait((void *)arg1);
	case 0x111:
		return sys_sem_post((void *)arg1);
	case 0x112:
		return sys_sys_sysctlbyname((void *)arg1, arg2, (void *)arg3,
				(void *)arg4, (void *)arg5, arg6);
	case 0x113:
		return sys_enosys();
	case 0x114:
		return sys_enosys();
	case 0x115:
		return sys_open_extended((void *)arg1, arg2, (void *)arg3,
				(void *)arg4, arg5, (void *)arg6);
	case 0x116:
		return sys_umask_extended(arg1, (void *)arg2);
	case 0x117:
		return sys_stat_extended((void *)arg1, (void *)arg2,
				(void *)arg3, (void *)arg4);
	case 0x118:
		return sys_lstat_extended((void *)arg1, (void *)arg2,
				(void *)arg3, (void *)arg4);
	case 0x119:
		return sys_sys_fstat_extended(
				arg1, (void *)arg2, (void *)arg3, (void *)arg4);
	case 0x11a:
		return sys_chmod_extended((void *)arg1, (void *)arg2,
				(void *)arg3, arg4, (void *)arg5);
	case 0x11b:
		return sys_fchmod_extended(
				arg1, arg2, arg3, arg4, (void *)arg5);
	case 0x11c:
		return sys_access_extended(
				(void *)arg1, arg2, (void *)arg3, (void *)arg4);
	case 0x11d:
		return sys_settid((void *)arg1, (void *)arg2);
	case 0x11e:
		return sys_gettid((void *)arg1, (void *)arg2);
	case 0x11f:
		return sys_setsgroups(arg1, (void *)arg2);
	case 0x120:
		return sys_getsgroups((void *)arg1, (void *)arg2);
	case 0x121:
		return sys_setwgroups(arg1, (void *)arg2);
	case 0x122:
		return sys_getwgroups((void *)arg1, (void *)arg2);
	case 0x123:
		return sys_mkfifo_extended((void *)arg1, (void *)arg2,
				(void *)arg3, arg4, (void *)arg5);
	case 0x124:
		return sys_mkdir_extended((void *)arg1, (void *)arg2,
				(void *)arg3, arg4, (void *)arg5);
	case 0x125:
		return sys_identitysvc(arg1, (void *)arg2);
	case 0x126:
		return sys_shared_region_check_np((void *)arg1);
	case 0x127:
		return sys_nosys();
	case 0x128:
		return sys_vm_pressure_monitor(arg1, arg2, (void *)arg3);
	case 0x129:
		return sys_nosys();
	case 0x12a:
		return sys_nosys();
	case 0x12b:
		return sys_enosys();
	case 0x12c:
		return sys_enosys();
	case 0x12d:
		return sys_psynch_mutexwait(
				(void *)arg1, arg2, arg3, arg4, arg5);
	case 0x12e:
		return sys_psynch_mutexdrop(
				(void *)arg1, arg2, arg3, arg4, arg5);
	case 0x12f:
		return sys_psynch_cvbroad((void *)arg1, arg2, arg3, arg4,
				(void *)arg5, arg6, sp[1]);
	case 0x130:
		return sys_psynch_cvsignal((void *)arg1, arg2, arg3, arg4,
				(void *)arg5, arg6, sp[1], sp[2]);
	case 0x131:
		return sys_psynch_cvwait((void *)arg1, arg2, arg3, (void *)arg4,
				arg5, arg6, sp[1], sp[2]);
	case 0x132:
		return sys_psynch_rw_rdlock(
				(void *)arg1, arg2, arg3, arg4, arg5);
	case 0x133:
		return sys_psynch_rw_wrlock(
				(void *)arg1, arg2, arg3, arg4, arg5);
	case 0x134:
		return sys_psynch_rw_unlock(
				(void *)arg1, arg2, arg3, arg4, arg5);
	case 0x135:
		return sys_nosys();
	case 0x136:
		return sys_getsid(arg1);
	case 0x137:
		return sys_settid_with_pid(arg1, arg2);
	case 0x138:
		return sys_psynch_cvclrprepost((void *)arg1, arg2, arg3, arg4,
				arg5, arg6, sp[1]);
	case 0x139:
		return sys_aio_fsync(arg1, (void *)arg2);
	case 0x13a:
		return sys_aio_return((void *)arg1);
	case 0x13b:
	case 0x1a5: /* $nocancel */
		return sys_aio_suspend((void *)arg1, arg2, (void *)arg3);
	case 0x13c:
		return sys_aio_cancel(arg1, (void *)arg2);
	case 0x13d:
		return sys_aio_error((void *)arg1);
	case 0x13e:
		return sys_aio_read((void *)arg1);
	case 0x13f:
		return sys_aio_write((void *)arg1);
	case 0x140:
		return sys_lio_listio(arg1, (void *)arg2, arg3, (void *)arg4);
	case 0x141:
		return sys_nosys();
	case 0x142:
		return sys_iopolicysys(arg1, (void *)arg2);
	case 0x143:
		return sys_process_policy(arg1, arg2, arg3, arg4, (void *)arg5,
				arg6, sp[1]);
	case 0x144:
		return sys_mlockall(arg1);
	case 0x145:
		return sys_munlockall(arg1);
	case 0x146:
		return sys_nosys();
	case 0x147:
		return sys_issetugid();
	case 0x148:
		return sys___pthread_kill(arg1, arg2);
	case 0x149:
		return sys___pthread_sigmask(arg1, (void *)arg2, (void *)arg3);
	case 0x14a:
	case 0x1a6: /* $nocancel */
		return sys___sigwait((void *)arg1, (void *)arg2);
	case 0x14b:
		return sys___disable_threadsignal(arg1);
	case 0x14c:
		return sys___pthread_markcancel(arg1);
	case 0x14d:
		return sys___pthread_canceled(arg1);
	case 0x14e:
	case 0x1a7: /* $nocancel */
		return sys___semwait_signal(arg1, arg2, arg3, arg4, arg5, arg6);
	case 0x14f:
		return sys_nosys();
	case 0x150:
		return sys_proc_info(
				arg1, arg2, arg3, arg4, (void *)arg5, arg6);
	case 0x151:
		return sys_sendfile(arg1, arg2, arg3, (void *)arg4,
				(void *)arg5, arg6);
	case 0x152:
		return sys_stat64((void *)arg1, (void *)arg2);
	case 0x153:
		return sys_sys_fstat64(arg1, (void *)arg2);
	case 0x154:
		return sys_lstat64((void *)arg1, (void *)arg2);
	case 0x155:
		return sys_stat64_extended((void *)arg1, (void *)arg2,
				(void *)arg3, (void *)arg4);
	case 0x156:
		return sys_lstat64_extended((void *)arg1, (void *)arg2,
				(void *)arg3, (void *)arg4);
	case 0x157:
		return sys_sys_fstat64_extended(
				arg1, (void *)arg2, (void *)arg3, (void *)arg4);
	case 0x158:
		return sys_getdirentries64(
				arg1, (void *)arg2, arg3, (void *)arg4);
	case 0x159:
		return sys_statfs64((void *)arg1, (void *)arg2);
	case 0x15a:
		return sys_fstatfs64(arg1, (void *)arg2);
	case 0x15b:
		return sys_getfsstat64((void *)arg1, arg2, arg3);
	case 0x15c:
		return sys___pthread_chdir((void *)arg1);
	case 0x15d:
		return sys___pthread_fchdir(arg1);
	case 0x15e:
		return sys_audit((void *)arg1, arg2);
	case 0x15f:
		return sys_auditon(arg1, (void *)arg2, arg3);
	case 0x160:
		return sys_nosys();
	case 0x161:
		return sys_getauid((void *)arg1);
	case 0x162:
		return sys_setauid((void *)arg1);
	case 0x163:
		return sys_nosys();
	case 0x164:
		return sys_nosys();
	case 0x165:
		return sys_getaudit_addr((void *)arg1, arg2);
	case 0x166:
		return sys_setaudit_addr((void *)arg1, arg2);
	case 0x167:
		return sys_auditctl((void *)arg1);
	case 0x168:
		return (uint64_t)sys_bsdthread_create((void *)arg1,
				(void *)arg2, (void *)arg3, (void *)arg4, arg5);
	case 0x169:
		return sys_bsdthread_terminate((void *)arg1, arg2, arg3, arg4);
	case 0x16a:
		return sys_kqueue();
	case 0x16b:
		return sys_kevent(arg1, (void *)arg2, arg3, (void *)arg4, arg5,
				(void *)arg6);
	case 0x16c:
		return sys_lchown((void *)arg1, (void *)arg2, (void *)arg3);
	case 0x16d:
		return sys_nosys();
	case 0x16e:
		return sys_bsdthread_register((void *)arg1, (void *)arg2, arg3,
				(void *)arg4, arg5, arg6);
	case 0x16f:
		return sys_workq_open();
	case 0x170:
		return sys_workq_kernreturn(arg1, (void *)arg2, arg3, arg4);
	case 0x171:
		return sys_kevent64(arg1, (void *)arg2, arg3, (void *)arg4,
				arg5, arg6, (void *)sp[1]);
	case 0x172:
		return sys_nosys();
	case 0x173:
		return sys_nosys();
	case 0x174:
		return sys_thread_selfid();
	case 0x175:
		return sys_ledger(
				arg1, (void *)arg2, (void *)arg3, (void *)arg4);
	case 0x176:
		return sys_kevent_qos(arg1, (void *)arg2, arg3, (void *)arg4,
				arg5, (void *)arg6, (void *)sp[1], sp[2]);
	case 0x177:
		return sys_kevent_id(arg1, (void *)arg2, arg3, (void *)arg4,
				arg5, (void *)arg6, (void *)sp[1], sp[2]);
	case 0x178:
		return sys_nosys();
	case 0x179:
		return sys_nosys();
	case 0x17a:
		return sys_nosys();
	case 0x17b:
		return sys_nosys();
	case 0x17c:
		return sys___mac_execve((void *)arg1, (void *)arg2,
				(void *)arg3, (void *)arg4);
	case 0x17d:
		return sys___mac_syscall((void *)arg1, arg2, (void *)arg3);
	case 0x17e:
		return sys___mac_get_file((void *)arg1, (void *)arg2);
	case 0x17f:
		return sys___mac_set_file((void *)arg1, (void *)arg2);
	case 0x180:
		return sys___mac_get_link((void *)arg1, (void *)arg2);
	case 0x181:
		return sys___mac_set_link((void *)arg1, (void *)arg2);
	case 0x182:
		return sys___mac_get_proc((void *)arg1);
	case 0x183:
		return sys___mac_set_proc((void *)arg1);
	case 0x184:
		return sys___mac_get_fd(arg1, (void *)arg2);
	case 0x185:
		return sys___mac_set_fd(arg1, (void *)arg2);
	case 0x186:
		return sys___mac_get_pid(arg1, (void *)arg2);
	case 0x187:
		return sys_enosys();
	case 0x188:
		return sys_enosys();
	case 0x189:
		return sys_enosys();
	case 0x18a:
	case 0x18b: /* $nocancel */
		return sys_pselect(arg1, (void *)arg2, (void *)arg3,
				(void *)arg4, (void *)arg5, (void *)arg6);
	case 0x1a8:
		return sys___mac_mount((void *)arg1, (void *)arg2, arg3,
				(void *)arg4, (void *)arg5);
	case 0x1a9:
		return sys___mac_get_mount((void *)arg1, (void *)arg2);
	case 0x1aa:
		return sys___mac_getfsstat(
				(void *)arg1, arg2, (void *)arg3, arg4, arg5);
	case 0x1ab:
		return sys_fsgetpath((void *)arg1, arg2, (void *)arg3, arg4);
	case 0x1ac:
		return sys_audit_session_self();
	case 0x1ad:
		return sys_audit_session_join(arg1);
	case 0x1ae:
		return sys_sys_fileport_makeport(arg1, (void *)arg2);
	case 0x1af:
		return sys_sys_fileport_makefd(arg1);
	case 0x1b0:
		return sys_audit_session_port((void *)arg1, (void *)arg2);
	case 0x1b1:
		return sys_pid_suspend(arg1);
	case 0x1b2:
		return sys_pid_resume(arg1);
	case 0x1b3:
		return sys_nosys();
	case 0x1b4:
		return sys_pid_shutdown_sockets(arg1, arg2);
	case 0x1b5:
		return sys_nosys();
	case 0x1b6:
		return sys_shared_region_map_and_slide_np(arg1, arg2,
				(void *)arg3, arg4, (void *)arg5, arg6);
	case 0x1b7:
		return sys_kas_info(arg1, (void *)arg2, (void *)arg3);
	case 0x1b8:
		return sys_memorystatus_control(
				arg1, arg2, arg3, (void *)arg4, arg5);
	case 0x1b9:
		return sys_guarded_open_np(
				(void *)arg1, (void *)arg2, arg3, arg4, arg5);
	case 0x1ba:
		return sys_guarded_close_np(arg1, (void *)arg2);
	case 0x1bb:
		return sys_guarded_kqueue_np((void *)arg1, arg2);
	case 0x1bc:
		return sys_change_fdguard_np(arg1, (void *)arg2, arg3,
				(void *)arg4, arg5, (void *)arg6);
	case 0x1bd:
		return sys_usrctl(arg1);
	case 0x1be:
		return sys_proc_rlimit_control(arg1, arg2, (void *)arg3);
	case 0x1bf:
		return sys_connectx(arg1, (void *)arg2, (void *)arg3,
				(void *)arg4, (void *)arg5, (void *)arg6,
				(void *)sp[1], (void *)sp[2]);
	case 0x1c0:
		return sys_disconnectx(arg1, (void *)arg2, (void *)arg3);
	case 0x1c1:
		return sys_peeloff(arg1, (void *)arg2);
	case 0x1c2:
		return sys_socket_delegate(arg1, arg2, arg3, arg4);
	case 0x1c3:
		return sys_telemetry(arg1, arg2, arg3, arg4, arg5, arg6);
	case 0x1c4:
		return sys_proc_uuid_policy(arg1, (void *)arg2, arg3, arg4);
	case 0x1c5:
		return sys_memorystatus_get_level((void *)arg1);
	case 0x1c6:
		return sys_system_override(arg1, arg2);
	case 0x1c7:
		return sys_vfs_purge();
	case 0x1c8:
		return sys_sfi_ctl(arg1, arg2, arg3, (void *)arg4);
	case 0x1c9:
		return sys_sfi_pidctl(arg1, arg2, arg3, (void *)arg4);
	case 0x1ca:
		return sys_coalition(arg1, (void *)arg2, arg3);
	case 0x1cb:
		return sys_coalition_info(
				arg1, (void *)arg2, (void *)arg3, (void *)arg4);
	case 0x1cc:
		return sys_nosys();
	case 0x1cd:
		return sys_getattrlistbulk(
				arg1, (void *)arg2, (void *)arg3, arg4, arg5);
	case 0x1ce:
		return sys_clonefileat(
				arg1, (void *)arg2, arg3, (void *)arg4, arg5);
	case 0x1cf:
	case 0x1d0: /* $nocancel */
		return sys_openat(arg1, (void *)arg2, arg3, arg4);
	case 0x1d1:
		return sys_renameat(arg1, (void *)arg2, arg3, (void *)arg4);
	case 0x1d2:
		return sys_faccessat(arg1, (void *)arg2, arg3, arg4);
	case 0x1d3:
		return sys_fchmodat(arg1, (void *)arg2, arg3, arg4);
	case 0x1d4:
		return sys_fchownat(arg1, (void *)arg2, (void *)arg3,
				(void *)arg4, arg5);
	case 0x1d5:
		return sys_fstatat(arg1, (void *)arg2, (void *)arg3, arg4);
	case 0x1d6:
		return sys_fstatat64(arg1, (void *)arg2, (void *)arg3, arg4);
	case 0x1d7:
		return sys_linkat(arg1, (void *)arg2, arg3, (void *)arg4, arg5);
	case 0x1d8:
		return sys_unlinkat(arg1, (void *)arg2, arg3);
	case 0x1d9:
		return sys_readlinkat(arg1, (void *)arg2, (void *)arg3, arg4);
	case 0x1da:
		return sys_symlinkat((void *)arg1, arg2, (void *)arg3);
	case 0x1db:
		return sys_mkdirat(arg1, (void *)arg2, arg3);
	case 0x1dc:
		return sys_getattrlistat(arg1, (void *)arg2, (void *)arg3,
				(void *)arg4, arg5, arg6);
	case 0x1dd:
		return sys_proc_trace_log(arg1, arg2);
	case 0x1de:
		return sys_bsdthread_ctl((void *)arg1, (void *)arg2,
				(void *)arg3, (void *)arg4);
	case 0x1df:
		return sys_openbyid_np((void *)arg1, (void *)arg2, arg3);
	case 0x1e0:
		return sys_recvmsg_x(arg1, (void *)arg2, arg3, arg4);
	case 0x1e1:
		return sys_sendmsg_x(arg1, (void *)arg2, arg3, arg4);
	case 0x1e2:
		return sys_thread_selfusage();
	case 0x1e3:
		return sys_csrctl(arg1, (void *)arg2, (void *)arg3);
	case 0x1e4:
		return sys_guarded_open_dprotected_np((void *)arg1,
				(void *)arg2, arg3, arg4, arg5, arg6, sp[1]);
	case 0x1e5:
		return sys_guarded_write_np(
				arg1, (void *)arg2, (void *)arg3, arg4);
	case 0x1e6:
		return sys_guarded_pwrite_np(
				arg1, (void *)arg2, (void *)arg3, arg4, arg5);
	case 0x1e7:
		return sys_guarded_writev_np(
				arg1, (void *)arg2, (void *)arg3, arg4);
	case 0x1e8:
		return sys_renameatx_np(
				arg1, (void *)arg2, arg3, (void *)arg4, arg5);
	case 0x1e9:
		return sys_mremap_encrypted(
				(void *)arg1, arg2, arg3, arg4, arg5);
	case 0x1ea:
		return sys_netagent_trigger((void *)arg1, arg2);
	case 0x1eb:
		return sys_stack_snapshot_with_config(arg1, (void *)arg2, arg3);
	case 0x1ec:
		return sys_microstackshot((void *)arg1, arg2, arg3);
	case 0x1ed:
		return sys_enosys();
	case 0x1ee:
		return sys_persona(arg1, arg2, (void *)arg3, (void *)arg4,
				(void *)arg5, (void *)arg6);
	case 0x1ef:
		return sys_enosys();
	case 0x1f0:
		return sys_mach_eventlink_signal(arg1, arg2);
	case 0x1f1:
		return sys_mach_eventlink_wait_until(
				arg1, arg2, arg3, arg4, arg5);
	case 0x1f2:
		return sys_mach_eventlink_signal_wait_until(
				arg1, arg2, arg3, arg4, arg5, arg6);
	case 0x1f3:
		return sys_work_interval_ctl(arg1, arg2, (void *)arg3, arg4);
	case 0x1f4:
		return sys_getentropy((void *)arg1, arg2);
	case 0x1f5:
		return sys_necp_open(arg1);
	case 0x1f6:
		return sys_necp_client_action(arg1, arg2, (void *)arg3, arg4,
				(void *)arg5, arg6);
	case 0x1f7:
		return sys_enosys();
	case 0x1f8:
		return sys_enosys();
	case 0x1f9:
		return sys_enosys();
	case 0x1fa:
		return sys_enosys();
	case 0x1fb:
		return sys_enosys();
	case 0x1fc:
		return sys_enosys();
	case 0x1fd:
		return sys_enosys();
	case 0x1fe:
		return sys_enosys();
	case 0x1ff:
		return sys_enosys();
	case 0x200:
		return sys_enosys();
	case 0x201:
		return sys_enosys();
	case 0x202:
		return sys_enosys();
	case 0x203:
		return sys_ulock_wait(arg1, (void *)arg2, arg3, arg4);
	case 0x204:
		return sys_ulock_wake(arg1, (void *)arg2, arg3);
	case 0x205:
		return sys_fclonefileat(arg1, arg2, (void *)arg3, arg4);
	case 0x206:
		return sys_fs_snapshot(arg1, arg2, (void *)arg3, (void *)arg4,
				(void *)arg5, arg6);
	case 0x207:
		return sys_enosys();
	case 0x208:
		return sys_terminate_with_payload(arg1, arg2, arg3,
				(void *)arg4, arg5, (void *)arg6, sp[1]);
	case 0x209:
		return sys_abort_with_payload(arg1, arg2, (void *)arg3, arg4,
				(void *)arg5, arg6);
	case 0x20a:
		return sys_necp_session_open(arg1);
	case 0x20b:
		return sys_necp_session_action(arg1, arg2, (void *)arg3, arg4,
				(void *)arg5, arg6);
	case 0x20c:
		return sys_setattrlistat(arg1, (void *)arg2, (void *)arg3,
				(void *)arg4, arg5, arg6);
	case 0x20d:
		return sys_net_qos_guideline((void *)arg1, arg2);
	case 0x20e:
		return sys_fmount((void *)arg1, arg2, arg3, (void *)arg4);
	case 0x20f:
		return sys_ntp_adjtime((void *)arg1);
	case 0x210:
		return sys_ntp_gettime((void *)arg1);
	case 0x211:
		return sys_os_fault_with_payload(arg1, arg2, (void *)arg3, arg4,
				(void *)arg5, arg6);
	case 0x212:
		return sys_kqueue_workloop_ctl(
				(void *)arg1, arg2, (void *)arg3, arg4);
	case 0x213:
		return sys___mach_bridge_remote_time(arg1);
	case 0x214:
		return sys_coalition_ledger(
				arg1, (void *)arg2, (void *)arg3, (void *)arg4);
	case 0x215:
		return sys_log_data((void *)arg1, (void *)arg2, (void *)arg3,
				(void *)arg4);
	case 0x216:
		return sys_memorystatus_available_memory();
	case 0x217:
		return sys_enosys();
	case 0x218:
		return sys_shared_region_map_and_slide_2_np(
				arg1, (void *)arg2, arg3, (void *)arg4);
	case 0x219:
		return sys_pivot_root((void *)arg1, (void *)arg2);
	case 0x21a:
		return sys_task_inspect_for_pid(arg1, arg2, (void *)arg3);
	case 0x21b:
		return sys_task_read_for_pid(arg1, arg2, (void *)arg3);
	case 0x21c:
	case 0x21e: /* $nocancel */
		return sys_sys_preadv(arg1, (void *)arg2, arg3, arg4);
	case 0x21d:
	case 0x21f: /* $nocancel */
		return sys_sys_pwritev(arg1, (void *)arg2, arg3, arg4);
	case 0x220:
		return sys_ulock_wait2(arg1, (void *)arg2, arg3, arg4, arg5);
	case 0x221:
		return sys_proc_info_extended_id(arg1, arg2, arg3, arg4, arg5,
				arg6, (void *)sp[1], sp[2]);
	case 0x222:
	case 0x223:
	case 0x224:
	case 0x225:
		return sys_enosys();
	case 0x226:
		return sys_map_with_linking_np(
				(void *)arg1, arg2, (void *)arg3, arg4);
	case 0x22c:
		return sys_coalition_policy_set(arg1, arg2, arg3);
	default:
		fprintf(stderr, ">> Missing BSD system call: %#lx\n", syscall);
		unimplemented();
	}
}
