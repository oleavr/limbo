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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "at.h"
#include "bsd_flags.h"
#include "bsd/xnu-errno.h"
#include "device.h"
#include "sysroot.h"

typedef void *user_addr_t;

typedef int32_t __darwin_dev_t;
typedef uint16_t __darwin_mode_t;
typedef uint16_t __darwin_nlink_t;
typedef uint32_t __darwin_uid_t;
typedef uint32_t __darwin_gid_t;
typedef uint64_t __darwin_ino64_t;
typedef int32_t __darwin_blksize_t;
typedef int64_t __darwin_blkcnt_t;
typedef int64_t __darwin_off_t;

typedef int64_t __darwin_user64_time_t __attribute__((aligned(8)));

struct __darwin_user64_timespec {
	__darwin_user64_time_t tv_sec;
	__darwin_user64_time_t tv_nsec;
};

struct __darwin_user64_stat64 {
	__darwin_dev_t st_dev;
	__darwin_mode_t st_mode;
	__darwin_nlink_t st_nlink;
	__darwin_ino64_t st_ino;
	__darwin_uid_t st_uid;
	__darwin_gid_t st_gid;
	__darwin_dev_t st_rdev;
	struct __darwin_user64_timespec st_atimespec;
	struct __darwin_user64_timespec st_mtimespec;
	struct __darwin_user64_timespec st_ctimespec;
	struct __darwin_user64_timespec st_birthtimespec;
	__darwin_off_t st_size;
	__darwin_blkcnt_t st_blocks;
	__darwin_blksize_t st_blksize;
	uint32_t st_flags;
	uint32_t st_gen;
	uint32_t st_lspare;
	int64_t st_qspare[2];
};

#define MFSNAMELEN     15
#define MFSTYPENAMELEN 16

#define MAXPATHLEN 1024
#define MNAMELEN   MAXPATHLEN

#define MNT_EXT_ROOT_DATA_VOL 0x00000001

struct __darwin_struct_statfs64 {
	uint32_t f_bsize;
	int32_t f_iosize;
	uint64_t f_blocks;
	uint64_t f_bfree;
	uint64_t f_bavail;
	uint64_t f_files;
	uint64_t f_ffree;
	fsid_t f_fsid;
	uid_t f_owner;
	uint32_t f_type;
	uint32_t f_flags;
	uint32_t f_fssubtype;
	char f_fstypename[MFSTYPENAMELEN];
	char f_mntonname[MAXPATHLEN];
	char f_mntfromname[MAXPATHLEN];
	uint32_t f_flags_ext;
	uint32_t f_reserved[7];
};

static int stat_at(int fd, const char *path, int flags,
		struct __darwin_user64_stat64 *ub);
static int stat_extended_at(int fd, const char *path, int flags,
		struct __darwin_user64_stat64 *ub, uint64_t *xsecurity_size);
static void convert_statfs(const struct statfs *src, dev_t device,
		struct __darwin_struct_statfs64 *dest);
static void convert_statx(
		struct statx *stat, struct __darwin_user64_stat64 *dest);
static void encode_timespec(struct __darwin_user64_timespec *to,
		struct statx_timestamp *from);

int
sys_getfsstat(user_addr_t buf, int bufsize, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getfsstat(%p, %p, %p)\n", (void *)buf, (void *)bufsize,
			(void *)flags);
#endif
	unimplemented();
}

int
sys_statfs(char *path, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "statfs(%p, %p)\n", (void *)path, (void *)buf);
#endif
	unimplemented();
}

int
sys_fstatfs(int fd, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fstatfs(%p, %p)\n", (void *)fd, (void *)buf);
#endif
	unimplemented();
}

int
sys_stat(user_addr_t path, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stat(%p, %p)\n", (void *)path, (void *)ub);
#endif
	unimplemented();
}

int
sys_sys_fstat(int fd, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fstat(%p, %p)\n", (void *)fd, (void *)ub);
#endif
	unimplemented();
}

int
sys_lstat(user_addr_t path, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lstat(%p, %p)\n", (void *)path, (void *)ub);
#endif
	return stat_at(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, ub);
}

static int
stat_at(int fd, const char *path, int flags, struct __darwin_user64_stat64 *ub)
{
	char buffer[PATH_MAX];
	const char *host_path = sysroot_host_path(path, flags, buffer);
	struct statx tmp;
	if (statx(fd, host_path, flags, STATX_BASIC_STATS | STATX_BTIME, &tmp)
			== -1) {
		return err_map(errno);
	}
	convert_statx(&tmp, ub);
	if (!S_ISLNK(tmp.stx_mode)) {
		ub->st_flags = bsd_flags_get_at(fd, host_path, flags);
	}
	return 0;
}

static void
convert_statx(struct statx *stat, struct __darwin_user64_stat64 *dest)
{
	dest->st_dev = darwin_device(
			makedev(stat->stx_dev_major, stat->stx_dev_minor));
	dest->st_mode = stat->stx_mode;
	dest->st_nlink = stat->stx_nlink;
	dest->st_ino = sysroot_file_id(
			makedev(stat->stx_dev_major, stat->stx_dev_minor),
			stat->stx_ino);
	dest->st_uid = stat->stx_uid;
	dest->st_gid = stat->stx_gid;
	dest->st_rdev = (stat->stx_rdev_major << 24) | stat->stx_rdev_minor;
	encode_timespec(&dest->st_atimespec, &stat->stx_atime);
	encode_timespec(&dest->st_mtimespec, &stat->stx_mtime);
	encode_timespec(&dest->st_ctimespec, &stat->stx_ctime);
	encode_timespec(&dest->st_birthtimespec, &stat->stx_btime);
	dest->st_size = stat->stx_size;
	dest->st_blocks = stat->stx_blocks;
	dest->st_blksize = stat->stx_blksize;
	dest->st_flags = 0;
	dest->st_gen = 0;
}

static void
encode_timespec(struct __darwin_user64_timespec *to,
		struct statx_timestamp *from)
{
	to->tv_sec = from->tv_sec;
	to->tv_nsec = from->tv_nsec;
}

static int
stat_extended_at(int fd, const char *path, int flags,
		struct __darwin_user64_stat64 *ub, uint64_t *xsecurity_size)
{
	int result = stat_at(fd, path, flags, ub);
	if (result == 0 && xsecurity_size != NULL) {
		*xsecurity_size = 0;
	}
	return result;
}

int
sys_stat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stat_extended(%p, %p, %p, %p)\n", (void *)path,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_lstat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lstat_extended(%p, %p, %p, %p)\n", (void *)path,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_sys_fstat_extended(int fd, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fstat_extended(%p, %p, %p, %p)\n", (void *)fd,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_stat64(user_addr_t path, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stat64(\"%s\", %p)\n", (char *)path, (void *)ub);
#endif
	return stat_at(AT_FDCWD, path, 0, ub);
}

int
sys_sys_fstat64(int fd, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fstat64(%p, %p)\n", (void *)fd, (void *)ub);
#endif
	return stat_at(fd, "", AT_EMPTY_PATH, ub);
}

int
sys_lstat64(user_addr_t path, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lstat64(\"%s\", %p)\n", (char *)path, (void *)ub);
#endif
	return stat_at(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, ub);
}

int
sys_stat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stat64_extended(\"%s\", %p, %p, %p)\n", (char *)path,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	return stat_extended_at(AT_FDCWD, path, 0, ub, xsecurity_size);
}

int
sys_lstat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lstat64_extended(\"%s\", %p, %p, %p)\n", (char *)path,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	return stat_extended_at(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, ub,
			xsecurity_size);
}

int
sys_sys_fstat64_extended(int fd, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fstat64_extended(%p, %p, %p, %p)\n", (void *)fd,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	return stat_extended_at(fd, "", AT_EMPTY_PATH, ub, xsecurity_size);
}

int
sys_statfs64(char *path, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "statfs64(\"%s\", %p)\n", path, (void *)buf);
#endif
	char buffer[PATH_MAX];
	const char *host_path = sysroot_host_path(path, 0, buffer);
	struct statfs tmp = {0};
	struct stat st;
	if (statfs(host_path, &tmp) == -1 || stat(host_path, &st) == -1) {
#ifdef ENABLE_STRACE
		perror("statfs");
#endif
		return err_map(errno);
	}
	convert_statfs(&tmp, st.st_dev, buf);
	return 0;
}

static void
convert_statfs(const struct statfs *src, dev_t device,
		struct __darwin_struct_statfs64 *dest)
{
	memset(dest, 0, sizeof(*dest));
	/* Technically this is f_iosize and distinct from f_bsize, but it is
	 * correct enough */
	dest->f_bsize = src->f_bsize;
	dest->f_iosize = src->f_bsize;
	dest->f_blocks = src->f_blocks;
	dest->f_bfree = src->f_bfree;
	dest->f_bavail = src->f_bavail;
	dest->f_files = src->f_files;
	dest->f_ffree = src->f_ffree;
	/* TODO: These are not going to be compatible */
	dest->f_fsid.__val[0] = darwin_device(device);
	dest->f_fsid.__val[1] = DARWIN_FSTYPE_APFS;
	dest->f_type = src->f_type;
	dest->f_flags = DARWIN_MOUNT_FLAGS;
	strcpy(dest->f_fstypename, "apfs");
	strcpy(dest->f_mntonname, "/");
	strcpy(dest->f_mntfromname, "/dev/disk1s1");
}

int
sys_fstatfs64(int fd, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fstatfs64(%p, %p)\n", (void *)fd, (void *)buf);
#endif
	struct statfs tmp = {0};
	struct stat st;
	if (fstatfs(fd, &tmp) == -1 || fstat(fd, &st) == -1) {
#ifdef ENABLE_STRACE
		perror("fstatfs");
#endif
		return err_map(errno);
	}
	convert_statfs(&tmp, st.st_dev, buf);
	return 0;
}

int
sys_getfsstat64(user_addr_t buf, int bufsize, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getfsstat64(%p, %p, %p)\n", (void *)buf,
			(void *)bufsize, (void *)flags);
#endif
	if (buf == NULL
			|| bufsize < (int)sizeof(
					   struct __darwin_struct_statfs64)) {
		return 1;
	}

	char buffer[PATH_MAX];
	const char *host_path = sysroot_host_path("/", 0, buffer);
	struct statfs tmp = {0};
	struct stat st;
	if (statfs(host_path, &tmp) == -1 || stat(host_path, &st) == -1) {
		return err_map(errno);
	}
	convert_statfs(&tmp, st.st_dev, buf);
	return 1;
}

int
sys_fstatat(int fd, user_addr_t path, user_addr_t ub, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fstatat(%p, %p, %p, %p)\n", (void *)fd, (void *)path,
			(void *)ub, (void *)flag);
#endif
	unimplemented();
}

int
sys_fstatat64(int fd, user_addr_t path, user_addr_t ub, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fstatat64(%p, \"%s\", %p, %p)\n", (void *)fd, (char *)path,
			(void *)ub, (void *)flag);
#endif
	return stat_at(at_fd(fd), path, at_flags(flag), ub);
}
