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
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "at.h"
#include "bsd/xnu-errno.h"
#include "bsd_flags.h"
#include "device.h"
#include "fileid.h"
#include "sysroot.h"

typedef uint32_t attrgroup_t;
struct __darwin_attrlist {
	uint16_t bitmapcount;
	uint16_t reserved;
	attrgroup_t commonattr;
	attrgroup_t volattr;
	attrgroup_t dirattr;
	attrgroup_t fileattr;
	attrgroup_t forkattr;
};
#define ATTR_BIT_MAP_COUNT 5

typedef struct attribute_set {
	attrgroup_t commonattr;
	attrgroup_t volattr;
	attrgroup_t dirattr;
	attrgroup_t fileattr;
	attrgroup_t forkattr;
} attribute_set_t;

typedef struct attrreference {
	int32_t attr_dataoffset;
	uint32_t attr_length;
} attrreference_t;

struct reference {
	uint32_t offset;
	const char *value;
};

#define FSOPT_NOFOLLOW          1
#define FSOPT_REPORT_FULLSIZE   4
#define FSOPT_PACK_INVAL_ATTRS  8
#define FSOPT_ATTR_CMN_EXTENDED 0x20

#define ATTR_CMN_NAME               0x00000001
#define ATTR_CMN_DEVID              0x00000002
#define ATTR_CMN_FSID               0x00000004
#define ATTR_CMN_OBJTYPE            0x00000008
#define ATTR_CMN_OBJTAG             0x00000010
#define ATTR_CMN_OBJID              0x00000020
#define ATTR_CMN_OBJPERMANENTID     0x00000040
#define ATTR_CMN_PAROBJID           0x00000080
#define ATTR_CMN_SCRIPT             0x00000100
#define ATTR_CMN_CRTIME             0x00000200
#define ATTR_CMN_MODTIME            0x00000400
#define ATTR_CMN_CHGTIME            0x00000800
#define ATTR_CMN_ACCTIME            0x00001000
#define ATTR_CMN_BKUPTIME           0x00002000
#define ATTR_CMN_FNDRINFO           0x00004000

#define FINDER_INFO_XATTR           "user.com.apple.FinderInfo"
#define FINDER_INFO_SIZE            32
#define ATTR_CMN_OWNERID            0x00008000
#define ATTR_CMN_GRPID              0x00010000
#define ATTR_CMN_ACCESSMASK         0x00020000
#define ATTR_CMN_FLAGS              0x00040000
#define ATTR_CMN_GEN_COUNT          0x00080000
#define ATTR_CMN_DOCUMENT_ID        0x00100000
#define ATTR_CMN_USERACCESS         0x00200000
#define ATTR_CMN_EXTENDED_SECURITY  0x00400000
#define ATTR_CMN_UUID               0x00800000
#define ATTR_CMN_GRPUUID            0x01000000
#define ATTR_CMN_FILEID             0x02000000
#define ATTR_CMN_PARENTID           0x04000000
#define ATTR_CMN_FULLPATH           0x08000000
#define ATTR_CMN_ADDEDTIME          0x10000000
#define ATTR_CMN_ERROR              0x20000000
#define ATTR_CMN_DATA_PROTECT_FLAGS 0x40000000
#define ATTR_CMN_RETURNED_ATTRS     0x80000000
#define ATTR_CMN_VALIDMASK          0xFFFFFFFF

#define ATTR_VOL_FSTYPE          0x00000001
#define ATTR_VOL_SIGNATURE       0x00000002
#define ATTR_VOL_SIZE            0x00000004
#define ATTR_VOL_SPACEFREE       0x00000008
#define ATTR_VOL_SPACEAVAIL      0x00000010
#define ATTR_VOL_MINALLOCATION   0x00000020
#define ATTR_VOL_ALLOCATIONCLUMP 0x00000040
#define ATTR_VOL_IOBLOCKSIZE     0x00000080
#define ATTR_VOL_OBJCOUNT        0x00000100
#define ATTR_VOL_FILECOUNT       0x00000200
#define ATTR_VOL_DIRCOUNT        0x00000400
#define ATTR_VOL_MAXOBJCOUNT     0x00000800
#define ATTR_VOL_MOUNTPOINT      0x00001000
#define ATTR_VOL_NAME            0x00002000
#define ATTR_VOL_MOUNTFLAGS      0x00004000
#define ATTR_VOL_MOUNTEDDEVICE   0x00008000
#define ATTR_VOL_ENCODINGSUSED   0x00010000
#define ATTR_VOL_CAPABILITIES    0x00020000
#define ATTR_VOL_UUID            0x00040000
#define ATTR_VOL_MOUNTEXTFLAGS   0x00080000
#define ATTR_VOL_FSTYPENAME      0x00100000
#define ATTR_VOL_FSSUBTYPE       0x00200000
#define ATTR_VOL_OWNER           0x00400000
#define ATTR_VOL_SPACEUSED       0x00800000
#define ATTR_VOL_QUOTA_SIZE      0x10000000
#define ATTR_VOL_RESERVED_SIZE   0x20000000
#define ATTR_VOL_ATTRIBUTES      0x40000000
#define ATTR_VOL_INFO            0x80000000

#define ATTR_DIR_LINKCOUNT   0x00000001
#define ATTR_DIR_MOUNTSTATUS 0x00000004

#define DIR_MNTSTATUS_MNTPOINT 0x00000001

#define VOLUME_NAME "Macintosh HD"

#define VOLUME_SIGNATURE                0x4244
#define VOL_CAP_FMT_CASE_SENSITIVE      0x00000100
#define VOL_CAP_FMT_DECMPFS_COMPRESSION 0x00010000
#define VOLUME_FORMAT_CAPABILITIES                                             \
	((0x039b6edf | VOL_CAP_FMT_CASE_SENSITIVE)                             \
			& ~VOL_CAP_FMT_DECMPFS_COMPRESSION)
#define VOLUME_FORMAT_VALID           0x07ffffff
#define VOLUME_INTERFACE_CAPABILITIES 0x01ad6fc7
#define VOLUME_INTERFACE_VALID        0x01ffffff

#define ATTR_FILE_LINKCOUNT     0x00000001
#define ATTR_FILE_TOTALSIZE     0x00000002
#define ATTR_FILE_ALLOCSIZE     0x00000004
#define ATTR_FILE_IOBLOCKSIZE   0x00000008
#define ATTR_FILE_DEVTYPE       0x00000020
#define ATTR_FILE_FORKCOUNT     0x00000080
#define ATTR_FILE_FORKLIST      0x00000100
#define ATTR_FILE_DATALENGTH    0x00000200
#define ATTR_FILE_DATAALLOCSIZE 0x00000400
#define ATTR_FILE_RSRCLENGTH    0x00001000
#define ATTR_FILE_RSRCALLOCSIZE 0x00002000

#define ATTR_CMNEXT_RELPATH        0x00000004
#define ATTR_CMNEXT_LINKID         0x00000010
#define ATTR_CMNEXT_NOFIRMLINKPATH 0x00000020
#define ATTR_CMNEXT_REALDEVID      0x00000040
#define ATTR_CMNEXT_REALFSID       0x00000080
#define ATTR_CMNEXT_CLONEID        0x00000100
#define ATTR_CMNEXT_EXT_FLAGS      0x00000200

typedef uint32_t __darwin_dev_t;
typedef uint32_t fsobj_type_t;
typedef struct fsobj_id {
	uint32_t fid_objno;
	uint32_t fid_generation;
} fsobj_id_t;
enum vtype {
	VNON,
	VREG,
	VDIR,
	VBLK,
	VCHR,
	VLNK,
	VSOCK,
	VFIFO,
	VBAD,
	VSTR,
	VCPLX
};
typedef uint32_t vol_capabilities_set_t[4];

#define VOL_CAPABILITIES_FORMAT     0
#define VOL_CAPABILITIES_INTERFACES 1
#define VOL_CAPABILITIES_RESERVED1  2
#define VOL_CAPABILITIES_RESERVED2  3

typedef struct vol_capabilities_attr {
	vol_capabilities_set_t capabilities;
	vol_capabilities_set_t valid;
} vol_capabilities_attr_t;

#define ATTRIBUTES_SIZE_MAX (2 * PATH_MAX + 4096)

static int pack_attributes(int fd, const struct __darwin_attrlist *alistp,
		uint64_t options, char *buffer);
static int attrlist_open(int dirfd, const char *path, uint64_t options);
static uint32_t pack_reference(char *buffer, uint32_t offset,
		struct reference *references, uint32_t *reference_count,
		const char *value);
static uint32_t pack_reference_data(char *buffer, uint32_t offset,
		const struct reference *reference);
static uint32_t pack_timespec(
		char *buffer, uint32_t offset, const struct timespec *ts);
static uint64_t parent_id(const char *path, const char *host_path);
static uint32_t pack_u32(char *buffer, uint32_t offset, uint32_t value);
static uint32_t pack_u64(char *buffer, uint32_t offset, uint64_t value);
static const char *unpack_timespec(const char *buffer, struct timespec *ts);

static int
fgetattrlist(int fd, void *alist, void *attributeBuffer, size_t bufferSize,
		uint64_t options)
{
	char attributes[ATTRIBUTES_SIZE_MAX];
	if (pack_attributes(fd, alist, options, attributes)) {
		return 1;
	}

	uint32_t length = *(uint32_t *)attributes;
	uint32_t copied = (length < bufferSize) ? length : bufferSize;
	memcpy(attributeBuffer, attributes, copied);
	if (!(options & FSOPT_REPORT_FULLSIZE)) {
		*(uint32_t *)attributeBuffer = copied;
	}
	return 0;
}

static int
pack_attributes(int fd, const struct __darwin_attrlist *alistp,
		uint64_t options, char *buffer)
{
	if (alistp->bitmapcount != ATTR_BIT_MAP_COUNT) {
		errno = EINVAL;
		return 1;
	}
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"  attrlist(common=%#x, vol=%#x, dir=%#x, file=%#x, "
			"fork=%#x)\n",
			alistp->commonattr, alistp->volattr, alistp->dirattr,
			alistp->fileattr, alistp->forkattr);
#endif

	if (alistp->forkattr && !(options & FSOPT_ATTR_CMN_EXTENDED)) {
		unimplemented();
	}

	struct stat s = {0};
	if (fstat(fd, &s)) {
#ifdef ENABLE_STRACE
		perror("fstat");
#endif
		return 1;
	}

	char link[48], host_path[PATH_MAX] = {0};
	snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
	readlink(link, host_path, sizeof(host_path) - 1);
	const char *path = sysroot_guest_path(host_path);
	fileid_remember(sysroot_file_id(s.st_dev, s.st_ino), path);

	attribute_set_t returned = {
			.commonattr = alistp->commonattr & ~ATTR_CMN_ERROR,
			.volattr = alistp->volattr,
			.dirattr = alistp->dirattr,
			.fileattr = alistp->fileattr,
			.forkattr = alistp->forkattr,
	};
	if (!(options & FSOPT_PACK_INVAL_ATTRS)) {
		if (S_ISDIR(s.st_mode)) {
			returned.fileattr = 0;
		} else {
			returned.dirattr = 0;
		}
	}

	uint32_t commonattr = returned.commonattr;
	uint32_t volattr = returned.volattr;
	uint32_t dirattr = returned.dirattr;
	uint32_t fileattr = returned.fileattr;
	uint32_t cmnextattr = returned.forkattr;

	/* Order must follow the definitions above, and be written to the buffer
	 * all the same */

	/* The buffer begins with a uint32_t size */
	uint32_t offset = sizeof(uint32_t);
	struct reference references[8];
	uint32_t reference_count = 0;

	if (returned.commonattr & ATTR_CMN_RETURNED_ATTRS) {
		attribute_set_t reported = returned;
		reported.volattr &= ~ATTR_VOL_INFO;
		memcpy(buffer + offset, &reported, sizeof(reported));
		offset += sizeof(returned);
		commonattr &= ~ATTR_CMN_RETURNED_ATTRS;
	}

	if (returned.commonattr & ATTR_CMN_NAME) {
		offset = pack_reference(buffer, offset, references,
				&reference_count,
				strcmp(path, "/") == 0 ? VOLUME_NAME
						       : basename(path));
		commonattr &= ~ATTR_CMN_NAME;
	}

	if (returned.commonattr & ATTR_CMN_DEVID) {
		__darwin_dev_t d = darwin_device(s.st_dev);
		memcpy(buffer + offset, &d, sizeof(d));
		offset += sizeof(d);
		commonattr &= ~ATTR_CMN_DEVID;
	}

	if (returned.commonattr & ATTR_CMN_FSID) {
		offset = pack_u32(buffer, offset, darwin_device(s.st_dev));
		offset = pack_u32(buffer, offset, DARWIN_FSTYPE_APFS);
		commonattr &= ~ATTR_CMN_FSID;
	}

	if (returned.commonattr & ATTR_CMN_OBJTYPE) {
		fsobj_type_t type = VREG;
		switch (s.st_mode & S_IFMT) {
		case S_IFBLK:
			type = VBLK;
			break;
		case S_IFCHR:
			type = VCHR;
			break;
		case S_IFDIR:
			type = VDIR;
			break;
		case S_IFIFO:
			type = VFIFO;
			break;
		case S_IFLNK:
			type = VLNK;
			break;
		case S_IFSOCK:
			type = VSOCK;
			break;
		}

		memcpy(buffer + offset, &type, sizeof(type));
		offset += sizeof(type);
		commonattr &= ~ATTR_CMN_OBJTYPE;
	}

	if (returned.commonattr & ATTR_CMN_OBJID) {
		fsobj_id_t id = {
				.fid_objno
				= (uint32_t)sysroot_file_id(s.st_dev, s.st_ino),
				.fid_generation = 0xfffffff,
		};
		memcpy(buffer + offset, &id, sizeof(id));
		offset += sizeof(fsobj_id_t);
		commonattr &= ~ATTR_CMN_OBJID;
	}

	if (returned.commonattr & ATTR_CMN_PAROBJID) {
		fsobj_id_t id = {
				.fid_objno = (uint32_t)parent_id(path, host_path),
				.fid_generation = 0,
		};
		memcpy(buffer + offset, &id, sizeof(id));
		offset += sizeof(fsobj_id_t);
		commonattr &= ~ATTR_CMN_PAROBJID;
	}

	if (returned.commonattr & ATTR_CMN_SCRIPT) {
		offset = pack_u32(buffer, offset, 0);
		commonattr &= ~ATTR_CMN_SCRIPT;
	}

	if (returned.commonattr & ATTR_CMN_CRTIME) {
		offset = pack_timespec(buffer, offset, &s.st_ctim);
		commonattr &= ~ATTR_CMN_CRTIME;
	}

	if (returned.commonattr & ATTR_CMN_MODTIME) {
		offset = pack_timespec(buffer, offset, &s.st_mtim);
		commonattr &= ~ATTR_CMN_MODTIME;
	}

	if (returned.commonattr & ATTR_CMN_CHGTIME) {
		offset = pack_timespec(buffer, offset, &s.st_ctim);
		commonattr &= ~ATTR_CMN_CHGTIME;
	}

	if (returned.commonattr & ATTR_CMN_ACCTIME) {
		offset = pack_timespec(buffer, offset, &s.st_atim);
		commonattr &= ~ATTR_CMN_ACCTIME;
	}

	if (returned.commonattr & ATTR_CMN_FNDRINFO) {
		memset(buffer + offset, 0, FINDER_INFO_SIZE);
		char link[48];
		snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
		getxattr(link, FINDER_INFO_XATTR, buffer + offset,
				FINDER_INFO_SIZE);
		offset += FINDER_INFO_SIZE;
		commonattr &= ~ATTR_CMN_FNDRINFO;
	}

	if (returned.commonattr & ATTR_CMN_OWNERID) {
		offset = pack_u32(buffer, offset, s.st_uid);
		commonattr &= ~ATTR_CMN_OWNERID;
	}

	if (returned.commonattr & ATTR_CMN_GRPID) {
		offset = pack_u32(buffer, offset, s.st_gid);
		commonattr &= ~ATTR_CMN_GRPID;
	}

	if (returned.commonattr & ATTR_CMN_ACCESSMASK) {
		offset = pack_u32(buffer, offset, s.st_mode);
		commonattr &= ~ATTR_CMN_ACCESSMASK;
	}

	if (returned.commonattr & ATTR_CMN_FLAGS) {
		offset = pack_u32(buffer, offset,
				S_ISLNK(s.st_mode) ? 0 : bsd_flags_get(fd));
		commonattr &= ~ATTR_CMN_FLAGS;
	}

	if (returned.commonattr & ATTR_CMN_GEN_COUNT) {
		offset = pack_u32(buffer, offset, 0);
		commonattr &= ~ATTR_CMN_GEN_COUNT;
	}

	if (returned.commonattr & ATTR_CMN_DOCUMENT_ID) {
		offset = pack_u32(buffer, offset, 0);
		commonattr &= ~ATTR_CMN_DOCUMENT_ID;
	}

	if (returned.commonattr & ATTR_CMN_USERACCESS) {
		uint32_t access_mask = 0;
		access_mask |= access(host_path, R_OK) == 0 ? R_OK : 0;
		access_mask |= access(host_path, W_OK) == 0 ? W_OK : 0;
		access_mask |= access(host_path, X_OK) == 0 ? X_OK : 0;
		offset = pack_u32(buffer, offset, access_mask);
		commonattr &= ~ATTR_CMN_USERACCESS;
	}

	if (returned.commonattr & ATTR_CMN_EXTENDED_SECURITY) {
		attrreference_t none = {0, 0};
		memcpy(buffer + offset, &none, sizeof(none));
		offset += sizeof(none);
		commonattr &= ~ATTR_CMN_EXTENDED_SECURITY;
	}

	if (returned.commonattr & ATTR_CMN_UUID) {
		static const uint8_t prefix[12] = {0xff, 0xff, 0xee, 0xee, 0xdd,
				0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa};
		memcpy(buffer + offset, prefix, sizeof(prefix));
		uint32_t id = htonl(s.st_uid);
		memcpy(buffer + offset + sizeof(prefix), &id, sizeof(id));
		offset += 16;
		commonattr &= ~ATTR_CMN_UUID;
	}

	if (returned.commonattr & ATTR_CMN_GRPUUID) {
		static const uint8_t prefix[12] = {0xab, 0xcd, 0xef, 0xab, 0xcd,
				0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef};
		memcpy(buffer + offset, prefix, sizeof(prefix));
		uint32_t id = htonl(s.st_gid);
		memcpy(buffer + offset + sizeof(prefix), &id, sizeof(id));
		offset += 16;
		commonattr &= ~ATTR_CMN_GRPUUID;
	}

	if (returned.commonattr & ATTR_CMN_FILEID) {
		uint64_t ino = sysroot_file_id(s.st_dev, s.st_ino);
		memcpy(buffer + offset, &ino, sizeof(ino));
		offset += sizeof(uint64_t);
		commonattr &= ~ATTR_CMN_FILEID;
	}

	if (returned.commonattr & ATTR_CMN_PARENTID) {
		offset = pack_u64(buffer, offset, parent_id(path, host_path));
		commonattr &= ~ATTR_CMN_PARENTID;
	}

	if (returned.commonattr & ATTR_CMN_FULLPATH) {
		offset = pack_reference(buffer, offset, references,
				&reference_count, path);
		commonattr &= ~ATTR_CMN_FULLPATH;
	}

	if (returned.commonattr & ATTR_CMN_ADDEDTIME) {
		offset = pack_timespec(buffer, offset, &s.st_ctim);
		commonattr &= ~ATTR_CMN_ADDEDTIME;
	}

	if (returned.commonattr & ATTR_CMN_DATA_PROTECT_FLAGS) {
		offset = pack_u32(buffer, offset, 0);
		commonattr &= ~ATTR_CMN_DATA_PROTECT_FLAGS;
	}

	if (returned.volattr & ATTR_VOL_FSTYPE) {
		offset = pack_u32(buffer, offset, DARWIN_FSTYPE_APFS);
		volattr &= ~ATTR_VOL_FSTYPE;
	}

	struct statvfs vfs = {0};
	fstatvfs(fd, &vfs);
	uint64_t block = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;

	if (returned.volattr & ATTR_VOL_SIGNATURE) {
		offset = pack_u32(buffer, offset, VOLUME_SIGNATURE);
		volattr &= ~ATTR_VOL_SIGNATURE;
	}

	if (returned.volattr & ATTR_VOL_SIZE) {
		offset = pack_u64(buffer, offset, vfs.f_blocks * block);
		volattr &= ~ATTR_VOL_SIZE;
	}

	if (returned.volattr & ATTR_VOL_SPACEFREE) {
		offset = pack_u64(buffer, offset, vfs.f_bfree * block);
		volattr &= ~ATTR_VOL_SPACEFREE;
	}

	if (returned.volattr & ATTR_VOL_SPACEAVAIL) {
		offset = pack_u64(buffer, offset, vfs.f_bavail * block);
		volattr &= ~ATTR_VOL_SPACEAVAIL;
	}

	if (returned.volattr & ATTR_VOL_SPACEUSED) {
		offset = pack_u64(buffer, offset,
				(vfs.f_blocks - vfs.f_bfree) * block);
		volattr &= ~ATTR_VOL_SPACEUSED;
	}

	if (returned.volattr & ATTR_VOL_MINALLOCATION) {
		offset = pack_u64(buffer, offset, block);
		volattr &= ~ATTR_VOL_MINALLOCATION;
	}

	if (returned.volattr & ATTR_VOL_ALLOCATIONCLUMP) {
		offset = pack_u64(buffer, offset, block);
		volattr &= ~ATTR_VOL_ALLOCATIONCLUMP;
	}

	if (returned.volattr & ATTR_VOL_IOBLOCKSIZE) {
		offset = pack_u32(buffer, offset, (uint32_t)vfs.f_bsize);
		volattr &= ~ATTR_VOL_IOBLOCKSIZE;
	}

	if (returned.volattr & ATTR_VOL_OBJCOUNT) {
		offset = pack_u32(buffer, offset,
				(uint32_t)(vfs.f_files - vfs.f_ffree));
		volattr &= ~ATTR_VOL_OBJCOUNT;
	}

	if (returned.volattr & ATTR_VOL_FILECOUNT) {
		offset = pack_u32(buffer, offset,
				(uint32_t)(vfs.f_files - vfs.f_ffree));
		volattr &= ~ATTR_VOL_FILECOUNT;
	}

	if (returned.volattr & ATTR_VOL_DIRCOUNT) {
		offset = pack_u32(buffer, offset, 0);
		volattr &= ~ATTR_VOL_DIRCOUNT;
	}

	if (returned.volattr & ATTR_VOL_MAXOBJCOUNT) {
		offset = pack_u32(buffer, offset, (uint32_t)vfs.f_files);
		volattr &= ~ATTR_VOL_MAXOBJCOUNT;
	}

	if (returned.volattr & ATTR_VOL_MOUNTPOINT) {
		offset = pack_reference(buffer, offset, references,
				&reference_count, "/");
		volattr &= ~ATTR_VOL_MOUNTPOINT;
	}

	if (returned.volattr & ATTR_VOL_NAME) {
		offset = pack_reference(buffer, offset, references,
				&reference_count, VOLUME_NAME);
		volattr &= ~ATTR_VOL_NAME;
	}

	if (returned.volattr & ATTR_VOL_MOUNTFLAGS) {
		uint32_t flags = DARWIN_MOUNT_FLAGS;
		memcpy(buffer + offset, &flags, sizeof(flags));
		offset += sizeof(flags);
		volattr &= ~ATTR_VOL_MOUNTFLAGS;
	}

	if (returned.volattr & ATTR_VOL_MOUNTEDDEVICE) {
		offset = pack_reference(buffer, offset, references,
				&reference_count, "/dev/disk1s1");
		volattr &= ~ATTR_VOL_MOUNTEDDEVICE;
	}

	if (returned.volattr & ATTR_VOL_ENCODINGSUSED) {
		offset = pack_u64(buffer, offset, 0);
		volattr &= ~ATTR_VOL_ENCODINGSUSED;
	}

	if (returned.volattr & ATTR_VOL_CAPABILITIES) {
		vol_capabilities_attr_t cap = {
				.capabilities = {VOLUME_FORMAT_CAPABILITIES,
						VOLUME_INTERFACE_CAPABILITIES},
				.valid
				= {VOLUME_FORMAT_VALID, VOLUME_INTERFACE_VALID},
		};
		memcpy(buffer + offset, &cap, sizeof(cap));
		offset += sizeof(cap);
		volattr &= ~ATTR_VOL_CAPABILITIES;
	}

	if (returned.volattr & ATTR_VOL_UUID) {
		struct statfs fs;
		fstatfs(fd, &fs);
		uint64_t uuid[2] = {*(uint64_t *)&fs.f_fsid, s.st_dev};
		memcpy(buffer + offset, uuid, sizeof(uuid));
		offset += sizeof(uuid);
		volattr &= ~ATTR_VOL_UUID;
	}

	if (returned.volattr & ATTR_VOL_MOUNTEXTFLAGS) {
		offset = pack_u32(buffer, offset, 0);
		volattr &= ~ATTR_VOL_MOUNTEXTFLAGS;
	}

	if (returned.volattr & ATTR_VOL_QUOTA_SIZE) {
		offset = pack_u64(buffer, offset, vfs.f_blocks * block);
		volattr &= ~ATTR_VOL_QUOTA_SIZE;
	}

	if (returned.volattr & ATTR_VOL_RESERVED_SIZE) {
		offset = pack_u64(buffer, offset, 0);
		volattr &= ~ATTR_VOL_RESERVED_SIZE;
	}

	if (returned.volattr & ATTR_VOL_ATTRIBUTES) {
		attribute_set_t supported = {
				.commonattr = ATTR_CMN_NAME | ATTR_CMN_DEVID
						| ATTR_CMN_FSID
						| ATTR_CMN_OBJTYPE
						| ATTR_CMN_OBJID
						| ATTR_CMN_PAROBJID
						| ATTR_CMN_SCRIPT
						| ATTR_CMN_CRTIME
						| ATTR_CMN_MODTIME
						| ATTR_CMN_CHGTIME
						| ATTR_CMN_ACCTIME
						| ATTR_CMN_FNDRINFO
						| ATTR_CMN_OWNERID
						| ATTR_CMN_GRPID
						| ATTR_CMN_ACCESSMASK
						| ATTR_CMN_FLAGS
						| ATTR_CMN_GEN_COUNT
						| ATTR_CMN_DOCUMENT_ID
						| ATTR_CMN_USERACCESS
						| ATTR_CMN_FILEID
						| ATTR_CMN_PARENTID
						| ATTR_CMN_FULLPATH
						| ATTR_CMN_ADDEDTIME
						| ATTR_CMN_DATA_PROTECT_FLAGS
						| ATTR_CMN_RETURNED_ATTRS,
				.volattr = ATTR_VOL_FSTYPE | ATTR_VOL_SIGNATURE
						| ATTR_VOL_SIZE
						| ATTR_VOL_SPACEFREE
						| ATTR_VOL_SPACEAVAIL
						| ATTR_VOL_MINALLOCATION
						| ATTR_VOL_ALLOCATIONCLUMP
						| ATTR_VOL_IOBLOCKSIZE
						| ATTR_VOL_OBJCOUNT
						| ATTR_VOL_FILECOUNT
						| ATTR_VOL_DIRCOUNT
						| ATTR_VOL_MAXOBJCOUNT
						| ATTR_VOL_MOUNTPOINT
						| ATTR_VOL_NAME
						| ATTR_VOL_MOUNTFLAGS
						| ATTR_VOL_MOUNTEDDEVICE
						| ATTR_VOL_ENCODINGSUSED
						| ATTR_VOL_CAPABILITIES
						| ATTR_VOL_UUID
						| ATTR_VOL_MOUNTEXTFLAGS
						| ATTR_VOL_FSTYPENAME
						| ATTR_VOL_FSSUBTYPE
						| ATTR_VOL_OWNER
						| ATTR_VOL_SPACEUSED
						| ATTR_VOL_QUOTA_SIZE
						| ATTR_VOL_RESERVED_SIZE
						| ATTR_VOL_ATTRIBUTES
						| ATTR_VOL_INFO,
				.dirattr
				= ATTR_DIR_LINKCOUNT | ATTR_DIR_MOUNTSTATUS,
				.fileattr = ATTR_FILE_LINKCOUNT
						| ATTR_FILE_TOTALSIZE
						| ATTR_FILE_ALLOCSIZE
						| ATTR_FILE_IOBLOCKSIZE
						| ATTR_FILE_DEVTYPE
						| ATTR_FILE_DATALENGTH
						| ATTR_FILE_DATAALLOCSIZE
						| ATTR_FILE_RSRCLENGTH
						| ATTR_FILE_RSRCALLOCSIZE,
		};
		memcpy(buffer + offset, &supported, sizeof(supported));
		offset += sizeof(supported);
		memcpy(buffer + offset, &supported, sizeof(supported));
		offset += sizeof(supported);
		volattr &= ~ATTR_VOL_ATTRIBUTES;
	}

	if (returned.volattr & ATTR_VOL_FSTYPENAME) {
		offset = pack_reference(buffer, offset, references,
				&reference_count, "apfs");
		volattr &= ~ATTR_VOL_FSTYPENAME;
	}

	if (returned.volattr & ATTR_VOL_FSSUBTYPE) {
		offset = pack_u32(buffer, offset, 0);
		volattr &= ~ATTR_VOL_FSSUBTYPE;
	}

	if (returned.volattr & ATTR_VOL_OWNER) {
		offset = pack_u32(buffer, offset, 0);
		volattr &= ~ATTR_VOL_OWNER;
	}

	if (returned.volattr & ATTR_VOL_INFO) {
		/* From the man pages, it looks like this does nothing */
		volattr &= ~ATTR_VOL_INFO;
	}

	if (returned.dirattr & ATTR_DIR_LINKCOUNT) {
		offset = pack_u32(buffer, offset, s.st_nlink);
		dirattr &= ~ATTR_DIR_LINKCOUNT;
	}

	if (returned.dirattr & ATTR_DIR_MOUNTSTATUS) {
		offset = pack_u32(buffer, offset,
				strcmp(path, "/") == 0 ? DIR_MNTSTATUS_MNTPOINT
						       : 0);
		dirattr &= ~ATTR_DIR_MOUNTSTATUS;
	}

	if (returned.fileattr & ATTR_FILE_LINKCOUNT) {
		offset = pack_u32(buffer, offset, s.st_nlink);
		fileattr &= ~ATTR_FILE_LINKCOUNT;
	}

	if (returned.fileattr & ATTR_FILE_TOTALSIZE) {
		offset = pack_u64(buffer, offset, s.st_size);
		fileattr &= ~ATTR_FILE_TOTALSIZE;
	}

	if (returned.fileattr & ATTR_FILE_ALLOCSIZE) {
		offset = pack_u64(buffer, offset, s.st_blocks * 512);
		fileattr &= ~ATTR_FILE_ALLOCSIZE;
	}

	if (returned.fileattr & ATTR_FILE_IOBLOCKSIZE) {
		offset = pack_u32(buffer, offset, s.st_blksize);
		fileattr &= ~ATTR_FILE_IOBLOCKSIZE;
	}

	if (returned.fileattr & ATTR_FILE_DEVTYPE) {
		offset = pack_u32(buffer, offset,
				S_ISBLK(s.st_mode) || S_ISCHR(s.st_mode)
						? s.st_rdev
						: 0);
		fileattr &= ~ATTR_FILE_DEVTYPE;
	}

	if (returned.fileattr & ATTR_FILE_DATALENGTH) {
		offset = pack_u64(buffer, offset, s.st_size);
		fileattr &= ~ATTR_FILE_DATALENGTH;
	}

	if (returned.fileattr & ATTR_FILE_DATAALLOCSIZE) {
		offset = pack_u64(buffer, offset, s.st_blocks * 512);
		fileattr &= ~ATTR_FILE_DATAALLOCSIZE;
	}

	if (returned.fileattr & ATTR_FILE_RSRCLENGTH) {
		offset = pack_u64(buffer, offset, 0);
		fileattr &= ~ATTR_FILE_RSRCLENGTH;
	}

	if (returned.fileattr & ATTR_FILE_RSRCALLOCSIZE) {
		offset = pack_u64(buffer, offset, 0);
		fileattr &= ~ATTR_FILE_RSRCALLOCSIZE;
	}

	if (returned.forkattr & ATTR_CMNEXT_RELPATH) {
		offset = pack_reference(buffer, offset, references,
				&reference_count, path);
		cmnextattr &= ~ATTR_CMNEXT_RELPATH;
	}

	if (returned.forkattr & ATTR_CMNEXT_LINKID) {
		offset = pack_u64(buffer, offset,
				sysroot_file_id(s.st_dev, s.st_ino));
		cmnextattr &= ~ATTR_CMNEXT_LINKID;
	}

	if (returned.forkattr & ATTR_CMNEXT_NOFIRMLINKPATH) {
		offset = pack_reference(buffer, offset, references,
				&reference_count, path);
		cmnextattr &= ~ATTR_CMNEXT_NOFIRMLINKPATH;
	}

	if (returned.forkattr & ATTR_CMNEXT_REALDEVID) {
		offset = pack_u32(buffer, offset, darwin_device(s.st_dev));
		cmnextattr &= ~ATTR_CMNEXT_REALDEVID;
	}

	if (returned.forkattr & ATTR_CMNEXT_REALFSID) {
		offset = pack_u32(buffer, offset, darwin_device(s.st_dev));
		offset = pack_u32(buffer, offset, DARWIN_FSTYPE_APFS);
		cmnextattr &= ~ATTR_CMNEXT_REALFSID;
	}

	if (returned.forkattr & ATTR_CMNEXT_CLONEID) {
		offset = pack_u64(buffer, offset,
				sysroot_file_id(s.st_dev, s.st_ino));
		cmnextattr &= ~ATTR_CMNEXT_CLONEID;
	}

	if (returned.forkattr & ATTR_CMNEXT_EXT_FLAGS) {
		offset = pack_u64(buffer, offset, 0);
		cmnextattr &= ~ATTR_CMNEXT_EXT_FLAGS;
	}

	for (uint32_t i = 0; i < reference_count; i++) {
		offset = pack_reference_data(buffer, offset, &references[i]);
	}

	if (commonattr) {
		fprintf(stderr, "limbo: getattrlist: commonattr %x\n",
				commonattr);
		unimplemented();
	}

	if (volattr) {
		fprintf(stderr, "limbo: getattrlist: volattr %x\n", volattr);
		unimplemented();
	}

	if (dirattr) {
		fprintf(stderr, "limbo: getattrlist: dirattr %x\n", dirattr);
		unimplemented();
	}

	if (fileattr) {
		fprintf(stderr, "limbo: getattrlist: fileattr %x\n", fileattr);
		unimplemented();
	}

	if (cmnextattr) {
		fprintf(stderr, "limbo: getattrlist: cmnextattr %x\n",
				cmnextattr);
		unimplemented();
	}

	/* Total aligned size is written to the beginning of the buffer */
	*(uint32_t *)buffer = offset + (-offset & 3);
	return 0;
}

static uint32_t
pack_reference(char *buffer, uint32_t offset, struct reference *references,
		uint32_t *reference_count, const char *value)
{
	attrreference_t reference = {0, 0};
	memcpy(buffer + offset, &reference, sizeof(reference));
	references[(*reference_count)++] = (struct reference){offset, value};
	return offset + sizeof(reference);
}

static uint32_t
pack_reference_data(char *buffer, uint32_t offset,
		const struct reference *reference)
{
	attrreference_t *ref = (attrreference_t *)(buffer + reference->offset);
	ref->attr_dataoffset = offset - reference->offset;
	ref->attr_length = strlen(reference->value) + 1;
	memcpy(buffer + offset, reference->value, ref->attr_length);
	return offset + ((ref->attr_length + 3) & ~3);
}

static uint32_t
pack_timespec(char *buffer, uint32_t offset, const struct timespec *ts)
{
	int64_t value[2] = {ts->tv_sec, ts->tv_nsec};
	memcpy(buffer + offset, value, sizeof(value));
	return offset + sizeof(value);
}

static uint64_t
parent_id(const char *path, const char *host_path)
{
	char parent_path[PATH_MAX];
	memcpy(parent_path, host_path, sizeof(parent_path));
	strrchr(parent_path, '/')[1] = '\0';
	struct stat parent = {0};
	stat(parent_path, &parent);
	uint64_t id = strcmp(path, "/") == 0
			? 1
			: sysroot_file_id(parent.st_dev, parent.st_ino);
	parent_path[strlen(parent_path) - 1] = '\0';
	fileid_remember(id,
			parent_path[0] != '\0' ? sysroot_guest_path(parent_path)
						: "/");
	return id;
}

static uint32_t
pack_u32(char *buffer, uint32_t offset, uint32_t value)
{
	memcpy(buffer + offset, &value, sizeof(value));
	return offset + sizeof(value);
}

static uint32_t
pack_u64(char *buffer, uint32_t offset, uint64_t value)
{
	memcpy(buffer + offset, &value, sizeof(value));
	return offset + sizeof(value);
}

static int
set_attributes(int dirfd, const char *path, int flags, void *alist,
		void *attributeBuffer)
{
	const struct __darwin_attrlist *alistp = alist;
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"  attrlist(common=%#x, vol=%#x, dir=%#x, file=%#x, "
			"fork=%#x)\n",
			alistp->commonattr, alistp->volattr, alistp->dirattr,
			alistp->fileattr, alistp->forkattr);
#endif
	if ((alistp->commonattr
			    & ~(ATTR_CMN_CRTIME | ATTR_CMN_MODTIME
					    | ATTR_CMN_ACCTIME
					    | ATTR_CMN_FNDRINFO
					    | ATTR_CMN_OWNERID | ATTR_CMN_GRPID
					    | ATTR_CMN_ACCESSMASK
					    | ATTR_CMN_FLAGS
					    | ATTR_CMN_EXTENDED_SECURITY
					    | ATTR_CMN_UUID | ATTR_CMN_GRPUUID))
			|| alistp->volattr || alistp->dirattr
			|| alistp->fileattr || alistp->forkattr) {
		unimplemented();
	}

	struct timespec times[2] = {
			{.tv_nsec = UTIME_OMIT},
			{.tv_nsec = UTIME_OMIT},
	};
	const char *cursor = attributeBuffer;
	if (alistp->commonattr & ATTR_CMN_CRTIME) {
		struct timespec creation;
		cursor = unpack_timespec(cursor, &creation);
	}
	if (alistp->commonattr & ATTR_CMN_MODTIME) {
		cursor = unpack_timespec(cursor, &times[1]);
	}
	if (alistp->commonattr & ATTR_CMN_ACCTIME) {
		cursor = unpack_timespec(cursor, &times[0]);
	}
	if (alistp->commonattr & ATTR_CMN_FNDRINFO) {
		char target[PATH_MAX];
		if (path == NULL) {
			snprintf(target, sizeof(target),
					"/proc/thread-self/fd/%d", dirfd);
		} else if (path[0] == '/' || dirfd == AT_FDCWD) {
			snprintf(target, sizeof(target), "%s", path);
		} else {
			snprintf(target, sizeof(target),
					"/proc/thread-self/fd/%d/%s", dirfd,
					path);
		}
		int r = (flags & AT_SYMLINK_NOFOLLOW)
				? lsetxattr(target, FINDER_INFO_XATTR, cursor,
						  FINDER_INFO_SIZE, 0)
				: setxattr(target, FINDER_INFO_XATTR, cursor,
						  FINDER_INFO_SIZE, 0);
		if (r == -1 && errno != EPERM && errno != ENOTSUP) {
			return -1;
		}
		cursor += FINDER_INFO_SIZE;
	}
	if (alistp->commonattr & (ATTR_CMN_OWNERID | ATTR_CMN_GRPID)) {
		uint32_t owner = UINT32_MAX, group = UINT32_MAX;
		if (alistp->commonattr & ATTR_CMN_OWNERID) {
			memcpy(&owner, cursor, sizeof(owner));
			cursor += sizeof(owner);
		}
		if (alistp->commonattr & ATTR_CMN_GRPID) {
			memcpy(&group, cursor, sizeof(group));
			cursor += sizeof(group);
		}
		int r = (path == NULL)
				? fchown(dirfd, owner, group)
				: fchownat(dirfd, path, owner, group,
						  flags & AT_SYMLINK_NOFOLLOW);
		if (r == -1) {
			return -1;
		}
	}
	if (alistp->commonattr & ATTR_CMN_ACCESSMASK) {
		uint32_t mode;
		memcpy(&mode, cursor, sizeof(mode));
		cursor += sizeof(mode);
		int r = (path == NULL)
				? fchmod(dirfd, mode & 07777)
				: fchmodat(dirfd, path, mode & 07777, flags);
		if (r == -1 && !(errno == EOPNOTSUPP
					    && (flags & AT_SYMLINK_NOFOLLOW))) {
			return -1;
		}
	}
	return (path == NULL) ? futimens(dirfd, times)
			      : utimensat(dirfd, path, times, flags);
}

static const char *
unpack_timespec(const char *buffer, struct timespec *ts)
{
	int64_t value[2];
	memcpy(value, buffer, sizeof(value));
	ts->tv_sec = value[0];
	ts->tv_nsec = value[1];
	return buffer + sizeof(value);
}

int
sys_getattrlistbulk(int dirfd, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getattrlistbulk(%p, %p, %p, %p, %p)\n", (void *)dirfd,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	off_t start = lseek(dirfd, 0, SEEK_CUR);
	if (start == -1) {
		return err_map(errno);
	}

	char entries[4096];
	long size = syscall(SYS_getdents64, dirfd, entries, sizeof(entries));
	if (size == -1) {
		return err_map(errno);
	}

	char *buffer = attributeBuffer;
	size_t used = 0;
	int count = 0;
	off_t resume = start;
	bool full = false;
	for (long offset = 0; offset < size;) {
		struct dirent64 *d = (struct dirent64 *)(entries + offset);
		offset += d->d_reclen;
		if (strcmp(d->d_name, ".") == 0
				|| strcmp(d->d_name, "..") == 0) {
			resume = d->d_off;
			continue;
		}

		char attributes[ATTRIBUTES_SIZE_MAX];
		int fd = openat(dirfd, d->d_name, O_PATH | O_NOFOLLOW);
		if (fd == -1) {
			return err_map(errno);
		}
		int error = pack_attributes(fd, alist, options, attributes);
		close(fd);
		if (error) {
			return err_map(errno);
		}

		uint32_t length = (*(uint32_t *)attributes + 7) & ~7;
		if (used + length > bufferSize) {
			full = true;
			break;
		}
		*(uint32_t *)attributes = length;
		memcpy(buffer + used, attributes, length);
		used += length;
		count++;
		resume = d->d_off;
	}

	lseek(dirfd, resume, SEEK_SET);
	if (count == 0 && full) {
		return _EINVAL;
	}
	if (count == 0 && size != 0) {
		return sys_getattrlistbulk(dirfd, alist, attributeBuffer,
				bufferSize, options);
	}
	return count;
}

int
sys_getattrlist(const char *path, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getattrlist(\"%s\", %p, %p, %p, %p)\n", path,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	int fd = attrlist_open(AT_FDCWD, path, options);
	if (fd == -1) {
#ifdef ENABLE_STRACE
		perror("open");
#endif
		return err_map(errno);
	}

	if (fgetattrlist(fd, alist, attributeBuffer, bufferSize, options)) {
		close(fd);
		return err_map(errno);
	}

	close(fd);
	return 0;
}

int
sys_setattrlist(const char *path, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setattrlist(\"%s\", %p, %p, %p, %p)\n", path,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	int flags = (options & FSOPT_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0;
	char buffer[PATH_MAX];
	if (set_attributes(AT_FDCWD, sysroot_host_path(path, flags, buffer),
			    flags, alist, attributeBuffer)) {
		return err_map(errno);
	}
	return 0;
}

int
sys_fgetattrlist(int fd, void *alist, void *attributeBuffer, size_t bufferSize,
		uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fgetattrlist(%p, %p, %p, %p, %p)\n", (void *)fd,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	if (fgetattrlist(fd, alist, attributeBuffer, bufferSize, options)) {
		return err_map(errno);
	}

	return 0;
}

int
sys_fsetattrlist(int fd, void *alist, void *attributeBuffer, size_t bufferSize,
		uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fsetattrlist(%p, %p, %p, %p, %p)\n", (void *)fd,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	if (set_attributes(fd, NULL, 0, alist, attributeBuffer)) {
		return err_map(errno);
	}

	return 0;
}

int
sys_getattrlistat(int dirfd, const char *path, void *alist,
		void *attributeBuffer, size_t bufferSize, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getattrlistat(%p, %p, %p, %p, %p, %p)\n",
			(void *)dirfd, (void *)path, (void *)alist,
			(void *)attributeBuffer, (void *)bufferSize,
			(void *)options);
#endif
	int fd = attrlist_open(at_fd(dirfd), path, options);
	if (fd == -1) {
#ifdef ENABLE_STRACE
		perror("open");
#endif
		return err_map(errno);
	}

	if (fgetattrlist(fd, alist, attributeBuffer, bufferSize, options)) {
		close(fd);
		return err_map(errno);
	}

	close(fd);
	return 0;
}

int
sys_setattrlistat(int dirfd, const char *path, void *alist,
		void *attributeBuffer, size_t bufferSize, uint32_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setattrlistat(%p, \"%s\", %p, %p, %p, %p)\n",
			(void *)dirfd, path, (void *)alist,
			(void *)attributeBuffer, (void *)bufferSize,
			(void *)options);
#endif
	int flags = (options & FSOPT_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0;
	char buffer[PATH_MAX];
	if (set_attributes(at_fd(dirfd), sysroot_host_path(path, flags, buffer),
			    flags, alist, attributeBuffer)) {
		return err_map(errno);
	}
	return 0;
}

static int
attrlist_open(int dirfd, const char *path, uint64_t options)
{
	int flags = (options & FSOPT_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0;
	char buffer[PATH_MAX];
	return openat(dirfd, sysroot_host_path(path, flags, buffer),
			O_PATH | ((flags != 0) ? O_NOFOLLOW : 0));
}
