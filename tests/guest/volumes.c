/*
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

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "check.h"

#define DATA_VOLUME "/System/Volumes/Data"

#ifndef AT_REALDEV
#define AT_REALDEV 0x0200
#endif
#ifndef MNT_EXT_ROOT_DATA_VOL
#define MNT_EXT_ROOT_DATA_VOL 0x00000001
#endif

struct volume {
	char mount_point[PATH_MAX];
	char name[NAME_MAX + 1];
	char device[PATH_MAX];
	uint32_t flags;
	uint32_t extended_flags;
	uuid_t uuid;
};

struct place {
	char name[NAME_MAX + 1];
	fsid_t fsid;
	fsid_t real_fsid;
	dev_t real_device;
	uint32_t mount_status;
};

static void check_paths(void);
static void check_statfs(void);
static void check_mounts(void);
static void check_real_device(void);
static void check_attributes(void);
static void volume_of(const char *path, struct volume *volume);
static void place_of(const char *path, struct place *place);

int
main(void)
{
	check_paths();
	check_statfs();
	check_mounts();
	check_real_device();
	check_attributes();
	return 0;
}

static void
check_paths(void)
{
	struct stat direct, through;
	CHECK(stat("/private/tmp", &direct) == 0);
	CHECK(stat(DATA_VOLUME "/private/tmp", &through) == 0);
	CHECK(direct.st_ino == through.st_ino);
	CHECK(direct.st_dev == through.st_dev);
	CHECK(stat(DATA_VOLUME, &through) == 0);
	CHECK(S_ISDIR(through.st_mode));
	CHECK(stat(DATA_VOLUME "X", &through) == -1);
}

static void
check_statfs(void)
{
	struct statfs system, data, named, relative, open_data, open_system;
	struct stat root;
	CHECK(statfs("/", &system) == 0);
	CHECK(statfs("/private/tmp", &data) == 0);
	CHECK(statfs(DATA_VOLUME, &named) == 0);
	CHECK(stat("/", &root) == 0);

	CHECK(strcmp(system.f_mntonname, "/") == 0);
	CHECK(strcmp(data.f_mntonname, DATA_VOLUME) == 0);
	CHECK(strcmp(named.f_mntonname, DATA_VOLUME) == 0);
	CHECK(strcmp(system.f_mntfromname, data.f_mntfromname) != 0);
	CHECK(strcmp(named.f_mntfromname, data.f_mntfromname) == 0);
	CHECK(data.f_fsid.val[0] == root.st_dev);
	CHECK(system.f_fsid.val[0] != root.st_dev);
	CHECK(system.f_flags & MNT_ROOTFS);
	CHECK(!(data.f_flags & MNT_ROOTFS));
	CHECK(data.f_flags & MNT_LOCAL);
	CHECK(data.f_flags & MNT_DONTBROWSE);
	CHECK(data.f_flags_ext & MNT_EXT_ROOT_DATA_VOL);
	CHECK(!(system.f_flags_ext & MNT_EXT_ROOT_DATA_VOL));
	struct statfs devices;
	struct stat dev;
	CHECK(statfs("/dev", &devices) == 0);
	CHECK(stat("/dev", &dev) == 0);
	CHECK(devices.f_fsid.val[0] == dev.st_dev);

	int fd = open("/private/tmp", O_RDONLY);
	CHECK(fd != -1);
	CHECK(fstatfs(fd, &open_data) == 0);
	CHECK(strcmp(open_data.f_mntonname, DATA_VOLUME) == 0);
	CHECK(fchdir(fd) == 0);
	CHECK(statfs(".", &relative) == 0);
	CHECK(strcmp(relative.f_mntonname, DATA_VOLUME) == 0);
	CHECK(chdir("/") == 0);
	CHECK(close(fd) == 0);
	fd = open("/usr", O_RDONLY);
	CHECK(fd != -1);
	CHECK(fstatfs(fd, &open_system) == 0);
	CHECK(strcmp(open_system.f_mntonname, "/") == 0);
	CHECK(close(fd) == 0);
}

static void
check_mounts(void)
{
	int count = getfsstat(NULL, 0, MNT_NOWAIT);
	CHECK(count >= 2);
	static struct statfs mounts[64];
	count = getfsstat(mounts, sizeof(mounts), MNT_NOWAIT);
	CHECK(count >= 2);
	bool system = false, data = false;
	for (int i = 0; i != count; i++) {
		system |= strcmp(mounts[i].f_mntonname, "/") == 0;
		data |= strcmp(mounts[i].f_mntonname, DATA_VOLUME) == 0;
	}
	CHECK(system && data);
	CHECK(getfsstat(mounts, sizeof(mounts[0]), MNT_NOWAIT) == 1);
	CHECK(strcmp(mounts[0].f_mntonname, "/") == 0);
}

static void
check_real_device(void)
{
	struct statfs system, data;
	CHECK(statfs("/", &system) == 0);
	CHECK(statfs("/private/tmp", &data) == 0);
	struct stat shown, real;
	CHECK(stat("/usr", &shown) == 0);
	CHECK(fstatat(AT_FDCWD, "/usr", &real, AT_REALDEV) == 0);
	CHECK(shown.st_dev == data.f_fsid.val[0]);
	CHECK(real.st_dev == system.f_fsid.val[0]);
	CHECK(real.st_ino == shown.st_ino);
	CHECK(fstatat(AT_FDCWD, "/private/tmp", &real, AT_REALDEV) == 0);
	CHECK(real.st_dev == data.f_fsid.val[0]);
	int fd = open("/usr", O_RDONLY);
	CHECK(fd != -1);
	CHECK(fstatat(fd, "bin", &real, AT_REALDEV) == 0);
	CHECK(real.st_dev == system.f_fsid.val[0]);
	CHECK(close(fd) == 0);
}

static void
check_attributes(void)
{
	struct statfs system_fs, data_fs;
	CHECK(statfs("/", &system_fs) == 0);
	CHECK(statfs("/private/tmp", &data_fs) == 0);
	struct stat root;
	CHECK(stat("/", &root) == 0);

	struct volume system, data, named, through;
	volume_of("/usr", &system);
	volume_of("/private/tmp", &data);
	volume_of(DATA_VOLUME, &named);
	volume_of(DATA_VOLUME "/usr", &through);
	CHECK(strcmp(through.mount_point, DATA_VOLUME) == 0);
	CHECK(strcmp(through.device, data_fs.f_mntfromname) == 0);
	CHECK(strcmp(system.mount_point, "/") == 0);
	CHECK(strcmp(data.mount_point, DATA_VOLUME) == 0);
	CHECK(strcmp(named.mount_point, DATA_VOLUME) == 0);
	CHECK(strcmp(system.name, data.name) != 0);
	CHECK(strcmp(named.name, data.name) == 0);
	CHECK(strcmp(system.device, system_fs.f_mntfromname) == 0);
	CHECK(strcmp(data.device, data_fs.f_mntfromname) == 0);
	CHECK(system.flags & MNT_ROOTFS);
	CHECK(!(data.flags & MNT_ROOTFS));
	CHECK(data.flags & MNT_DONTBROWSE);
	CHECK(!(system.extended_flags & MNT_EXT_ROOT_DATA_VOL));
	CHECK(data.extended_flags & MNT_EXT_ROOT_DATA_VOL);
	CHECK(uuid_compare(system.uuid, data.uuid) != 0);
	CHECK(uuid_compare(named.uuid, data.uuid) == 0);

	struct place top, usr, tmp, mount;
	place_of("/", &top);
	place_of("/usr", &usr);
	place_of("/private/tmp", &tmp);
	place_of(DATA_VOLUME, &mount);
	CHECK(top.mount_status & DIR_MNTSTATUS_MNTPOINT);
	CHECK(mount.mount_status & DIR_MNTSTATUS_MNTPOINT);
	CHECK(!(usr.mount_status & DIR_MNTSTATUS_MNTPOINT));
	CHECK(!(tmp.mount_status & DIR_MNTSTATUS_MNTPOINT));
	CHECK(strcmp(mount.name, "Data") == 0);
	CHECK(strcmp(usr.name, "usr") == 0);
	CHECK(usr.fsid.val[0] == root.st_dev);
	CHECK(tmp.fsid.val[0] == root.st_dev);
	CHECK(usr.real_fsid.val[0] == system_fs.f_fsid.val[0]);
	CHECK(usr.real_device == system_fs.f_fsid.val[0]);
	CHECK(tmp.real_fsid.val[0] == data_fs.f_fsid.val[0]);
	CHECK(tmp.real_device == data_fs.f_fsid.val[0]);
	CHECK(mount.real_fsid.val[0] == data_fs.f_fsid.val[0]);
	struct place under;
	place_of(DATA_VOLUME "/usr", &under);
	CHECK(under.real_fsid.val[0] == data_fs.f_fsid.val[0]);
	CHECK(!(under.mount_status & DIR_MNTSTATUS_MNTPOINT));
}

static void
volume_of(const char *path, struct volume *volume)
{
	struct attrlist request = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.volattr = ATTR_VOL_INFO | ATTR_VOL_MOUNTPOINT
					| ATTR_VOL_NAME | ATTR_VOL_MOUNTFLAGS
					| ATTR_VOL_MOUNTEDDEVICE | ATTR_VOL_UUID
					| ATTR_VOL_MOUNTEXTFLAGS,
	};
	struct {
		uint32_t length;
		attrreference_t mount_point;
		attrreference_t name;
		uint32_t flags;
		attrreference_t device;
		uuid_t uuid;
		uint32_t extended_flags;
		char data[3 * PATH_MAX];
	} __attribute__((packed)) buffer;
	CHECK(getattrlist(path, &request, &buffer, sizeof(buffer), 0) == 0);
	strlcpy(volume->mount_point,
			(char *)&buffer.mount_point
					+ buffer.mount_point.attr_dataoffset,
			sizeof(volume->mount_point));
	strlcpy(volume->name,
			(char *)&buffer.name + buffer.name.attr_dataoffset,
			sizeof(volume->name));
	strlcpy(volume->device,
			(char *)&buffer.device + buffer.device.attr_dataoffset,
			sizeof(volume->device));
	volume->flags = buffer.flags;
	volume->extended_flags = buffer.extended_flags;
	uuid_copy(volume->uuid, buffer.uuid);
}

static void
place_of(const char *path, struct place *place)
{
	struct attrlist request = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_NAME | ATTR_CMN_FSID,
			.dirattr = ATTR_DIR_MOUNTSTATUS,
			.forkattr
			= ATTR_CMNEXT_REALDEVID | ATTR_CMNEXT_REALFSID,
	};
	struct {
		uint32_t length;
		attrreference_t name;
		fsid_t fsid;
		uint32_t mount_status;
		dev_t real_device;
		fsid_t real_fsid;
		char data[NAME_MAX + 1];
	} __attribute__((packed)) buffer;
	CHECK(getattrlist(path, &request, &buffer, sizeof(buffer),
			      FSOPT_ATTR_CMN_EXTENDED)
			== 0);
	strlcpy(place->name, (char *)&buffer.name + buffer.name.attr_dataoffset,
			sizeof(place->name));
	place->fsid = buffer.fsid;
	place->real_fsid = buffer.real_fsid;
	place->real_device = buffer.real_device;
	place->mount_status = buffer.mount_status;
}
