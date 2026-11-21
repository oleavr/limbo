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
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"

#define DATA_VOLUME "/System/Volumes/Data"

#ifndef MNT_EXT_ROOT_DATA_VOL
#define MNT_EXT_ROOT_DATA_VOL 0x00000001
#endif

static void check_paths(void);
static void check_statfs(void);
static void check_mounts(void);

int
main(void)
{
	check_paths();
	check_statfs();
	check_mounts();
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
