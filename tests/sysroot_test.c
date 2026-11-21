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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"
#include "sysroot.h"

#define SKIP 77

static char root[PATH_MAX];

static void populate(void);
static bool mount_volume(void);
static bool write_file(const char *path, const char *text);
static void check_devices(void);
static void check_data_volume(void);
static void check_too_long(void);
static void make_dir(const char *path);
static void make_file(const char *path);
static void make_link(const char *target, const char *path);
static void check_host_path(const char *path, int flags, const char *expected);
static void check_creation_path(
		const char *path, int flags, const char *expected);
static int remove_entry(const char *path, const struct stat *st, int type,
		struct FTW *ftw);

int
main(int argc, char *argv[])
{
	bool mounts = argc == 2 && strcmp(argv[1], "mounts") == 0;
	char template[] = "/tmp/limbo-sysroot test-XXXXXX";
	CHECK(mkdtemp(template) != NULL);
	CHECK(realpath(template, root) != NULL);
	populate();
	if (mounts && !mount_volume()) {
		printf("skipping: no mount in a user namespace here\n");
		CHECK(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
		return SKIP;
	}

	CHECK(setenv("LIMBO_SYSROOT", template, 1) == 0);
	CHECK(sysroot_open() == 0);
	if (mounts) {
		check_devices();
	}
	check_data_volume();

	check_host_path("/System/Library/file", 0, "/System/Library/file");
	check_host_path("/absolute/file", 0, "/System/Library/file");
	check_host_path("/relative/file", 0, "/System/Library/file");
	check_host_path("/absolute", AT_SYMLINK_NOFOLLOW, "/absolute");
	check_host_path("/System/../System/Library", 0, "/System/Library");
	check_host_path("/etc/new", 0, "/private/etc/new");
	check_host_path("/.resolve/33/private/etc/new", 0, "/private/etc/new");
	check_host_path("/.resolve/0/etc/new", 0, "/private/etc/new");
	check_host_path("/.resolve/32/System/Library/file", 0,
			"/System/Library/file");
	check_host_path("/", 0, "");
	check_host_path("/dangling", 0, "/dangling");
	check_creation_path("/dangling", 0, "/System/Library/new");
	check_creation_path("/dangling", AT_SYMLINK_NOFOLLOW, "/dangling");
	check_creation_path("/dangling-absolute", 0, "/private/etc/new");
	check_creation_path("/dangling-chain", 0, "/System/Library/new");
	check_creation_path("/dangling-outside", 0, "/new");
	check_creation_path("/absolute/file", 0, "/System/Library/file");
	check_creation_path("dangling-absolute", 0, "/private/etc/new");
	check_host_path("/System/Volumes/Data", 0, "");
	check_host_path("/System/Volumes/Data/System/Library/file", 0,
			"/System/Library/file");
	check_host_path("/System/Volumes/Data/etc/new", 0, "/private/etc/new");
	check_host_path("/System/Volumes/DataX", 0, "/System/Volumes/DataX");
	check_host_path("/proc/self", 0, "/proc/self");
	check_host_path("/proc/self/status", 0, "/proc/self/status");

	char buffer[PATH_MAX];
	CHECK(strcmp(sysroot_host_path("/tmp", 0, buffer), "/tmp") == 0);
	CHECK(strcmp(sysroot_host_path("/missing/new", 0, buffer),
			      "/missing/new")
			== 0);
	check_too_long();
	CHECK(strcmp(sysroot_host_path("relative", 0, buffer), "relative")
			== 0);

	char path[PATH_MAX + 16];
	snprintf(path, sizeof(path), "%s/System/Library", root);
	CHECK(strcmp(sysroot_guest_path(path), "/System/Library") == 0);
	CHECK(strcmp(sysroot_guest_path(root), "/") == 0);
	snprintf(path, sizeof(path), "%s-sibling/file", root);
	CHECK(strcmp(sysroot_guest_path(path), path) == 0);
	CHECK(strcmp(sysroot_guest_path("/home"), "/home") == 0);

	CHECK(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
	return 0;
}

static void
populate(void)
{
	make_dir("/System");
	make_dir("/System/Library");
	make_file("/System/Library/file");
	make_dir("/private");
	make_dir("/private/etc");
	make_link("private/etc", "/etc");
	make_link("/System/Library", "/absolute");
	make_link("System/Library", "/relative");
	make_link("System/Library/new", "/dangling");
	make_link("/etc/new", "/dangling-absolute");
	make_link("dangling", "/dangling-chain");
	make_link("../../new", "/dangling-outside");
	make_dir("/proc");
	make_dir("/usr");
	make_dir("/usr/share");
	make_file("/usr/share/firmlinks");
	char firmlinks[PATH_MAX * 2];
	snprintf(firmlinks, sizeof(firmlinks), "%s/usr/share/firmlinks", root);
	CHECK(write_file(firmlinks, "/private\tprivate\n/Users\tUsers\n"));
}

static bool
mount_volume(void)
{
	char uid_map[32], gid_map[32], point[PATH_MAX * 2];
	snprintf(uid_map, sizeof(uid_map), "0 %u 1", getuid());
	snprintf(gid_map, sizeof(gid_map), "0 %u 1", getgid());
	make_dir("/Volumes");
	snprintf(point, sizeof(point), "%s/Volumes", root);
	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == -1
			|| !write_file("/proc/self/setgroups", "deny")
			|| !write_file("/proc/self/uid_map", uid_map)
			|| !write_file("/proc/self/gid_map", gid_map)
			|| mount("none", point, "tmpfs", 0, NULL) == -1) {
		return false;
	}
	make_file("/Volumes/file");
	return true;
}

static bool
write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY);
	ssize_t length = strlen(text);
	bool written = fd != -1 && write(fd, text, length) == length;
	close(fd);
	return written;
}

static void
check_devices(void)
{
	char path[PATH_MAX * 2];
	struct stat top, own, mounted;
	CHECK(stat(root, &top) == 0);
	snprintf(path, sizeof(path), "%s/System/Library/file", root);
	CHECK(stat(path, &own) == 0);
	snprintf(path, sizeof(path), "%s/Volumes/file", root);
	CHECK(stat(path, &mounted) == 0);
	CHECK(mounted.st_dev != top.st_dev);
	CHECK(sysroot_device(mounted.st_dev) == top.st_dev);
	CHECK(sysroot_device(own.st_dev) == top.st_dev);
	CHECK(sysroot_file_id(own.st_dev, own.st_ino) == own.st_ino);
	CHECK(sysroot_file_id(mounted.st_dev, mounted.st_ino)
			== (mounted.st_ino | (uint64_t)1 << 40));
	CHECK(sysroot_file_id(top.st_dev, top.st_ino) == 2);
	snprintf(path, sizeof(path), "%s/Volumes", root);
	CHECK(umount(path) == 0);
}

static void
check_data_volume(void)
{
	char host[PATH_MAX * 2];
	snprintf(host, sizeof(host), "%s/private/etc", root);
	CHECK(sysroot_at_on_data_volume(AT_FDCWD, "/private/etc", host));
	CHECK(sysroot_at_on_data_volume(AT_FDCWD, "/etc", host));
	int fd = open(host, O_RDONLY);
	CHECK(fd != -1);
	CHECK(sysroot_fd_on_data_volume(fd));
	CHECK(sysroot_at_on_data_volume(fd, "", ""));
	CHECK(sysroot_at_on_data_volume(fd, "new", "new"));
	close(fd);

	snprintf(host, sizeof(host), "%s/System/Library", root);
	CHECK(!sysroot_at_on_data_volume(AT_FDCWD, "/System/Library", host));
	CHECK(sysroot_at_on_data_volume(
			AT_FDCWD, "/System/Volumes/Data/System/Library", host));
	fd = open(host, O_RDONLY);
	CHECK(fd != -1);
	CHECK(!sysroot_fd_on_data_volume(fd));
	CHECK(!sysroot_at_on_data_volume(fd, "file", "file"));
	close(fd);
	CHECK(!sysroot_at_on_data_volume(AT_FDCWD, "/privateer", "/privateer"));
}

static void
check_creation_path(const char *path, int flags, const char *expected)
{
	char buffer[PATH_MAX];
	char full[PATH_MAX * 2];
	snprintf(full, sizeof(full), "%s%s", root, expected);
	int top = open(root, O_RDONLY | O_DIRECTORY);
	CHECK(top != -1);
	const char *host_path = sysroot_creation_path(top, path, flags, buffer);
	CHECK(close(top) == 0);
	if (strcmp(host_path, full) != 0) {
		fprintf(stderr, "%s: expected %s to make, got %s\n", path, full,
				host_path);
		exit(1);
	}
}

static void
check_too_long(void)
{
	char path[PATH_MAX] = "/System", buffer[PATH_MAX];
	size_t top = strlen(path);
	size_t fitting_alone = PATH_MAX - strlen(root) / 2;
	for (size_t i = top; i < fitting_alone; i++) {
		path[i] = ((i - top) % 100 == 0) ? '/' : 'a';
	}
	path[fitting_alone] = '\0';
	errno = 0;
	CHECK(open(sysroot_host_path(path, 0, buffer), O_RDONLY) == -1);
	CHECK(errno == ENAMETOOLONG);
}

static void
make_dir(const char *path)
{
	char full[PATH_MAX * 2];
	snprintf(full, sizeof(full), "%s%s", root, path);
	CHECK(mkdir(full, 0755) == 0);
}

static void
make_file(const char *path)
{
	char full[PATH_MAX * 2];
	snprintf(full, sizeof(full), "%s%s", root, path);
	int fd = open(full, O_CREAT | O_WRONLY, 0644);
	CHECK(fd != -1);
	close(fd);
}

static void
make_link(const char *target, const char *path)
{
	char full[PATH_MAX * 2];
	snprintf(full, sizeof(full), "%s%s", root, path);
	CHECK(symlink(target, full) == 0);
}

static void
check_host_path(const char *path, int flags, const char *expected)
{
	char buffer[PATH_MAX];
	char full[PATH_MAX * 2];
	snprintf(full, sizeof(full), "%s%s", root, expected);
	const char *host_path = sysroot_host_path(path, flags, buffer);
	if (strcmp(host_path, full) != 0) {
		fprintf(stderr, "%s: expected %s, got %s\n", path, full,
				host_path);
		exit(1);
	}
}

static int
remove_entry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	return remove(path);
}
