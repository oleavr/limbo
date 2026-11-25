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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/openat2.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "bsd/fs/fileid.h"
#include "sysroot.h"
#include "trace.h"

#define NOFOLLOW_PREFIX "/.nofollow"

#define RESOLVE_PREFIX       "/.resolve/"
#define RESOLVE_NOFOLLOW_ANY 0x1
#define LINKS_MAX            32

#define DATA_VOLUME     "/System/Volumes/Data"
#define IOS_DATA_VOLUME "/private/var"

#define DARWIN_PTY_PREFIX "/dev/ttys"

#define DEVICES_MAX     8
#define DEVICE_ID_SHIFT 40

static char root[PATH_MAX];
static dev_t root_dev;
static ino_t root_ino;
static size_t root_length;
static char too_long[PATH_MAX + 1];
static dev_t devices[DEVICES_MAX];
static size_t device_count;
static char **firmlinks;
static size_t firmlink_count;
static bool ios_layout;

static void note_devices(void);
static const char *unescaped(char *field);
static void load_firmlinks(void);
static bool leads_on(
		int dirfd, const char *path, const char *host, char *target);
static const char *host_path(const char *path, int flags, char *buffer);
static const char *pty_host_path(const char *path, char *buffer);
static bool under(const char *path, const char *prefix);
static bool covers(const char *path);
static const char *in_root(const char *path, char *buffer);
static int open_in_root(const char *path, int flags, uint64_t resolve);
static ssize_t read_fd_path(int fd, char *buffer);
static bool on_data_volume(const char *host_path);

int
sysroot_open(void)
{
	const char *path = getenv("LIMBO_SYSROOT");
	if (path == NULL) {
		return 0;
	}

	if (realpath(path, root) == NULL) {
		fprintf(stderr, "limbo: invalid sysroot %s\n", path);
		return 1;
	}
	root_length = strlen(root);
	struct stat s;
	memset(too_long, 'x', PATH_MAX);
	if (stat(root, &s) == 0) {
		root_dev = s.st_dev;
		root_ino = s.st_ino;
	}
	note_devices();
	load_firmlinks();

	return 0;
}

static void
note_devices(void)
{
	devices[0] = root_dev;
	device_count = 1;
	FILE *file = fopen("/proc/self/mountinfo", "re");
	if (file == NULL) {
		return;
	}
	char *line = NULL;
	size_t capacity = 0;
	while (getline(&line, &capacity, file) > 0) {
		unsigned major_number, minor_number;
		char point[PATH_MAX];
		if (sscanf(line, "%*u %*u %u:%u %*s %4095s", &major_number,
				    &minor_number,
				    point) != 3
				|| !under(unescaped(point), root)) {
			continue;
		}
		dev_t dev = makedev(major_number, minor_number);
		size_t i = 0;
		while (i < device_count && devices[i] != dev) {
			i++;
		}
		if (i == device_count && device_count < DEVICES_MAX) {
			devices[device_count++] = dev;
		}
	}
	free(line);
	fclose(file);
}

static const char *
unescaped(char *field)
{
	char *out = field;
	for (const char *in = field; *in != '\0'; in++) {
		if (in[0] == '\\' && isdigit(in[1]) && isdigit(in[2])
				&& isdigit(in[3])) {
			*out++ = (char)((in[1] - '0') << 6 | (in[2] - '0') << 3
					| (in[3] - '0'));
			in += 3;
		} else {
			*out++ = *in;
		}
	}
	*out = '\0';
	return field;
}

static void
load_firmlinks(void)
{
	char path[PATH_MAX + sizeof("/usr/share/firmlinks")];
	snprintf(path, sizeof(path), "%s/usr/share/firmlinks", root);
	FILE *file = fopen(path, "re");
	if (file == NULL) {
		char volumes[PATH_MAX + sizeof("/System/Volumes")];
		char var[PATH_MAX + sizeof(IOS_DATA_VOLUME)];
		snprintf(volumes, sizeof(volumes), "%s/System/Volumes", root);
		snprintf(var, sizeof(var), "%s" IOS_DATA_VOLUME, root);
		struct stat s;
		if (stat(volumes, &s) != 0 && stat(var, &s) == 0
				&& S_ISDIR(s.st_mode)) {
			ios_layout = true;
			firmlinks = malloc(sizeof(*firmlinks));
			firmlinks[firmlink_count++] = strdup(IOS_DATA_VOLUME);
		}
		return;
	}
	char line[PATH_MAX];
	while (fgets(line, sizeof(line), file) != NULL) {
		line[strcspn(line, "\t\n")] = '\0';
		if (line[0] != '/' || line[1] == '\0') {
			continue;
		}
		firmlinks = realloc(firmlinks,
				(firmlink_count + 1) * sizeof(*firmlinks));
		firmlinks[firmlink_count++] = strdup(line);
	}
	fclose(file);
}

const char *
sysroot_host_path(const char *path, int flags, char *buffer)
{
	const char *host = host_path(path, flags, buffer);
	if (path != NULL) {
		trace_path(path, host);
	}
	return host;
}

const char *
sysroot_creation_path(int dirfd, const char *path, int flags, char *buffer)
{
	const char *host = sysroot_host_path(path, flags, buffer);
	char target[PATH_MAX];
	for (int links = 0; links < LINKS_MAX && !(flags & AT_SYMLINK_NOFOLLOW)
			&& leads_on(dirfd, path, host, target);
			links++) {
		const char *next = host_path(target, 0, buffer);
		if (next != buffer) {
			snprintf(buffer, PATH_MAX, "%s", next);
		}
		host = buffer;
	}
	return host;
}

static bool
leads_on(int dirfd, const char *path, const char *host, char *target)
{
	char link[PATH_MAX];
	ssize_t length = readlinkat(dirfd, host, link, sizeof(link) - 1);
	if (length == -1
			|| strncmp(path, NOFOLLOW_PREFIX,
					   strlen(NOFOLLOW_PREFIX))
					== 0
			|| strncmp(path, RESOLVE_PREFIX, strlen(RESOLVE_PREFIX))
					== 0) {
		return false;
	}
	link[length] = '\0';
	const char *folder = sysroot_guest_path(host);
	const char *name = strrchr(folder, '/');
	int folder_length = (link[0] == '/' || name == NULL)
			? 0
			: (int)(name - folder + 1);
	return snprintf(target, PATH_MAX, "%.*s%s", folder_length, folder, link)
			< PATH_MAX;
}

static const char *
host_path(const char *path, int flags, char *buffer)
{
	if (path == NULL || root_length == 0 || path[0] != '/') {
		return path;
	}

	char volfs[PATH_MAX];
	if (strncmp(path, "/.vol/", 6) == 0) {
		const char *at = path + 6;
		char *end;
		strtoll(at, &end, 10);
		if (end != at && *end == '/') {
			at = end + 1;
			uint64_t id = strtoull(at, &end, 10);
			char base[PATH_MAX];
			if (end != at && (*end == '/' || *end == '\0')
					&& fileid_path(id, base, sizeof(base))
							> 0) {
				bool top = strcmp(base, "/") == 0
						&& *end == '/';
				snprintf(volfs, sizeof(volfs), "%s%s",
						top ? "" : base, end);
				path = volfs[0] != '\0' ? volfs : "/";
			}
		}
	}

	uint64_t resolve = 0;
	if (strncmp(path, NOFOLLOW_PREFIX, strlen(NOFOLLOW_PREFIX)) == 0
			&& (path[strlen(NOFOLLOW_PREFIX)] == '/'
					|| path[strlen(NOFOLLOW_PREFIX)]
							== '\0')) {
		path += strlen(NOFOLLOW_PREFIX);
		if (path[0] == '\0') {
			path = "/";
		}
		resolve = RESOLVE_NO_SYMLINKS;
	}

	if (strncmp(path, RESOLVE_PREFIX, strlen(RESOLVE_PREFIX)) == 0) {
		const char *flags = path + strlen(RESOLVE_PREFIX);
		char *end;
		unsigned long value = strtoul(flags, &end, 10);
		if (end != flags && (*end == '/' || *end == '\0')) {
			path = (*end == '\0') ? "/" : end;
			if (value & RESOLVE_NOFOLLOW_ANY) {
				resolve = RESOLVE_NO_SYMLINKS;
			}
		}
	}

	if (under(path, DATA_VOLUME)) {
		path += strlen(DATA_VOLUME);
		if (path[0] == '\0') {
			path = "/";
		}
	}

	if (strncmp(path, "/dev", 4) == 0
			&& (path[4] == '/' || path[4] == '\0')) {
		return pty_host_path(path, buffer);
	}

	int fd = open_in_root(path, flags, resolve);
	if (fd != -1) {
		return (read_fd_path(fd, buffer) != -1) ? buffer : path;
	}

	bool missing = errno == ENOENT;
	bool covered = covers(path);
	if (!missing) {
		return covered ? in_root(path, buffer) : path;
	}
	if (!covered
			&& faccessat(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW)
					== 0) {
		return path;
	}

	size_t path_length = strlen(path);
	while (path_length > 1 && path[path_length - 1] == '/') {
		path_length--;
	}
	const char *name = path + path_length;
	while (name > path && name[-1] != '/') {
		name--;
	}
	size_t name_length = (path + path_length) - name;
	if (name_length == 0 || (name_length == 1 && name[0] == '.')
			|| (name_length == 2 && name[0] == '.' && name[1] == '.')) {
		return covered ? in_root(path, buffer) : path;
	}

	char parent[PATH_MAX];
	snprintf(parent, sizeof(parent), "%.*s", (int)(name - path), path);
	fd = open_in_root(parent, 0, resolve);
	if (fd == -1) {
		return covered ? in_root(path, buffer) : path;
	}

	ssize_t length = read_fd_path(fd, buffer);
	if (length == -1) {
		return covered ? in_root(path, buffer) : path;
	}
	snprintf(buffer + length, PATH_MAX - length, "/%.*s",
			(int)name_length, name);
	return buffer;
}

static const char *
pty_host_path(const char *path, char *buffer)
{
	const char *digits = path + strlen(DARWIN_PTY_PREFIX);
	if (strncmp(path, DARWIN_PTY_PREFIX, strlen(DARWIN_PTY_PREFIX)) != 0
			|| !isdigit((unsigned char)*digits)) {
		return path;
	}
	char *end;
	unsigned long number = strtoul(digits, &end, 10);
	if (*end != '\0' && *end != '/') {
		return path;
	}
	snprintf(buffer, PATH_MAX, "/dev/pts/%lu%s", number, end);
	return buffer;
}

static bool
under(const char *path, const char *prefix)
{
	size_t length = strlen(prefix);
	return strncmp(path, prefix, length) == 0
			&& (path[length] == '\0' || path[length] == '/');
}

static bool
covers(const char *path)
{
	const char *name = path + strspn(path, "/");
	size_t length = strcspn(name, "/");
	if (length == 0) {
		return true;
	}
	char top[NAME_MAX + 2];
	snprintf(top, sizeof(top), "/%.*s", (int)length, name);
	int fd = open_in_root(top, AT_SYMLINK_NOFOLLOW, 0);
	if (fd == -1) {
		return false;
	}
	close(fd);
	return true;
}

static const char *
in_root(const char *path, char *buffer)
{
	int length = snprintf(buffer, PATH_MAX, "%s%s", root, path);
	return length < PATH_MAX ? buffer : too_long;
}

const char *
sysroot_guest_path(const char *path)
{
	if (root_length == 0 || strncmp(path, root, root_length) != 0) {
		return path;
	}

	switch (path[root_length]) {
	case '\0':
		return "/";
	case '/':
		return path + root_length;
	default:
		return path;
	}
}

static int
open_in_root(const char *path, int flags, uint64_t resolve)
{
	int root_fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (root_fd == -1) {
		return -1;
	}

	struct open_how how = {
			.flags = O_PATH | O_CLOEXEC,
			.resolve
			= RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | resolve,
	};
	if (flags & AT_SYMLINK_NOFOLLOW) {
		how.flags |= O_NOFOLLOW;
	}
	int fd = syscall(SYS_openat2, root_fd, path, &how, sizeof(how));
	close(root_fd);

	return fd;
}

static ssize_t
read_fd_path(int fd, char *buffer)
{
	char link[48];
	snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
	ssize_t length = readlink(link, buffer, PATH_MAX - 1);
	close(fd);
	if (length != -1) {
		buffer[length] = '\0';
	}
	return length;
}

uint64_t
sysroot_file_id(dev_t dev, uint64_t ino)
{
	if (root_length != 0 && dev == root_dev && ino == root_ino) {
		return 2;
	}
	for (size_t i = 1; i < device_count; i++) {
		if (devices[i] == dev) {
			return ino | ((uint64_t)i << DEVICE_ID_SHIFT);
		}
	}
	return ino;
}

dev_t
sysroot_device(dev_t dev)
{
	for (size_t i = 1; i < device_count; i++) {
		if (devices[i] == dev) {
			return root_dev;
		}
	}
	return dev;
}

dev_t
sysroot_root_device(void)
{
	return root_dev;
}

bool
sysroot_space(dev_t dev, struct statvfs *space)
{
	size_t i = 0;
	while (i < device_count && devices[i] != dev) {
		i++;
	}
	if (root_length == 0 || i == device_count) {
		return false;
	}
	int fd = -1;
	for (i = 0; i < firmlink_count && fd == -1; i++) {
		fd = open_in_root(firmlinks[i], 0, 0);
	}
	if (fd == -1) {
		return statvfs(root, space) == 0;
	}
	bool found = fstatvfs(fd, space) == 0;
	close(fd);
	return found;
}

bool
sysroot_fd_on_data_volume(int fd)
{
	char link[48], host[PATH_MAX];
	snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
	ssize_t length = readlink(link, host, sizeof(host) - 1);
	if (length == -1) {
		return false;
	}
	host[length] = '\0';
	return on_data_volume(host);
}

static bool
on_data_volume(const char *host_path)
{
	const char *guest = sysroot_guest_path(host_path);
	if (guest == host_path) {
		return false;
	}
	for (size_t i = 0; i < firmlink_count; i++) {
		if (under(guest, firmlinks[i])) {
			return true;
		}
	}
	return false;
}

const char *
sysroot_data_mount_point(void)
{
	return ios_layout ? IOS_DATA_VOLUME : DATA_VOLUME;
}

bool
sysroot_at_on_data_volume(int dirfd, const char *path, const char *host_path)
{
	if (path == NULL || path[0] == '\0') {
		return sysroot_fd_on_data_volume(dirfd);
	}
	if (path[0] == '/') {
		return under(path, DATA_VOLUME) || on_data_volume(host_path);
	}
	char folder[PATH_MAX], joined[PATH_MAX * 2];
	if (dirfd == AT_FDCWD) {
		if (getcwd(folder, sizeof(folder)) == NULL) {
			return false;
		}
	} else {
		char link[48];
		snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", dirfd);
		ssize_t length = readlink(link, folder, sizeof(folder) - 1);
		if (length == -1) {
			return false;
		}
		folder[length] = '\0';
	}
	snprintf(joined, sizeof(joined), "%s/%s", folder, path);
	return on_data_volume(joined);
}
