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
#include <sys/syscall.h>
#include <unistd.h>

#include "sysroot.h"

#define NOFOLLOW_PREFIX "/.nofollow"

#define RESOLVE_PREFIX       "/.resolve/"
#define RESOLVE_NOFOLLOW_ANY 0x1

static char root[PATH_MAX];
static dev_t root_dev;
static ino_t root_ino;
static size_t root_length;

static int open_in_root(const char *path, int flags, uint64_t resolve);
static ssize_t read_fd_path(int fd, char *buffer);

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
	if (stat(root, &s) == 0) {
		root_dev = s.st_dev;
		root_ino = s.st_ino;
	}

	return 0;
}

const char *
sysroot_host_path(const char *path, int flags, char *buffer)
{
	if (path == NULL || root_length == 0 || path[0] != '/') {
		return path;
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

	if (strncmp(path, "/dev", 4) == 0
			&& (path[4] == '/' || path[4] == '\0')) {
		return path;
	}

	int fd = open_in_root(path, flags, resolve);
	if (fd != -1) {
		return (read_fd_path(fd, buffer) != -1) ? buffer : path;
	}

	if (errno != ENOENT
			|| faccessat(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW)
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
		return path;
	}

	char parent[PATH_MAX];
	snprintf(parent, sizeof(parent), "%.*s", (int)(name - path), path);
	fd = open_in_root(parent, 0, resolve);
	if (fd == -1) {
		return path;
	}

	ssize_t length = read_fd_path(fd, buffer);
	if (length == -1) {
		return path;
	}
	snprintf(buffer + length, PATH_MAX - length, "/%.*s",
			(int)name_length, name);
	return buffer;
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
	return ino;
}
