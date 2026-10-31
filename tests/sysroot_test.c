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

#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"
#include "sysroot.h"

static char root[PATH_MAX];

static void populate(void);
static void make_dir(const char *path);
static void make_file(const char *path);
static void make_link(const char *target, const char *path);
static void check_host_path(const char *path, int flags, const char *expected);
static int remove_entry(const char *path, const struct stat *st, int type,
		struct FTW *ftw);

int
main(void)
{
	char template[] = "/tmp/limbo-sysroot-XXXXXX";
	CHECK(mkdtemp(template) != NULL);
	CHECK(realpath(template, root) != NULL);
	populate();

	CHECK(setenv("LIMBO_SYSROOT", template, 1) == 0);
	CHECK(sysroot_open() == 0);

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

	char buffer[PATH_MAX];
	CHECK(strcmp(sysroot_host_path("/tmp", 0, buffer), "/tmp") == 0);
	CHECK(strcmp(sysroot_host_path("/missing/new", 0, buffer),
			      "/missing/new")
			== 0);
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
