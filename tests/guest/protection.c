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

#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "check.h"

#define USER 501
#define SKIP 77

#define CLASS_DIR_NONE 0
#define CLASS_A        1
#define CLASS_B        2
#define CLASS_C        3
#define CLASS_D        4
#define CLASS_E        5
#define CLASS_F        6
#define CLASS_CX       7

static void clean_up(void);
static int remove_entry(const char *path, const struct stat *st, int type,
		struct FTW *ftw);
static void check_defaults(void);
static void check_kept(void);
static void check_attrlist(void);
static void check_hidden(void);
static void check_inherited(void);
static void check_copy(void);
static void check_user(void);
static void user_sets(void);
static int class_of(const char *path);
static int attrlist_class_of(const char *path);
static int set_class(const char *path, int dpclass);
static int set_attrlist_class(const char *path, uint32_t dpclass);
static void make_file(const char *path);
static int as_user(void (*body)(void));

static char folder[] = "/tmp/limbo-protection-XXXXXX";
static pid_t owner;
static bool skipped;

int
main(void)
{
	CHECK(mkdtemp(folder) != NULL);
	owner = getpid();
	CHECK(atexit(clean_up) == 0);
	CHECK(chmod(folder, 0755) == 0);
	CHECK(chdir(folder) == 0);

	check_defaults();
	check_kept();
	check_attrlist();
	check_hidden();
	check_inherited();
	check_copy();
	check_user();

	CHECK(chdir("/") == 0);
	CHECK(rmdir(folder) == 0);
	return skipped ? SKIP : 0;
}

static void
clean_up(void)
{
	if (getpid() == owner) {
		nftw(folder, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
	}
}

static int
remove_entry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	return remove(path);
}

static void
check_defaults(void)
{
	CHECK(mkdir("plain", 0755) == 0);
	make_file("plain/file");
	CHECK(mkdir("plain/folder", 0755) == 0);
	CHECK(class_of("plain") == CLASS_DIR_NONE);
	CHECK(class_of("plain/file") == CLASS_C);
	CHECK(class_of("plain/folder") == CLASS_DIR_NONE);
	CHECK(rmdir("plain/folder") == 0);
	CHECK(unlink("plain/file") == 0);
	CHECK(rmdir("plain") == 0);
}

static void
check_kept(void)
{
	CHECK(mkdir("kept", 0755) == 0);
	make_file("kept/file");

	CHECK(set_class("kept", CLASS_A) == 0);
	CHECK(class_of("kept") == CLASS_A);
	CHECK(set_class("kept/file", CLASS_B) == 0);
	CHECK(class_of("kept/file") == CLASS_B);

	CHECK(set_class("kept/file", CLASS_D) == 0);
	CHECK(class_of("kept/file") == CLASS_C);
	CHECK(set_class("kept", CLASS_D) == 0);
	CHECK(class_of("kept") == CLASS_C);
	CHECK(set_class("kept", CLASS_CX) == 0);
	CHECK(class_of("kept") == CLASS_C);

	CHECK(set_class("kept/file", CLASS_C) == 0);
	CHECK(class_of("kept/file") == CLASS_C);
	CHECK(set_class("kept", CLASS_DIR_NONE) == 0);
	CHECK(class_of("kept") == CLASS_DIR_NONE);

	errno = 0;
	CHECK(set_class("kept/file", CLASS_DIR_NONE) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(set_class("kept/file", CLASS_E) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(set_class("kept", CLASS_E) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(set_class("kept/file", 9) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(set_class("kept", CLASS_F) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(set_class("kept/file", CLASS_F) == -1 && errno == EPERM);
	errno = 0;
	CHECK(set_class("kept/file", CLASS_CX) == -1 && errno == EPERM);
	CHECK(class_of("kept/file") == CLASS_C);
	CHECK(class_of("kept") == CLASS_DIR_NONE);

	CHECK(unlink("kept/file") == 0);
	CHECK(rmdir("kept") == 0);
}

static void
check_attrlist(void)
{
	CHECK(mkdir("listed", 0755) == 0);
	make_file("listed/file");
	CHECK(attrlist_class_of("listed") == CLASS_DIR_NONE);
	CHECK(attrlist_class_of("listed/file") == CLASS_C);

	CHECK(set_class("listed", CLASS_A) == 0);
	CHECK(attrlist_class_of("listed") == CLASS_A);
	CHECK(set_class("listed/file", CLASS_B) == 0);
	CHECK(attrlist_class_of("listed/file") == CLASS_B);

	CHECK(set_attrlist_class("listed/file", CLASS_A) == 0);
	CHECK(class_of("listed/file") == CLASS_A);
	CHECK(attrlist_class_of("listed/file") == CLASS_A);
	CHECK(set_attrlist_class("listed", CLASS_B) == 0);
	CHECK(class_of("listed") == CLASS_B);
	errno = 0;
	CHECK(set_attrlist_class("listed/file", CLASS_E) == -1
			&& errno == EINVAL);
	CHECK(class_of("listed/file") == CLASS_A);

	CHECK(unlink("listed/file") == 0);
	CHECK(rmdir("listed") == 0);
}

static void
check_hidden(void)
{
	CHECK(mkdir("hidden", 0755) == 0);
	CHECK(set_class("hidden", CLASS_A) == 0);

	char names[1024];
	ssize_t length = listxattr("hidden", names, sizeof(names), 0);
	CHECK(length >= 0);
	for (const char *name = names; name < names + length;
			name += strlen(name) + 1) {
		CHECK(strstr(name, "limbo") == NULL);
	}
	uint32_t value = CLASS_B;
	errno = 0;
	CHECK(getxattr("hidden", "limbo.protection_class", &value,
			      sizeof(value), 0, 0)
			== -1);
	CHECK(errno == ENOATTR);
	if (setxattr("hidden", "limbo.protection_class", &value, sizeof(value),
			    0, 0)
			== 0) {
		CHECK(removexattr("hidden", "limbo.protection_class", 0) == 0);
	} else {
		CHECK(errno == EPERM);
		CHECK(removexattr("hidden", "limbo.protection_class", 0) == -1);
		CHECK(errno == EPERM);
	}
	CHECK(class_of("hidden") == CLASS_A);

	CHECK(rmdir("hidden") == 0);
}

static void
check_inherited(void)
{
	CHECK(mkdir("given", 0755) == 0);
	CHECK(set_class("given", CLASS_A) == 0);
	make_file("given/file");
	CHECK(mkdir("given/folder", 0755) == 0);
	make_file("given/folder/file");
	CHECK(class_of("given/file") == CLASS_A);
	CHECK(class_of("given/folder") == CLASS_A);
	CHECK(class_of("given/folder/file") == CLASS_A);
	int dir = open("given", O_RDONLY);
	CHECK(dir != -1);
	int fd = openat(dir, "relative", O_RDWR | O_CREAT, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(mkdirat(dir, "relative-folder", 0755) == 0);
	CHECK(close(dir) == 0);
	CHECK(class_of("given/relative") == CLASS_A);
	CHECK(class_of("given/relative-folder") == CLASS_A);

	CHECK(set_class("given", CLASS_B) == 0);
	CHECK(class_of("given/file") == CLASS_A);
	fd = open("given/file", O_RDWR | O_CREAT, 0644);
	CHECK(fd != -1);
	CHECK(close(fd) == 0);
	CHECK(class_of("given/file") == CLASS_A);

	CHECK(symlink("given/through", "dangling") == 0);
	fd = open("dangling", O_RDWR | O_CREAT, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(class_of("given/through") == CLASS_B);
	CHECK(unlink("given/through") == 0);
	CHECK(unlink("dangling") == 0);

	CHECK(rmdir("given/relative-folder") == 0);
	CHECK(unlink("given/relative") == 0);
	CHECK(unlink("given/folder/file") == 0);
	CHECK(rmdir("given/folder") == 0);
	CHECK(unlink("given/file") == 0);
	CHECK(rmdir("given") == 0);
}

static void
check_copy(void)
{
	CHECK(mkdir("source", 0755) == 0);
	CHECK(set_class("source", CLASS_A) == 0);
	make_file("source/file");
	CHECK(set_class("source/file", CLASS_B) == 0);
	CHECK(copyfile("source", "copy", NULL,
			      COPYFILE_ALL | COPYFILE_RECURSIVE)
			== 0);
	struct stat s;
	CHECK(stat("copy/file", &s) == 0);
	CHECK(unlink("copy/file") == 0);
	CHECK(rmdir("copy") == 0);
	CHECK(unlink("source/file") == 0);
	CHECK(rmdir("source") == 0);
}

static void
check_user(void)
{
	if (geteuid() != 0) {
		printf("skipping the user's classes: not root\n");
		skipped = true;
		return;
	}
	make_file("theirs");
	make_file("open");
	CHECK(chown("theirs", 1, 1) == 0);
	CHECK(chown("open", 1, 1) == 0);
	CHECK(chmod("open", 0666) == 0);
	int result = as_user(user_sets);
	if (result == SKIP) {
		printf("skipping the user's classes: no user %d here\n", USER);
		skipped = true;
	} else {
		CHECK(result == 0);
	}
	CHECK(unlink("open") == 0);
	CHECK(unlink("theirs") == 0);
}

static void
user_sets(void)
{
	errno = 0;
	CHECK(set_class("theirs", CLASS_A) == -1 && errno == EBADF);
	CHECK(class_of("theirs") == CLASS_C);
	CHECK(set_class("open", CLASS_A) == 0);
	CHECK(class_of("open") == CLASS_A);
}

static int
class_of(const char *path)
{
	int fd = open(path, O_RDONLY);
	CHECK(fd != -1);
	int dpclass = fcntl(fd, F_GETPROTECTIONCLASS);
	CHECK(close(fd) == 0);
	return dpclass;
}

static int
attrlist_class_of(const char *path)
{
	struct attrlist list = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_DATA_PROTECT_FLAGS,
	};
	struct {
		uint32_t length;
		uint32_t dpclass;
	} __attribute__((packed)) buffer;
	CHECK(getattrlist(path, &list, &buffer, sizeof(buffer), 0) == 0);
	CHECK(buffer.length == sizeof(buffer));
	return (int)buffer.dpclass;
}

static int
set_class(const char *path, int dpclass)
{
	int fd = open(path, O_RDONLY);
	CHECK(fd != -1);
	int r = fcntl(fd, F_SETPROTECTIONCLASS, dpclass);
	int saved = errno;
	CHECK(close(fd) == 0);
	errno = saved;
	return r;
}

static int
set_attrlist_class(const char *path, uint32_t dpclass)
{
	struct attrlist list = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_DATA_PROTECT_FLAGS,
	};
	return setattrlist(path, &list, &dpclass, sizeof(dpclass), 0);
}

static void
make_file(const char *path)
{
	int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
	CHECK(fd != -1);
	CHECK(close(fd) == 0);
}

static int
as_user(void (*body)(void))
{
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		if (setgid(USER) != 0 || setuid(USER) != 0
				|| getuid() != USER) {
			_exit(SKIP);
		}
		body();
		_exit(0);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status));
	return WEXITSTATUS(status);
}
