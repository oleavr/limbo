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
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
static void check_copy(void);
static void check_user(void);
static void user_sets(void);
static int class_of(const char *path);
static int set_class(const char *path, int dpclass);
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
