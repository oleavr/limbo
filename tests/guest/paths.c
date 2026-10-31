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

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"

static bool directory_contains(const char *path, const char *name);

int
main(void)
{
	struct stat st;
	CHECK(stat("/usr/lib/dyld", &st) == 0 && S_ISREG(st.st_mode));
	CHECK(stat("/System/Library/dyld", &st) == 0 && S_ISDIR(st.st_mode));
	CHECK(directory_contains("/", "System"));
	CHECK(directory_contains("/usr/lib", "dyld"));

	CHECK(chdir("/usr/lib") == 0);
	char cwd[PATH_MAX];
	CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
	CHECK(strcmp(cwd, "/usr/lib") == 0);

	int fd = open("dyld", O_RDONLY);
	CHECK(fd != -1);
	char path[MAXPATHLEN];
	CHECK(fcntl(fd, F_GETPATH, path) == 0);
	CHECK(strcmp(path, "/usr/lib/dyld") == 0);
	CHECK(close(fd) == 0);

	char resolved[PATH_MAX];
	CHECK(realpath("/usr/lib/../lib/./dyld", resolved) != NULL);
	CHECK(strcmp(resolved, "/usr/lib/dyld") == 0);

	CHECK(stat("/.nofollow/usr/lib/dyld", &st) == 0 && S_ISREG(st.st_mode));
	fd = open("/.nofollow/usr/lib", O_RDONLY | O_DIRECTORY);
	CHECK(fd != -1);
	CHECK(close(fd) == 0);
	CHECK(stat("/.resolve/33/usr/lib/dyld", &st) == 0
			&& S_ISREG(st.st_mode));
	CHECK(stat("/.resolve/0/usr/lib/dyld", &st) == 0
			&& S_ISREG(st.st_mode));

	CHECK(stat("/dev/null", &st) == 0 && S_ISCHR(st.st_mode));
	fd = posix_openpt(O_RDWR | O_NOCTTY);
	CHECK(fd != -1);
	CHECK(close(fd) == 0);

	char template[] = "/tmp/limbo-paths-XXXXXX";
	CHECK(mkdtemp(template) != NULL);
	CHECK(stat(template, &st) == 0 && S_ISDIR(st.st_mode));
	CHECK(rmdir(template) == 0);
	return 0;
}

static bool
directory_contains(const char *path, const char *name)
{
	DIR *dir = opendir(path);
	CHECK(dir != NULL);
	bool found = false;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		found = found || strcmp(entry->d_name, name) == 0;
	}
	closedir(dir);
	return found;
}
