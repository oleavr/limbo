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

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"

int
main(void)
{
	int master = posix_openpt(O_RDWR | O_NOCTTY);
	CHECK(master >= 0);
	CHECK(grantpt(master) == 0 && unlockpt(master) == 0);
	const char *name = ptsname(master);
	CHECK(name != NULL);
	CHECK(strncmp(name, "/dev/ttys", 9) == 0);
	char path[64];
	snprintf(path, sizeof(path), "%s", name);

	int slave = open(path, O_RDWR | O_NOCTTY);
	CHECK(slave >= 0);
	CHECK(isatty(slave));
	struct stat st, named;
	CHECK(fstat(slave, &st) == 0 && stat(path, &named) == 0);
	CHECK(S_ISCHR(st.st_mode) && st.st_rdev == named.st_rdev);
	const char *tty = ttyname(slave);
	CHECK(tty != NULL && strcmp(tty, path) == 0);
	const char *dev = devname(st.st_rdev, S_IFCHR);
	CHECK(dev != NULL && strcmp(dev, path + strlen("/dev/")) == 0);

	DIR *dir = opendir("/dev");
	CHECK(dir != NULL);
	int seen = 0;
	long position = -1;
	for (struct dirent *d; (d = readdir(dir)) != NULL;) {
		if (strcmp(d->d_name, path + strlen("/dev/")) == 0) {
			seen++;
			position = telldir(dir);
		}
	}
	CHECK(seen == 1);
	rewinddir(dir);
	seen = 0;
	for (struct dirent *d; (d = readdir(dir)) != NULL;) {
		seen += strcmp(d->d_name, path + strlen("/dev/")) == 0;
	}
	CHECK(seen == 1);
	seekdir(dir, position);
	for (struct dirent *d; (d = readdir(dir)) != NULL;) {
		CHECK(strcmp(d->d_name, path + strlen("/dev/")) != 0);
	}
	closedir(dir);

	CHECK(close(slave) == 0);
	CHECK(close(master) == 0);
	return 0;
}
