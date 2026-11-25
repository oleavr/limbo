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

#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "check.h"

#define APFSIOC_MARK_PURGEABLE 0xc0084a44UL
#define PURGEABLE              0x10000
#define OTHER_FLAGS            0x8205

int fsctl(const char *path, unsigned long request, void *data,
		unsigned int options);
int ffsctl(int fd, unsigned long request, void *data, unsigned int options);

static void check_marked(const char *path);
static void check_by_path(void);
static void check_link(void);
static void check_hidden(void);
static int mark(const char *path, uint64_t flags);
static bool ext_purgeable(const char *path, unsigned int options);
static bool cf_purgeable(const char *path);

int
main(void)
{
	char template[] = "/tmp/limbo-purgeable-XXXXXX";
	CHECK(mkdtemp(template) != NULL);
	CHECK(chdir(template) == 0);

	int fd = open("file", O_RDWR | O_CREAT | O_EXCL, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(mkdir("folder", 0755) == 0);
	check_marked("file");
	check_marked("folder");
	check_by_path();
	check_link();
	check_hidden();

	CHECK(rmdir("folder") == 0);
	CHECK(unlink("file") == 0);
	CHECK(chdir("/") == 0);
	CHECK(rmdir(template) == 0);
	return 0;
}

static void
check_marked(const char *path)
{
	CHECK(!ext_purgeable(path, 0) && !cf_purgeable(path));
	CHECK(mark(path, 0) == 0);
	CHECK(!ext_purgeable(path, 0) && !cf_purgeable(path));
	CHECK(mark(path, PURGEABLE | OTHER_FLAGS) == 0);
	CHECK(ext_purgeable(path, 0) && cf_purgeable(path));
	CHECK(mark(path, OTHER_FLAGS) == 0);
	CHECK(!ext_purgeable(path, 0) && !cf_purgeable(path));
	CHECK(mark(path, PURGEABLE) == 0);
	CHECK(ext_purgeable(path, 0) && cf_purgeable(path));
	CHECK(mark(path, 0) == 0);
	CHECK(!ext_purgeable(path, 0) && !cf_purgeable(path));
}

static void
check_by_path(void)
{
	uint64_t flags = PURGEABLE | OTHER_FLAGS;
	CHECK(fsctl("file", APFSIOC_MARK_PURGEABLE, &flags, 0) == 0);
	CHECK(flags == (PURGEABLE | OTHER_FLAGS));
	CHECK(ext_purgeable("file", 0) && cf_purgeable("file"));
	flags = 0;
	CHECK(fsctl("file", APFSIOC_MARK_PURGEABLE, &flags, 0) == 0);
	CHECK(!ext_purgeable("file", 0) && !cf_purgeable("file"));

	errno = 0;
	CHECK(fsctl("missing", APFSIOC_MARK_PURGEABLE, &flags, 0) == -1);
	CHECK(errno == ENOENT);
}

static void
check_link(void)
{
	CHECK(symlink("file", "link") == 0);
	uint64_t flags = PURGEABLE;
	errno = 0;
	CHECK(fsctl("link", APFSIOC_MARK_PURGEABLE, &flags, FSOPT_NOFOLLOW)
			== -1);
	CHECK(errno == EINVAL);
	CHECK(!ext_purgeable("file", 0));
	CHECK(fsctl("link", APFSIOC_MARK_PURGEABLE, &flags, 0) == 0);
	CHECK(ext_purgeable("file", 0));
	CHECK(!ext_purgeable("link", FSOPT_NOFOLLOW));
	CHECK(mark("file", 0) == 0);
	CHECK(unlink("link") == 0);
}

static void
check_hidden(void)
{
	CHECK(mark("file", PURGEABLE) == 0);
	char names[1024];
	ssize_t length = listxattr("file", names, sizeof(names), 0);
	CHECK(length >= 0);
	for (const char *name = names; name < names + length;
			name += strlen(name) + 1) {
		CHECK(strstr(name, "purgeable") == NULL);
	}
	uint64_t value = 0;
	errno = 0;
	CHECK(getxattr("file", "limbo.purgeable", &value, sizeof(value), 0, 0)
					== -1
			&& errno == ENOATTR);
	if (removexattr("file", "limbo.purgeable", 0) == -1) {
		CHECK(errno == EPERM || errno == ENOATTR);
	}
	CHECK(ext_purgeable("file", 0));
	CHECK(mark("file", 0) == 0);
}

static int
mark(const char *path, uint64_t flags)
{
	int fd = open(path, O_RDONLY);
	CHECK(fd != -1);
	uint64_t value = flags;
	int r = ffsctl(fd, APFSIOC_MARK_PURGEABLE, &value, 0);
	CHECK(close(fd) == 0);
	CHECK(value == flags);
	return r;
}

static bool
ext_purgeable(const char *path, unsigned int options)
{
	struct attrlist list = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.forkattr = ATTR_CMNEXT_EXT_FLAGS,
	};
	struct {
		uint32_t length;
		uint64_t flags;
	} __attribute__((packed)) buffer;
	CHECK(getattrlist(path, &list, &buffer, sizeof(buffer),
			      FSOPT_ATTR_CMN_EXTENDED | options)
			== 0);
	CHECK(buffer.length == sizeof(buffer));
	return (buffer.flags & EF_IS_PURGEABLE) != 0;
}

static bool
cf_purgeable(const char *path)
{
	char absolute[PATH_MAX];
	CHECK(realpath(path, absolute) != NULL);
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
			(const UInt8 *)absolute, (CFIndex)strlen(absolute),
			false);
	CHECK(url != NULL);
	CFTypeRef value = NULL;
	CHECK(CFURLCopyResourcePropertyForKey(
			url, CFSTR("NSURLIsPurgeableKey"), &value, NULL));
	CFRelease(url);
	CHECK(value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID());
	bool purgeable = CFBooleanGetValue(value);
	CFRelease(value);
	return purgeable;
}
