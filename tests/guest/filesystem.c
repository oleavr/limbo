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

#include <copyfile.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/file.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "check.h"

#ifndef O_CLOFORK
#define O_CLOFORK 0x08000000
#endif

#ifndef F_GETLKPID
#define F_GETLKPID 66
#endif
#ifndef F_OFD_GETLKPID
#define F_OFD_GETLKPID 94
#endif
#ifndef F_SETCONFINED
#define F_SETCONFINED 95
#endif

static void check_files(void);
static void check_directories(void);
static void check_attributes(void);
static void check_copyfile(void);
static void check_xattrs(void);
static void check_locks_of_pid(void);
static void check_file_ids(void);
extern char **environ;
static int resolve_file_id(char **argv);
static void write_file(const char *path, const char *contents);
static int count_entries(const char *path);

int
main(int argc, char **argv)
{
	if (argc == 5 && strcmp(argv[1], "fsgetpath") == 0) {
		return resolve_file_id(argv + 2);
	}
	char template[] = "/tmp/limbo-filesystem-XXXXXX";
	CHECK(mkdtemp(template) != NULL);
	CHECK(chdir(template) == 0);

	check_files();
	check_directories();
	check_attributes();
	check_copyfile();
	check_xattrs();
	check_locks_of_pid();
	check_file_ids();

	CHECK(chdir("/") == 0);
	CHECK(rmdir(template) == 0);
	return 0;
}

static void
check_files(void)
{
	write_file("a", "data");
	struct stat st;
	CHECK(stat("a", &st) == 0);
	CHECK(S_ISREG(st.st_mode) && st.st_size == 4 && st.st_nlink == 1);

	CHECK(link("a", "b") == 0);
	CHECK(stat("a", &st) == 0 && st.st_nlink == 2);
	CHECK(unlink("b") == 0);

	CHECK(symlink("a", "c") == 0);
	CHECK(lstat("c", &st) == 0 && S_ISLNK(st.st_mode));
	char target[PATH_MAX];
	ssize_t length = readlink("c", target, sizeof(target));
	CHECK(length == 1 && target[0] == 'a');
	CHECK(stat("c", &st) == 0 && S_ISREG(st.st_mode));

	CHECK(rename("c", "d") == 0);
	CHECK(access("c", F_OK) == -1 && errno == ENOENT);
	CHECK(unlink("d") == 0);

	CHECK(chmod("a", 0600) == 0);
	CHECK(stat("a", &st) == 0 && (st.st_mode & 0777) == 0600);
	struct timeval times[2] = {{1000000000, 0}, {1000000000, 0}};
	CHECK(utimes("a", times) == 0);
	CHECK(stat("a", &st) == 0 && st.st_mtime == 1000000000);
	CHECK(truncate("a", 2) == 0);
	CHECK(stat("a", &st) == 0 && st.st_size == 2);

	int fd = open("a", O_RDWR | O_APPEND);
	CHECK(fd != -1);
	CHECK((fcntl(fd, F_GETFL) & (O_ACCMODE | O_APPEND))
			== (O_RDWR | O_APPEND));
	char path[MAXPATHLEN];
	CHECK(fcntl(fd, F_GETPATH, path) == 0);
	CHECK(strncmp(path, "/private/tmp/limbo-filesystem-", 30) == 0);
	CHECK(strcmp(strrchr(path, '/'), "/a") == 0);
	CHECK(write(fd, "ta", 2) == 2);
	CHECK(fstat(fd, &st) == 0 && st.st_size == 4);
	CHECK(flock(fd, LOCK_EX | LOCK_NB) == 0);
	CHECK(flock(fd, LOCK_UN) == 0);
	CHECK(fcntl(fd, F_SINGLE_WRITER, 1) == 0);
	CHECK(fchflags(fd, 0) == 0);
	CHECK(close(fd) == 0);

	CHECK(stat(NULL, &st) == -1 && errno == EFAULT);

	write_file("e", "other");
	CHECK(renamex_np("a", "e", RENAME_SWAP) == 0);
	CHECK(stat("a", &st) == 0 && st.st_size == 5);
	CHECK(unlink("a") == 0);
	CHECK(unlink("e") == 0);
}

static void
check_directories(void)
{
	CHECK(mkdir("dir", 0755) == 0);
	int dirfd = open("dir", O_RDONLY | O_DIRECTORY);
	CHECK(dirfd != -1);
	for (int i = 0; i < 100; i++) {
		char name[16];
		snprintf(name, sizeof(name), "file%d", i);
		int fd = openat(dirfd, name, O_CREAT | O_WRONLY, 0644);
		CHECK(fd != -1);
		close(fd);
	}
	CHECK(count_entries("dir") == 100);

	struct stat st;
	CHECK(fstatat(dirfd, "file7", &st, 0) == 0 && S_ISREG(st.st_mode));
	CHECK(faccessat(dirfd, "file7", R_OK, 0) == 0);
	for (int i = 0; i < 100; i++) {
		char name[16];
		snprintf(name, sizeof(name), "file%d", i);
		CHECK(unlinkat(dirfd, name, 0) == 0);
	}
	CHECK(close(dirfd) == 0);
	CHECK(count_entries("dir") == 0);
	char cwd[PATH_MAX], path[PATH_MAX + 8];
	CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
	const char *dots[] = {"dir/.", "dir/./", "dir/.."};
	for (size_t i = 0; i < sizeof(dots) / sizeof(dots[0]); i++) {
		CHECK(rmdir(dots[i]) == -1 && errno == EINVAL);
		snprintf(path, sizeof(path), "%s/%s", cwd, dots[i]);
		CHECK(rmdir(path) == -1 && errno == EINVAL);
	}
	CHECK(rmdir("dir") == 0);
}

static void
check_attributes(void)
{
	write_file("attributes", "");
	struct attrlist request = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE,
	};
	struct {
		uint32_t length;
		attrreference_t name;
		fsobj_type_t type;
		char names[64];
	} __attribute__((packed)) reply;
	CHECK(getattrlist("attributes", &request, &reply, sizeof(reply), 0)
			== 0);
	CHECK(reply.type == VREG);
	CHECK(strcmp((char *)&reply.name + reply.name.attr_dataoffset,
			      "attributes")
			== 0);
	CHECK(pathconf("attributes", _PC_NAME_MAX) >= 255);

	struct attrlist times_request = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME,
	};
	struct timespec times[2] = {{1000000000, 0}, {1100000000, 0}};
	int fd = open("attributes", O_RDONLY);
	CHECK(fd != -1);
	CHECK(fsetattrlist(fd, &times_request, times, sizeof(times), 0) == 0);
	CHECK(close(fd) == 0);
	struct stat st;
	CHECK(stat("attributes", &st) == 0);
	CHECK(st.st_mtime == 1000000000 && st.st_atime == 1100000000);

	char path[PATH_MAX];
	CHECK(getcwd(path, sizeof(path)) != NULL);
	strlcat(path, "/attributes", sizeof(path));
	times[0].tv_sec = 1200000000;
	CHECK(setattrlist(path, &times_request, times, sizeof(times), 0) == 0);
	CHECK(stat("attributes", &st) == 0);
	CHECK(st.st_mtime == 1200000000);

	CHECK(symlink("nowhere", "link") == 0);
	struct attrlist flags_request = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_FLAGS,
	};
	uint32_t flags = UF_HIDDEN;
	CHECK(setattrlist("link", &flags_request, &flags, sizeof(flags),
			      FSOPT_NOFOLLOW)
			== 0);
	CHECK(setattrlist("link", &times_request, times, sizeof(times),
			      FSOPT_NOFOLLOW)
			== 0);
	CHECK(lstat("link", &st) == 0);
	CHECK(st.st_mtime == 1200000000);
	CHECK(lchmod("link", 0700) == 0);
	CHECK(lchmod("attributes", 0600) == 0);
	CHECK(stat("attributes", &st) == 0);
	CHECK((st.st_mode & 0777) == 0600);
	acl_t acl = acl_init(1);
	CHECK(acl != NULL);
	CHECK(acl_set_file("attributes", ACL_TYPE_EXTENDED, acl) == 0);
	acl_free(acl);
	CHECK(setattrlist("link", &times_request, times, sizeof(times), 0)
			== -1);
	CHECK(errno == ENOENT);
	CHECK(unlink("link") == 0);

	CHECK(chflags("attributes", UF_HIDDEN) == 0);
	CHECK(chflags("missing", UF_HIDDEN) == -1 && errno == ENOENT);
	struct stat flagged;
	CHECK(stat("attributes", &flagged) == 0);
	CHECK(flagged.st_flags == UF_HIDDEN);
	CHECK(listxattr("attributes", NULL, 0, 0) == 0);
	fd = open("attributes", O_RDONLY);
	CHECK(fd != -1);
	CHECK(fchflags(fd, SF_NOUNLINK) == 0);
	CHECK(fstat(fd, &flagged) == 0);
	CHECK(flagged.st_flags == SF_NOUNLINK);
	CHECK(fchflags(fd, 0) == 0);
	CHECK(fstat(fd, &flagged) == 0);
	CHECK(flagged.st_flags == 0);
	CHECK(close(fd) == 0);
	CHECK(unlink("attributes") == 0);
}

static void
check_copyfile(void)
{
	write_file("source", "data");
	CHECK(chmod("source", 0640) == 0);
	int fd = open("destination", O_CREAT | O_WRONLY, 0600);
	CHECK(fd != -1);
	copyfile_state_t state = copyfile_state_alloc();
	CHECK(copyfile_state_set(state, COPYFILE_STATE_DST_FD, &fd) == 0);
	CHECK(copyfile("source", NULL, state, COPYFILE_METADATA) == 0);
	CHECK(copyfile_state_free(state) == 0);
	CHECK(close(fd) == 0);
	struct stat st;
	CHECK(stat("destination", &st) == 0 && (st.st_mode & 0777) == 0640);
	CHECK(unlink("source") == 0);
	CHECK(unlink("destination") == 0);
}

static void
check_xattrs(void)
{
	write_file("xattrs", "");
	if (setxattr("xattrs", "com.limbo.test", "value", 5, 0, 0) == -1) {
		CHECK(errno == ENOTSUP);
		CHECK(unlink("xattrs") == 0);
		return;
	}
	char value[16];
	CHECK(getxattr("xattrs", "com.limbo.test", value, sizeof(value), 0, 0)
			== 5);
	CHECK(memcmp(value, "value", 5) == 0);
	char names[64];
	CHECK(listxattr("xattrs", names, sizeof(names), 0)
			== sizeof("com.limbo.test"));
	CHECK(strcmp(names, "com.limbo.test") == 0);
	CHECK(removexattr("xattrs", "com.limbo.test", 0) == 0);
	CHECK(getxattr("xattrs", "com.limbo.test", value, sizeof(value), 0, 0)
			== -1);
	CHECK(errno == ENOATTR);
	CHECK(unlink("xattrs") == 0);
}

static void
check_locks_of_pid(void)
{
	write_file("l", "locked");
	int ready[2], done[2];
	CHECK(pipe(ready) == 0 && pipe(done) == 0);
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		close(ready[0]);
		close(done[1]);
		int fd = open("l", O_RDWR | O_CLOFORK);
		struct flock lock = {
				.l_type = F_WRLCK,
				.l_whence = SEEK_SET,
				.l_start = 2,
				.l_len = 2,
		};
		struct flock record = {
				.l_type = F_WRLCK,
				.l_whence = SEEK_SET,
				.l_start = 6,
				.l_len = 2,
		};
		char byte = 0;
		if (fd == -1 || fcntl(fd, F_SETCONFINED, 1) == -1
				|| fcntl(fd, F_OFD_SETLK, &lock) == -1
				|| fcntl(fd, F_SETLK, &record) == -1) {
			perror("lock");
			_exit(1);
		}
		if (write(ready[1], &byte, 1) != 1
				|| read(done[0], &byte, 1) == -1) {
			_exit(1);
		}
		_exit(0);
	}
	CHECK(close(ready[1]) == 0 && close(done[0]) == 0);
	char byte;
	CHECK(read(ready[0], &byte, 1) == 1);

	int fd = open("l", O_RDONLY);
	CHECK(fd != -1);
	struct flock lock = {
			.l_type = F_RDLCK,
			.l_whence = SEEK_SET,
			.l_pid = child,
	};
	CHECK(fcntl(fd, F_OFD_GETLKPID, &lock) == 0);
	CHECK(lock.l_type == F_WRLCK && lock.l_start == 2 && lock.l_len == 2
			&& lock.l_pid == child);

	lock = (struct flock){
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_start = 4,
			.l_pid = child,
	};
	CHECK(fcntl(fd, F_OFD_GETLKPID, &lock) == 0 && lock.l_type == F_UNLCK);
	lock = (struct flock){
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_pid = getpid(),
	};
	CHECK(fcntl(fd, F_OFD_GETLKPID, &lock) == 0 && lock.l_type == F_UNLCK);

	lock = (struct flock){
			.l_type = F_RDLCK,
			.l_whence = SEEK_SET,
			.l_start = 4,
			.l_pid = child,
	};
	CHECK(fcntl(fd, F_GETLKPID, &lock) == 0);
	CHECK(lock.l_type == F_WRLCK && lock.l_start == 6 && lock.l_len == 2
			&& lock.l_pid == child);
	lock = (struct flock){
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_pid = getpid(),
	};
	CHECK(fcntl(fd, F_GETLKPID, &lock) == 0 && lock.l_type == F_UNLCK);

	lock = (struct flock){
			.l_type = F_RDLCK,
			.l_whence = SEEK_SET,
			.l_pid = -1,
	};
	CHECK(fcntl(fd, F_OFD_GETLKPID, &lock) == 0);
	CHECK(lock.l_type == F_WRLCK && lock.l_start == 2 && lock.l_len == 2);

	CHECK(close(done[1]) == 0);
	int status;
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status)
			&& WEXITSTATUS(status) == 0);
	CHECK(close(fd) == 0);
	CHECK(close(ready[0]) == 0);
	CHECK(unlink("l") == 0);
}

static void
write_file(const char *path, const char *contents)
{
	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	CHECK(fd != -1);
	ssize_t length = strlen(contents);
	CHECK(write(fd, contents, length) == length);
	CHECK(close(fd) == 0);
}

static int
count_entries(const char *path)
{
	DIR *dir = opendir(path);
	CHECK(dir != NULL);
	int count = 0;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") != 0
				&& strcmp(entry->d_name, "..") != 0) {
			count++;
		}
	}
	closedir(dir);
	return count;
}

static void
check_file_ids(void)
{
	write_file("e", "id");
	char path[PATH_MAX];
	CHECK(realpath("e", path) != NULL);
	struct attrlist request = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_FSID | ATTR_CMN_FILEID,
	};
	struct __attribute__((packed)) {
		uint32_t length;
		fsid_t fsid;
		uint64_t file_id;
	} reply;
	CHECK(getattrlist(path, &request, &reply, sizeof(reply), 0) == 0);

	fsid_t volume = reply.fsid;
	char found[PATH_MAX];
	CHECK(fsgetpath(found, sizeof(found), &volume, reply.file_id) > 0);
	CHECK(strcmp(found, path) == 0);

	char executable[PATH_MAX];
	uint32_t size = sizeof(executable);
	CHECK(_NSGetExecutablePath(executable, &size) == 0);
	char fsid[32], id[32];
	snprintf(fsid, sizeof(fsid), "%d.%d", volume.val[0], volume.val[1]);
	snprintf(id, sizeof(id), "%llu", (unsigned long long)reply.file_id);
	char *arguments[] = {executable, "fsgetpath", fsid, id, path, NULL};
	pid_t pid;
	CHECK(posix_spawn(&pid, executable, NULL, NULL, arguments, environ)
			== 0);
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(unlink("e") == 0);
}

static int
resolve_file_id(char **argv)
{
	fsid_t fsid;
	CHECK(sscanf(argv[0], "%d.%d", &fsid.val[0], &fsid.val[1]) == 2);
	uint64_t id = strtoull(argv[1], NULL, 10);
	char found[PATH_MAX];
	CHECK(fsgetpath(found, sizeof(found), &fsid, id) > 0);
	CHECK(strcmp(found, argv[2]) == 0);
	return 0;
}
