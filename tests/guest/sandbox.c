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

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/clonefile.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

extern const char *const APP_SANDBOX_READ_WRITE;
extern char *sandbox_extension_issue_file(
		const char *extension_class, const char *path, uint32_t flags);
extern char *sandbox_extension_issue_mach(
		const char *extension_class, const char *name, uint32_t flags);
extern int64_t sandbox_extension_consume(const char *token);
extern int sandbox_extension_release(int64_t handle);
extern int __mac_syscall(const char *policy, int call, void *arg);
extern int sandbox_init(const char *profile, uint64_t flags, char **error);
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

#define AMFI_QUERY_BOOTARG_STATE 96

#define SANDBOX_FILTER_PATH     1
#define SANDBOX_CHECK_NO_REPORT 0x40000000

#define LOCK    "/tmp/limbo-sandbox.lock"
#define MISSING "/private/tmp/limbo-sandbox-missing"
#define DENIED  "/tmp/limbo-sandbox-denied"
#define ALLOWED "/tmp/limbo-sandbox-allowed"

#define DEEP  "/tmp/limbo-sandbox-deep"
#define DEPTH 60
#define DEEP_NAME                                                              \
	"dddddddddddddddddddddddddddddddddddddddddddddddddd"                   \
	"dddddddddddddddddddddddddddddddddddddddddddddddddd"

#define ALLOW_ALL   "(version 1) (allow default)"
#define DENY_SECRET ALLOW_ALL " (deny file-write* (regex #\"\\.secret$\"))"
#define DENY(operation)                                                        \
	ALLOW_ALL " (deny " operation " (subpath \"/private" DENIED "\"))"
#define DENY_FOLDER DENY("file-write*")

static void clean_up(void);
static void remove_deep(void);
static void denied_spawning(void);
static void check_deep(void);
static void enter_deep(void);
static void check_entered(void);
static void enter(void);
static void check_missing(void);
static void check_profile(void);
static void ask_profile(void);
static void check_enforced(void);
static void denied_opening(void);
static void denied_creating(void);
static void denied_unlinking(void);
static void denied_renaming(void);
static void denied_truncating(void);
static void denied_mode(void);
static void denied_owner(void);
static void in_denied_folder(void (*body)(void));
static void in_sandbox(const char *profile, void (*body)(void));
static int remove_entry(const char *path, const struct stat *st, int type,
		struct FTW *ftw);
static void enter_and_run(void);
static void make_file(const char *path);
static int exit_status_of(void (*body)(void));

static const char *sandboxed_profile;
static void (*sandboxed_body)(void);
static pid_t owner;
static int denied_fd;

int
main(int argc, char *argv[])
{
	if (argc == 2) {
		return 1;
	}
	int lock = open(LOCK, O_RDONLY | O_CREAT, 0644);
	CHECK(lock >= 0);
	CHECK(flock(lock, LOCK_EX) == 0);
	owner = getpid();
	CHECK(atexit(clean_up) == 0);

	check_entered();
	check_missing();
	check_profile();
	check_enforced();

	char *token = sandbox_extension_issue_file(
			APP_SANDBOX_READ_WRITE, "/tmp", 0);
	CHECK(token != NULL);
	CHECK(strstr(token, ";com.apple.app-sandbox.read-write;") != NULL);
	size_t length = strlen(token);
	CHECK(length > 4 && strcmp(token + length - 4, "/tmp") == 0);
	int64_t handle = sandbox_extension_consume(token);
	CHECK(handle >= 0);
	CHECK(sandbox_extension_release(handle) == 0);
	free(token);

	token = sandbox_extension_issue_mach(
			"com.apple.app-sandbox.mach", "com.apple.lsd.mapdb", 0);
	CHECK(token != NULL);
	CHECK(strstr(token, ";com.apple.lsd.mapdb") != NULL);
	free(token);

	unlink("/tmp/limbo-unmade");
	token = sandbox_extension_issue_file(
			APP_SANDBOX_READ_WRITE, "/tmp/limbo-unmade", 0);
	CHECK(token != NULL);
	CHECK(strstr(token, ";com.apple.app-sandbox.read-write;00;") != NULL);
	free(token);

	CHECK(sandbox_extension_issue_file(APP_SANDBOX_READ_WRITE,
			      "/nonexistent/limbo", 0)
			== NULL);

	uint64_t bootarg_state = UINT64_MAX;
	CHECK(__mac_syscall("AMFI", AMFI_QUERY_BOOTARG_STATE, &bootarg_state)
			== 0);
	CHECK(bootarg_state == 0);
	return 0;
}

static void
check_entered(void)
{
	CHECK(exit_status_of(enter) == 0);
	CHECK(sandbox_check(getpid(), NULL, 0) == 0);
}

static void
enter(void)
{
	CHECK(sandbox_check(getpid(), NULL, 0) == 0);
	char *error = NULL;
	CHECK(sandbox_init(ALLOW_ALL, 0, &error) == 0);
	CHECK(sandbox_check(getpid(), NULL, 0) == 1);
	CHECK(sandbox_check(getpid(), "file-read-data", 0) == 0);
	pid_t child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		_exit(sandbox_check(getpid(), NULL, 0) == 1 ? 0 : 1);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void
check_missing(void)
{
	unlink(MISSING);
	CHECK(sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH,
			      MISSING)
			== 1);
	CHECK(sandbox_check(getpid(), "file-write-create", SANDBOX_FILTER_PATH,
			      MISSING)
			== 1);
	CHECK(sandbox_check(getpid(), "file-write-create",
			      SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
			      MISSING)
			== 1);
	CHECK(sandbox_check(getppid(), "file-read-data", SANDBOX_FILTER_PATH,
			      MISSING)
			== 1);
	CHECK(sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH,
			      "/private/tmp")
			== 0);
	CHECK(sandbox_check(getpid(), "file-write-data",
			      SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
			      "/private/tmp")
			== 0);
	CHECK(sandbox_check(getpid(), "file-read-data", 0) == 0);
	CHECK(sandbox_check(getpid(), NULL, SANDBOX_FILTER_PATH, MISSING) == 0);
}

static void
check_profile(void)
{
	in_denied_folder(ask_profile);
}

static void
ask_profile(void)
{
	char *error = NULL;
	CHECK(sandbox_check(getpid(), "file-write-data", SANDBOX_FILTER_PATH,
			      "/private" DENIED "/existing")
			== 1);
	CHECK(sandbox_check(getpid(), "file-write-unlink", SANDBOX_FILTER_PATH,
			      DENIED "/existing")
			== 1);
	CHECK(sandbox_check(getpid(), "file-write-create", SANDBOX_FILTER_PATH,
			      "/private" DENIED)
			== 1);
	CHECK(sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH,
			      "/private" DENIED "/existing")
			== 0);
	CHECK(sandbox_check(getpid(), "file-write-data", SANDBOX_FILTER_PATH,
			      "/private" ALLOWED)
			== 0);
	CHECK(sandbox_check(getpid(), "file-write-create", SANDBOX_FILTER_PATH,
			      "/private/tmp")
			== 0);

	CHECK(sandbox_init(DENY_FOLDER, 0, &error) == 0);
	CHECK(sandbox_init(ALLOW_ALL, 0, &error) == -1);
	CHECK(strcmp(error, strerror(EPERM)) == 0);
	CHECK(sandbox_check(getpid(), "file-write-data", SANDBOX_FILTER_PATH,
			      "/private" DENIED "/existing")
			== 1);
}

static void
check_enforced(void)
{
	check_deep();
	in_denied_folder(denied_spawning);
	in_denied_folder(denied_opening);
	in_denied_folder(denied_creating);
	in_denied_folder(denied_unlinking);
	in_denied_folder(denied_renaming);
	in_denied_folder(denied_truncating);
	in_sandbox(DENY("file-write-mode"), denied_mode);
	in_sandbox(DENY("file-write-owner"), denied_owner);
}

static void
check_deep(void)
{
	CHECK(exit_status_of(enter_deep) == 0);
	remove_deep();
	CHECK(access(DEEP, F_OK) == -1);
}

static void
enter_deep(void)
{
	char *error = NULL;
	CHECK(mkdir(DEEP, 0755) == 0);
	CHECK(chdir(DEEP) == 0);
	for (int i = 0; i != DEPTH; i++) {
		CHECK(mkdir(DEEP_NAME, 0755) == 0);
		CHECK(chdir(DEEP_NAME) == 0);
	}
	CHECK(sandbox_init(DENY_SECRET, 0, &error) == 0);
	errno = 0;
	CHECK(open("x.secret", O_WRONLY | O_CREAT, 0644) == -1);
	CHECK(errno == EPERM);
}

static void
denied_spawning(void)
{
	extern char **environ;
	char self[PATH_MAX];
	uint32_t size = sizeof(self);
	CHECK(_NSGetExecutablePath(self, &size) == 0);
	char *argv[] = {self, "unreached", NULL};
	int flags = O_WRONLY | O_CREAT;
	posix_spawn_file_actions_t named, moved;
	CHECK(posix_spawn_file_actions_init(&named) == 0);
	CHECK(posix_spawn_file_actions_addopen(
			      &named, 3, DENIED "/made", flags, 0644)
			== 0);
	CHECK(posix_spawn(NULL, self, &named, NULL, argv, environ) == EPERM);
	CHECK(posix_spawn_file_actions_init(&moved) == 0);
	CHECK(posix_spawn_file_actions_addchdir(&moved, DENIED) == 0);
	CHECK(posix_spawn_file_actions_addopen(&moved, 3, "made", flags, 0644)
			== 0);
	CHECK(posix_spawn(NULL, self, &moved, NULL, argv, environ) == EPERM);
	posix_spawnattr_t replacing;
	CHECK(posix_spawnattr_init(&replacing) == 0);
	CHECK(posix_spawnattr_setflags(&replacing, POSIX_SPAWN_SETEXEC) == 0);
	CHECK(posix_spawn(NULL, self, &named, &replacing, argv, environ)
			== EPERM);
	CHECK(access(DENIED "/made", F_OK) == -1);
}

static void
denied_opening(void)
{
	errno = 0;
	CHECK(open(DENIED "/file", O_WRONLY | O_CREAT, 0644) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(open(DENIED "/existing", O_WRONLY) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(open(DENIED "/existing", O_RDWR | O_APPEND) == -1);
	CHECK(errno == EPERM);
	int dir = open(DENIED, O_RDONLY);
	CHECK(dir >= 0);
	errno = 0;
	CHECK(openat(dir, "file", O_WRONLY | O_CREAT, 0644) == -1);
	CHECK(errno == EPERM);
	CHECK(close(dir) == 0);
	CHECK(access(DENIED "/file", F_OK) == -1);

	int fd = open(DENIED "/existing", O_RDONLY | O_CREAT, 0644);
	CHECK(fd >= 0);
	CHECK(close(fd) == 0);
	fd = open(ALLOWED, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	CHECK(close(fd) == 0);
	fd = open(ALLOWED "-new", O_WRONLY | O_CREAT | O_EXCL, 0644);
	CHECK(fd >= 0);
	CHECK(close(fd) == 0);
	CHECK(unlink(ALLOWED "-new") == 0);

	fd = open(DENIED "/existing", O_RDONLY | O_APPEND);
	CHECK(fd >= 0);
	CHECK(close(fd) == 0);
	errno = 0;
	CHECK(open(DENIED "/existing", O_RDONLY | O_TRUNC) == -1);
	CHECK(errno == EPERM);
	const char *targets[] = {DENIED "/made", "limbo-sandbox-denied/made"};
	for (int i = 0; i != 2; i++) {
		CHECK(symlink(targets[i], ALLOWED "-link") == 0);
		errno = 0;
		CHECK(open(ALLOWED "-link", O_WRONLY | O_CREAT, 0644) == -1);
		CHECK(errno == EPERM);
		CHECK(unlink(ALLOWED "-link") == 0);
	}
	CHECK(access(DENIED "/made", F_OK) == -1);
}

static void
denied_creating(void)
{
	int dir = open(DENIED, O_RDONLY);
	CHECK(dir >= 0);
	errno = 0;
	CHECK(mkdir(DENIED "/folder", 0755) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(mkdirat(dir, "folder", 0755) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(mkfifo(DENIED "/fifo", 0644) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(symlink("existing", DENIED "/link") == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(symlinkat("existing", dir, "link") == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(link(ALLOWED, DENIED "/hard") == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(linkat(AT_FDCWD, ALLOWED, dir, "hard", 0) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(clonefile(ALLOWED, DENIED "/clone", 0) == -1);
	CHECK(errno == EPERM);
	int source = open(ALLOWED, O_RDONLY);
	CHECK(source >= 0);
	errno = 0;
	CHECK(fclonefileat(source, AT_FDCWD, DENIED "/clone", 0) == -1);
	CHECK(errno == EPERM);
	CHECK(close(source) == 0);
	filesec_t filesec = filesec_init();
	mode_t mode = 0755;
	CHECK(filesec_set_property(filesec, FILESEC_MODE, &mode) == 0);
	errno = 0;
	CHECK(mkdirx_np(DENIED "/folder", filesec) == -1);
	CHECK(errno == EPERM);
	filesec_free(filesec);
	CHECK(close(dir) == 0);

	CHECK(mkdir(ALLOWED "-folder", 0755) == 0);
	CHECK(rmdir(ALLOWED "-folder") == 0);
	CHECK(symlink("existing", ALLOWED "-link") == 0);
	CHECK(unlink(ALLOWED "-link") == 0);
	CHECK(link(ALLOWED, ALLOWED "-hard") == 0);
	CHECK(unlink(ALLOWED "-hard") == 0);
}

static void
denied_unlinking(void)
{
	int dir = open(DENIED, O_RDONLY);
	CHECK(dir >= 0);
	errno = 0;
	CHECK(unlink(DENIED "/existing") == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(unlinkat(dir, "existing", 0) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(rmdir(DENIED) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(unlinkat(AT_FDCWD, DENIED, AT_REMOVEDIR) == -1);
	CHECK(errno == EPERM);
	CHECK(close(dir) == 0);
	CHECK(access(DENIED "/existing", F_OK) == 0);

	make_file(ALLOWED "-new");
	CHECK(unlink(ALLOWED "-new") == 0);
	CHECK(mkdir(ALLOWED "-folder", 0755) == 0);
	CHECK(rmdir(ALLOWED "-folder") == 0);
}

static void
denied_renaming(void)
{
	int dir = open(DENIED, O_RDONLY);
	CHECK(dir >= 0);
	errno = 0;
	CHECK(rename(DENIED "/existing", ALLOWED "-moved") == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(rename(ALLOWED, DENIED "/moved") == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(renameat(dir, "existing", AT_FDCWD, ALLOWED "-moved") == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(renameat(AT_FDCWD, ALLOWED, dir, "moved") == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(renamex_np(ALLOWED, DENIED "/moved", RENAME_EXCL) == -1);
	CHECK(errno == EPERM);
	CHECK(close(dir) == 0);
	CHECK(access(DENIED "/existing", F_OK) == 0);
	CHECK(access(DENIED "/moved", F_OK) == -1);

	CHECK(rename(ALLOWED, ALLOWED "-moved") == 0);
	CHECK(rename(ALLOWED "-moved", ALLOWED) == 0);
}

static void
denied_truncating(void)
{
	errno = 0;
	CHECK(truncate(DENIED "/existing", 0) == -1);
	CHECK(errno == EPERM);
	CHECK(ftruncate(denied_fd, 0) == 0);

	CHECK(truncate(ALLOWED, 1) == 0);
	int fd = open(ALLOWED, O_WRONLY);
	CHECK(fd >= 0);
	CHECK(ftruncate(fd, 0) == 0);
	CHECK(close(fd) == 0);
}

static void
denied_mode(void)
{
	errno = 0;
	CHECK(chmod(DENIED "/existing", 0600) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(fchmod(denied_fd, 0600) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, DENIED "/existing", 0600, 0) == -1);
	CHECK(errno == EPERM);
	filesec_t filesec = filesec_init();
	mode_t mode = 0600;
	CHECK(filesec_set_property(filesec, FILESEC_MODE, &mode) == 0);
	errno = 0;
	CHECK(chmodx_np(DENIED "/existing", filesec) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(fchmodx_np(denied_fd, filesec) == -1);
	CHECK(errno == EPERM);
	filesec_free(filesec);
	struct stat st;
	CHECK(stat(DENIED "/existing", &st) == 0);
	CHECK((st.st_mode & 0777) == 0644);

	CHECK(chmod(ALLOWED, 0600) == 0);
	CHECK(utimes(DENIED "/existing", NULL) == 0);
}

static void
denied_owner(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	errno = 0;
	CHECK(chown(DENIED "/existing", uid, gid) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(fchown(denied_fd, uid, gid) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(lchown(DENIED "/existing", uid, gid) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(fchownat(AT_FDCWD, DENIED "/existing", uid, gid, 0) == -1);
	CHECK(errno == EPERM);
	filesec_t filesec = filesec_init();
	CHECK(filesec_set_property(filesec, FILESEC_OWNER, &uid) == 0);
	errno = 0;
	CHECK(chmodx_np(DENIED "/existing", filesec) == -1);
	CHECK(errno == EPERM);
	errno = 0;
	CHECK(fchmodx_np(denied_fd, filesec) == -1);
	CHECK(errno == EPERM);
	filesec_free(filesec);

	CHECK(chown(ALLOWED, uid, gid) == 0);
	CHECK(chmod(DENIED "/existing", 0600) == 0);
}

static void
in_denied_folder(void (*body)(void))
{
	in_sandbox(DENY_FOLDER, body);
}

static void
in_sandbox(const char *profile, void (*body)(void))
{
	clean_up();
	CHECK(mkdir(DENIED, 0755) == 0);
	make_file(DENIED "/existing");
	make_file(ALLOWED);
	denied_fd = open(DENIED "/existing", O_RDWR);
	CHECK(denied_fd >= 0);
	sandboxed_profile = profile;
	sandboxed_body = body;
	CHECK(exit_status_of(enter_and_run) == 0);
	CHECK(close(denied_fd) == 0);
	CHECK(unlink(ALLOWED) == 0);
	CHECK(unlink(DENIED "/existing") == 0);
	CHECK(rmdir(DENIED) == 0);
}

static int
remove_entry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	return remove(path);
}

static void
enter_and_run(void)
{
	char *error = NULL;
	CHECK(sandbox_init(sandboxed_profile, 0, &error) == 0);
	sandboxed_body();
}

static void
make_file(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT, 0644);
	CHECK(fd >= 0);
	CHECK(close(fd) == 0);
}

static int
exit_status_of(void (*body)(void))
{
	pid_t child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		body();
		_exit(0);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status));
	return WEXITSTATUS(status);
}

static void
clean_up(void)
{
	if (getpid() == owner) {
		nftw(DENIED, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
		remove_deep();
		glob_t allowed;
		if (glob(ALLOWED "*", 0, NULL, &allowed) == 0) {
			for (size_t i = 0; i != allowed.gl_pathc; i++) {
				remove(allowed.gl_pathv[i]);
			}
			globfree(&allowed);
		}
	}
}

static void
remove_deep(void)
{
	int depth = 0;
	if (chdir(DEEP) == 0) {
		while (chdir(DEEP_NAME) == 0) {
			depth++;
		}
		unlink("x.secret");
		for (; depth != 0; depth--) {
			chdir("..");
			rmdir(DEEP_NAME);
		}
		chdir("/");
		rmdir(DEEP);
	}
}
