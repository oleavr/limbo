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

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "check.h"

#define USER 501
#define SKIP 77

#define FILESEC_MAGIC 0x012cc16d
#define FILESEC_NOACL UINT32_MAX

#define INHERITED         (1 << 4)
#define FILE_INHERIT      (1 << 5)
#define DIRECTORY_INHERIT (1 << 6)
#define LIMIT_INHERIT     (1 << 7)
#define ONLY_INHERIT      (1 << 8)

struct entry {
	uint8_t applicable[16];
	uint32_t flags;
	uint32_t rights;
};

struct filesec {
	uint32_t magic;
	uint8_t owner[16];
	uint8_t group[16];
	uint32_t count;
	uint32_t flags;
	struct entry entry[16];
};

static void clean_up(void);
static int remove_entry(const char *path, const struct stat *st, int type,
		struct FTW *ftw);
static void check_as_another(void (*body)(void));
static void opens_as_itself(void);
static void makes_as_itself(void);
static void check_kept(void);
static void check_listed(void);
static void check_hidden(void);
static void check_inherited(void);
static void check_opened_with(void);
static void check_made_with(void);
static filesec_t filesec_of(mode_t mode, acl_t acl);
static acl_t list_of(int count, const uid_t *users, const acl_perm_t *perms,
		const int *flags);
static void user_guid(uid_t user, uint8_t guid[16]);
static void set_list(const char *path, int count, const uid_t *users,
		const acl_perm_t *perms, const int *flags);
static void remove_list(const char *path);
static int entries(const char *path);
static int entries_of(acl_t acl);
static bool allows(const char *path, uid_t user, acl_perm_t perm);
static bool read_filesec(const char *path, struct filesec *filesec);
static bool entry_for(const char *path, uid_t user, struct entry *found);
static int write_filesec(
		const char *path, const struct filesec *filesec, size_t size);
static void check_enforced(void);
static void works_inside(void);
static void kept_out(void);
static int as_user(void (*body)(void));

static char folder[] = "/tmp/limbo-access-XXXXXX";
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
	CHECK(mkdir("shared", 0777) == 0);
	CHECK(chmod("shared", 0777) == 0);

	check_kept();
	check_listed();
	check_hidden();
	check_inherited();
	check_opened_with();
	check_made_with();
	check_enforced();

	CHECK(rmdir("shared") == 0);
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
check_as_another(void (*body)(void))
{
	if (geteuid() != 0) {
		body();
		return;
	}
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
	if (WEXITSTATUS(status) == SKIP) {
		printf("skipping what another user is refused: no user %d\n",
				USER);
		skipped = true;
	} else {
		CHECK(WEXITSTATUS(status) == 0);
	}
}

static void
opens_as_itself(void)
{
	uid_t users[] = {USER + 1};
	acl_perm_t perms[] = {ACL_READ_DATA};
	int flags[] = {0};
	acl_t one = list_of(1, users, perms, flags);
	filesec_t another = filesec_of(0640, one);
	uid_t root = 0;
	CHECK(filesec_set_property(another, FILESEC_OWNER, &root) == 0);
	errno = 0;
	CHECK(openx_np("shared/given", O_CREAT | O_WRONLY, another) == -1);
	CHECK(errno == EPERM);
	CHECK(access("shared/given", F_OK) == -1);

	filesec_t unwritable = filesec_of(0444, one);
	int fd = openx_np("shared/listed", O_CREAT | O_WRONLY, unwritable);
	if (fd == -1) {
		CHECK(access("shared/listed", F_OK) == -1);
	} else {
		CHECK(entries("shared/listed") == 1);
		CHECK(close(fd) == 0);
		CHECK(unlink("shared/listed") == 0);
	}
	filesec_free(unwritable);
	filesec_free(another);
	acl_free(one);
}

static void
makes_as_itself(void)
{
	uid_t users[] = {USER + 1};
	acl_perm_t perms[] = {ACL_LIST_DIRECTORY};
	int flags[] = {0};
	acl_t one = list_of(1, users, perms, flags);
	filesec_t unwritable = filesec_of(0555, one);
	if (mkdirx_np("shared/listed", unwritable) == -1) {
		CHECK(access("shared/listed", F_OK) == -1);
	} else {
		CHECK(entries("shared/listed") == 1);
		CHECK(rmdir("shared/listed") == 0);
	}
	filesec_free(unwritable);
	acl_free(one);
}

static void
check_kept(void)
{
	int fd = open("file", O_CREAT | O_RDWR | O_EXCL, 0644);
	CHECK(fd != -1);
	CHECK(entries("file") == -1);

	uid_t users[] = {USER, USER + 1};
	acl_perm_t perms[] = {ACL_READ_DATA | ACL_WRITE_DATA, ACL_READ_DATA};
	int flags[] = {0, 0};
	set_list("file", 2, users, perms, flags);
	CHECK(entries("file") == 2);
	CHECK(allows("file", USER, ACL_READ_DATA));
	CHECK(allows("file", USER, ACL_WRITE_DATA));
	CHECK(!allows("file", USER, ACL_EXECUTE));
	CHECK(allows("file", USER + 1, ACL_READ_DATA));
	CHECK(!allows("file", USER + 1, ACL_WRITE_DATA));
	CHECK(!allows("file", USER + 2, ACL_READ_DATA));

	acl_t acl = acl_get_fd(fd);
	CHECK(acl != NULL);
	CHECK(entries_of(acl) == 2);
	acl_free(acl);

	acl = list_of(1, users, perms, flags);
	CHECK(acl_set_fd(fd, acl) == 0);
	acl_free(acl);
	CHECK(entries("file") == 1);
	CHECK(close(fd) == 0);

	struct stat st;
	CHECK(stat("file", &st) == 0 && (st.st_mode & 0777) == 0644);

	remove_list("file");
	CHECK(entries("file") == -1);
	CHECK(stat("file", &st) == 0 && (st.st_mode & 0777) == 0644);

	acl = list_of(1, users, perms, flags);
	filesec_t both = filesec_init();
	mode_t mode = 0600;
	CHECK(filesec_set_property(both, FILESEC_MODE, &mode) == 0);
	CHECK(filesec_set_property(both, FILESEC_ACL, &acl) == 0);
	CHECK(chmodx_np("file", both) == 0);
	CHECK(entries("file") == 1);
	CHECK(stat("file", &st) == 0 && (st.st_mode & 0777) == 0600);
	mode = 0640;
	CHECK(filesec_set_property(both, FILESEC_MODE, &mode) == 0);
	CHECK(filesec_set_property(both, FILESEC_ACL, _FILESEC_REMOVE_ACL)
			== 0);
	CHECK(chmodx_np("file", both) == 0);
	CHECK(entries("file") == -1);
	CHECK(stat("file", &st) == 0 && (st.st_mode & 0777) == 0640);
	filesec_free(both);
	acl_free(acl);
	CHECK(unlink("file") == 0);

	CHECK(mkdir("folder", 0755) == 0);
	set_list("folder", 1, users, perms, flags);
	CHECK(entries("folder") == 1);
	remove_list("folder");
	CHECK(entries("folder") == -1);
	CHECK(rmdir("folder") == 0);
}

static void
check_listed(void)
{
	int fd = open("listed", O_CREAT | O_WRONLY | O_EXCL, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	struct filesec filesec;
	CHECK(!read_filesec("listed", &filesec));

	uid_t users[] = {USER, USER + 1};
	acl_perm_t perms[] = {ACL_READ_DATA | ACL_WRITE_DATA, ACL_EXECUTE};
	int flags[] = {0, 0};
	set_list("listed", 2, users, perms, flags);
	CHECK(read_filesec("listed", &filesec));
	CHECK(filesec.count == 2);
	struct entry found;
	CHECK(entry_for("listed", USER, &found));
	CHECK(found.flags == ACL_EXTENDED_ALLOW);
	CHECK(found.rights == (ACL_READ_DATA | ACL_WRITE_DATA));
	CHECK(entry_for("listed", USER + 1, &found));
	CHECK(found.rights == ACL_EXECUTE);
	CHECK(!entry_for("listed", USER + 2, &found));

	remove_list("listed");
	CHECK(!read_filesec("listed", &filesec));

	struct filesec wanted = {.magic = FILESEC_MAGIC, .count = 1};
	user_guid(USER, wanted.entry[0].applicable);
	wanted.entry[0].flags = ACL_EXTENDED_ALLOW;
	wanted.entry[0].rights = ACL_READ_DATA;
	size_t size = offsetof(struct filesec, entry) + sizeof(struct entry);
	CHECK(write_filesec("listed", &wanted, size) == 0);
	CHECK(entries("listed") == 1);
	CHECK(allows("listed", USER, ACL_READ_DATA));
	errno = 0;
	CHECK(write_filesec("listed", &wanted, size - 1) == -1);
	CHECK(errno == EINVAL);
	wanted.magic = 0;
	errno = 0;
	CHECK(write_filesec("listed", &wanted, size) == -1);
	CHECK(errno == EINVAL);
	CHECK(entries("listed") == 1);
	wanted.magic = FILESEC_MAGIC;
	wanted.count = FILESEC_NOACL;
	CHECK(write_filesec("listed", &wanted, offsetof(struct filesec, entry))
			== 0);
	CHECK(entries("listed") == -1);
	CHECK(unlink("listed") == 0);
}

static void
check_hidden(void)
{
	int fd = open("hidden", O_CREAT | O_WRONLY | O_EXCL, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	uid_t users[] = {USER};
	acl_perm_t perms[] = {ACL_READ_DATA};
	int flags[] = {0};
	set_list("hidden", 1, users, perms, flags);

	char names[1024];
	ssize_t length = listxattr("hidden", names, sizeof(names), 0);
	CHECK(length >= 0);
	for (const char *name = names; name < names + length;
			name += strlen(name) + 1) {
		CHECK(strstr(name, "limbo") == NULL);
	}
	char value[8];
	errno = 0;
	CHECK(getxattr("hidden", "limbo.acl", value, sizeof(value), 0, 0)
			== -1);
	CHECK(errno == ENOATTR);
	if (setxattr("hidden", "limbo.acl", "x", 1, 0, 0) == 0) {
		CHECK(removexattr("hidden", "limbo.acl", 0) == 0);
	} else {
		CHECK(errno == EPERM);
		CHECK(removexattr("hidden", "limbo.acl", 0) == -1);
		CHECK(errno == EPERM);
	}
	CHECK(entries("hidden") == 1);
	CHECK(unlink("hidden") == 0);
}

static void
check_inherited(void)
{
	CHECK(mkdir("parent", 0755) == 0);
	uid_t users[] = {USER, USER + 1, USER + 2};
	acl_perm_t perms[] = {ACL_READ_DATA | ACL_WRITE_DATA | ACL_EXECUTE,
			ACL_READ_DATA, ACL_READ_DATA};
	int flags[] = {FILE_INHERIT | DIRECTORY_INHERIT,
			DIRECTORY_INHERIT | LIMIT_INHERIT,
			FILE_INHERIT | ONLY_INHERIT};
	set_list("parent", 3, users, perms, flags);
	CHECK(entries("parent") == 3);

	struct entry found;
	int fd = open("parent/file", O_CREAT | O_WRONLY, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("parent/file") == 2);
	CHECK(entry_for("parent/file", USER, &found));
	CHECK(found.flags == (ACL_EXTENDED_ALLOW | INHERITED));
	CHECK(found.rights == perms[0]);
	CHECK(entry_for("parent/file", USER + 2, &found));
	CHECK(found.flags == (ACL_EXTENDED_ALLOW | INHERITED));
	CHECK(!entry_for("parent/file", USER + 1, &found));
	struct stat st;
	CHECK(stat("parent/file", &st) == 0 && (st.st_mode & 0777) == 0644);

	remove_list("parent/file");
	fd = open("parent/file", O_CREAT | O_WRONLY, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("parent/file") == -1);

	fd = open("parent/exclusive", O_CREAT | O_EXCL | O_WRONLY, 0600);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("parent/exclusive") == 2);
	CHECK(open("parent/exclusive", O_CREAT | O_EXCL | O_WRONLY, 0600)
			== -1);
	CHECK(errno == EEXIST);

	CHECK(mkdir("parent/folder", 0) == 0);
	CHECK(entries("parent/folder") == 2);
	CHECK(stat("parent/folder", &st) == 0 && (st.st_mode & 0777) == 0);
	CHECK(entry_for("parent/folder", USER, &found));
	CHECK(found.flags
			== (ACL_EXTENDED_ALLOW | INHERITED | FILE_INHERIT
					| DIRECTORY_INHERIT));
	CHECK(found.rights == perms[0]);
	CHECK(entry_for("parent/folder", USER + 1, &found));
	CHECK(found.flags == (ACL_EXTENDED_ALLOW | INHERITED));
	CHECK(!entry_for("parent/folder", USER + 2, &found));

	CHECK(chmod("parent/folder", 0700) == 0);
	fd = open("parent/folder/grandchild", O_CREAT | O_WRONLY, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("parent/folder/grandchild") == 1);
	CHECK(entry_for("parent/folder/grandchild", USER, &found));
	CHECK(mkdirat(AT_FDCWD, "parent/folder/deeper", 0755) == 0);
	CHECK(entries("parent/folder/deeper") == 1);

	CHECK(symlink("parent/through", "dangling") == 0);
	fd = open("dangling", O_CREAT | O_WRONLY, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("parent/through") == 2);
	CHECK(unlink("parent/through") == 0);
	CHECK(unlink("dangling") == 0);

	CHECK(mkdir("plain", 0755) == 0);
	fd = open("plain/file", O_CREAT | O_WRONLY, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("plain/file") == -1);
	CHECK(mkdir("plain/folder", 0755) == 0);
	CHECK(entries("plain/folder") == -1);

	CHECK(rmdir("plain/folder") == 0);
	CHECK(unlink("plain/file") == 0);
	CHECK(rmdir("plain") == 0);
	CHECK(rmdir("parent/folder/deeper") == 0);
	CHECK(unlink("parent/folder/grandchild") == 0);
	CHECK(rmdir("parent/folder") == 0);
	CHECK(unlink("parent/exclusive") == 0);
	CHECK(unlink("parent/file") == 0);
	CHECK(rmdir("parent") == 0);
}

static void
check_opened_with(void)
{
	uid_t users[] = {USER, USER + 1};
	acl_perm_t perms[] = {ACL_READ_DATA, ACL_WRITE_DATA};
	int flags[] = {0, FILE_INHERIT};
	acl_t one = list_of(1, users, perms, flags);
	acl_t two = list_of(2, users, perms, flags);
	filesec_t with_one = filesec_of(0640, one);
	filesec_t with_two = filesec_of(0600, two);

	int fd = openx_np("opened", O_CREAT | O_WRONLY | O_EXCL, with_one);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("opened") == 1);
	struct stat st;
	CHECK(stat("opened", &st) == 0 && (st.st_mode & 0777) == 0640);
	fd = openx_np("opened", O_CREAT | O_WRONLY, with_two);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("opened") == 1);
	CHECK(stat("opened", &st) == 0 && (st.st_mode & 0777) == 0640);

	CHECK(mkdir("giving", 0755) == 0);
	CHECK(acl_set_file("giving", ACL_TYPE_EXTENDED, two) == 0);
	fd = openx_np("giving/file", O_CREAT | O_WRONLY, with_one);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(entries("giving/file") == 2);
	struct entry found;
	CHECK(entry_for("giving/file", USER, &found));
	CHECK(found.flags == ACL_EXTENDED_ALLOW);
	CHECK(entry_for("giving/file", USER + 1, &found));
	CHECK(found.flags == (ACL_EXTENDED_ALLOW | INHERITED));

	if (geteuid() == 0) {
		uid_t given = USER;
		CHECK(filesec_set_property(with_one, FILESEC_OWNER, &given)
				== 0);
		fd = openx_np("given", O_CREAT | O_WRONLY | O_EXCL, with_one);
		CHECK(fd != -1 && close(fd) == 0);
		CHECK(stat("given", &st) == 0 && st.st_uid == USER);
		CHECK(entries("given") == 1);
		CHECK(unlink("given") == 0);
	}
	check_as_another(opens_as_itself);

	CHECK(unlink("giving/file") == 0);
	CHECK(rmdir("giving") == 0);
	CHECK(unlink("opened") == 0);
	filesec_free(with_two);
	filesec_free(with_one);
	acl_free(two);
	acl_free(one);
}

static void
check_made_with(void)
{
	uid_t users[] = {USER, USER + 1};
	acl_perm_t perms[] = {ACL_LIST_DIRECTORY, ACL_SEARCH};
	int flags[] = {0, DIRECTORY_INHERIT};
	acl_t one = list_of(1, users, perms, flags);
	acl_t two = list_of(2, users, perms, flags);
	filesec_t with_one = filesec_of(0750, one);

	CHECK(mkdirx_np("made", with_one) == 0);
	CHECK(entries("made") == 1);
	struct stat st;
	CHECK(stat("made", &st) == 0 && (st.st_mode & 0777) == 0750);
	CHECK(mkdirx_np("made", with_one) == -1 && errno == EEXIST);

	CHECK(acl_set_file("made", ACL_TYPE_EXTENDED, two) == 0);
	CHECK(mkdirx_np("made/inside", with_one) == 0);
	CHECK(entries("made/inside") == 2);
	struct entry found;
	CHECK(entry_for("made/inside", USER, &found));
	CHECK(found.flags == ACL_EXTENDED_ALLOW);
	CHECK(entry_for("made/inside", USER + 1, &found));
	CHECK(found.flags
			== (ACL_EXTENDED_ALLOW | INHERITED
					| DIRECTORY_INHERIT));

	uid_t another = geteuid() + 1;
	CHECK(filesec_set_property(with_one, FILESEC_OWNER, &another) == 0);
	CHECK(mkdirx_np("given", with_one) == 0);
	CHECK(stat("given", &st) == 0 && st.st_uid == geteuid());
	CHECK(rmdir("given") == 0);
	check_as_another(makes_as_itself);

	CHECK(rmdir("made/inside") == 0);
	CHECK(rmdir("made") == 0);
	filesec_free(with_one);
	acl_free(two);
	acl_free(one);
}

static void
check_enforced(void)
{
	if (geteuid() != 0) {
		skipped = true;
		return;
	}
	CHECK(mkdir("entered", 0700) == 0);
	CHECK(mkdir("closed", 0700) == 0);
	CHECK(mkdir("writable", 0755) == 0);
	int fd = open("readable", O_CREAT | O_WRONLY | O_EXCL, 0640);
	CHECK(fd != -1 && close(fd) == 0);
	uid_t users[] = {USER};
	int flags[] = {0};
	acl_perm_t enter[] = {ACL_LIST_DIRECTORY | ACL_ADD_FILE | ACL_SEARCH
			| ACL_ADD_SUBDIRECTORY | ACL_DELETE_CHILD};
	set_list("entered", 1, users, enter, flags);
	acl_perm_t add[] = {ACL_ADD_FILE};
	set_list("writable", 1, users, add, flags);
	acl_perm_t read[] = {ACL_READ_DATA};
	set_list("readable", 1, users, read, flags);
	struct stat st;
	CHECK(stat("entered", &st) == 0 && (st.st_mode & 0777) == 0700);
	CHECK(stat("readable", &st) == 0 && (st.st_mode & 0777) == 0640);

	int result = as_user(works_inside);
	if (result == SKIP) {
		skipped = true;
	} else {
		CHECK(result == 0);
		CHECK(chmod("entered", 0750) == 0);
		CHECK(stat("entered", &st) == 0 && (st.st_mode & 0777) == 0750);
		CHECK(entries("entered") == 1);
		CHECK(as_user(works_inside) == 0);
		CHECK(chmod("entered", 0700) == 0);
		CHECK(as_user(works_inside) == 0);
		remove_list("entered");
		CHECK(stat("entered", &st) == 0 && (st.st_mode & 0777) == 0700);
		CHECK(as_user(kept_out) == 0);
	}
	CHECK(unlink("readable") == 0);
	CHECK(rmdir("writable") == 0);
	CHECK(rmdir("closed") == 0);
	CHECK(rmdir("entered") == 0);
}

static void
works_inside(void)
{
	CHECK(mkdir("entered/folder", 0755) == 0);
	int fd = open("entered/folder/file", O_CREAT | O_WRONLY, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(unlink("entered/folder/file") == 0);
	CHECK(rmdir("entered/folder") == 0);
	CHECK(mkdir("closed/folder", 0755) == -1 && errno == EACCES);
	fd = open("writable/file", O_CREAT | O_WRONLY, 0644);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(unlink("writable/file") == 0);
	fd = open("readable", O_RDONLY);
	CHECK(fd != -1 && close(fd) == 0);
	CHECK(open("readable", O_WRONLY) == -1 && errno == EACCES);
}

static void
kept_out(void)
{
	CHECK(mkdir("entered/folder", 0755) == -1 && errno == EACCES);
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

static filesec_t
filesec_of(mode_t mode, acl_t acl)
{
	filesec_t filesec = filesec_init();
	CHECK(filesec != NULL);
	CHECK(filesec_set_property(filesec, FILESEC_MODE, &mode) == 0);
	CHECK(filesec_set_property(filesec, FILESEC_ACL, &acl) == 0);
	return filesec;
}

static acl_t
list_of(int count, const uid_t *users, const acl_perm_t *perms,
		const int *flags)
{
	acl_t acl = acl_init(count);
	CHECK(acl != NULL);
	for (int i = 0; i < count; i++) {
		acl_entry_t entry;
		CHECK(acl_create_entry(&acl, &entry) == 0);
		CHECK(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0);
		uint8_t guid[16];
		user_guid(users[i], guid);
		CHECK(acl_set_qualifier(entry, guid) == 0);
		acl_permset_t permset;
		CHECK(acl_get_permset(entry, &permset) == 0);
		CHECK(acl_clear_perms(permset) == 0);
		for (int bit = 0; bit < 32; bit++) {
			if (perms[i] & (1U << bit)) {
				CHECK(acl_add_perm(permset, 1U << bit) == 0);
			}
		}
		CHECK(acl_set_permset(entry, permset) == 0);
		acl_flagset_t flagset;
		CHECK(acl_get_flagset_np(entry, &flagset) == 0);
		CHECK(acl_clear_flags_np(flagset) == 0);
		for (int bit = 0; bit < 32; bit++) {
			if (flags[i] & (1 << bit)) {
				CHECK(acl_add_flag_np(flagset, 1 << bit) == 0);
			}
		}
		CHECK(acl_set_flagset_np(entry, flagset) == 0);
	}
	return acl;
}

static void
user_guid(uid_t user, uint8_t guid[16])
{
	static const uint8_t prefix[12] = {0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd,
			0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa};
	memcpy(guid, prefix, sizeof(prefix));
	guid[12] = user >> 24;
	guid[13] = user >> 16;
	guid[14] = user >> 8;
	guid[15] = user;
}

static void
set_list(const char *path, int count, const uid_t *users,
		const acl_perm_t *perms, const int *flags)
{
	acl_t acl = list_of(count, users, perms, flags);
	CHECK(acl_set_file(path, ACL_TYPE_EXTENDED, acl) == 0);
	acl_free(acl);
}

static void
remove_list(const char *path)
{
	filesec_t filesec = filesec_init();
	CHECK(filesec != NULL);
	CHECK(filesec_set_property(filesec, FILESEC_ACL, _FILESEC_REMOVE_ACL)
			== 0);
	CHECK(chmodx_np(path, filesec) == 0);
	filesec_free(filesec);
}

static int
entries(const char *path)
{
	acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		CHECK(errno == ENOENT);
		return -1;
	}
	int count = entries_of(acl);
	acl_free(acl);
	return count;
}

static int
entries_of(acl_t acl)
{
	int count = 0;
	acl_entry_t entry;
	for (int id = ACL_FIRST_ENTRY; acl_get_entry(acl, id, &entry) == 0;
			id = ACL_NEXT_ENTRY) {
		count++;
	}
	return count;
}

static bool
allows(const char *path, uid_t user, acl_perm_t perm)
{
	acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
	CHECK(acl != NULL);
	uint8_t guid[16];
	user_guid(user, guid);
	bool allowed = false;
	acl_entry_t entry;
	for (int id = ACL_FIRST_ENTRY; acl_get_entry(acl, id, &entry) == 0;
			id = ACL_NEXT_ENTRY) {
		acl_tag_t tag;
		CHECK(acl_get_tag_type(entry, &tag) == 0);
		void *qualifier = acl_get_qualifier(entry);
		CHECK(qualifier != NULL);
		acl_permset_t permset;
		CHECK(acl_get_permset(entry, &permset) == 0);
		if (tag == ACL_EXTENDED_ALLOW
				&& memcmp(qualifier, guid, sizeof(guid)) == 0
				&& acl_get_perm_np(permset, perm) == 1) {
			allowed = true;
		}
		acl_free(qualifier);
	}
	acl_free(acl);
	return allowed;
}

static bool
read_filesec(const char *path, struct filesec *filesec)
{
	struct attrlist request = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_EXTENDED_SECURITY,
	};
	struct {
		uint32_t length;
		attrreference_t reference;
		char data[sizeof(struct filesec) + 64];
	} __attribute__((packed)) buffer;
	CHECK(getattrlist(path, &request, &buffer, sizeof(buffer), 0) == 0);
	if (buffer.reference.attr_length == 0) {
		return false;
	}
	CHECK(buffer.reference.attr_length <= sizeof(*filesec));
	memcpy(filesec,
			(char *)&buffer.reference
					+ buffer.reference.attr_dataoffset,
			buffer.reference.attr_length);
	CHECK(filesec->magic == FILESEC_MAGIC);
	size_t entries_size = filesec->count * sizeof(struct entry);
	CHECK(buffer.reference.attr_length
			== offsetof(struct filesec, entry) + entries_size);
	return true;
}

static bool
entry_for(const char *path, uid_t user, struct entry *found)
{
	struct filesec filesec;
	if (!read_filesec(path, &filesec)) {
		return false;
	}
	uint8_t guid[16];
	user_guid(user, guid);
	for (uint32_t i = 0; i < filesec.count; i++) {
		if (memcmp(filesec.entry[i].applicable, guid, 16) == 0) {
			*found = filesec.entry[i];
			return true;
		}
	}
	return false;
}

static int
write_filesec(const char *path, const struct filesec *filesec, size_t size)
{
	struct {
		attrreference_t reference;
		struct filesec filesec;
	} __attribute__((packed)) buffer;
	buffer.reference.attr_dataoffset = sizeof(buffer.reference);
	buffer.reference.attr_length = size;
	buffer.filesec = *filesec;
	struct attrlist request = {
			.bitmapcount = ATTR_BIT_MAP_COUNT,
			.commonattr = ATTR_CMN_EXTENDED_SECURITY,
	};
	return setattrlist(path, &request, &buffer, sizeof(buffer), 0);
}
