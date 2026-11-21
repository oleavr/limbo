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
#include <stdint.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "check.h"

#define USER 501

static void clean_up(void);
static int remove_entry(const char *path, const struct stat *st, int type,
		struct FTW *ftw);
static void check_kept(void);
static void check_hidden(void);
static acl_t list_of(int count, const uid_t *users, const acl_perm_t *perms,
		const int *flags);
static void user_guid(uid_t user, uint8_t guid[16]);
static void set_list(const char *path, int count, const uid_t *users,
		const acl_perm_t *perms, const int *flags);
static void remove_list(const char *path);
static int entries(const char *path);
static int entries_of(acl_t acl);
static bool allows(const char *path, uid_t user, acl_perm_t perm);

static char folder[] = "/tmp/limbo-access-XXXXXX";
static pid_t owner;

int
main(void)
{
	CHECK(mkdtemp(folder) != NULL);
	owner = getpid();
	CHECK(atexit(clean_up) == 0);
	CHECK(chmod(folder, 0755) == 0);
	CHECK(chdir(folder) == 0);

	check_kept();
	check_hidden();

	CHECK(chdir("/") == 0);
	CHECK(rmdir(folder) == 0);
	return 0;
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
