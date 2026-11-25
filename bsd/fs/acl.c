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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "acl.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bsd/gid.h"
#include "protection.h"

struct filesec_header {
	uint32_t magic;
	uint8_t owner[16];
	uint8_t group[16];
	uint32_t count;
	uint32_t flags;
};

_Static_assert(sizeof(struct filesec_header) == ACL_FILESEC_HEADER_SIZE,
		"kauth_filesec");

static int object_open(int dirfd, const char *host_path, int at_flags);
static enum acl_result evaluate(const char *path, uint32_t rights);
static uint32_t open_rights(int flags);
static void object_path(int fd, char *buffer, size_t size);
static bool may_set(const struct stat *s);
static bool parent_gives(
		int dirfd, const char *host_path, struct acl_list *parent);
static void parent_path(
		int dirfd, const char *host_path, char *buffer, size_t size);
static uint32_t class_given(int dirfd, const char *host_path);
static int open_or_make(int dirfd, const char *host_path, int flags,
		mode_t mode, bool *made);
static int inherit(int fd, const struct acl_list *parent,
		const struct acl_list *initial);
static int open_reaching(
		int dirfd, const char *host_path, int flags, mode_t mode);

int
acl_from_filesec(const void *xsecurity, struct acl_list *list)
{
	if (xsecurity == ACL_FILESEC_DELETE) {
		list->count = KAUTH_FILESEC_NOACL;
		list->flags = 0;
		return 0;
	}
	struct filesec_header header;
	memcpy(&header, xsecurity, sizeof(header));
	list->count = header.count;
	list->flags = header.flags;
	bool listed = header.count != KAUTH_FILESEC_NOACL;
	if (header.magic != KAUTH_FILESEC_MAGIC
			|| (listed && header.count > KAUTH_ACL_MAX_ENTRIES)) {
		errno = EINVAL;
		return -1;
	}
	if (!listed) {
		return 0;
	}
	memcpy(list->ace, (const char *)xsecurity + sizeof(header),
			header.count * sizeof(struct kauth_ace));
	return 0;
}

int
acl_set_at(int dirfd, const char *host_path, int at_flags,
		const struct acl_list *list)
{
	int fd = object_open(dirfd, host_path, at_flags);
	if (fd == -1) {
		return -1;
	}
	char path[48];
	object_path(fd, path, sizeof(path));
	struct stat s;
	int r = fstat(fd, &s);
	if (r == 0 && S_ISLNK(s.st_mode)) {
		errno = EOPNOTSUPP;
		r = -1;
	} else if (r == 0 && !may_set(&s)) {
		errno = EPERM;
		r = -1;
	} else if (r == 0) {
		r = acl_store(path, list);
	}
	int saved = errno;
	close(fd);
	errno = saved;
	return r;
}

static int
object_open(int dirfd, const char *host_path, int at_flags)
{
	if ((at_flags & AT_EMPTY_PATH) && host_path[0] == '\0') {
		char link[48];
		object_path(dirfd, link, sizeof(link));
		return open(link, O_PATH | O_CLOEXEC);
	}
	int nofollow = (at_flags & AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0;
	return openat(dirfd, host_path, O_PATH | O_CLOEXEC | nofollow);
}

static void
object_path(int fd, char *buffer, size_t size)
{
	snprintf(buffer, size, "/proc/thread-self/fd/%d", fd);
}

int
acl_check_at(int dirfd, const char *host_path, int at_flags, uint32_t rights)
{
	int fd = object_open(dirfd, host_path, at_flags);
	if (fd == -1) {
		return 0;
	}
	char path[48];
	object_path(fd, path, sizeof(path));
	enum acl_result result = evaluate(path, rights);
	close(fd);
	if (result == ACL_DENY) {
		errno = EACCES;
		return -1;
	}
	return 0;
}

int
acl_check_delete_at(int dirfd, const char *host_path)
{
	int fd = object_open(dirfd, host_path, AT_SYMLINK_NOFOLLOW);
	if (fd == -1) {
		return 0;
	}
	char path[48];
	object_path(fd, path, sizeof(path));
	enum acl_result result = evaluate(path, KAUTH_VNODE_DELETE);
	close(fd);
	if (result == ACL_UNDECIDED) {
		char parent[PATH_MAX];
		parent_path(dirfd, host_path, parent, sizeof(parent));
		result = evaluate(parent, KAUTH_VNODE_DELETE_CHILD);
	}
	if (result == ACL_DENY) {
		errno = EACCES;
		return -1;
	}
	return 0;
}

static enum acl_result
evaluate(const char *path, uint32_t rights)
{
	uid_t uid = (uid_t)setfsuid((uid_t)-1);
	if (uid == 0 || rights == 0) {
		return ACL_UNDECIDED;
	}
	struct acl_list list;
	acl_record_read(path, &list);
	if (list.count == KAUTH_FILESEC_NOACL) {
		return ACL_UNDECIDED;
	}
	gid_t groups[NGROUPS_MAX];
	int count = getgroups(NGROUPS_MAX, groups);
	for (int i = 0; i < count; i++) {
		groups[i] = gid_from_linux(groups[i]);
	}
	gid_t gid = gid_from_linux((gid_t)setfsgid((gid_t)-1));
	return acl_evaluate(
			&list, uid, gid, groups, count > 0 ? count : 0, rights);
}

static uint32_t
open_rights(int flags)
{
	int access = flags & O_ACCMODE;
	uint32_t rights = 0;
	if (access == O_RDONLY || access == O_RDWR) {
		rights |= KAUTH_VNODE_READ_DATA;
	}
	if (access == O_WRONLY || access == O_RDWR) {
		rights |= (flags & O_APPEND) ? KAUTH_VNODE_APPEND_DATA
					     : KAUTH_VNODE_WRITE_DATA;
	}
	if (flags & O_TRUNC) {
		rights |= KAUTH_VNODE_WRITE_DATA;
	}
	return rights;
}

static bool
may_set(const struct stat *s)
{
	uid_t me = (uid_t)setfsuid((uid_t)-1);
	return me == 0 || me == s->st_uid;
}

int
acl_openat(int dirfd, const char *host_path, int flags, mode_t mode,
		const struct acl_list *initial, bool *created)
{
	bool unasked;
	bool *made = created != NULL ? created : &unasked;
	*made = false;
	int follow = (flags & O_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0;
	if (acl_check_at(dirfd, host_path, follow, open_rights(flags)) == -1) {
		return -1;
	}
	if (!(flags & O_CREAT)) {
		return openat(dirfd, host_path, flags, mode);
	}
	struct acl_list parent;
	bool gives = parent_gives(dirfd, host_path, &parent);
	uint32_t dpclass = class_given(dirfd, host_path);
	if (!gives && initial == NULL && created == NULL
			&& dpclass == PROTECTION_CLASS_DIR_NONE) {
		return open_reaching(dirfd, host_path, flags, mode);
	}
	int fd = open_or_make(dirfd, host_path, flags, mode, made);
	if (*made && (gives || initial != NULL)
			&& inherit(fd, &parent, initial) == -1
			&& initial != NULL) {
		int error = errno;
		unlinkat(dirfd, host_path, 0);
		close(fd);
		errno = error;
		return -1;
	}
	if (*made && dpclass != PROTECTION_CLASS_DIR_NONE) {
		protection_set(fd, (int)dpclass);
	}
	return fd;
}

static bool
parent_gives(int dirfd, const char *host_path, struct acl_list *parent)
{
	char path[PATH_MAX + 48];
	parent_path(dirfd, host_path, path, sizeof(path));
	acl_record_read(path, parent);
	return acl_inheritable(parent);
}

static void
parent_path(int dirfd, const char *host_path, char *buffer, size_t size)
{
	size_t end = strlen(host_path);
	while (end > 1 && host_path[end - 1] == '/') {
		end--;
	}
	while (end > 0 && host_path[end - 1] != '/') {
		end--;
	}
	while (end > 1 && host_path[end - 1] == '/') {
		end--;
	}
	if (end > 0 && (host_path[0] == '/' || dirfd == AT_FDCWD)) {
		snprintf(buffer, size, "%.*s", (int)end, host_path);
	} else if (end > 0) {
		snprintf(buffer, size, "/proc/thread-self/fd/%d/%.*s", dirfd,
				(int)end, host_path);
	} else if (dirfd == AT_FDCWD) {
		snprintf(buffer, size, ".");
	} else {
		object_path(dirfd, buffer, size);
	}
}

static uint32_t
class_given(int dirfd, const char *host_path)
{
	char path[PATH_MAX + 48];
	parent_path(dirfd, host_path, path, sizeof(path));
	return protection_folder_gives(path);
}

static int
open_or_make(int dirfd, const char *host_path, int flags, mode_t mode,
		bool *made)
{
	*made = false;
	int fd = -1;
	for (int attempt = 0; attempt < 2 && fd == -1; attempt++) {
		fd = openat(dirfd, host_path, flags | O_EXCL, mode);
		if (fd != -1) {
			*made = true;
		} else if (errno == EEXIST && !(flags & O_EXCL)) {
			fd = openat(dirfd, host_path, flags & ~O_CREAT, mode);
			if (fd == -1 && errno != ENOENT) {
				return -1;
			}
		} else {
			return -1;
		}
	}
	return fd != -1 ? fd : open_reaching(dirfd, host_path, flags, mode);
}

static int
open_reaching(int dirfd, const char *host_path, int flags, mode_t mode)
{
	int fd = openat(dirfd, host_path, flags, mode);
	if (fd == -1 && errno == EISDIR && (flags & O_ACCMODE) == O_RDONLY) {
		fd = openat(dirfd, host_path, flags & ~O_CREAT);
	}
	return fd;
}

static int
inherit(int fd, const struct acl_list *parent, const struct acl_list *initial)
{
	char path[48];
	object_path(fd, path, sizeof(path));
	struct stat s;
	fstat(fd, &s);
	struct acl_list list;
	bool stores = !S_ISLNK(s.st_mode)
			&& acl_inherit(parent, initial, S_ISDIR(s.st_mode),
					&list);
	return stores ? acl_store(path, &list) : 0;
}

int
acl_mkdirat(int dirfd, const char *host_path, mode_t mode,
		const struct acl_list *initial)
{
	struct acl_list parent;
	bool gives = parent_gives(dirfd, host_path, &parent);
	uint32_t dpclass = class_given(dirfd, host_path);
	if (mkdirat(dirfd, host_path, mode) == -1) {
		return -1;
	}
	bool lists = gives || initial != NULL;
	if (!lists && dpclass == PROTECTION_CLASS_DIR_NONE) {
		return 0;
	}
	int fd = openat(dirfd, host_path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1) {
		return 0;
	}
	if (lists && inherit(fd, &parent, initial) == -1 && initial != NULL) {
		int error = errno;
		close(fd);
		unlinkat(dirfd, host_path, AT_REMOVEDIR);
		errno = error;
		return -1;
	}
	if (dpclass != PROTECTION_CLASS_DIR_NONE) {
		protection_set(fd, (int)dpclass);
	}
	close(fd);
	return 0;
}

size_t
acl_filesec_at(int dirfd, const char *host_path, int at_flags, void *buffer,
		size_t size)
{
	int fd = object_open(dirfd, host_path, at_flags);
	if (fd == -1) {
		return 0;
	}
	char path[48];
	object_path(fd, path, sizeof(path));
	struct acl_list list;
	acl_record_read(path, &list);
	close(fd);
	if (list.count == KAUTH_FILESEC_NOACL) {
		return 0;
	}
	size_t entries_size = list.count * sizeof(struct kauth_ace);
	size_t length = sizeof(struct filesec_header) + entries_size;
	if (buffer != NULL && size >= length) {
		struct filesec_header header = {
				.magic = KAUTH_FILESEC_MAGIC,
				.count = list.count,
				.flags = list.flags,
		};
		memcpy(buffer, &header, sizeof(header));
		memcpy((char *)buffer + sizeof(header), list.ace, entries_size);
	}
	return length;
}
