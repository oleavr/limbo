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

#include "broker_acl.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bsd/gid.h"

#define GROUPS_MAX 256

struct requester {
	uid_t uid;
	gid_t gid;
	gid_t groups[GROUPS_MAX];
	size_t group_count;
};

struct object {
	char path[48];
	struct stat s;
	bool owned;
	struct acl_list list;
};

static bool identify(int connection, struct requester *who);
static int set(const struct broker_acl *request, const struct requester *who,
		const struct object *object);
static bool list_valid(const struct acl_list *list);
static bool grants(const struct acl_list *list, const struct requester *who,
		uint32_t rights);
static int inherit(const struct broker_acl *request,
		const struct object *object, int folder);
static bool made_in(int folder, const char *name, const struct stat *s);
static int rederive(const struct object *object);
static int change_mode(const struct broker_acl *request,
		const struct requester *who, struct object *object);

int
broker_acl(int connection, const struct broker_acl *request, const int *fds,
		size_t fd_count)
{
	if (geteuid() != 0 || !acl_trusted_available()) {
		return BROKER_ACL_UNKEPT;
	}
	struct requester who;
	struct object object;
	if (fd_count == 0 || !identify(connection, &who)
			|| fstat(fds[0], &object.s) == -1) {
		return EPERM;
	}
	if (S_ISLNK(object.s.st_mode)) {
		return EOPNOTSUPP;
	}
	snprintf(object.path, sizeof(object.path), "/proc/thread-self/fd/%d",
			fds[0]);
	object.owned = who.uid == 0 || who.uid == object.s.st_uid;
	acl_record_read(object.path, true, &object.list);
	switch (request->op) {
	case BROKER_ACL_SET:
		return set(request, &who, &object);
	case BROKER_ACL_INHERIT:
		return fd_count < 2 ? EPERM : inherit(request, &object, fds[1]);
	case BROKER_ACL_REDERIVE:
		return object.owned ? rederive(&object) : EPERM;
	case BROKER_ACL_CHMOD:
		return change_mode(request, &who, &object);
	}
	return EINVAL;
}

static bool
identify(int connection, struct requester *who)
{
	struct ucred peer;
	socklen_t size = sizeof(peer);
	if (getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &peer, &size)
			!= 0) {
		return false;
	}
	who->uid = peer.uid;
	who->gid = gid_from_linux(peer.gid);
	socklen_t groups_size = sizeof(who->groups);
	who->group_count = 0;
	if (getsockopt(connection, SOL_SOCKET, SO_PEERGROUPS, who->groups,
			    &groups_size)
			== 0) {
		who->group_count = groups_size / sizeof(gid_t);
	}
	for (size_t i = 0; i < who->group_count; i++) {
		who->groups[i] = gid_from_linux(who->groups[i]);
	}
	return true;
}

static int
set(const struct broker_acl *request, const struct requester *who,
		const struct object *object)
{
	if (!list_valid(&request->list)) {
		return EINVAL;
	}
	if (!object->owned
			&& !grants(&object->list, who,
					KAUTH_VNODE_WRITE_SECURITY)) {
		return EPERM;
	}
	int r = acl_store(object->path, &object->s, &request->list, true);
	return r == 0 ? 0 : errno;
}

static bool
list_valid(const struct acl_list *list)
{
	return list->count == KAUTH_FILESEC_NOACL
			|| list->count <= KAUTH_ACL_MAX_ENTRIES;
}

static bool
grants(const struct acl_list *list, const struct requester *who,
		uint32_t rights)
{
	return acl_evaluate(list, who->uid, who->gid, who->groups,
			       who->group_count, rights)
			== ACL_ALLOW;
}

static int
inherit(const struct broker_acl *request, const struct object *object,
		int folder)
{
	if (!object->owned || !made_in(folder, request->name, &object->s)) {
		return EPERM;
	}
	if (!list_valid(&request->list)) {
		return EINVAL;
	}
	char path[48];
	snprintf(path, sizeof(path), "/proc/thread-self/fd/%d", folder);
	struct acl_list parent;
	acl_record_read(path, true, &parent);
	bool listed = request->list.count != KAUTH_FILESEC_NOACL;
	struct acl_list list;
	if (!acl_inherit(&parent, listed ? &request->list : NULL,
			    S_ISDIR(object->s.st_mode), &list)) {
		return 0;
	}
	return acl_store(object->path, &object->s, &list, true) == 0 ? 0
								     : errno;
}

static bool
made_in(int folder, const char *name, const struct stat *s)
{
	struct stat folder_stat, named;
	return name[0] != '\0' && strchr(name, '/') == NULL
			&& strcmp(name, ".") != 0 && strcmp(name, "..") != 0
			&& fstat(folder, &folder_stat) == 0
			&& S_ISDIR(folder_stat.st_mode)
			&& fstatat(folder, name, &named, AT_SYMLINK_NOFOLLOW)
			== 0
			&& named.st_dev == s->st_dev
			&& named.st_ino == s->st_ino;
}

static int
rederive(const struct object *object)
{
	int group = (object->s.st_mode & S_IRWXG) >> 3;
	if (object->list.count != KAUTH_FILESEC_NOACL
			&& acl_posix_write(object->path, &object->list,
					   &object->s, group)
					== -1
			&& errno != EOPNOTSUPP) {
		return errno;
	}
	return 0;
}

static int
change_mode(const struct broker_acl *request, const struct requester *who,
		struct object *object)
{
	mode_t mode = request->mode & 07777;
	bool lets = grants(&object->list, who, KAUTH_VNODE_WRITE_SECURITY)
			&& !(mode & (S_ISUID | S_ISGID));
	if (!object->owned && !lets) {
		return EPERM;
	}
	if (chmod(object->path, mode) == -1) {
		return errno;
	}
	object->s.st_mode = (object->s.st_mode & S_IFMT) | mode;
	return rederive(object);
}
