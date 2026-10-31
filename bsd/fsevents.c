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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "commpage.h"
#include "fs/device.h"
#include "fsevents.h"
#include "sysroot.h"
#include "xnu-errno.h"

#define FSE_CREATE_FILE      0
#define FSE_DELETE           1
#define FSE_STAT_CHANGED     2
#define FSE_RENAME           3
#define FSE_CONTENT_MODIFIED 4
#define FSE_CREATE_DIR       7
#define FSE_MAX_EVENTS       16
#define FSE_EVENTS_DROPPED   999
#define FSE_REPORT           1

#define FSE_ARG_STRING 0x0002
#define FSE_ARG_INT64  0x0005
#define FSE_ARG_INO    0x0007
#define FSE_ARG_UID    0x0008
#define FSE_ARG_DEV    0x0009
#define FSE_ARG_MODE   0x000a
#define FSE_ARG_GID    0x000b
#define FSE_ARG_FINFO  0x000c
#define FSE_ARG_DONE   0xb33f

#define xnu_FSEVENTS_CLONE               0x80187301
#define xnu_FSEVENTS_DEVICE_FILTER       0x800c7364
#define xnu_FSEVENTS_WANT_COMPACT_EVENTS 0x20007365
#define xnu_FSEVENTS_WANT_EXTENDED_INFO  0x20007366
#define xnu_FSEVENTS_GET_CURRENT_ID      0x40087367
#define xnu_FSEVENTS_UNMOUNT_PENDING_ACK 0x80047368

#define FSEVENTS_READ_MIN 2048

struct clone_args {
	int8_t *event_list;
	int32_t num_events;
	int32_t event_queue_depth;
	int32_t *fd;
};

struct __attribute__((packed, aligned(4))) device_filter_args {
	uint32_t num_devices;
	int32_t *devices;
};

_Static_assert(sizeof(struct clone_args) == 24, "fsevent_clone_args");
_Static_assert(sizeof(struct device_filter_args) == 12,
		"fsevent_dev_filter_args");

enum kind {
	KIND_NONE,
	KIND_DEVICE,
	KIND_WATCHER,
};

static struct entry {
	uint8_t kind;
	bool compact;
	bool extended;
	bool dropped;
	int peer;
	int8_t events[FSE_MAX_EVENTS];
	int32_t *devices;
	uint32_t device_count;
} entries[1024];

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t current_id;
static bool watching;

struct item {
	char path[PATH_MAX];
	bool has_info;
	int32_t dev;
	uint64_t ino;
	int32_t mode;
	uint32_t uid;
};

static struct known_directory {
	uint8_t handle[MAX_HANDLE_SZ + 8];
	size_t length;
	char path[PATH_MAX];
} known_directories[64];
static size_t known_next;

static bool is_kind(int fd, enum kind kind);
static int clone_watcher(const struct clone_args *args);
static void start_watching(void);
static void *watch_main(void *argument);
static void handle_event(
		int mount_fd, const struct fanotify_event_metadata *metadata);
static bool make_item(int mount_fd, struct file_handle *directory,
		const char *name, bool is_dir, bool deleted, struct item *item);
static bool handle_path(int mount_fd, struct file_handle *handle, char *out);
static struct known_directory *known_directory(
		const struct file_handle *handle);
static size_t handle_length(const struct file_handle *handle);
static void post(int32_t type, int32_t pid, const struct item *items,
		size_t count);
static size_t encode(uint8_t *out, int32_t type, int32_t pid,
		const struct item *items, size_t count, bool compact,
		uint64_t time);
static size_t put_argument(
		uint8_t *out, uint16_t type, const void *data, uint16_t length);

bool
fsevents_is_device_path(const char *path)
{
	return strcmp(path, "/dev/fsevents") == 0;
}

int
fsevents_open(bool cloexec)
{
	if (geteuid() != 0) {
		return _EPERM;
	}
	int fd = open("/dev/null", O_RDONLY | (cloexec ? O_CLOEXEC : 0));
	if (fd == -1) {
		return err_map(errno);
	}
	if ((size_t)fd >= sizeof(entries) / sizeof(*entries)) {
		close(fd);
		return _EMFILE;
	}
	pthread_mutex_lock(&lock);
	entries[fd] = (struct entry){.kind = KIND_DEVICE};
	pthread_mutex_unlock(&lock);
	return fd;
}

bool
fsevents_is_watcher(int fd)
{
	return is_kind(fd, KIND_WATCHER);
}

static bool
is_kind(int fd, enum kind kind)
{
	return fd >= 0 && (size_t)fd < sizeof(entries) / sizeof(*entries)
			&& entries[fd].kind == kind;
}

void
fsevents_close(int fd)
{
	if (!is_kind(fd, KIND_DEVICE) && !is_kind(fd, KIND_WATCHER)) {
		return;
	}
	pthread_mutex_lock(&lock);
	if (entries[fd].kind == KIND_WATCHER) {
		close(entries[fd].peer);
		free(entries[fd].devices);
	}
	entries[fd] = (struct entry){0};
	pthread_mutex_unlock(&lock);
}

int
fsevents_ioctl(int fd, uint64_t command, void *data)
{
	if (is_kind(fd, KIND_DEVICE)) {
		if (command != xnu_FSEVENTS_CLONE) {
			return _ENOTTY;
		}
		return clone_watcher(data);
	}
	if (!is_kind(fd, KIND_WATCHER)) {
		return 1;
	}
	int result = 0;
	pthread_mutex_lock(&lock);
	struct entry *watcher = &entries[fd];
	switch (command) {
	case xnu_FSEVENTS_WANT_COMPACT_EVENTS:
		watcher->compact = true;
		break;
	case xnu_FSEVENTS_WANT_EXTENDED_INFO:
		watcher->extended = true;
		break;
	case xnu_FSEVENTS_GET_CURRENT_ID:
		*(uint64_t *)data = current_id;
		break;
	case xnu_FSEVENTS_DEVICE_FILTER: {
		const struct device_filter_args *filter = data;
		if (filter->num_devices > 256) {
			result = _EINVAL;
			break;
		}
		free(watcher->devices);
		watcher->devices = NULL;
		watcher->device_count = filter->num_devices;
		if (filter->num_devices != 0) {
			watcher->devices = malloc(
					filter->num_devices * sizeof(int32_t));
			memcpy(watcher->devices, filter->devices,
					filter->num_devices * sizeof(int32_t));
		}
		break;
	}
	case xnu_FSEVENTS_UNMOUNT_PENDING_ACK:
		break;
	default:
		pthread_mutex_unlock(&lock);
		return 1;
	}
	pthread_mutex_unlock(&lock);
	return result;
}

static int
clone_watcher(const struct clone_args *args)
{
	if (args->num_events < 0 || args->num_events > 4096
			|| (args->num_events != 0 && args->event_list == NULL)
			|| args->fd == NULL) {
		return _EINVAL;
	}
	int pair[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == -1) {
		return err_map(errno);
	}
	if ((size_t)pair[0] >= sizeof(entries) / sizeof(*entries)) {
		close(pair[0]);
		close(pair[1]);
		return _EMFILE;
	}
	fcntl(pair[0], F_SETFD, 0);
	int size = 4 * 1024 * 1024;
	setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	struct entry watcher = {
			.kind = KIND_WATCHER,
			.peer = pair[1],
	};
	for (int32_t i = 0; i < args->num_events && i < FSE_MAX_EVENTS; i++) {
		watcher.events[i] = args->event_list[i];
	}
	pthread_mutex_lock(&lock);
	entries[pair[0]] = watcher;
	start_watching();
	pthread_mutex_unlock(&lock);
	*args->fd = pair[0];
#ifdef ENABLE_STRACE
	fprintf(stderr, "  fsevents: watcher %d for %d event types\n", pair[0],
			args->num_events);
#endif
	return 0;
}

static void
start_watching(void)
{
	if (watching) {
		return;
	}
	int fan = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC
					| FAN_REPORT_DFID_NAME_TARGET,
			O_RDONLY | O_LARGEFILE | O_CLOEXEC);
	if (fan == -1) {
#ifdef ENABLE_STRACE
		fprintf(stderr, "  fsevents: no fanotify: %s\n",
				strerror(errno));
#endif
		return;
	}
	char root[PATH_MAX];
	uint64_t mask = FAN_CREATE | FAN_DELETE | FAN_RENAME | FAN_CLOSE_WRITE
			| FAN_ATTRIB | FAN_ONDIR;
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask,
			    AT_FDCWD, sysroot_host_path("/", 0, root))
			== -1) {
#ifdef ENABLE_STRACE
		fprintf(stderr, "  fsevents: no mark: %s\n", strerror(errno));
#endif
		close(fan);
		return;
	}
	watching = true;
	sigset_t all, previous;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &previous);
	pthread_t handle;
	pthread_create(&handle, NULL, watch_main, (void *)(intptr_t)fan);
	pthread_detach(handle);
	pthread_sigmask(SIG_SETMASK, &previous, NULL);
}

static void *
watch_main(void *argument)
{
	int fan = (int)(intptr_t)argument;
	char root[PATH_MAX];
	int mount_fd = open(sysroot_host_path("/", 0, root),
			O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	static uint8_t buffer[64 * 1024] __attribute__((aligned(8)));
	for (;;) {
		ssize_t length = read(fan, buffer, sizeof(buffer));
		if (length < 0) {
			if (errno == EINTR) {
				continue;
			}
			return NULL;
		}
		const struct fanotify_event_metadata *metadata
				= (const void *)buffer;
		size_t remaining = (size_t)length;
		while (FAN_EVENT_OK(metadata, remaining)) {
			if (metadata->mask & FAN_Q_OVERFLOW) {
				pthread_mutex_lock(&lock);
				for (size_t fd = 0; fd < sizeof(entries)
								/ sizeof(*entries);
						fd++) {
					if (entries[fd].kind == KIND_WATCHER) {
						entries[fd].dropped = true;
					}
				}
				pthread_mutex_unlock(&lock);
			} else {
				handle_event(mount_fd, metadata);
			}
			metadata = FAN_EVENT_NEXT(metadata, remaining);
		}
	}
	return NULL;
}

static void
handle_event(int mount_fd, const struct fanotify_event_metadata *metadata)
{
	struct file_handle *directory = NULL, *old_directory = NULL,
			   *new_directory = NULL;
	const char *name = NULL, *old_name = NULL, *new_name = NULL;
	const uint8_t *cursor
			= (const uint8_t *)metadata + metadata->metadata_len;
	const uint8_t *end = (const uint8_t *)metadata + metadata->event_len;
	while (cursor + sizeof(struct fanotify_event_info_header) <= end) {
		const struct fanotify_event_info_header *header
				= (const void *)cursor;
		if (header->len == 0 || cursor + header->len > end) {
			break;
		}
		const struct fanotify_event_info_fid *fid
				= (const void *)cursor;
		struct file_handle *handle = (struct file_handle *)fid->handle;
		const char *child = (const char *)handle->f_handle
				+ handle->handle_bytes;
		switch (header->info_type) {
		case FAN_EVENT_INFO_TYPE_DFID_NAME:
			directory = handle;
			name = child;
			break;
		case FAN_EVENT_INFO_TYPE_DFID:
			if (directory == NULL) {
				directory = handle;
			}
			break;
		case FAN_EVENT_INFO_TYPE_OLD_DFID_NAME:
			old_directory = handle;
			old_name = child;
			break;
		case FAN_EVENT_INFO_TYPE_NEW_DFID_NAME:
			new_directory = handle;
			new_name = child;
			break;
		}
		cursor += header->len;
	}

#ifdef ENABLE_STRACE
	fprintf(stderr, "  fsevents: fanotify %#llx by %d, %s\n",
			(unsigned long long)metadata->mask, metadata->pid,
			name != NULL ? name
				     : (new_name != NULL ? new_name : "-"));
#endif
	bool is_dir = metadata->mask & FAN_ONDIR;
	struct item items[2];
	if (metadata->mask & FAN_RENAME) {
		if (old_directory == NULL || new_directory == NULL
				|| !make_item(mount_fd, old_directory, old_name,
						is_dir, true, &items[0])
				|| !make_item(mount_fd, new_directory, new_name,
						is_dir, false, &items[1])) {
			return;
		}
		items[0].has_info = items[1].has_info;
		items[0].dev = items[1].dev;
		items[0].ino = items[1].ino;
		items[0].mode = items[1].mode;
		items[0].uid = items[1].uid;
		post(FSE_RENAME, metadata->pid, items, 2);
		return;
	}
	if (directory == NULL) {
		return;
	}
	bool deleted = metadata->mask & FAN_DELETE;
	if (!make_item(mount_fd, directory, name, is_dir, deleted, &items[0])) {
		return;
	}
	if (metadata->mask & FAN_CREATE) {
		post(is_dir ? FSE_CREATE_DIR : FSE_CREATE_FILE, metadata->pid,
				items, 1);
	}
	if (metadata->mask & FAN_DELETE) {
		post(FSE_DELETE, metadata->pid, items, 1);
	}
	if (metadata->mask & FAN_CLOSE_WRITE) {
		post(FSE_CONTENT_MODIFIED, metadata->pid, items, 1);
	}
	if (metadata->mask & FAN_ATTRIB) {
		post(FSE_STAT_CHANGED, metadata->pid, items, 1);
	}
}

static bool
make_item(int mount_fd, struct file_handle *directory, const char *name,
		bool is_dir, bool deleted, struct item *item)
{
	*item = (struct item){0};
	char parent[PATH_MAX];
	if (!handle_path(mount_fd, directory, parent)) {
		return false;
	}
	if (name == NULL || name[0] == '\0' || strcmp(name, ".") == 0) {
		snprintf(item->path, sizeof(item->path), "%s", parent);
	} else {
		snprintf(item->path, sizeof(item->path), "%s%s%s", parent,
				strcmp(parent, "/") == 0 ? "" : "/", name);
	}
	char buffer[PATH_MAX];
	struct stat s;
	if (!deleted
			&& lstat(sysroot_host_path(item->path,
						 AT_SYMLINK_NOFOLLOW, buffer),
					   &s)
					== 0) {
		item->has_info = true;
		item->dev = darwin_device(s.st_dev);
		item->ino = sysroot_file_id(s.st_dev, s.st_ino);
		item->mode = (int32_t)s.st_mode;
		item->uid = s.st_uid;
	} else if (deleted) {
		char root[PATH_MAX];
		if (stat(sysroot_host_path("/", 0, root), &s) == 0) {
			item->has_info = true;
			item->dev = darwin_device(s.st_dev);
			item->ino = 0;
			item->mode = is_dir ? S_IFDIR : S_IFREG;
		}
	}
	return true;
}

static bool
handle_path(int mount_fd, struct file_handle *handle, char *out)
{
	int fd = open_by_handle_at(mount_fd, handle, O_PATH | O_CLOEXEC);
	if (fd == -1) {
#ifdef ENABLE_STRACE
		fprintf(stderr, "  fsevents: no directory for a handle: %s\n",
				strerror(errno));
#endif
		struct known_directory *known = known_directory(handle);
		if (known == NULL) {
			return false;
		}
		snprintf(out, PATH_MAX, "%s", known->path);
		return true;
	}
	char link[64];
	snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
	char host[PATH_MAX];
	ssize_t length = readlink(link, host, sizeof(host) - 1);
	close(fd);
	if (length <= 0) {
		return false;
	}
	host[length] = '\0';
	const char *guest = sysroot_guest_path(host);
	if (guest == host) {
		return false;
	}
	snprintf(out, PATH_MAX, "%s", guest);
	struct known_directory *known = known_directory(handle);
	size_t handle_size = handle_length(handle);
	if (known == NULL && handle_size != 0) {
		known = &known_directories[known_next++
				% (sizeof(known_directories)
						/ sizeof(*known_directories))];
		memcpy(known->handle, handle, handle_size);
		known->length = handle_size;
	}
	if (known != NULL) {
		snprintf(known->path, sizeof(known->path), "%s", guest);
	}
	return true;
}

static struct known_directory *
known_directory(const struct file_handle *handle)
{
	size_t length = handle_length(handle);
	for (size_t i = 0; length != 0
			&& i < sizeof(known_directories)
							/ sizeof(*known_directories);
			i++) {
		if (known_directories[i].length == length
				&& memcmp(known_directories[i].handle, handle,
						   length)
						== 0) {
			return &known_directories[i];
		}
	}
	return NULL;
}

static size_t
handle_length(const struct file_handle *handle)
{
	size_t length = sizeof(*handle) + handle->handle_bytes;
	return length <= sizeof(known_directories[0].handle) ? length : 0;
}

static void
post(int32_t type, int32_t pid, const struct item *items, size_t count)
{
	uint64_t time = commpage_absolute_time();
	static uint8_t message[2 * (PATH_MAX + 128)];
	pthread_mutex_lock(&lock);
	current_id++;
	for (size_t fd = 0; fd < sizeof(entries) / sizeof(*entries); fd++) {
		struct entry *watcher = &entries[fd];
		if (watcher->kind != KIND_WATCHER || type >= FSE_MAX_EVENTS
				|| watcher->events[type] != FSE_REPORT) {
			continue;
		}
		if (watcher->device_count != 0) {
			bool wanted = false;
			for (uint32_t i = 0; i < watcher->device_count; i++) {
				wanted |= watcher->devices[i] == items[0].dev;
			}
			if (!wanted) {
				continue;
			}
		}
		size_t length = encode(message, type, pid, items, count,
				watcher->compact, time);
		if (send(watcher->peer, message, length,
				    MSG_DONTWAIT | MSG_NOSIGNAL)
				== -1) {
			watcher->dropped = true;
		}
	}
	pthread_mutex_unlock(&lock);
#ifdef ENABLE_STRACE
	fprintf(stderr, "  fsevents: %d by %d: %s%s%s\n", type, pid,
			items[0].path, count > 1 ? " -> " : "",
			count > 1 ? items[1].path : "");
#endif
}

static size_t
encode(uint8_t *out, int32_t type, int32_t pid, const struct item *items,
		size_t count, bool compact, uint64_t time)
{
	size_t used = 0;
	memcpy(out, &type, sizeof(type));
	memcpy(out + 4, &pid, sizeof(pid));
	used = 8;
	for (size_t i = 0; i < count; i++) {
		const struct item *item = &items[i];
		used += put_argument(out + used, FSE_ARG_STRING, item->path,
				(uint16_t)(strlen(item->path) + 1));
		if (!item->has_info) {
			continue;
		}
		if (compact) {
			uint8_t info[24] = {0};
			memcpy(info, &item->ino, 8);
			memcpy(info + 8, &item->dev, 4);
			memcpy(info + 12, &item->mode, 4);
			memcpy(info + 16, &item->uid, 4);
			used += put_argument(out + used, FSE_ARG_FINFO, info,
					sizeof(info));
		} else {
			uint32_t document_id = 0;
			used += put_argument(
					out + used, FSE_ARG_DEV, &item->dev, 4);
			used += put_argument(
					out + used, FSE_ARG_INO, &item->ino, 8);
			used += put_argument(out + used, FSE_ARG_MODE,
					&item->mode, 4);
			used += put_argument(
					out + used, FSE_ARG_UID, &item->uid, 4);
			used += put_argument(out + used, FSE_ARG_GID,
					&document_id, 4);
		}
	}
	used += put_argument(out + used, FSE_ARG_INT64, &time, sizeof(time));
	uint16_t done = FSE_ARG_DONE;
	memcpy(out + used, &done, sizeof(done));
	return used + sizeof(done);
}

static size_t
put_argument(uint8_t *out, uint16_t type, const void *data, uint16_t length)
{
	memcpy(out, &type, sizeof(type));
	memcpy(out + 2, &length, sizeof(length));
	memcpy(out + 4, data, length);
	return 4 + (size_t)length;
}

long
fsevents_read(int fd, void *buffer, size_t size)
{
	if (size < FSEVENTS_READ_MIN) {
		return _EINVAL;
	}
	uint8_t *out = buffer;
	size_t used = 0;
	pthread_mutex_lock(&lock);
	bool dropped = entries[fd].dropped;
	entries[fd].dropped = false;
	pthread_mutex_unlock(&lock);
	if (dropped) {
		int32_t record[2] = {FSE_EVENTS_DROPPED, 0};
		uint16_t done = FSE_ARG_DONE;
		memcpy(out, record, sizeof(record));
		memcpy(out + sizeof(record), &done, sizeof(done));
		used = sizeof(record) + sizeof(done);
	}
	for (;;) {
		int wait = used != 0 ? MSG_DONTWAIT : 0;
		ssize_t length = recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC | wait);
		if (length < 0) {
			if (used != 0) {
				break;
			}
			return err_map(errno);
		}
		if (length == 0 || (size_t)length > size - used) {
			break;
		}
		ssize_t received = recv(
				fd, out + used, (size_t)length, MSG_DONTWAIT);
		if (received <= 0) {
			break;
		}
		used += (size_t)received;
	}
	return (long)used;
}
