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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"

typedef struct {
	int8_t *event_list;
	int32_t num_events;
	int32_t event_queue_depth;
	int32_t *fd;
} fsevent_clone_args;

#define FSEVENTS_CLONE               _IOW('s', 1, fsevent_clone_args)
#define FSEVENTS_WANT_COMPACT_EVENTS _IO('s', 101)
#define FSE_CREATE_FILE              0
#define FSE_MAX_EVENTS               16
#define FSE_ARG_STRING               0x0002
#define FSE_ARG_DONE                 0xb33f

static bool
created(const uint8_t *buffer, ssize_t length, const char *path)
{
	for (ssize_t offset = 0; offset + 8 <= length;) {
		int32_t type;
		memcpy(&type, buffer + offset, sizeof(type));
		offset += 8;
		bool match = false;
		for (;;) {
			uint16_t argument, size;
			memcpy(&argument, buffer + offset, sizeof(argument));
			offset += 2;
			if (argument == FSE_ARG_DONE) {
				break;
			}
			memcpy(&size, buffer + offset, sizeof(size));
			offset += 2;
			if (argument == FSE_ARG_STRING
					&& strcmp((const char *)buffer + offset,
							   path)
							== 0) {
				match = true;
			}
			offset += size;
		}
		if (match && (type & 0xfff) == FSE_CREATE_FILE) {
			return true;
		}
	}
	return false;
}

int
main(void)
{
	int device = open("/dev/fsevents", O_RDONLY);
	if (geteuid() != 0) {
		CHECK(device == -1 && errno == EPERM);
		printf("fsevents: ok (not root)\n");
		return 0;
	}
	CHECK(device != -1);
	int8_t events[FSE_MAX_EVENTS];
	memset(events, 1, sizeof(events));
	int32_t watcher = -1;
	fsevent_clone_args clone = {events, FSE_MAX_EVENTS, 64, &watcher};
	CHECK(ioctl(device, FSEVENTS_CLONE, &clone) == 0 && watcher >= 0);
	CHECK(ioctl(watcher, FSEVENTS_WANT_COMPACT_EVENTS) == 0);

	char path[] = "/private/tmp/limbo-fsevents-XXXXXX";
	int fd = mkstemp(path);
	CHECK(fd != -1);
	CHECK(close(fd) == 0);

	uint8_t buffer[16384];
	CHECK(read(watcher, buffer, 64) == -1 && errno == EINVAL);
	bool found = false;
	CHECK(fcntl(watcher, F_SETFL, O_NONBLOCK) == 0);
	for (int attempt = 0; attempt < 50 && !found; attempt++) {
		ssize_t length = read(watcher, buffer, sizeof(buffer));
		if (length > 0) {
			found = created(buffer, length, path);
		} else {
			usleep(100000);
		}
	}
	CHECK(found);
	CHECK(unlink(path) == 0);
	printf("fsevents: ok\n");
	return 0;
}
