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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsd/boot_state.h"
#include "bsd/kmsg.h"

#define MSGBUF_PATH  "/private/var/run/limbo-msgbuf"
#define MSGBUF_MAGIC 0x4655424d

struct msgbuf {
	struct boot_state_header header;
	uint64_t written;
	char text[KMSG_SIZE];
};

static struct msgbuf msgbuf;
static struct boot_state msgbuf_state
		= BOOT_STATE_INIT(MSGBUF_PATH, MSGBUF_MAGIC, &msgbuf);

void
kmsg_log(const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	kmsg_vlog(format, arguments);
	va_end(arguments);
}

void
kmsg_vlog(const char *format, va_list arguments)
{
	int saved = errno;
	char name[17] = "?";
	int comm = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
	if (comm != -1) {
		ssize_t got = read(comm, name, sizeof(name) - 1);
		name[got > 0 ? got : 0] = '\0';
		name[strcspn(name, "\n")] = '\0';
		if (name[0] == '\0') {
			strcpy(name, "?");
		}
		close(comm);
	}
	char line[1024];
	int prefix = snprintf(line, sizeof(line), "%s[%d]: ", name, getpid());
	vsnprintf(line + prefix, sizeof(line) - (size_t)prefix, format,
			arguments);
	size_t length = strlen(line);
	if (line[length - 1] != '\n') {
		if (length == sizeof(line) - 1) {
			length--;
		}
		line[length++] = '\n';
	}

	struct msgbuf *shared = boot_state_begin(&msgbuf_state);
	if (shared != NULL) {
		for (size_t i = 0; i < length; i++) {
			shared->text[(shared->written + i) % KMSG_SIZE]
					= line[i];
		}
		shared->written += length;
		boot_state_end(&msgbuf_state, true);
		boot_state_close(&msgbuf_state);
	}
	errno = saved;
}

int
kmsg_read(char *buffer, uint32_t size)
{
	char *text = malloc(KMSG_SIZE + 2);
	size_t length = 0;
	struct msgbuf *shared = boot_state_begin(&msgbuf_state);
	if (shared != NULL) {
		uint64_t first = shared->written > KMSG_SIZE
				? shared->written - KMSG_SIZE
				: 0;
		for (uint64_t at = first; at < shared->written; at++) {
			char c = shared->text[at % KMSG_SIZE];
			if (c != '\0') {
				text[length++] = c;
			}
		}
		boot_state_end(&msgbuf_state, false);
		boot_state_close(&msgbuf_state);
	}
	if (length == 0 || text[length - 1] != '\n') {
		text[length++] = '\n';
	}
	text[length++] = '\0';

	size_t start = length > size ? length - size : 0;
	memcpy(buffer, text + start, length - start);
	free(text);
	return (int)(length - start);
}
