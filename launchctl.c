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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "broker.h"

#define REPLY_MAX (1 << 20)

int
main(int argc, char *argv[])
{
	const char *path = getenv(LIMBO_BROKER_SOCKET_ENV);
	if (path == NULL) {
		path = "/tmp/broker.sock";
	}
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s%s", path,
			LIMBO_LAUNCHD_CONTROL_SUFFIX);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror(addr.sun_path);
		return 1;
	}

	size_t length = sizeof(struct broker_frame);
	for (int i = 1; i < argc; i++) {
		length += strlen(argv[i]) + 1;
	}
	char *request = malloc(length);
	struct broker_frame header = {
			.type = BROKER_CONTROL,
			.length = (uint32_t)(length - sizeof(header)),
	};
	memcpy(request, &header, sizeof(header));
	char *words = request + sizeof(header);
	for (int i = 1; i < argc; i++) {
		size_t size = strlen(argv[i]) + 1;
		memcpy(words, argv[i], size);
		words += size;
	}
	if (send(fd, request, length, 0) != (ssize_t)length) {
		perror("send");
		return 1;
	}

	char *reply = malloc(REPLY_MAX);
	ssize_t n;
	uint32_t status;
	do {
		n = recv(fd, reply, REPLY_MAX, 0);
		if (n < (ssize_t)sizeof(header)) {
			fprintf(stderr, "limbo-launchctl: no reply\n");
			return 1;
		}
		memcpy(&header, reply, sizeof(header));
	} while ((header.type & ~BROKER_FRAME_OOL) != BROKER_CONTROL_REPLY);
	if (header.type != BROKER_CONTROL_REPLY
			|| n < (ssize_t)(sizeof(header) + sizeof(status))) {
		fprintf(stderr, "limbo-launchctl: a reply it can't read\n");
		return 1;
	}
	memcpy(&status, reply + sizeof(header), sizeof(status));
	size_t offset = sizeof(header) + sizeof(status);
	fwrite(reply + offset, 1, (size_t)n - offset, stdout);
	return (int)status;
}
