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
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "check.h"

int
main(void)
{
	int bytes;
	CHECK(ioctl(-1, FIONREAD, &bytes) == -1 && errno == EBADF);

	int pair[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
	CHECK(write(pair[0], "x", 1) == 1);
	fd_set readable;
	FD_ZERO(&readable);
	FD_SET(pair[1], &readable);
	struct timeval timeout = {1, 0};
	CHECK(select(pair[1] + 1, &readable, NULL, NULL, &timeout) == 1);
	CHECK(FD_ISSET(pair[1], &readable));
	char byte;
	CHECK(read(pair[1], &byte, 1) == 1 && byte == 'x');
	FD_ZERO(&readable);
	FD_SET(pair[1], &readable);
	timeout = (struct timeval){0, 1000};
	CHECK(select(pair[1] + 1, &readable, NULL, NULL, &timeout) == 0);

	int type = 0;
	socklen_t length = sizeof(type);
	CHECK(getsockopt(pair[0], SOL_SOCKET, SO_TYPE, &type, &length) == 0);
	CHECK(type == SOCK_STREAM && length == sizeof(type));
	int on = 1;
	CHECK(setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on))
			== 0);
	CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);

	char path[64];
	snprintf(path, sizeof(path), "/tmp/limbo-socket-%d", getpid());
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(s != -1);
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	strlcpy(address.sun_path, path, sizeof(address.sun_path));
	address.sun_len = SUN_LEN(&address);
	CHECK(bind(s, (struct sockaddr *)&address, SUN_LEN(&address)) == 0);
	CHECK(listen(s, 4) == 0);
	CHECK(access(path, F_OK) == 0);
	CHECK(bind(socket(AF_UNIX, SOCK_STREAM, 0), (struct sockaddr *)&address,
			      SUN_LEN(&address))
			== -1);
	CHECK(errno == EADDRINUSE);
	CHECK(close(s) == 0);
	CHECK(unlink(path) == 0);
	return 0;
}
