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
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "kctl.h"
#include "xnu-errno.h"

#define xnu_CTLIOCGINFO 0xc0644e03
#define xnu_SOCK_STREAM 1
#define xnu_SOCK_DGRAM  2
#define xnu_AF_SYSTEM   32

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static bool sockets[1024];

int
kctl_socket(int type)
{
	if (type != xnu_SOCK_DGRAM && type != xnu_SOCK_STREAM) {
		return _EPROTOTYPE;
	}
	int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd == -1) {
		return err_map(errno);
	}
	if ((size_t)fd >= sizeof(sockets) / sizeof(*sockets)) {
		close(fd);
		return _EMFILE;
	}
	pthread_mutex_lock(&lock);
	sockets[fd] = true;
	pthread_mutex_unlock(&lock);
	return fd;
}

bool
kctl_is_socket(int fd)
{
	return fd >= 0 && (size_t)fd < sizeof(sockets) / sizeof(*sockets)
			&& sockets[fd];
}

int
kctl_ioctl(int fd, uint64_t command, void *data)
{
	if (!kctl_is_socket(fd) || command != xnu_CTLIOCGINFO) {
		return 1;
	}
	return _ENOENT;
}

int
kctl_connect(int fd, const void *name, uint32_t length)
{
	if (length < 2 || ((const uint8_t *)name)[1] != xnu_AF_SYSTEM) {
		return _EAFNOSUPPORT;
	}
	return _ENOENT;
}

void
kctl_close(int fd)
{
	if (!kctl_is_socket(fd)) {
		return;
	}
	pthread_mutex_lock(&lock);
	sockets[fd] = false;
	pthread_mutex_unlock(&lock);
}
