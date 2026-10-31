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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "icmp.h"
#include "xnu-errno.h"

#define ICMP_ECHO     8
#define HEADER_LENGTH 20
#define SOCKETS_MAX   1024

struct icmp_socket {
	bool open;
	bool sent;
	uint8_t id[2];
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct icmp_socket sockets[SOCKETS_MAX];

static uint16_t checksum(const uint8_t *data, size_t length);

int
icmp_socket(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (fd == -1) {
		return err_map(errno);
	}
	if (fd >= SOCKETS_MAX) {
		close(fd);
		return _EMFILE;
	}
	int on = 1;
	setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
	setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	pthread_mutex_lock(&lock);
	sockets[fd] = (struct icmp_socket){.open = true};
	pthread_mutex_unlock(&lock);
	return fd;
}

bool
icmp_is_socket(int fd)
{
	return fd >= 0 && fd < SOCKETS_MAX && sockets[fd].open;
}

void
icmp_close(int fd)
{
	if (icmp_is_socket(fd)) {
		pthread_mutex_lock(&lock);
		sockets[fd] = (struct icmp_socket){0};
		pthread_mutex_unlock(&lock);
	}
}

void
icmp_sending(int fd, const struct iovec *iov, size_t count)
{
	uint8_t start[8];
	size_t have = 0;
	for (size_t i = 0; i != count && have < sizeof(start); i++) {
		size_t take = iov[i].iov_len < sizeof(start) - have
				? iov[i].iov_len
				: sizeof(start) - have;
		memcpy(start + have, iov[i].iov_base, take);
		have += take;
	}
	if (have < sizeof(start) || start[0] != ICMP_ECHO) {
		return;
	}
	pthread_mutex_lock(&lock);
	sockets[fd].sent = true;
	memcpy(sockets[fd].id, start + 4, 2);
	pthread_mutex_unlock(&lock);
}

ssize_t
icmp_receive(int fd, const struct iovec *iov, size_t count, int flags,
		struct sockaddr_in *from, bool *truncated)
{
	static __thread uint8_t packet[HEADER_LENGTH + 65536];
	uint8_t *message = packet + HEADER_LENGTH;
	uint8_t control[CMSG_SPACE(sizeof(int))
			+ CMSG_SPACE(sizeof(struct in_pktinfo))]
			__attribute__((aligned(8)));
	struct sockaddr_in source = {0};
	struct iovec in = {message, sizeof(packet) - HEADER_LENGTH};
	struct msghdr msg = {
			.msg_name = &source,
			.msg_namelen = sizeof(source),
			.msg_iov = &in,
			.msg_iovlen = 1,
			.msg_control = control,
			.msg_controllen = sizeof(control),
	};
	ssize_t length = recvmsg(fd, &msg, flags);
	if (length < 0) {
		return -1;
	}
	int ttl = 64;
	struct in_addr destination = {0};
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP
				&& cmsg->cmsg_type == IP_TTL) {
			memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
		} else if (cmsg->cmsg_level == IPPROTO_IP
				&& cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo info;
			memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
			destination = info.ipi_addr;
		}
	}

	pthread_mutex_lock(&lock);
	struct icmp_socket state = sockets[fd];
	pthread_mutex_unlock(&lock);
	if (state.sent && length >= 8) {
		memcpy(message + 4, state.id, 2);
		message[2] = message[3] = 0;
		uint16_t sum = checksum(message, (size_t)length);
		memcpy(message + 2, &sum, 2);
	}

	size_t total = HEADER_LENGTH + (size_t)length;
	struct ip header = {
			.ip_hl = HEADER_LENGTH / 4,
			.ip_v = 4,
			.ip_len = htons((uint16_t)total),
			.ip_ttl = (uint8_t)ttl,
			.ip_p = IPPROTO_ICMP,
			.ip_src = source.sin_addr,
			.ip_dst = destination,
	};
	header.ip_sum = checksum((const uint8_t *)&header, sizeof(header));
	memcpy(packet, &header, sizeof(header));

	size_t copied = 0;
	for (size_t i = 0; i != count && copied < total; i++) {
		size_t take = iov[i].iov_len < total - copied ? iov[i].iov_len
							      : total - copied;
		memcpy(iov[i].iov_base, packet + copied, take);
		copied += take;
	}
	*truncated = copied < total;
	if (from != NULL) {
		*from = source;
	}
	return (ssize_t)copied;
}

static uint16_t
checksum(const uint8_t *data, size_t length)
{
	uint32_t sum = 0;
	for (size_t i = 0; i + 1 < length; i += 2) {
		sum += (uint32_t)(data[i] | data[i + 1] << 8);
	}
	if (length & 1) {
		sum += data[length - 1];
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (uint16_t)~sum;
}
