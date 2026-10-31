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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "check.h"

#define ROUNDUP(a)                                                             \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1)))                  \
		 : sizeof(uint32_t))

struct request {
	struct rt_msghdr header;
	uint8_t addresses[512];
};

static void
addresses(const struct rt_msghdr *header, const struct sockaddr *out[RTAX_MAX])
{
	const uint8_t *cursor = (const uint8_t *)(header + 1);
	for (int i = 0; i < RTAX_MAX; i++) {
		out[i] = NULL;
		if (header->rtm_addrs & (1 << i)) {
			out[i] = (const struct sockaddr *)cursor;
			cursor += ROUNDUP(out[i]->sa_len);
		}
	}
}

static int
route_get(int s, const char *destination, int bits, int seq,
		struct request *reply)
{
	struct request request = {0};
	struct sockaddr_in *dst = (struct sockaddr_in *)request.addresses;
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;
	inet_pton(AF_INET, destination, &dst->sin_addr);
	size_t length = sizeof(request.header) + sizeof(*dst);
	request.header.rtm_addrs = RTA_DST | RTA_IFP;
	if (bits >= 0) {
		struct sockaddr_in *mask
				= (struct sockaddr_in *)(request.addresses
						+ sizeof(*dst));
		mask->sin_len = sizeof(*mask);
		mask->sin_family = AF_INET;
		mask->sin_addr.s_addr
				= bits == 0 ? 0 : htonl(~0u << (32 - bits));
		request.header.rtm_addrs |= RTA_NETMASK;
		length += sizeof(*mask);
	}
	struct sockaddr_dl *ifp
			= (struct sockaddr_dl *)((uint8_t *)&request + length);
	ifp->sdl_len = sizeof(*ifp);
	ifp->sdl_family = AF_LINK;
	length += sizeof(*ifp);
	request.header.rtm_msglen = (u_short)length;
	request.header.rtm_version = RTM_VERSION;
	request.header.rtm_type = RTM_GET;
	request.header.rtm_seq = seq;
	ssize_t written = write(s, &request, length);
	int error = written == -1 ? errno : 0;
	if (written != -1) {
		CHECK(written == (ssize_t)length);
	}
	for (;;) {
		ssize_t received = read(s, reply, sizeof(*reply));
		CHECK(received >= (ssize_t)sizeof(reply->header));
		CHECK(reply->header.rtm_msglen == received);
		if (reply->header.rtm_type == RTM_GET
				&& reply->header.rtm_seq == seq
				&& reply->header.rtm_pid == getpid()) {
			break;
		}
	}
	CHECK(reply->header.rtm_version == RTM_VERSION);
	CHECK(reply->header.rtm_errno == error);
	return error;
}

int
main(void)
{
	int s = socket(PF_ROUTE, SOCK_RAW, 0);
	CHECK(s != -1);
	struct request reply;
	CHECK(route_get(s, "127.0.0.1", -1, 1, &reply) == 0);
	CHECK(reply.header.rtm_flags & RTF_UP);
	CHECK(reply.header.rtm_flags & RTF_DONE);
	CHECK(reply.header.rtm_index != 0);
	const struct sockaddr *found[RTAX_MAX];
	addresses(&reply.header, found);
	CHECK(found[RTAX_DST] != NULL && found[RTAX_DST]->sa_family == AF_INET);
	CHECK(found[RTAX_GATEWAY] != NULL);
	CHECK(found[RTAX_IFP] != NULL && found[RTAX_IFP]->sa_family == AF_LINK);
	const struct sockaddr_dl *ifp
			= (const struct sockaddr_dl *)found[RTAX_IFP];
	CHECK(ifp->sdl_index == reply.header.rtm_index);
	char name[IF_NAMESIZE];
	CHECK(if_indextoname(ifp->sdl_index, name) != NULL);
	CHECK(ifp->sdl_nlen == strlen(name)
			&& memcmp(ifp->sdl_data, name, ifp->sdl_nlen) == 0);
	CHECK(found[RTAX_IFA] != NULL && found[RTAX_IFA]->sa_family == AF_INET);

	int error = route_get(s, "0.0.0.0", 0, 2, &reply);
	CHECK(error == 0 || error == ESRCH);
	if (error == 0) {
		addresses(&reply.header, found);
		CHECK(reply.header.rtm_flags & RTF_GATEWAY);
		CHECK(found[RTAX_GATEWAY] != NULL
				&& found[RTAX_GATEWAY]->sa_family == AF_INET);
	}

	if (route_get(s, "203.0.113.0", 30, 3, &reply) == 0) {
		addresses(&reply.header, found);
		CHECK(reply.header.rtm_flags & RTF_GATEWAY);
	}
	CHECK(route_get(s, "127.0.0.1", 8, 4, &reply) == 0);
	addresses(&reply.header, found);
	CHECK(found[RTAX_NETMASK] != NULL);

	if (geteuid() != 0) {
		struct request add = {0};
		struct sockaddr_in *dst = (struct sockaddr_in *)add.addresses;
		dst->sin_len = sizeof(*dst);
		dst->sin_family = AF_INET;
		inet_pton(AF_INET, "203.0.113.1", &dst->sin_addr);
		add.header.rtm_msglen = sizeof(add.header) + 2 * sizeof(*dst);
		memcpy(dst + 1, dst, sizeof(*dst));
		add.header.rtm_version = RTM_VERSION;
		add.header.rtm_type = RTM_ADD;
		add.header.rtm_flags = RTF_UP | RTF_HOST | RTF_STATIC;
		add.header.rtm_addrs = RTA_DST | RTA_GATEWAY;
		CHECK(write(s, &add, add.header.rtm_msglen) == -1
				&& errno == EPERM);
	}
	struct request old = {0};
	old.header.rtm_msglen = sizeof(old.header);
	old.header.rtm_version = 4;
	old.header.rtm_type = RTM_GET;
	CHECK(write(s, &old, sizeof(old.header)) == -1
			&& errno == EPROTONOSUPPORT);
	CHECK(close(s) == 0);

	int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
	size_t size = 0;
	CHECK(sysctl(mib, 6, NULL, &size, NULL, 0) == 0 && size > 0);
	size += 4096;
	uint8_t *table = malloc(size);
	CHECK(sysctl(mib, 6, table, &size, NULL, 0) == 0);
	bool loopback = false;
	for (size_t offset = 0; offset < size;) {
		const struct rt_msghdr *header
				= (const struct rt_msghdr *)(table + offset);
		CHECK(header->rtm_version == RTM_VERSION);
		CHECK(header->rtm_type == RTM_GET);
		CHECK(header->rtm_msglen >= sizeof(*header)
				&& offset + header->rtm_msglen <= size);
		addresses(header, found);
		CHECK(found[RTAX_DST] != NULL
				&& found[RTAX_DST]->sa_family == AF_INET);
		const struct sockaddr_in *dst
				= (const struct sockaddr_in *)found[RTAX_DST];
		if ((ntohl(dst->sin_addr.s_addr) >> 24) == 127) {
			loopback = true;
		}
		offset += header->rtm_msglen;
	}
	CHECK(loopback);
	free(table);

	int e = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
	CHECK(e != -1);
	struct kev_request back = {0};
	CHECK(ioctl(e, SIOCGKEVFILT, &back) == 0);
	CHECK(back.vendor_code == 0xffffffff);
	struct kev_request filter = {
			.vendor_code = KEV_VENDOR_APPLE,
			.kev_class = KEV_NETWORK_CLASS,
			.kev_subclass = KEV_ANY_SUBCLASS,
	};
	CHECK(ioctl(e, SIOCSKEVFILT, &filter) == 0);
	CHECK(ioctl(e, SIOCGKEVFILT, &back) == 0);
	CHECK(memcmp(&back, &filter, sizeof(back)) == 0);
	uint32_t id;
	CHECK(ioctl(e, SIOCGKEVID, &id) == 0);
	struct kev_vendor_code vendor = {0};
	strlcpy(vendor.vendor_string, "com.apple",
			sizeof(vendor.vendor_string));
	CHECK(ioctl(e, SIOCGKEVVENDOR, &vendor) == -1 && errno == ENOENT);
	CHECK(fcntl(e, F_SETFL, O_NONBLOCK) == 0);
	uint8_t buffer[1024];
	CHECK(read(e, buffer, sizeof(buffer)) == -1 && errno == EAGAIN);
	CHECK(close(e) == 0);

	printf("route: ok\n");
	return 0;
}
