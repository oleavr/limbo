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
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <unistd.h>

#include "check.h"
static void check_icmp(void);
static void check_connection_info(void);
static void check_refused_error(void);
static void check_control_with_many_open(void);
static void check_pcblist(void);
static void check_statistics(void);
static void read_statistics(const char *name, void *stats, size_t size);
static uint8_t *read_list(const char *name, size_t *size);
static const uint8_t *find_socket(const uint8_t *list, size_t size,
		uint16_t local_port, uint16_t remote_port);
static const uint8_t *next_record(const uint8_t *record, uint32_t kind);
static uint16_t field16(const uint8_t *record, size_t offset);
static uint32_t field32(const uint8_t *record, size_t offset);
static uint16_t bound_port(int fd);

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
	check_connection_info();
	check_refused_error();
	check_control_with_many_open();
	check_pcblist();
	check_statistics();
	check_icmp();
	return 0;
}

struct so_cinforeq {
	uint32_t cid;
	uint32_t flags;
	uint32_t ifindex;
	int32_t error;
	uint64_t src;
	uint32_t src_len;
	uint64_t dst;
	uint32_t dst_len;
	uint32_t aux_type;
	uint64_t aux_data;
	uint32_t aux_len;
};
#define SIOCGCONNINFO _IOWR('s', 152, struct so_cinforeq)

static void
check_connection_info(void)
{
	int listener = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in address = {
			.sin_len = sizeof(address),
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t length = sizeof(address);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address))
			== 0);
	CHECK(listen(listener, 1) == 0);
	CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0);
	int client = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(connect(client, (struct sockaddr *)&address, sizeof(address))
			== 0);

	struct sockaddr_in source = {0}, destination = {0};
	struct so_cinforeq request = {
			.src = (uintptr_t)&source,
			.src_len = sizeof(source),
			.dst = (uintptr_t)&destination,
			.dst_len = sizeof(destination),
	};
	CHECK(ioctl(client, SIOCGCONNINFO, &request) == 0);
	CHECK(request.flags == 0x82);
	CHECK(request.ifindex != 0);
	CHECK(request.src_len == sizeof(source)
			&& source.sin_family == AF_INET);
	CHECK(source.sin_addr.s_addr == htonl(INADDR_LOOPBACK)
			&& source.sin_port != 0);
	CHECK(request.dst_len == sizeof(destination));
	CHECK(destination.sin_port == address.sin_port);
	CHECK(close(client) == 0 && close(listener) == 0);
}

static void
check_refused_error(void)
{
	int listener = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(listener != -1);
	struct sockaddr_in address = {
			.sin_len = sizeof(address),
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t length = sizeof(address);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address))
			== 0);
	CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0);
	CHECK(close(listener) == 0);

	int s = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(s != -1);
	CHECK(fcntl(s, F_SETFL, O_NONBLOCK) == 0);
	int result = connect(s, (struct sockaddr *)&address, sizeof(address));
	CHECK(result == -1 && (errno == EINPROGRESS || errno == ECONNREFUSED));
	if (errno == EINPROGRESS) {
		fd_set writable;
		FD_ZERO(&writable);
		FD_SET(s, &writable);
		struct timeval timeout = {5, 0};
		CHECK(select(s + 1, NULL, &writable, NULL, &timeout) == 1);
		int error = 0;
		length = sizeof(error);
		CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &length)
				== 0);
		CHECK(error == ECONNREFUSED);
		length = sizeof(error);
		CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &length)
				== 0);
		CHECK(error == 0);
	}
	CHECK(close(s) == 0);
}

static void
check_control_with_many_open(void)
{
	enum { OPEN = 1100 };
	static int fds[OPEN];
	for (int i = 0; i < OPEN; i++) {
		fds[i] = open("/dev/null", O_RDONLY);
		CHECK(fds[i] >= 0);
	}
	int control = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	CHECK(control >= 0);
	CHECK(close(control) == 0);
	for (int i = 0; i < OPEN; i++) {
		CHECK(close(fds[i]) == 0);
	}
}

static void
check_icmp(void)
{
	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (s == -1 && (errno == EACCES || errno == EPERM)) {
		printf("skipping ICMP: no ICMP sockets for this group\n");
		return;
	}
	CHECK(s != -1);
	struct sockaddr_in to = {
			.sin_len = sizeof(to),
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	uint8_t request[ICMP_MINLEN + 8] = {0};
	struct icmp *echo = (struct icmp *)request;
	echo->icmp_type = ICMP_ECHO;
	echo->icmp_id = htons(0x4c42);
	echo->icmp_seq = htons(7);
	memcpy(request + ICMP_MINLEN, "limbo!!!", 8);
	CHECK(sendto(s, request, sizeof(request), 0, (struct sockaddr *)&to,
			      sizeof(to))
			== (ssize_t)sizeof(request));

	uint8_t reply[256];
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);
	ssize_t n = recvfrom(s, reply, sizeof(reply), 0,
			(struct sockaddr *)&from, &from_len);
	const struct ip *header = (const struct ip *)reply;
	CHECK(n == (ssize_t)(sizeof(struct ip) + sizeof(request)));
	CHECK(header->ip_v == 4 && header->ip_hl == 5);
	CHECK(header->ip_p == IPPROTO_ICMP && header->ip_ttl > 0);
	CHECK(header->ip_src.s_addr == htonl(INADDR_LOOPBACK));
	CHECK(from.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
	const struct icmp *answer
			= (const struct icmp *)(reply + sizeof(*header));
	CHECK(answer->icmp_type == ICMP_ECHOREPLY);
	CHECK(answer->icmp_id == htons(0x4c42) && answer->icmp_seq == htons(7));
	CHECK(memcmp(reply + sizeof(*header) + ICMP_MINLEN, "limbo!!!", 8)
			== 0);
	CHECK(close(s) == 0);
}

enum {
	RECORD_LENGTH = 0,
	RECORD_KIND = 4,
	XSO_SOCKET = 0x001,
	XSO_RCVBUF = 0x002,
	XSO_SNDBUF = 0x004,
	XSO_STATS = 0x008,
	XSO_INPCB = 0x010,
	XSO_TCPCB = 0x020,
	INPCB_FPORT = 16,
	INPCB_LPORT = 18,
	INPCB_VFLAG = 44,
	INPCB_LADDR4 = 76,
	SOCKET_TYPE = 16,
	SOCKET_OPTIONS = 20,
	SOCKET_PROTOCOL = 36,
	SOCKET_FAMILY = 40,
	SOCKBUF_CC = 8,
	TCPCB_STATE = 36,
};

static void
check_pcblist(void)
{
	struct sockaddr_in loopback = {
			.sin_len = sizeof(loopback),
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int listener = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(listener != -1);
	CHECK(bind(listener, (struct sockaddr *)&loopback, sizeof(loopback))
			== 0);
	CHECK(listen(listener, 1) == 0);
	struct sockaddr_in listening = loopback;
	listening.sin_port = bound_port(listener);
	int client = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(client != -1);
	CHECK(connect(client, (struct sockaddr *)&listening, sizeof(listening))
			== 0);
	int accepted = accept(listener, NULL, NULL);
	CHECK(accepted != -1 && write(client, "hello", 5) == 5);
	char byte;
	CHECK(recv(accepted, &byte, 1, MSG_PEEK) == 1);
	int datagram = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(datagram != -1);
	CHECK(bind(datagram, (struct sockaddr *)&loopback, sizeof(loopback))
			== 0);

	size_t size;
	uint8_t *list = read_list("net.inet.tcp.pcblist_n", &size);
	struct xinpgen first, last;
	memcpy(&first, list, sizeof(first));
	memcpy(&last, list + size - sizeof(last), sizeof(last));
	CHECK(first.xig_len == sizeof(first) && last.xig_len == sizeof(last));
	CHECK(first.xig_count >= 3);

	const uint8_t *record = find_socket(list, size, listening.sin_port, 0);
	CHECK(record != NULL && record[INPCB_VFLAG] == INP_IPV4);
	CHECK(field32(record, INPCB_LADDR4) == loopback.sin_addr.s_addr);
	record = next_record(record, XSO_SOCKET);
	CHECK(field16(record, SOCKET_TYPE) == SOCK_STREAM);
	CHECK(field32(record, SOCKET_OPTIONS) & SO_ACCEPTCONN);
	CHECK(field32(record, SOCKET_PROTOCOL) == IPPROTO_TCP);
	CHECK(field32(record, SOCKET_FAMILY) == AF_INET);
	record = next_record(record, XSO_RCVBUF);
	record = next_record(record, XSO_SNDBUF);
	record = next_record(record, XSO_STATS);
	record = next_record(record, XSO_TCPCB);
	CHECK(field32(record, TCPCB_STATE) == TCPS_LISTEN);

	record = find_socket(
			list, size, listening.sin_port, bound_port(client));
	CHECK(record != NULL);
	record = next_record(record, XSO_SOCKET);
	CHECK((field32(record, SOCKET_OPTIONS) & SO_ACCEPTCONN) == 0);
	record = next_record(record, XSO_RCVBUF);
	CHECK(field32(record, SOCKBUF_CC) == 5);
	record = next_record(record, XSO_SNDBUF);
	record = next_record(record, XSO_STATS);
	record = next_record(record, XSO_TCPCB);
	CHECK(field32(record, TCPCB_STATE) == TCPS_ESTABLISHED);
	free(list);

	uint8_t small[2 * sizeof(struct xinpgen)];
	size = sizeof(struct xinpgen) - 1;
	CHECK(sysctlbyname("net.inet.tcp.pcblist_n", small, &size, NULL, 0)
			== -1);
	CHECK(errno == ENOMEM && size == 0);
	size = sizeof(small);
	CHECK(sysctlbyname("net.inet.tcp.pcblist_n", small, &size, NULL, 0)
			== -1);
	CHECK(errno == ENOMEM && size == sizeof(struct xinpgen));

	list = read_list("net.inet.udp.pcblist_n", &size);
	record = find_socket(list, size, bound_port(datagram), 0);
	CHECK(record != NULL);
	record = next_record(record, XSO_SOCKET);
	CHECK(field16(record, SOCKET_TYPE) == SOCK_DGRAM);
	CHECK(field32(record, SOCKET_PROTOCOL) == IPPROTO_UDP);
	record = next_record(record, XSO_RCVBUF);
	record = next_record(record, XSO_SNDBUF);
	record = next_record(record, XSO_STATS);
	record += (field32(record, RECORD_LENGTH) + 7) & ~7u;
	CHECK(record == list + size - sizeof(struct xinpgen)
			|| field32(record, RECORD_KIND) == XSO_INPCB);
	free(list);

	CHECK(close(accepted) == 0 && close(client) == 0);
	CHECK(close(datagram) == 0);
	CHECK(close(listener) == 0);
}

static void
check_statistics(void)
{
	struct sockaddr_in loopback = {
			.sin_len = sizeof(loopback),
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct tcpstat tcp_before, tcp;
	struct udpstat udp_before, udp;
	read_statistics("net.inet.tcp.stats", &tcp_before, sizeof(tcp_before));
	read_statistics("net.inet.udp.stats", &udp_before, sizeof(udp_before));

	int listener = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(listener != -1);
	CHECK(bind(listener, (struct sockaddr *)&loopback, sizeof(loopback))
			== 0);
	CHECK(listen(listener, 1) == 0);
	struct sockaddr_in listening = loopback;
	listening.sin_port = bound_port(listener);
	int client = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(client != -1);
	CHECK(connect(client, (struct sockaddr *)&listening, sizeof(listening))
			== 0);
	int accepted = accept(listener, NULL, NULL);
	CHECK(accepted != -1);
	int receiver = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(receiver != -1);
	CHECK(bind(receiver, (struct sockaddr *)&loopback, sizeof(loopback))
			== 0);
	struct sockaddr_in receiving = loopback;
	receiving.sin_port = bound_port(receiver);
	CHECK(sendto(receiver, "x", 1, 0, (struct sockaddr *)&receiving,
			      sizeof(receiving))
			== 1);
	char byte;
	CHECK(read(receiver, &byte, 1) == 1);

	read_statistics("net.inet.tcp.stats", &tcp, sizeof(tcp));
	read_statistics("net.inet.udp.stats", &udp, sizeof(udp));
	if (getuid() == 0) {
		CHECK(tcp.tcps_connattempt - tcp_before.tcps_connattempt >= 1);
		CHECK(tcp.tcps_accepts - tcp_before.tcps_accepts >= 1);
		CHECK(tcp.tcps_sndtotal - tcp_before.tcps_sndtotal >= 1);
		CHECK(tcp.tcps_rcvtotal - tcp_before.tcps_rcvtotal >= 1);
	} else {
		struct tcpstat none = {0};
		CHECK(memcmp(&tcp, &none, sizeof(tcp)) == 0);
	}
	CHECK(udp.udps_ipackets - udp_before.udps_ipackets >= 1);
	CHECK(udp.udps_opackets - udp_before.udps_opackets >= 1);

	CHECK(close(receiver) == 0 && close(accepted) == 0);
	CHECK(close(client) == 0 && close(listener) == 0);
}

static void
read_statistics(const char *name, void *stats, size_t size)
{
	size_t needed;
	CHECK(sysctlbyname(name, NULL, &needed, NULL, 0) == 0);
	CHECK(needed == size);
	needed = size;
	CHECK(sysctlbyname(name, stats, &needed, NULL, 0) == 0);
	CHECK(needed == size);
	uint64_t start;
	needed = sizeof(start);
	CHECK(sysctlbyname(name, &start, &needed, NULL, 0) == 0);
	CHECK(needed == sizeof(start));
}

static uint8_t *
read_list(const char *name, size_t *size)
{
	size_t estimate;
	CHECK(sysctlbyname(name, NULL, &estimate, NULL, 0) == 0);
	uint8_t *list = malloc(estimate);
	CHECK(list != NULL);
	*size = estimate;
	CHECK(sysctlbyname(name, list, size, NULL, 0) == 0);
	CHECK(*size <= estimate && *size >= 2 * sizeof(struct xinpgen));
	return list;
}

static const uint8_t *
find_socket(const uint8_t *list, size_t size, uint16_t local_port,
		uint16_t remote_port)
{
	const uint8_t *end = list + size - sizeof(struct xinpgen);
	const uint8_t *record = list + sizeof(struct xinpgen);
	while (record < end) {
		if (field32(record, RECORD_KIND) == XSO_INPCB
				&& field16(record, INPCB_LPORT) == local_port
				&& field16(record, INPCB_FPORT)
						== remote_port) {
			return record;
		}
		record += (field32(record, RECORD_LENGTH) + 7) & ~7u;
	}
	return NULL;
}

static const uint8_t *
next_record(const uint8_t *record, uint32_t kind)
{
	record += (field32(record, RECORD_LENGTH) + 7) & ~7u;
	CHECK(field32(record, RECORD_KIND) == kind);
	return record;
}

static uint16_t
field16(const uint8_t *record, size_t offset)
{
	uint16_t value;
	memcpy(&value, record + offset, sizeof(value));
	return value;
}

static uint32_t
field32(const uint8_t *record, size_t offset)
{
	uint32_t value;
	memcpy(&value, record + offset, sizeof(value));
	return value;
}

static uint16_t
bound_port(int fd)
{
	struct sockaddr_in address;
	socklen_t length = sizeof(address);
	CHECK(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
	return address.sin_port;
}
