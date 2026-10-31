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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "net.h"
#include "route.h"
#include "xnu-errno.h"

#define xnu_AF_INET  2
#define xnu_AF_LINK  18
#define xnu_AF_INET6 30

#define RTM_VERSION        5
#define xnu_RTM_ADD        0x1
#define xnu_RTM_DELETE     0x2
#define xnu_RTM_CHANGE     0x3
#define xnu_RTM_GET        0x4
#define xnu_RTM_LOCK       0x8
#define xnu_RTM_NEWADDR    0xc
#define xnu_RTM_DELADDR    0xd
#define xnu_RTM_IFINFO     0xe
#define xnu_RTM_GET_SILENT 0x11
#define xnu_RTM_GET2       0x14

#define xnu_RTF_UP        0x1
#define xnu_RTF_GATEWAY   0x2
#define xnu_RTF_HOST      0x4
#define xnu_RTF_DONE      0x40
#define xnu_RTF_CLONING   0x100
#define xnu_RTF_STATIC    0x800
#define xnu_RTF_PRCLONING 0x10000
#define xnu_RTF_LOCAL     0x200000
#define xnu_RTF_IFSCOPE   0x1000000

#define xnu_RTA_DST     0x1
#define xnu_RTA_GATEWAY 0x2
#define xnu_RTA_NETMASK 0x4
#define xnu_RTA_IFP     0x10
#define xnu_RTA_IFA     0x20
#define xnu_RTA_BRD     0x80
#define xnu_RTAX_MAX    8

#define xnu_NET_RT_DUMP       1
#define xnu_NET_RT_FLAGS      2
#define xnu_NET_RT_DUMP2      7
#define xnu_NET_RT_FLAGS_PRIV 10

#define IFT_OTHER 0x1
#define IFT_ETHER 0x6
#define IFT_LOOP  0x18

#define KEV_ANY_VENDOR     0
#define KEV_ANY_CLASS      0
#define KEV_ANY_SUBCLASS   0
#define KEV_VENDOR_APPLE   1
#define KEV_NETWORK_CLASS  1
#define KEV_INET_SUBCLASS  1
#define KEV_DL_SUBCLASS    2
#define KEV_INET6_SUBCLASS 6

#define KEV_INET_NEW_ADDR        1
#define KEV_INET_CHANGED_ADDR    2
#define KEV_INET_ADDR_DELETED    3
#define KEV_DL_SIFFLAGS          1
#define KEV_DL_SIFMTU            3
#define KEV_DL_IF_ATTACHED       9
#define KEV_DL_IF_DETACHING      10
#define KEV_DL_IF_DETACHED       11
#define KEV_DL_LINK_OFF          12
#define KEV_DL_LINK_ON           13
#define KEV_INET6_NEW_USER_ADDR  1
#define KEV_INET6_CHANGED_ADDR   2
#define KEV_INET6_ADDR_DELETED   3
#define KEV_INET6_NEW_LL_ADDR    4
#define KEV_INET6_NEW_RTADV_ADDR 5

#define APPLE_IF_FAM_LOOPBACK 1
#define APPLE_IF_FAM_ETHERNET 2

#define IN6_IFF_TENTATIVE  0x0002
#define IN6_IFF_DUPLICATED 0x0004
#define IN6_IFF_DEPRECATED 0x0010
#define IN6_IFF_NODAD      0x0020
#define IN6_IFF_AUTOCONF   0x0040
#define IN6_IFF_TEMPORARY  0x0080
#define IN6_IFF_OPTIMISTIC 0x0200

#define xnu_SIOCGKEVID     0x40046501
#define xnu_SIOCSKEVFILT   0x800c6502
#define xnu_SIOCGKEVFILT   0x400c6503
#define xnu_SIOCGKEVVENDOR 0xc0cc6504

struct xnu_rt_metrics {
	uint32_t rmx_locks;
	uint32_t rmx_mtu;
	uint32_t rmx_hopcount;
	int32_t rmx_expire;
	uint32_t rmx_recvpipe;
	uint32_t rmx_sendpipe;
	uint32_t rmx_ssthresh;
	uint32_t rmx_rtt;
	uint32_t rmx_rttvar;
	uint32_t rmx_pksent;
	uint32_t rmx_state;
	uint32_t rmx_filler[3];
};

struct xnu_rt_msghdr {
	uint16_t rtm_msglen;
	uint8_t rtm_version;
	uint8_t rtm_type;
	uint16_t rtm_index;
	int32_t rtm_flags;
	int32_t rtm_addrs;
	int32_t rtm_pid;
	int32_t rtm_seq;
	int32_t rtm_errno;
	int32_t rtm_use;
	uint32_t rtm_inits;
	struct xnu_rt_metrics rtm_rmx;
};

struct xnu_ifa_msghdr {
	uint16_t ifam_msglen;
	uint8_t ifam_version;
	uint8_t ifam_type;
	int32_t ifam_addrs;
	int32_t ifam_flags;
	uint16_t ifam_index;
	int32_t ifam_metric;
};

struct kern_event_msg {
	uint32_t total_size;
	uint32_t vendor_code;
	uint32_t kev_class;
	uint32_t kev_subclass;
	uint32_t id;
	uint32_t event_code;
};

struct kev_request {
	uint32_t vendor_code;
	uint32_t kev_class;
	uint32_t kev_subclass;
};

struct net_event_data {
	uint32_t if_family;
	uint32_t if_unit;
	char if_name[IFNAMSIZ];
};

struct kev_in_data {
	struct net_event_data link_data;
	uint32_t ia_addr;
	uint32_t ia_net;
	uint32_t ia_netmask;
	uint32_t ia_subnet;
	uint32_t ia_subnetmask;
	uint32_t ia_netbroadcast;
	uint32_t ia_dstaddr;
};

struct xnu_sockaddr_in6 {
	uint8_t sin6_len;
	uint8_t sin6_family;
	uint16_t sin6_port;
	uint32_t sin6_flowinfo;
	uint8_t sin6_addr[16];
	uint32_t sin6_scope_id;
};

struct kev_in6_data {
	struct net_event_data link_data;
	struct xnu_sockaddr_in6 ia_addr;
	struct xnu_sockaddr_in6 ia_net;
	struct xnu_sockaddr_in6 ia_dstaddr;
	struct xnu_sockaddr_in6 ia_prefixmask;
	uint32_t ia_plen;
	uint32_t ia6_flags;
	struct {
		uint32_t ia6t_expire;
		uint32_t ia6t_preferred;
		uint32_t ia6t_vltime;
		uint32_t ia6t_pltime;
	} ia_lifetime;
	uint8_t ia_mac[6];
};

_Static_assert(sizeof(struct xnu_rt_metrics) == 56, "rt_metrics");
_Static_assert(sizeof(struct xnu_rt_msghdr) == 92, "rt_msghdr");
_Static_assert(sizeof(struct xnu_ifa_msghdr) == 20, "ifa_msghdr");
_Static_assert(sizeof(struct kern_event_msg) == 24, "kern_event_msg");
_Static_assert(sizeof(struct kev_in_data) == 52, "kev_in_data");
_Static_assert(sizeof(struct kev_in6_data) == 168, "kev_in6_data");

static struct route_socket {
	bool open;
	bool events;
	int peer;
	int family;
	struct kev_request filter;
} sockets[1024];

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t last_event_id;
static bool watching;
static void (*watchers[4])(void);
static size_t watcher_count;

struct output {
	uint8_t *bytes;
	size_t length;
	size_t capacity;
};

struct host_route {
	int family;
	uint8_t type;
	uint8_t length;
	bool local;
	uint8_t destination[16];
	uint8_t gateway[16];
	bool has_gateway;
	uint8_t source[16];
	bool has_source;
	uint32_t interface;
	uint32_t priority;
};

struct route_list {
	struct host_route *routes;
	size_t count;
	size_t capacity;
};

static struct link {
	bool present;
	bool seen;
	unsigned int index;
	unsigned int flags;
	unsigned int mtu;
	unsigned int type;
	char name[IFNAMSIZ];
} links[64];

static struct address {
	bool present;
	bool seen;
	unsigned int index;
	int family;
	uint8_t address[16];
	uint8_t prefix;
	uint8_t peer[16];
	bool has_peer;
	uint32_t flags;
	uint32_t valid;
	uint32_t preferred;
} addresses[256];

static void start_watching(void);
static void *watch_main(void *argument);
static void synchronize(bool initial);
static bool netlink_dump(int type, int family,
		void (*each)(const struct nlmsghdr *, void *), void *context);
static void handle_initial(const struct nlmsghdr *header, void *context);
static void handle_link(const struct nlmsghdr *header, bool initial);
static struct link *find_link(unsigned int index);
static void link_event_data(
		const struct link *link, struct net_event_data *data);
static void post_event(uint32_t subclass, uint32_t code, const void *data,
		size_t size);
static void deliver(const struct route_socket *socket, const void *message,
		size_t size);
static void post_interface_info(unsigned int index, unsigned int flags);
static void post_route_message(int family, const void *message, size_t size);
static void handle_address(const struct nlmsghdr *header, bool initial);
static size_t address_size(int family);
static void post_address_event(const struct address *address, uint32_t code);
static unsigned int read_interface_number(
		const char *name, const char *attribute);
static void prefix_mask(int family, unsigned int length, uint8_t *mask);
static void append_address(struct output *out, int family,
		const uint8_t *address, unsigned int index);
static void *grow(struct output *out, size_t size);
static uint32_t in6_flags(uint32_t flags);
static size_t read_link_address(const char *name, uint8_t *address);
static void post_address_message(const struct address *address, uint8_t type);
static void append_link(struct output *out, unsigned int index, bool named);
static uint8_t interface_type(const char *name);
static void notify_watchers(void);
static void handle_route(const struct nlmsghdr *header);
static bool parse_route(const struct nlmsghdr *header, struct host_route *out);
static void append_route(struct output *out, uint8_t type,
		const struct host_route *route, bool interface);
static int route_flags(const struct host_route *route);
static bool interface_address(unsigned int index, int family, uint8_t *out);
static int host_family(int xnu_family);
static struct route_list load_routes(int family);
static void collect_route(const struct nlmsghdr *header, void *context);
static void parse_addresses(const uint8_t *cursor, const uint8_t *end,
		int addrs, const uint8_t *found[xnu_RTAX_MAX]);
static int sockaddr_address(const uint8_t *sockaddr, uint8_t *address);
static unsigned int mask_length(const uint8_t *sockaddr, int family);
static bool find_route(int family, const uint8_t *destination, int length,
		unsigned int interface, struct host_route *out);
static bool prefix_matches(
		const uint8_t *a, const uint8_t *b, unsigned int bits);
static void route_fork_prepare(void);
static void route_fork_parent(void);
static void route_fork_child(void);

int
route_socket(bool events, int protocol)
{
	int pair[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == -1) {
		return err_map(errno);
	}
	if ((size_t)pair[0] >= sizeof(sockets) / sizeof(*sockets)) {
		close(pair[0]);
		close(pair[1]);
		return _EMFILE;
	}
	fcntl(pair[0], F_SETFD, 0);
	int size = 64 * 1024;
	setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	pthread_mutex_lock(&lock);
	sockets[pair[0]] = (struct route_socket){
			.open = true,
			.events = events,
			.peer = pair[1],
			.family = events ? 0 : protocol,
			.filter = {.vendor_code = 0xffffffff},
	};
	start_watching();
	pthread_mutex_unlock(&lock);
	return pair[0];
}

static void
start_watching(void)
{
	if (watching) {
		return;
	}
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd == -1) {
		return;
	}
	struct sockaddr_nl address = {
			.nl_family = AF_NETLINK,
			.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR
					| RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE
					| RTMGRP_IPV6_ROUTE,
	};
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		close(fd);
		return;
	}
	watching = true;
	sigset_t all, previous;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &previous);
	pthread_t handle;
	pthread_create(&handle, NULL, watch_main, (void *)(intptr_t)fd);
	pthread_detach(handle);
	pthread_sigmask(SIG_SETMASK, &previous, NULL);
}

static void *
watch_main(void *argument)
{
	int fd = (int)(intptr_t)argument;
	synchronize(true);
	static uint8_t buffer[64 * 1024] __attribute__((aligned(4)));
	for (;;) {
		ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
		if (received < 0) {
			if (errno == ENOBUFS) {
				synchronize(false);
				notify_watchers();
			} else if (errno != EINTR) {
				return NULL;
			}
			continue;
		}
		size_t remaining = (size_t)received;
		for (const struct nlmsghdr *header = (struct nlmsghdr *)buffer;
				NLMSG_OK(header, remaining);
				header = NLMSG_NEXT(header, remaining)) {
			switch (header->nlmsg_type) {
			case RTM_NEWLINK:
			case RTM_DELLINK:
				handle_link(header, false);
				break;
			case RTM_NEWADDR:
			case RTM_DELADDR:
				handle_address(header, false);
				break;
			case RTM_NEWROUTE:
			case RTM_DELROUTE:
				handle_route(header);
				break;
			}
		}
		notify_watchers();
	}
	return NULL;
}

static void
synchronize(bool initial)
{
	for (size_t i = 0; i < sizeof(links) / sizeof(*links); i++) {
		links[i].seen = false;
	}
	for (size_t i = 0; i < sizeof(addresses) / sizeof(*addresses); i++) {
		addresses[i].seen = false;
	}
	netlink_dump(RTM_GETLINK, AF_UNSPEC, handle_initial, &initial);
	netlink_dump(RTM_GETADDR, AF_UNSPEC, handle_initial, &initial);
	if (initial) {
		return;
	}
	for (size_t i = 0; i < sizeof(addresses) / sizeof(*addresses); i++) {
		struct address *address = &addresses[i];
		if (address->present && !address->seen) {
			address->present = false;
			post_address_event(address,
					address->family == AF_INET
							? KEV_INET_ADDR_DELETED
							: KEV_INET6_ADDR_DELETED);
			post_address_message(address, xnu_RTM_DELADDR);
		}
	}
	for (size_t i = 0; i < sizeof(links) / sizeof(*links); i++) {
		struct link *link = &links[i];
		if (link->present && !link->seen) {
			struct net_event_data data;
			link_event_data(link, &data);
			post_event(KEV_DL_SUBCLASS, KEV_DL_IF_DETACHED, &data,
					sizeof(data));
			post_interface_info(link->index, 0);
			link->present = false;
		}
	}
}

static bool
netlink_dump(int type, int family,
		void (*each)(const struct nlmsghdr *, void *), void *context)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd == -1) {
		return false;
	}
	struct {
		struct nlmsghdr header;
		struct rtgenmsg message;
	} request = {
		.header = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)),
			.nlmsg_type = (uint16_t)type,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
			.nlmsg_seq = 1,
		},
		.message = {.rtgen_family = (unsigned char)family},
	};
	if (send(fd, &request, request.header.nlmsg_len, 0) == -1) {
		close(fd);
		return false;
	}
	size_t capacity = 32 * 1024;
	uint8_t *buffer = malloc(capacity);
	bool done = false;
	bool ok = true;
	while (!done) {
		ssize_t received = recv(fd, buffer, capacity, 0);
		if (received <= 0) {
			ok = false;
			break;
		}
		size_t remaining = (size_t)received;
		for (const struct nlmsghdr *header = (struct nlmsghdr *)buffer;
				NLMSG_OK(header, remaining);
				header = NLMSG_NEXT(header, remaining)) {
			if (header->nlmsg_type == NLMSG_DONE) {
				done = true;
				break;
			}
			if (header->nlmsg_type == NLMSG_ERROR) {
				done = true;
				ok = false;
				break;
			}
			each(header, context);
		}
	}
	free(buffer);
	close(fd);
	return ok;
}

static void
handle_initial(const struct nlmsghdr *header, void *context)
{
	bool initial = *(bool *)context;
	if (header->nlmsg_type == RTM_NEWLINK) {
		handle_link(header, initial);
	} else if (header->nlmsg_type == RTM_NEWADDR) {
		handle_address(header, initial);
	}
}

static void
handle_link(const struct nlmsghdr *header, bool initial)
{
	const struct ifinfomsg *message = NLMSG_DATA(header);
	unsigned int index = (unsigned int)message->ifi_index;
	struct link *link = find_link(index);
	if (header->nlmsg_type == RTM_DELLINK) {
		if (link == NULL) {
			return;
		}
		struct net_event_data data;
		link_event_data(link, &data);
		post_event(KEV_DL_SUBCLASS, KEV_DL_IF_DETACHING, &data,
				sizeof(data));
		post_event(KEV_DL_SUBCLASS, KEV_DL_IF_DETACHED, &data,
				sizeof(data));
		post_interface_info(index, 0);
		link->present = false;
		return;
	}
	unsigned int mtu = 0;
	char name[IFNAMSIZ] = "";
	size_t remaining = IFLA_PAYLOAD(header);
	for (const struct rtattr *a = IFLA_RTA(message); RTA_OK(a, remaining);
			a = RTA_NEXT(a, remaining)) {
		if (a->rta_type == IFLA_MTU
				&& RTA_PAYLOAD(a) >= sizeof(uint32_t)) {
			memcpy(&mtu, RTA_DATA(a), sizeof(uint32_t));
		} else if (a->rta_type == IFLA_IFNAME) {
			snprintf(name, sizeof(name), "%.*s",
					(int)RTA_PAYLOAD(a),
					(const char *)RTA_DATA(a));
		}
	}
	bool attached = link == NULL;
	if (attached) {
		for (size_t i = 0; i < sizeof(links) / sizeof(*links); i++) {
			if (!links[i].present) {
				link = &links[i];
				break;
			}
		}
		if (link == NULL) {
			return;
		}
		*link = (struct link){.present = true, .index = index};
	}
	unsigned int old_flags = link->flags;
	unsigned int old_mtu = link->mtu;
	link->flags = message->ifi_flags;
	link->mtu = mtu;
	link->type = message->ifi_type;
	link->seen = true;
	snprintf(link->name, sizeof(link->name), "%s", name);
	if (initial) {
		return;
	}
	struct net_event_data data;
	link_event_data(link, &data);
	if (attached) {
		post_event(KEV_DL_SUBCLASS, KEV_DL_IF_ATTACHED, &data,
				sizeof(data));
	} else if ((old_flags ^ link->flags) & 0xffff & ~IFF_RUNNING) {
		post_event(KEV_DL_SUBCLASS, KEV_DL_SIFFLAGS, &data,
				sizeof(data));
	}
	if (!attached && old_mtu != mtu) {
		post_event(KEV_DL_SUBCLASS, KEV_DL_SIFMTU, &data, sizeof(data));
	}
	bool was_running = !attached && (old_flags & IFF_RUNNING);
	if (was_running != !!(link->flags & IFF_RUNNING)) {
		post_event(KEV_DL_SUBCLASS,
				(link->flags & IFF_RUNNING) ? KEV_DL_LINK_ON
							    : KEV_DL_LINK_OFF,
				&data, sizeof(data));
	}
	if (attached || old_flags != link->flags || old_mtu != mtu) {
		post_interface_info(index, link->flags);
	}
}

static struct link *
find_link(unsigned int index)
{
	for (size_t i = 0; i < sizeof(links) / sizeof(*links); i++) {
		if (links[i].present && links[i].index == index) {
			return &links[i];
		}
	}
	return NULL;
}

static void
link_event_data(const struct link *link, struct net_event_data *data)
{
	memset(data, 0, sizeof(*data));
	size_t length = strlen(link->name);
	size_t digits = length;
	while (digits > 0 && isdigit((unsigned char)link->name[digits - 1])) {
		digits--;
	}
	memcpy(data->if_name, link->name,
			digits < IFNAMSIZ ? digits : IFNAMSIZ - 1);
	data->if_unit = (uint32_t)strtoul(link->name + digits, NULL, 10);
	switch (link->type) {
	case 1:
		data->if_family = APPLE_IF_FAM_ETHERNET;
		break;
	case 772:
		data->if_family = APPLE_IF_FAM_LOOPBACK;
		break;
	}
}

static void
post_event(uint32_t subclass, uint32_t code, const void *data, size_t size)
{
	uint8_t message[sizeof(struct kern_event_msg) + 256];
	struct kern_event_msg *header = (struct kern_event_msg *)message;
	*header = (struct kern_event_msg){
			.total_size = (uint32_t)(sizeof(*header) + size),
			.vendor_code = KEV_VENDOR_APPLE,
			.kev_class = KEV_NETWORK_CLASS,
			.kev_subclass = subclass,
			.event_code = code,
	};
	memcpy(message + sizeof(*header), data, size);
	pthread_mutex_lock(&lock);
	header->id = ++last_event_id;
	for (size_t fd = 0; fd < sizeof(sockets) / sizeof(*sockets); fd++) {
		const struct route_socket *socket = &sockets[fd];
		if (!socket->open || !socket->events) {
			continue;
		}
		const struct kev_request *filter = &socket->filter;
		if (filter->vendor_code != KEV_ANY_VENDOR) {
			if (filter->vendor_code != header->vendor_code) {
				continue;
			}
			if (filter->kev_class != KEV_ANY_CLASS) {
				if (filter->kev_class != header->kev_class) {
					continue;
				}
				if (filter->kev_subclass != KEV_ANY_SUBCLASS
						&& filter->kev_subclass
								!= subclass) {
					continue;
				}
			}
		}
		deliver(socket, message, header->total_size);
	}
	pthread_mutex_unlock(&lock);
#ifdef ENABLE_STRACE
	fprintf(stderr, "  route: event %u/%u\n", subclass, code);
#endif
}

static void
deliver(const struct route_socket *socket, const void *message, size_t size)
{
	send(socket->peer, message, size, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void
post_interface_info(unsigned int index, unsigned int flags)
{
	size_t size = 0;
	if (net_interface_list(3 /* NET_RT_IFLIST */, 0, (int)index, NULL,
			    &size) != 0
			|| size == 0) {
		uint8_t message[112] = {0};
		*(uint16_t *)message = sizeof(message);
		message[2] = RTM_VERSION;
		message[3] = xnu_RTM_IFINFO;
		*(int32_t *)(message + 8) = net_translate_flags(flags);
		*(uint16_t *)(message + 12) = (uint16_t)index;
		post_route_message(0, message, sizeof(message));
		return;
	}
	uint8_t *list = malloc(size);
	if (net_interface_list(3, 0, (int)index, list, &size) == 0) {
		*(uint16_t *)list = 112;
		*(int32_t *)(list + 4) = 0;
		post_route_message(0, list, 112);
	}
	free(list);
}

static void
post_route_message(int family, const void *message, size_t size)
{
	int xnu_family = family == AF_INET   ? xnu_AF_INET
			: family == AF_INET6 ? xnu_AF_INET6
					     : 0;
	pthread_mutex_lock(&lock);
	for (size_t fd = 0; fd < sizeof(sockets) / sizeof(*sockets); fd++) {
		const struct route_socket *socket = &sockets[fd];
		if (socket->open && !socket->events
				&& (socket->family == 0 || xnu_family == 0
						|| socket->family
								== xnu_family)) {
			deliver(socket, message, size);
		}
	}
	pthread_mutex_unlock(&lock);
}

static void
handle_address(const struct nlmsghdr *header, bool initial)
{
	const struct ifaddrmsg *message = NLMSG_DATA(header);
	if (message->ifa_family != AF_INET && message->ifa_family != AF_INET6) {
		return;
	}
	struct address found = {
			.present = true,
			.seen = true,
			.index = message->ifa_index,
			.family = message->ifa_family,
			.prefix = message->ifa_prefixlen,
			.flags = message->ifa_flags,
			.valid = 0xffffffff,
			.preferred = 0xffffffff,
	};
	size_t size = address_size(found.family);
	uint8_t local[16], peer[16], broadcast[16];
	bool has_local = false, has_peer = false, has_broadcast = false;
	size_t remaining = IFA_PAYLOAD(header);
	for (const struct rtattr *a = IFA_RTA(message); RTA_OK(a, remaining);
			a = RTA_NEXT(a, remaining)) {
		switch (a->rta_type) {
		case IFA_LOCAL:
			if (RTA_PAYLOAD(a) == size) {
				memcpy(local, RTA_DATA(a), size);
				has_local = true;
			}
			break;
		case IFA_ADDRESS:
			if (RTA_PAYLOAD(a) == size) {
				memcpy(peer, RTA_DATA(a), size);
				has_peer = true;
			}
			break;
		case IFA_BROADCAST:
			if (RTA_PAYLOAD(a) == size) {
				memcpy(broadcast, RTA_DATA(a), size);
				has_broadcast = true;
			}
			break;
		case IFA_FLAGS:
			memcpy(&found.flags, RTA_DATA(a), sizeof(uint32_t));
			break;
		case IFA_CACHEINFO: {
			struct ifa_cacheinfo info;
			memcpy(&info, RTA_DATA(a), sizeof(info));
			found.valid = info.ifa_valid;
			found.preferred = info.ifa_prefered;
			break;
		}
		}
	}
	if (has_local) {
		memcpy(found.address, local, size);
		if (has_peer && memcmp(local, peer, size) != 0) {
			memcpy(found.peer, peer, size);
			found.has_peer = true;
		}
	} else if (has_peer) {
		memcpy(found.address, peer, size);
	} else {
		return;
	}
	if (has_broadcast && !found.has_peer) {
		memcpy(found.peer, broadcast, size);
		found.has_peer = true;
	}

	struct address *known = NULL;
	struct address *free_slot = NULL;
	for (size_t i = 0; i < sizeof(addresses) / sizeof(*addresses); i++) {
		struct address *address = &addresses[i];
		if (!address->present) {
			if (free_slot == NULL) {
				free_slot = address;
			}
			continue;
		}
		if (address->index == found.index
				&& address->family == found.family
				&& memcmp(address->address, found.address, size)
						== 0) {
			known = address;
			break;
		}
	}
	bool v4 = found.family == AF_INET;
	if (header->nlmsg_type == RTM_DELADDR) {
		if (known == NULL) {
			return;
		}
		known->present = false;
		post_address_event(known,
				v4 ? KEV_INET_ADDR_DELETED
				   : KEV_INET6_ADDR_DELETED);
		post_address_message(known, xnu_RTM_DELADDR);
		return;
	}
	if (known != NULL) {
		bool changed = known->prefix != found.prefix
				|| in6_flags(known->flags)
						!= in6_flags(found.flags)
				|| known->has_peer != found.has_peer;
		*known = found;
		if (changed && !initial) {
			post_address_event(known,
					v4 ? KEV_INET_CHANGED_ADDR
					   : KEV_INET6_CHANGED_ADDR);
		}
		return;
	}
	if (free_slot == NULL) {
		return;
	}
	*free_slot = found;
	if (initial) {
		return;
	}
	uint32_t code;
	if (v4) {
		code = KEV_INET_NEW_ADDR;
	} else if (found.address[0] == 0xfe
			&& (found.address[1] & 0xc0) == 0x80) {
		code = KEV_INET6_NEW_LL_ADDR;
	} else if (found.flags & IFA_F_PERMANENT) {
		code = KEV_INET6_NEW_USER_ADDR;
	} else {
		code = KEV_INET6_NEW_RTADV_ADDR;
	}
	post_address_event(free_slot, code);
	post_address_message(free_slot, xnu_RTM_NEWADDR);
}

static size_t
address_size(int family)
{
	return family == AF_INET ? 4 : 16;
}

static void
post_address_event(const struct address *address, uint32_t code)
{
	const struct link *link = find_link(address->index);
	struct link unknown = {.index = address->index};
	if (link == NULL) {
		if_indextoname(address->index, unknown.name);
		unknown.type = read_interface_number(unknown.name, "type");
		link = &unknown;
	}
	if (address->family == AF_INET) {
		struct kev_in_data data = {0};
		link_event_data(link, &data.link_data);
		uint8_t mask[16];
		prefix_mask(AF_INET, address->prefix, mask);
		uint32_t value, netmask;
		memcpy(&value, address->address, 4);
		memcpy(&netmask, mask, 4);
		data.ia_addr = value;
		data.ia_netmask = data.ia_subnetmask = ntohl(netmask);
		data.ia_net = data.ia_subnet = ntohl(value & netmask);
		data.ia_netbroadcast = value | ~netmask;
		if (address->has_peer) {
			memcpy(&data.ia_dstaddr, address->peer, 4);
		}
		post_event(KEV_INET_SUBCLASS, code, &data, sizeof(data));
		return;
	}
	struct kev_in6_data data = {0};
	link_event_data(link, &data.link_data);
	struct output out = {0};
	append_address(&out, AF_INET6, address->address, address->index);
	memcpy(&data.ia_addr, out.bytes, sizeof(data.ia_addr));
	uint8_t mask[16], network[16];
	prefix_mask(AF_INET6, address->prefix, mask);
	for (size_t i = 0; i < 16; i++) {
		network[i] = address->address[i] & mask[i];
	}
	out.length = 0;
	append_address(&out, AF_INET6, network, address->index);
	memcpy(&data.ia_net, out.bytes, sizeof(data.ia_net));
	out.length = 0;
	append_address(&out, AF_INET6, mask, 0);
	memcpy(&data.ia_prefixmask, out.bytes, sizeof(data.ia_prefixmask));
	free(out.bytes);
	data.ia_dstaddr.sin6_len = sizeof(data.ia_dstaddr);
	data.ia_dstaddr.sin6_family = xnu_AF_INET6;
	data.ia_plen = address->prefix;
	data.ia6_flags = in6_flags(address->flags);
	data.ia_lifetime.ia6t_vltime = address->valid;
	data.ia_lifetime.ia6t_pltime = address->preferred;
	read_link_address(link->name, data.ia_mac);
	post_event(KEV_INET6_SUBCLASS, code, &data, sizeof(data));
}

static unsigned int
read_interface_number(const char *name, const char *attribute)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", name, attribute);
	FILE *file = fopen(path, "r");
	unsigned int value = 0;
	if (file != NULL) {
		if (fscanf(file, "%u", &value) != 1) {
			value = 0;
		}
		fclose(file);
	}
	return value;
}

static void
prefix_mask(int family, unsigned int length, uint8_t *mask)
{
	memset(mask, 0, 16);
	for (size_t i = 0; i < address_size(family) && length > 0; i++) {
		unsigned int bits = length < 8 ? length : 8;
		mask[i] = (uint8_t)(0xff << (8 - bits));
		length -= bits;
	}
}

static void
append_address(struct output *out, int family, const uint8_t *address,
		unsigned int index)
{
	if (family == AF_INET) {
		uint8_t *in = grow(out, 16);
		in[0] = 16;
		in[1] = xnu_AF_INET;
		memcpy(in + 4, address, 4);
		return;
	}
	struct xnu_sockaddr_in6 *in6 = grow(out, sizeof(*in6));
	in6->sin6_len = sizeof(*in6);
	in6->sin6_family = xnu_AF_INET6;
	memcpy(in6->sin6_addr, address, 16);
	if (index != 0 && in6->sin6_addr[0] == 0xfe
			&& (in6->sin6_addr[1] & 0xc0) == 0x80) {
		in6->sin6_addr[2] = (uint8_t)(index >> 8);
		in6->sin6_addr[3] = (uint8_t)index;
	}
}

static void *
grow(struct output *out, size_t size)
{
	size = (size + 3) & ~(size_t)3;
	if (out->length + size > out->capacity) {
		out->capacity = (out->length + size) * 2;
		out->bytes = realloc(out->bytes, out->capacity);
	}
	void *start = out->bytes + out->length;
	memset(start, 0, size);
	out->length += size;
	return start;
}

static uint32_t
in6_flags(uint32_t flags)
{
	uint32_t translated = 0;
	if (flags & IFA_F_TENTATIVE) {
		translated |= IN6_IFF_TENTATIVE;
	}
	if (flags & IFA_F_DADFAILED) {
		translated |= IN6_IFF_DUPLICATED;
	}
	if (flags & IFA_F_DEPRECATED) {
		translated |= IN6_IFF_DEPRECATED;
	}
	if (flags & IFA_F_NODAD) {
		translated |= IN6_IFF_NODAD;
	}
	if (flags & IFA_F_TEMPORARY) {
		translated |= IN6_IFF_TEMPORARY;
	}
	if (flags & IFA_F_OPTIMISTIC) {
		translated |= IN6_IFF_OPTIMISTIC;
	}
	if (!(flags & IFA_F_PERMANENT)) {
		translated |= IN6_IFF_AUTOCONF;
	}
	return translated;
}

static size_t
read_link_address(const char *name, uint8_t *address)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/class/net/%s/address", name);
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		return 0;
	}
	size_t length = 0;
	unsigned int byte;
	while (length < 8
			&& fscanf(file, length == 0 ? "%2x" : ":%2x", &byte)
					== 1) {
		address[length++] = (uint8_t)byte;
	}
	fclose(file);
	bool zero = true;
	for (size_t i = 0; i < length; i++) {
		zero &= address[i] == 0;
	}
	return zero ? 0 : length;
}

static void
post_address_message(const struct address *address, uint8_t type)
{
	struct output out = {0};
	struct xnu_ifa_msghdr *header = grow(&out, sizeof(*header));
	header->ifam_version = RTM_VERSION;
	header->ifam_type = type;
	header->ifam_index = (uint16_t)address->index;
	const struct link *link = find_link(address->index);
	header->ifam_flags
			= link != NULL ? net_translate_flags(link->flags) : 0;
	uint8_t mask[16];
	prefix_mask(address->family, address->prefix, mask);
	append_address(&out, address->family, mask, 0);
	append_link(&out, address->index, true);
	append_address(&out, address->family, address->address, address->index);
	int addrs = xnu_RTA_NETMASK | xnu_RTA_IFP | xnu_RTA_IFA;
	if (address->has_peer) {
		append_address(&out, address->family, address->peer,
				address->index);
		addrs |= xnu_RTA_BRD;
	}
	header = (struct xnu_ifa_msghdr *)out.bytes;
	header->ifam_addrs = addrs;
	header->ifam_msglen = (uint16_t)out.length;
	post_route_message(address->family, out.bytes, out.length);
	free(out.bytes);
}

static void
append_link(struct output *out, unsigned int index, bool named)
{
	char name[IF_NAMESIZE] = "";
	uint8_t address[8];
	size_t address_length = 0;
	if (named && if_indextoname(index, name) != NULL) {
		address_length = read_link_address(name, address);
	} else if (if_indextoname(index, name) == NULL) {
		name[0] = '\0';
	}
	uint8_t type = name[0] != '\0' ? interface_type(name) : IFT_OTHER;
	if (!named) {
		name[0] = '\0';
	}
	size_t name_length = strlen(name);
	size_t length = 8 + name_length + address_length;
	if (length < 20) {
		length = 20;
	}
	uint8_t *dl = grow(out, length);
	dl[0] = (uint8_t)length;
	dl[1] = xnu_AF_LINK;
	dl[2] = (uint8_t)index;
	dl[3] = (uint8_t)(index >> 8);
	dl[4] = type;
	dl[5] = (uint8_t)name_length;
	dl[6] = (uint8_t)address_length;
	memcpy(dl + 8, name, name_length);
	memcpy(dl + 8 + name_length, address, address_length);
}

static uint8_t
interface_type(const char *name)
{
	switch (read_interface_number(name, "type")) {
	case 1:
		return IFT_ETHER;
	case 772:
		return IFT_LOOP;
	default:
		return IFT_OTHER;
	}
}

static void
notify_watchers(void)
{
	pthread_mutex_lock(&lock);
	size_t count = watcher_count;
	void (*callbacks[sizeof(watchers) / sizeof(*watchers)])(void);
	memcpy(callbacks, watchers, sizeof(callbacks));
	pthread_mutex_unlock(&lock);
	for (size_t i = 0; i < count; i++) {
		callbacks[i]();
	}
}

static void
handle_route(const struct nlmsghdr *header)
{
	struct host_route route;
	if (!parse_route(header, &route) || route.local) {
		return;
	}
	struct output out = {0};
	append_route(&out,
			header->nlmsg_type == RTM_NEWROUTE ? xnu_RTM_ADD
							   : xnu_RTM_DELETE,
			&route, false);
	((struct xnu_rt_msghdr *)out.bytes)->rtm_flags |= xnu_RTF_DONE;
	post_route_message(route.family, out.bytes, out.length);
	free(out.bytes);
}

static bool
parse_route(const struct nlmsghdr *header, struct host_route *out)
{
	if (header->nlmsg_type != RTM_NEWROUTE
			&& header->nlmsg_type != RTM_DELROUTE) {
		return false;
	}
	const struct rtmsg *message = NLMSG_DATA(header);
	if (message->rtm_family != AF_INET && message->rtm_family != AF_INET6) {
		return false;
	}
	if (message->rtm_flags & RTM_F_CLONED) {
		return false;
	}
	*out = (struct host_route){
			.family = message->rtm_family,
			.type = message->rtm_type,
			.length = message->rtm_dst_len,
	};
	uint32_t table = message->rtm_table;
	size_t size = address_size(out->family);
	size_t remaining = RTM_PAYLOAD(header);
	for (const struct rtattr *a = RTM_RTA(message); RTA_OK(a, remaining);
			a = RTA_NEXT(a, remaining)) {
		switch (a->rta_type) {
		case RTA_TABLE:
			memcpy(&table, RTA_DATA(a), sizeof(table));
			break;
		case RTA_DST:
			if (RTA_PAYLOAD(a) == size) {
				memcpy(out->destination, RTA_DATA(a), size);
			}
			break;
		case RTA_GATEWAY:
			if (RTA_PAYLOAD(a) == size) {
				memcpy(out->gateway, RTA_DATA(a), size);
				out->has_gateway = true;
			}
			break;
		case RTA_PREFSRC:
			if (RTA_PAYLOAD(a) == size) {
				memcpy(out->source, RTA_DATA(a), size);
				out->has_source = true;
			}
			break;
		case RTA_OIF:
			memcpy(&out->interface, RTA_DATA(a), sizeof(uint32_t));
			break;
		case RTA_PRIORITY:
			memcpy(&out->priority, RTA_DATA(a), sizeof(uint32_t));
			break;
		}
	}
	if (table == RT_TABLE_LOCAL && out->type == RTN_LOCAL) {
		out->local = true;
		return true;
	}
	return table == RT_TABLE_MAIN && out->type == RTN_UNICAST
			&& out->interface != 0;
}

static void
append_route(struct output *out, uint8_t type, const struct host_route *route,
		bool interface)
{
	size_t start = out->length;
	struct xnu_rt_msghdr *header = grow(out, sizeof(*header));
	header->rtm_version = RTM_VERSION;
	header->rtm_type = type;
	header->rtm_index = (uint16_t)route->interface;
	header->rtm_flags = route_flags(route);
	header->rtm_addrs = xnu_RTA_DST | xnu_RTA_GATEWAY;
	char name[IF_NAMESIZE];
	if (if_indextoname(route->interface, name) != NULL) {
		header->rtm_rmx.rmx_mtu = read_interface_number(name, "mtu");
	}
	append_address(out, route->family, route->destination,
			route->interface);
	if (route->has_gateway) {
		append_address(out, route->family, route->gateway,
				route->interface);
	} else {
		append_link(out, route->interface, false);
	}
	int addrs = xnu_RTA_DST | xnu_RTA_GATEWAY;
	if (!(route_flags(route) & xnu_RTF_HOST)) {
		uint8_t mask[16];
		prefix_mask(route->family, route->length, mask);
		append_address(out, route->family, mask, 0);
		addrs |= xnu_RTA_NETMASK;
	}
	if (interface) {
		append_link(out, route->interface, true);
		addrs |= xnu_RTA_IFP;
		uint8_t source[16];
		if (route->has_source) {
			memcpy(source, route->source, sizeof(source));
		}
		if (route->has_source
				|| interface_address(route->interface,
						route->family, source)) {
			append_address(out, route->family, source,
					route->interface);
			addrs |= xnu_RTA_IFA;
		}
	}
	header = (struct xnu_rt_msghdr *)(out->bytes + start);
	header->rtm_addrs = addrs;
	header->rtm_msglen = (uint16_t)(out->length - start);
}

static int
route_flags(const struct host_route *route)
{
	int flags = xnu_RTF_UP | xnu_RTF_STATIC;
	if (route->length == address_size(route->family) * 8) {
		flags |= xnu_RTF_HOST;
	}
	if (route->local) {
		flags |= xnu_RTF_LOCAL;
	} else if (route->has_gateway) {
		flags |= xnu_RTF_GATEWAY | xnu_RTF_PRCLONING;
	} else if (!(flags & xnu_RTF_HOST)) {
		flags |= xnu_RTF_CLONING;
	}
	return flags;
}

static bool
interface_address(unsigned int index, int family, uint8_t *out)
{
	char name[IF_NAMESIZE];
	if (if_indextoname(index, name) == NULL) {
		return false;
	}
	struct ifaddrs *list;
	if (getifaddrs(&list) == -1) {
		return false;
	}
	bool found = false;
	for (struct ifaddrs *entry = list; entry != NULL && !found;
			entry = entry->ifa_next) {
		if (entry->ifa_addr == NULL
				|| entry->ifa_addr->sa_family != family
				|| strcmp(entry->ifa_name, name) != 0) {
			continue;
		}
		if (family == AF_INET) {
			memcpy(out,
					&((struct sockaddr_in *)entry->ifa_addr)
							->sin_addr,
					4);
		} else {
			memcpy(out,
					&((struct sockaddr_in6 *)entry->ifa_addr)
							->sin6_addr,
					16);
		}
		found = true;
	}
	freeifaddrs(list);
	return found;
}

bool
route_is_socket(int fd)
{
	return fd >= 0 && (size_t)fd < sizeof(sockets) / sizeof(*sockets)
			&& sockets[fd].open;
}

void
route_close(int fd)
{
	if (!route_is_socket(fd)) {
		return;
	}
	pthread_mutex_lock(&lock);
	close(sockets[fd].peer);
	sockets[fd].open = false;
	pthread_mutex_unlock(&lock);
}

int
route_dump(int operation, int family, int flags, void *old, size_t *oldlenp)
{
	if (operation != xnu_NET_RT_DUMP && operation != xnu_NET_RT_DUMP2
			&& operation != xnu_NET_RT_FLAGS
			&& operation != xnu_NET_RT_FLAGS_PRIV) {
		return _EINVAL;
	}
	int host = host_family(family);
	if (host == -1) {
		host = AF_UNSPEC;
	}
	struct route_list list = load_routes(host);
	struct output out = {0};
	for (size_t i = 0; i != list.count; i++) {
		const struct host_route *route = &list.routes[i];
		if ((operation == xnu_NET_RT_FLAGS
				    || operation == xnu_NET_RT_FLAGS_PRIV)
				&& !(route_flags(route) & flags)) {
			continue;
		}
		append_route(&out,
				operation == xnu_NET_RT_DUMP2 ? xnu_RTM_GET2
							      : xnu_RTM_GET,
				route, false);
	}
	free(list.routes);

	int result = 0;
	if (old == NULL) {
		*oldlenp = out.length;
	} else if (*oldlenp < out.length) {
		result = _ENOMEM;
	} else {
		memcpy(old, out.bytes, out.length);
		*oldlenp = out.length;
	}
	free(out.bytes);
	return result;
}

static int
host_family(int xnu_family)
{
	switch (xnu_family) {
	case 0:
		return AF_UNSPEC;
	case xnu_AF_INET:
		return AF_INET;
	case xnu_AF_INET6:
		return AF_INET6;
	default:
		return -1;
	}
}

static struct route_list
load_routes(int family)
{
	struct route_list list = {0};
	netlink_dump(RTM_GETROUTE, family, collect_route, &list);
	return list;
}

static void
collect_route(const struct nlmsghdr *header, void *context)
{
	struct route_list *list = context;
	struct host_route route;
	if (!parse_route(header, &route)) {
		return;
	}
	if (list->count == list->capacity) {
		list->capacity = list->capacity ? list->capacity * 2 : 32;
		list->routes = realloc(list->routes,
				list->capacity * sizeof(*list->routes));
	}
	list->routes[list->count++] = route;
}

long
route_write(int fd, const void *buffer, size_t size)
{
	struct xnu_rt_msghdr request;
	if (size < sizeof(uint32_t)) {
		return _ENOBUFS;
	}
	if (size < sizeof(request) || size > 4096) {
		return _EINVAL;
	}
	memcpy(&request, buffer, sizeof(request));
	if (request.rtm_msglen != size) {
		return _EINVAL;
	}
	if (request.rtm_version != RTM_VERSION) {
		return _EPROTONOSUPPORT;
	}
	if (sockets[fd].events) {
		return _EOPNOTSUPP;
	}
	const uint8_t *addresses[xnu_RTAX_MAX];
	parse_addresses((const uint8_t *)buffer + sizeof(request),
			(const uint8_t *)buffer + size, request.rtm_addrs,
			addresses);

	struct output out = {0};
	int error = 0;
	switch (request.rtm_type) {
	case xnu_RTM_GET:
	case xnu_RTM_GET_SILENT: {
		uint8_t destination[16];
		int family = sockaddr_address(addresses[0], destination);
		if (family == AF_UNSPEC) {
			error = _EINVAL;
			break;
		}
		int length = addresses[2] != NULL
				? (int)mask_length(addresses[2], family)
				: -1;
		unsigned int interface = (request.rtm_flags & xnu_RTF_IFSCOPE)
				? request.rtm_index
				: 0;
		struct host_route route;
		if (!find_route(family, destination, length, interface,
				    &route)) {
			error = _ESRCH;
			break;
		}
		append_route(&out, request.rtm_type, &route,
				(request.rtm_addrs
						& (xnu_RTA_IFP | xnu_RTA_IFA))
						!= 0);
		struct xnu_rt_msghdr *reply = (struct xnu_rt_msghdr *)out.bytes;
		reply->rtm_flags |= xnu_RTF_DONE;
		reply->rtm_seq = request.rtm_seq;
		break;
	}
	case xnu_RTM_ADD:
	case xnu_RTM_DELETE:
	case xnu_RTM_CHANGE:
	case xnu_RTM_LOCK:
		if (geteuid() != 0) {
			error = _EPERM;
			break;
		}
		memcpy(grow(&out, size), buffer, size);
		((struct xnu_rt_msghdr *)out.bytes)->rtm_flags |= xnu_RTF_DONE;
		break;
	default:
		error = _EOPNOTSUPP;
		break;
	}
	if (error != 0 && error != _EPERM && error != _EOPNOTSUPP) {
		memcpy(grow(&out, size), buffer, size);
		((struct xnu_rt_msghdr *)out.bytes)->rtm_errno = -error;
	}
#ifdef ENABLE_STRACE
	fprintf(stderr, "  route: request %u: %d\n", request.rtm_type, error);
#endif
	if (out.length != 0) {
		((struct xnu_rt_msghdr *)out.bytes)->rtm_pid = getpid();
		pthread_mutex_lock(&lock);
		deliver(&sockets[fd], out.bytes, out.length);
		pthread_mutex_unlock(&lock);
	}
	free(out.bytes);
	return error != 0 ? error : (long)size;
}

static void
parse_addresses(const uint8_t *cursor, const uint8_t *end, int addrs,
		const uint8_t *found[xnu_RTAX_MAX])
{
	for (int i = 0; i < xnu_RTAX_MAX; i++) {
		found[i] = NULL;
		if (!(addrs & (1 << i)) || cursor + 2 > end) {
			continue;
		}
		size_t length = cursor[0] == 0
				? 4
				: ((size_t)cursor[0] + 3) & ~(size_t)3;
		if (cursor + length > end) {
			break;
		}
		found[i] = cursor;
		cursor += length;
	}
}

static int
sockaddr_address(const uint8_t *sockaddr, uint8_t *address)
{
	memset(address, 0, 16);
	if (sockaddr == NULL) {
		return AF_UNSPEC;
	}
	if (sockaddr[1] == xnu_AF_INET) {
		size_t length = sockaddr[0] > 4 ? sockaddr[0] - 4 : 0;
		memcpy(address, sockaddr + 4, length < 4 ? length : 4);
		return AF_INET;
	}
	if (sockaddr[1] == xnu_AF_INET6) {
		size_t length = sockaddr[0] > 8 ? sockaddr[0] - 8 : 0;
		memcpy(address, sockaddr + 8, length < 16 ? length : 16);
		if (address[0] == 0xfe && (address[1] & 0xc0) == 0x80) {
			address[2] = address[3] = 0;
		}
		return AF_INET6;
	}
	return AF_UNSPEC;
}

static unsigned int
mask_length(const uint8_t *sockaddr, int family)
{
	uint8_t mask[16];
	sockaddr_address(sockaddr, mask);
	unsigned int length = 0;
	for (size_t i = 0; i < address_size(family); i++) {
		for (int bit = 7; bit >= 0; bit--) {
			if (!(mask[i] & (1 << bit))) {
				return length;
			}
			length++;
		}
	}
	return length;
}

static bool
find_route(int family, const uint8_t *destination, int length,
		unsigned int interface, struct host_route *out)
{
	struct route_list list = load_routes(family);
	const struct host_route *best = NULL;
	for (size_t i = 0; i != list.count; i++) {
		const struct host_route *route = &list.routes[i];
		if (route->family != family
				|| (interface != 0
						&& route->interface != interface)
				|| !prefix_matches(route->destination,
						destination, route->length)) {
			continue;
		}
		bool exact = length >= 0 && route->length == length;
		bool best_exact = best != NULL && length >= 0
				&& best->length == length;
		if (best == NULL || (exact && !best_exact)
				|| (exact == best_exact
						&& (route->length > best->length
								|| (route->length == best->length
										&& route->priority
												< best->priority)))) {
			best = route;
		}
	}
	if (best != NULL) {
		*out = *best;
	}
	free(list.routes);
	return best != NULL;
}

static bool
prefix_matches(const uint8_t *a, const uint8_t *b, unsigned int bits)
{
	size_t bytes = bits / 8;
	if (memcmp(a, b, bytes) != 0) {
		return false;
	}
	if (bits % 8 == 0) {
		return true;
	}
	uint8_t mask = (uint8_t)(0xff << (8 - bits % 8));
	return (a[bytes] & mask) == (b[bytes] & mask);
}

long
route_writev(int fd, const void *iov, uint32_t count)
{
	const struct iovec *pieces = iov;
	size_t size = 0;
	for (uint32_t i = 0; i < count; i++) {
		size += pieces[i].iov_len;
	}
	if (size > 4096) {
		return _EINVAL;
	}
	uint8_t message[4096];
	size_t used = 0;
	for (uint32_t i = 0; i < count; i++) {
		memcpy(message + used, pieces[i].iov_base, pieces[i].iov_len);
		used += pieces[i].iov_len;
	}
	return route_write(fd, message, size);
}

int
route_ioctl(int fd, uint64_t command, void *data)
{
	if (((command >> 8) & 0xff) != 'e' || !route_is_socket(fd)
			|| !sockets[fd].events) {
		return 1;
	}
	int result = 0;
	pthread_mutex_lock(&lock);
	switch (command) {
	case xnu_SIOCGKEVID:
		*(uint32_t *)data = last_event_id;
		break;
	case xnu_SIOCSKEVFILT:
		memcpy(&sockets[fd].filter, data, sizeof(struct kev_request));
		break;
	case xnu_SIOCGKEVFILT:
		memcpy(data, &sockets[fd].filter, sizeof(struct kev_request));
		break;
	case xnu_SIOCGKEVVENDOR:
		result = _ENOENT;
		break;
	default:
		result = _EINVAL;
		break;
	}
	pthread_mutex_unlock(&lock);
	return result;
}

void
route_watch(void (*callback)(void))
{
	pthread_mutex_lock(&lock);
	if (watcher_count < sizeof(watchers) / sizeof(*watchers)) {
		watchers[watcher_count++] = callback;
	}
	start_watching();
	pthread_mutex_unlock(&lock);
}

__attribute__((constructor)) static void
route_init(void)
{
	pthread_atfork(route_fork_prepare, route_fork_parent, route_fork_child);
}

static void
route_fork_prepare(void)
{
	pthread_mutex_lock(&lock);
}

static void
route_fork_parent(void)
{
	pthread_mutex_unlock(&lock);
}

static void
route_fork_child(void)
{
	watching = false;
	pthread_mutex_unlock(&lock);
}
