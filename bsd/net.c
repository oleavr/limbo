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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "net.h"
#include "xnu-errno.h"

#define xnu_AF_INET  2
#define xnu_AF_LINK  18
#define xnu_AF_INET6 30

#define RTM_VERSION    5
#define RTM_NEWADDR    0xc
#define RTM_IFINFO     0xe
#define RTM_IFINFO2    0x12
#define NET_RT_IFLIST2 6

#define RTA_NETMASK 0x4
#define RTA_IFP     0x10
#define RTA_IFA     0x20
#define RTA_BRD     0x80

#define IFT_OTHER 0x1
#define IFT_ETHER 0x6
#define IFT_LOOP  0x18

#define xnu_IFF_SIMPLEX   0x800
#define xnu_IFF_MULTICAST 0x8000

struct xnu_if_data {
	uint8_t ifi_type;
	uint8_t ifi_typelen;
	uint8_t ifi_physical;
	uint8_t ifi_addrlen;
	uint8_t ifi_hdrlen;
	uint8_t ifi_recvquota;
	uint8_t ifi_xmitquota;
	uint8_t ifi_unused1;
	uint32_t ifi_mtu;
	uint32_t ifi_metric;
	uint32_t ifi_baudrate;
	uint32_t ifi_ipackets;
	uint32_t ifi_ierrors;
	uint32_t ifi_opackets;
	uint32_t ifi_oerrors;
	uint32_t ifi_collisions;
	uint32_t ifi_ibytes;
	uint32_t ifi_obytes;
	uint32_t ifi_imcasts;
	uint32_t ifi_omcasts;
	uint32_t ifi_iqdrops;
	uint32_t ifi_noproto;
	uint32_t ifi_recvtiming;
	uint32_t ifi_xmittiming;
	int32_t ifi_lastchange[2];
	uint32_t ifi_unused2;
	uint32_t ifi_hwassist;
	uint32_t ifi_reserved1;
	uint32_t ifi_reserved2;
};

struct xnu_if_data64 {
	uint8_t ifi_type;
	uint8_t ifi_typelen;
	uint8_t ifi_physical;
	uint8_t ifi_addrlen;
	uint8_t ifi_hdrlen;
	uint8_t ifi_recvquota;
	uint8_t ifi_xmitquota;
	uint8_t ifi_unused1;
	uint32_t ifi_mtu;
	uint32_t ifi_metric;
	uint64_t ifi_baudrate;
	uint64_t ifi_ipackets;
	uint64_t ifi_ierrors;
	uint64_t ifi_opackets;
	uint64_t ifi_oerrors;
	uint64_t ifi_collisions;
	uint64_t ifi_ibytes;
	uint64_t ifi_obytes;
	uint64_t ifi_imcasts;
	uint64_t ifi_omcasts;
	uint64_t ifi_iqdrops;
	uint64_t ifi_noproto;
	uint32_t ifi_recvtiming;
	uint32_t ifi_xmittiming;
	int32_t ifi_lastchange[2];
} __attribute__((packed, aligned(4)));

struct xnu_if_msghdr {
	uint16_t ifm_msglen;
	uint8_t ifm_version;
	uint8_t ifm_type;
	int32_t ifm_addrs;
	int32_t ifm_flags;
	uint16_t ifm_index;
	struct xnu_if_data ifm_data;
};

struct xnu_if_msghdr2 {
	uint16_t ifm_msglen;
	uint8_t ifm_version;
	uint8_t ifm_type;
	int32_t ifm_addrs;
	int32_t ifm_flags;
	uint16_t ifm_index;
	int32_t ifm_snd_len;
	int32_t ifm_snd_maxlen;
	int32_t ifm_snd_drops;
	int32_t ifm_timer;
	struct xnu_if_data64 ifm_data;
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

_Static_assert(sizeof(struct xnu_if_msghdr) == 112, "if_msghdr");
_Static_assert(sizeof(struct xnu_if_msghdr2) == 160, "if_msghdr2");
_Static_assert(sizeof(struct xnu_ifa_msghdr) == 20, "ifa_msghdr");

struct interface {
	const char *name;
	unsigned int index;
	unsigned int flags;
	unsigned int arp_type;
	unsigned int mtu;
	uint8_t address[8];
	uint8_t address_length;
	struct rtnl_link_stats stats;
};

struct output {
	uint8_t *bytes;
	size_t length;
	size_t capacity;
};

#define IOCGROUP(command) (((command) >> 8) & 0xff)
#define xnu_IOC_OUT       0x40000000

#define xnu_SIOCGIFFLAGS             0xc0206911
#define xnu_SIOCGIFMETRIC            0xc0206917
#define xnu_SIOCGIFADDR              0xc0206921
#define xnu_SIOCGIFDSTADDR           0xc0206922
#define xnu_SIOCGIFBRDADDR           0xc0206923
#define xnu_SIOCGIFNETMASK           0xc0206925
#define xnu_SIOCGIFMTU               0xc0206933
#define xnu_SIOCGIFMEDIA             0xc02c6938
#define xnu_SIOCGIFDEVMTU            0xc0206944
#define xnu_SIOCGIFAFLAG_IN6         0xc1206949
#define xnu_SIOCGIFALIFETIME_IN6     0xc1206951
#define xnu_SIOCGIFXMEDIA            0xc02c6948
#define xnu_SIOCGIFCAP               0xc020695b
#define xnu_SIOCGIFEFLAGS            0xc020698e
#define xnu_SIOCGIFTYPE              0xc020699f
#define xnu_SIOCGIFFUNCTIONALTYPE    0xc02069ad
#define xnu_SIOCGIFCONSTRAINED       0xc02069cc
#define xnu_SIOCSIFCONSTRAINED       0xc02069cd
#define xnu_SIOCGIFGENERATIONID      0xc02069d9
#define xnu_SIOCGIFLINKQUALITYMETRIC 0xc020698a
#define xnu_SIOCGIFDELEGATE          0xc020699d
#define xnu_SIOCGIFULTRACONSTRAINED  0xc02069da
#define xnu_SIOCGIFEXPENSIVE         0xc02069a0
#define xnu_SIOCGIFNAT64PREFIX       0xc06069c1
#define xnu_SIOCGIFCLAT46ADDR        0xc02469c9
#define xnu_SIOCGIFINFO_IN6          0xc030694c
#define xnu_SIOCARPIPLL              0xc0206928
#define xnu_SIOCPROTOATTACH          0xc0206950
#define xnu_SIOCSDEFIFACE_IN6        0xc0186955
#define xnu_SIOCPROTOATTACH_IN6      0xc080696e
#define xnu_SIOCLL_START             0xc0806982
#define xnu_SIOCSQOSMARKINGENABLED   0xc02069b5
#define xnu_SIOCSIFNETSIGNATURE      0xc02869ae
#define xnu_SIOCSIFORDER             0xc01069b2

#define IFNET_LQM_THRESH_UNKNOWN (-1)

#define ND6_IFF_PERFORMNUD          0x1
#define ND6_IFF_ACCEPT_RTADV        0x2
#define ND6_IFF_IFDISABLED          0x8
#define ND6_IFF_DAD                 0x200
#define ND6_RECALC_REACHTM_INTERVAL 7200

struct xnu_in6_ondireq {
	char name[IFNAMSIZ];
	uint32_t linkmtu;
	uint32_t maxmtu;
	uint32_t basereachable;
	uint32_t reachable;
	uint32_t retrans;
	uint32_t flags;
	int32_t recalctm;
	uint8_t chlim;
	uint8_t receivedra;
	uint8_t collision_count;
	uint8_t padding;
};

_Static_assert(sizeof(struct xnu_in6_ondireq) == 48, "in6_ondireq");

#define IFRTYPE_FAMILY_ANY      0
#define IFRTYPE_FAMILY_LOOPBACK 1
#define IFRTYPE_FAMILY_ETHERNET 2

#define IFM_ETHER  0x20
#define IFM_AUTO   0
#define IFM_10_T   0x3
#define IFM_100_TX 0x6
#define IFM_1000_T 0x10
#define IFM_10G_T  0x15
#define IFM_2500_T 0x16
#define IFM_5000_T 0x17
#define IFM_FDX    0x100000
#define IFM_AVALID 0x1
#define IFM_ACTIVE 0x2

#define IFRTYPE_FUNCTIONAL_UNKNOWN  0
#define IFRTYPE_FUNCTIONAL_LOOPBACK 1
#define IFRTYPE_FUNCTIONAL_WIRED    2

struct xnu_ifreq {
	char name[IFNAMSIZ];
	union {
		uint8_t sockaddr[16];
		int16_t flags;
		int32_t number;
		int32_t numbers[3];
		uint64_t eflags;
		uint64_t generation;
		uint32_t functional_type;
		uint32_t type[3];
	} u;
};

struct xnu_ifmediareq {
	char ifm_name[IFNAMSIZ];
	int32_t ifm_current;
	int32_t ifm_mask;
	int32_t ifm_status;
	int32_t ifm_active;
	int32_t ifm_count;
	int32_t *ifm_ulist;
} __attribute__((packed));

_Static_assert(sizeof(struct xnu_ifreq) == 32, "ifreq");
_Static_assert(sizeof(struct xnu_ifmediareq) == 44, "ifmediareq");

static int bpf_ioctl(int fd, uint64_t command, void *data);

#define xnu_BIOCGBLEN     0x40044266
#define xnu_BIOCSBLEN     0xc0044266
#define xnu_BIOCSETF      0x80104267
#define xnu_BIOCFLUSH     0x20004268
#define xnu_BIOCPROMISC   0x20004269
#define xnu_BIOCGDLT      0x4004426a
#define xnu_BIOCGETIF     0x4020426b
#define xnu_BIOCSETIF     0x8020426c
#define xnu_BIOCIMMEDIATE 0x80044270
#define xnu_BIOCVERSION   0x40044271
#define xnu_BIOCGSEESENT  0x40044276
#define xnu_BIOCSSEESENT  0x80044277

#define DLT_EN10MB          1
#define BPF_DEFAULT_BUFSIZE 4096
#define BPF_MAX_BUFSIZE     0x80000
#define BPF_HEADER_SIZE     18
#define BPF_WORDALIGN(n)    (((n) + 3) & ~(size_t)3)

struct xnu_bpf_hdr {
	int32_t bh_tstamp[2];
	uint32_t bh_caplen;
	uint32_t bh_datalen;
	uint16_t bh_hdrlen;
};

struct xnu_bpf_program {
	uint32_t bf_len;
	struct sock_filter *bf_insns;
};

_Static_assert(sizeof(struct xnu_bpf_hdr) == 20, "bpf_hdr");
_Static_assert(sizeof(struct xnu_bpf_program) == 16, "bpf_program");

static struct bpf_device {
	bool open;
	uint32_t buffer_size;
	char interface[IFNAMSIZ];
} bpf_devices[1024];

static unsigned int read_sys_number(
		const char *name, const char *attribute, unsigned int fallback);
static void *append(struct output *out, size_t size);
static int translate_flags(unsigned int flags);
static uint8_t interface_type(unsigned int arp_type);
static void append_link_sockaddr(
		struct output *out, const struct interface *interface);
static void append_sockaddr(struct output *out, const struct sockaddr *address,
		unsigned int index);
static int bpf_ioctl(int fd, uint64_t command, void *data);
static int host_interface_ioctl(
		unsigned long command, const char *name, struct ifreq *out);
static unsigned int read_ipv6_number(const char *directory, const char *name,
		const char *setting, unsigned int fallback);
static bool interface_address(const char *name, int family,
		bool (*pick)(const struct ifaddrs *), struct sockaddr *out,
		bool netmask);
static bool is_primary(const struct ifaddrs *entry);

int
net_interface_list(int type, int family, int index, void *old, size_t *oldlenp)
{
	struct ifaddrs *list;
	if (getifaddrs(&list) == -1) {
		return err_map(errno);
	}

	struct interface interfaces[64];
	size_t count = 0;
	for (struct ifaddrs *entry = list; entry != NULL;
			entry = entry->ifa_next) {
		if (entry->ifa_addr == NULL
				|| entry->ifa_addr->sa_family != AF_PACKET
				|| count == sizeof(interfaces) / sizeof(*interfaces)) {
			continue;
		}
		const struct sockaddr_ll *link
				= (const struct sockaddr_ll *)entry->ifa_addr;
		struct interface *interface = &interfaces[count++];
		memset(interface, 0, sizeof(*interface));
		interface->name = entry->ifa_name;
		interface->index = (unsigned int)link->sll_ifindex;
		interface->flags = entry->ifa_flags;
		interface->arp_type = link->sll_hatype;
		interface->mtu = read_sys_number(entry->ifa_name, "mtu", 1500);
		interface->address_length
				= link->sll_halen <= 8 ? link->sll_halen : 0;
		memcpy(interface->address, link->sll_addr,
				interface->address_length);
		if (entry->ifa_data != NULL) {
			interface->stats = *(struct rtnl_link_stats *)
							    entry->ifa_data;
		}
	}
	for (size_t i = 1; i < count; i++) {
		for (size_t j = i; j > 0
				&& interfaces[j - 1].index
						> interfaces[j].index;
				j--) {
			struct interface swap = interfaces[j];
			interfaces[j] = interfaces[j - 1];
			interfaces[j - 1] = swap;
		}
	}

	struct output out = {0};
	for (size_t i = 0; i != count; i++) {
		const struct interface *interface = &interfaces[i];
		if (index != 0 && interface->index != (unsigned int)index) {
			continue;
		}
		size_t start = out.length;
		if (type == NET_RT_IFLIST2) {
			struct xnu_if_msghdr2 *message
					= append(&out, sizeof(*message));
			message->ifm_version = RTM_VERSION;
			message->ifm_type = RTM_IFINFO2;
			message->ifm_addrs = RTA_IFP;
			message->ifm_flags = translate_flags(interface->flags);
			message->ifm_index = (uint16_t)interface->index;
			message->ifm_snd_maxlen = 128;
			struct xnu_if_data64 *data = &message->ifm_data;
			data->ifi_type = interface_type(interface->arp_type);
			data->ifi_addrlen = interface->address_length;
			data->ifi_hdrlen = data->ifi_type == IFT_ETHER ? 14 : 0;
			data->ifi_mtu = interface->mtu;
			data->ifi_ipackets = interface->stats.rx_packets;
			data->ifi_ierrors = interface->stats.rx_errors;
			data->ifi_opackets = interface->stats.tx_packets;
			data->ifi_oerrors = interface->stats.tx_errors;
			data->ifi_collisions = interface->stats.collisions;
			data->ifi_ibytes = interface->stats.rx_bytes;
			data->ifi_obytes = interface->stats.tx_bytes;
			data->ifi_imcasts = interface->stats.multicast;
			data->ifi_iqdrops = interface->stats.rx_dropped;
		} else {
			struct xnu_if_msghdr *message
					= append(&out, sizeof(*message));
			message->ifm_version = RTM_VERSION;
			message->ifm_type = RTM_IFINFO;
			message->ifm_addrs = RTA_IFP;
			message->ifm_flags = translate_flags(interface->flags);
			message->ifm_index = (uint16_t)interface->index;
			struct xnu_if_data *data = &message->ifm_data;
			data->ifi_type = interface_type(interface->arp_type);
			data->ifi_addrlen = interface->address_length;
			data->ifi_hdrlen = data->ifi_type == IFT_ETHER ? 14 : 0;
			data->ifi_mtu = interface->mtu;
			data->ifi_ipackets = interface->stats.rx_packets;
			data->ifi_ierrors = interface->stats.rx_errors;
			data->ifi_opackets = interface->stats.tx_packets;
			data->ifi_oerrors = interface->stats.tx_errors;
			data->ifi_collisions = interface->stats.collisions;
			data->ifi_ibytes = interface->stats.rx_bytes;
			data->ifi_obytes = interface->stats.tx_bytes;
			data->ifi_imcasts = interface->stats.multicast;
			data->ifi_iqdrops = interface->stats.rx_dropped;
		}
		append_link_sockaddr(&out, interface);
		*(uint16_t *)(out.bytes + start)
				= (uint16_t)(out.length - start);

		for (struct ifaddrs *entry = list; entry != NULL;
				entry = entry->ifa_next) {
			if (entry->ifa_addr == NULL
					|| strcmp(entry->ifa_name,
							   interface->name)
							!= 0
					|| (entry->ifa_addr->sa_family != AF_INET
							&& entry->ifa_addr->sa_family
									!= AF_INET6)) {
				continue;
			}
			if (family != 0
					&& family
							!= (entry->ifa_addr->sa_family == AF_INET
											? xnu_AF_INET
											: xnu_AF_INET6)) {
				continue;
			}
			start = out.length;
			struct xnu_ifa_msghdr *message
					= append(&out, sizeof(*message));
			message->ifam_version = RTM_VERSION;
			message->ifam_type = RTM_NEWADDR;
			message->ifam_addrs = RTA_IFA;
			message->ifam_flags = translate_flags(interface->flags);
			message->ifam_index = (uint16_t)interface->index;
			if (entry->ifa_netmask != NULL) {
				((struct xnu_ifa_msghdr *)(out.bytes + start))
						->ifam_addrs |= RTA_NETMASK;
				append_sockaddr(&out, entry->ifa_netmask, 0);
			}
			append_sockaddr(&out, entry->ifa_addr,
					interface->index);
			const struct sockaddr *peer = NULL;
			if (entry->ifa_flags & IFF_LOOPBACK) {
				peer = entry->ifa_addr;
			} else if ((entry->ifa_flags
						   & (IFF_BROADCAST
								   | IFF_POINTOPOINT))
					&& entry->ifa_addr->sa_family
							== AF_INET) {
				peer = entry->ifa_broadaddr;
			}
			if (peer != NULL) {
				((struct xnu_ifa_msghdr *)(out.bytes + start))
						->ifam_addrs |= RTA_BRD;
				append_sockaddr(&out, peer, interface->index);
			}
			*(uint16_t *)(out.bytes + start)
					= (uint16_t)(out.length - start);
		}
	}
	freeifaddrs(list);

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

static unsigned int
read_sys_number(const char *name, const char *attribute, unsigned int fallback)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", name, attribute);
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		return fallback;
	}
	unsigned int value = fallback;
	if (fscanf(file, "%u", &value) != 1) {
		value = fallback;
	}
	fclose(file);
	return value;
}

static void *
append(struct output *out, size_t size)
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

static int
translate_flags(unsigned int flags)
{
	int translated = flags & 0x3ff;
	if (flags & IFF_MULTICAST) {
		translated |= xnu_IFF_MULTICAST;
	}
	if (flags & IFF_BROADCAST) {
		translated |= xnu_IFF_SIMPLEX;
	}
	return translated;
}

static uint8_t
interface_type(unsigned int arp_type)
{
	switch (arp_type) {
	case 1:
		return IFT_ETHER;
	case 772:
		return IFT_LOOP;
	default:
		return IFT_OTHER;
	}
}

static void
append_link_sockaddr(struct output *out, const struct interface *interface)
{
	size_t name_length = strlen(interface->name);
	size_t length = 8 + name_length + interface->address_length;
	if (length < 20) {
		length = 20;
	}
	uint8_t *dl = append(out, length);
	dl[0] = (uint8_t)length;
	dl[1] = xnu_AF_LINK;
	dl[2] = (uint8_t)interface->index;
	dl[3] = (uint8_t)(interface->index >> 8);
	dl[4] = interface_type(interface->arp_type);
	dl[5] = (uint8_t)name_length;
	dl[6] = interface->address_length;
	memcpy(dl + 8, interface->name, name_length);
	memcpy(dl + 8 + name_length, interface->address,
			interface->address_length);
}

static void
append_sockaddr(struct output *out, const struct sockaddr *address,
		unsigned int index)
{
	if (address->sa_family == AF_INET) {
		struct sockaddr_in *in = append(out, sizeof(*in));
		memcpy(in, address, sizeof(*in));
		((uint8_t *)in)[0] = sizeof(*in);
		((uint8_t *)in)[1] = xnu_AF_INET;
		return;
	}
	struct sockaddr_in6 *in6 = append(out, sizeof(*in6));
	memcpy(in6, address, sizeof(*in6));
	((uint8_t *)in6)[0] = sizeof(*in6);
	((uint8_t *)in6)[1] = xnu_AF_INET6;
	if (index != 0 && IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
		in6->sin6_addr.s6_addr[2] = (uint8_t)(index >> 8);
		in6->sin6_addr.s6_addr[3] = (uint8_t)index;
		in6->sin6_scope_id = 0;
	}
}

int
net_translate_flags(unsigned int flags)
{
	return translate_flags(flags);
}

int
net_ioctl(int fd, uint64_t command, void *data)
{
	if (IOCGROUP(command) == 'B' && net_is_bpf(fd)) {
		return bpf_ioctl(fd, command, data);
	}
	if (IOCGROUP(command) != 'i') {
		return 1;
	}
	struct xnu_ifreq *request = data;
	char name[IFNAMSIZ + 1] = {0};
	memcpy(name, request->name, IFNAMSIZ);
	struct ifreq host;
	int error;

	switch (command) {
	case xnu_SIOCGIFFLAGS:
		error = host_interface_ioctl(SIOCGIFFLAGS, name, &host);
		if (error == 0) {
			request->u.flags = (int16_t)translate_flags(
					(uint16_t)host.ifr_flags);
		}
		return error;
	case xnu_SIOCGIFMTU:
		error = host_interface_ioctl(SIOCGIFMTU, name, &host);
		if (error == 0) {
			request->u.number = host.ifr_mtu;
		}
		return error;
	case xnu_SIOCGIFDEVMTU:
		error = host_interface_ioctl(SIOCGIFMTU, name, &host);
		if (error == 0) {
			request->u.numbers[0] = host.ifr_mtu;
			request->u.numbers[1] = 68;
			request->u.numbers[2] = host.ifr_mtu;
		}
		return error;
	case xnu_SIOCGIFTYPE: {
		error = host_interface_ioctl(SIOCGIFFLAGS, name, &host);
		if (error != 0) {
			return error;
		}
		uint8_t type = interface_type(read_sys_number(name, "type", 0));
		memset(&request->u, 0, sizeof(request->u));
		request->u.type[0] = type;
		request->u.type[1] = type == IFT_ETHER ? IFRTYPE_FAMILY_ETHERNET
				: type == IFT_LOOP     ? IFRTYPE_FAMILY_LOOPBACK
						       : IFRTYPE_FAMILY_ANY;
		return 0;
	}
	case xnu_SIOCGIFGENERATIONID: {
		unsigned int index = if_nametoindex(name);
		if (index == 0) {
			return _ENXIO;
		}
		memset(&request->u, 0, sizeof(request->u));
		request->u.generation = index;
		return 0;
	}
	case xnu_SIOCSIFCONSTRAINED:
		return if_nametoindex(name) == 0 ? _ENXIO : 0;
	case xnu_SIOCGIFMETRIC:
	case xnu_SIOCGIFCAP:
	case xnu_SIOCGIFEFLAGS:
	case xnu_SIOCGIFCONSTRAINED:
		if (if_nametoindex(name) == 0) {
			return _ENXIO;
		}
		memset(&request->u, 0, sizeof(request->u));
		return 0;
	case xnu_SIOCGIFLINKQUALITYMETRIC:
	case xnu_SIOCGIFDELEGATE:
	case xnu_SIOCGIFEXPENSIVE:
	case xnu_SIOCGIFULTRACONSTRAINED:
		if (if_nametoindex(name) == 0) {
			return _ENXIO;
		}
		memset(&request->u, 0, sizeof(request->u));
		if (command == xnu_SIOCGIFLINKQUALITYMETRIC) {
			request->u.number = IFNET_LQM_THRESH_UNKNOWN;
		}
		return 0;
	case xnu_SIOCGIFNAT64PREFIX:
	case xnu_SIOCGIFCLAT46ADDR:
		return if_nametoindex(name) == 0 ? _ENXIO : _ENOENT;
	case xnu_SIOCGIFINFO_IN6: {
		struct xnu_in6_ondireq *info = data;
		error = host_interface_ioctl(SIOCGIFMTU, name, &host);
		if (error != 0) {
			return error;
		}
		memset((uint8_t *)info + IFNAMSIZ, 0, sizeof(*info) - IFNAMSIZ);
		info->linkmtu = (uint32_t)host.ifr_mtu;
		info->maxmtu = (uint32_t)host.ifr_mtu;
		info->basereachable = read_ipv6_number(
				"neigh", name, "base_reachable_time_ms", 30000);
		info->reachable = info->basereachable;
		info->retrans = read_ipv6_number(
				"neigh", name, "retrans_time_ms", 1000);
		info->flags = ND6_IFF_PERFORMNUD | ND6_IFF_DAD
				| (read_ipv6_number("conf", name, "accept_ra",
						   0) != 0
								? ND6_IFF_ACCEPT_RTADV
								: 0)
				| (read_ipv6_number("conf", name,
						   "disable_ipv6", 0) != 0
								? ND6_IFF_IFDISABLED
								: 0);
		info->recalctm = ND6_RECALC_REACHTM_INTERVAL;
		info->chlim = (uint8_t)read_ipv6_number(
				"conf", name, "hop_limit", 64);
		return 0;
	}
	case xnu_SIOCARPIPLL:
	case xnu_SIOCPROTOATTACH:
	case xnu_SIOCSDEFIFACE_IN6:
	case xnu_SIOCPROTOATTACH_IN6:
	case xnu_SIOCLL_START:
	case xnu_SIOCSQOSMARKINGENABLED:
	case xnu_SIOCSIFNETSIGNATURE:
	case xnu_SIOCSIFORDER:
		return 0;
	case xnu_SIOCGIFFUNCTIONALTYPE: {
		error = host_interface_ioctl(SIOCGIFFLAGS, name, &host);
		if (error != 0) {
			return error;
		}
		unsigned int type = read_sys_number(name, "type", 0);
		memset(&request->u, 0, sizeof(request->u));
		request->u.functional_type = (host.ifr_flags & IFF_LOOPBACK)
				? IFRTYPE_FUNCTIONAL_LOOPBACK
				: type == 1 ? IFRTYPE_FUNCTIONAL_WIRED
					    : IFRTYPE_FUNCTIONAL_UNKNOWN;
		return 0;
	}
	case xnu_SIOCGIFADDR:
	case xnu_SIOCGIFNETMASK:
	case xnu_SIOCGIFBRDADDR:
	case xnu_SIOCGIFDSTADDR: {
		struct sockaddr_storage address;
		bool netmask = command == xnu_SIOCGIFNETMASK;
		if (command == xnu_SIOCGIFBRDADDR
				|| command == xnu_SIOCGIFDSTADDR) {
			error = host_interface_ioctl(
					command == xnu_SIOCGIFBRDADDR
							? SIOCGIFBRDADDR
							: SIOCGIFDSTADDR,
					name, &host);
			if (error != 0) {
				return error;
			}
			memcpy(&address, &host.ifr_addr, sizeof(host.ifr_addr));
		} else if (!interface_address(name, AF_INET, is_primary,
					   (struct sockaddr *)&address,
					   netmask)) {
			return if_nametoindex(name) == 0 ? _ENXIO
							 : _EADDRNOTAVAIL;
		}
		memcpy(request->u.sockaddr, &address, 16);
		request->u.sockaddr[0] = 16;
		request->u.sockaddr[1] = xnu_AF_INET;
		return 0;
	}
	case xnu_SIOCGIFAFLAG_IN6:
	case xnu_SIOCGIFALIFETIME_IN6:
		if (if_nametoindex(name) == 0) {
			return _ENXIO;
		}
		memset((uint8_t *)data + IFNAMSIZ, 0, 0x120 - IFNAMSIZ);
		return 0;
	case xnu_SIOCGIFMEDIA:
	case xnu_SIOCGIFXMEDIA: {
		struct xnu_ifmediareq *media = data;
		error = host_interface_ioctl(SIOCGIFFLAGS, name, &host);
		if (error != 0) {
			return error;
		}
		if (read_sys_number(name, "type", 0) != 1) {
			return _EOPNOTSUPP;
		}
		int subtype;
		switch (read_sys_number(name, "speed", 0)) {
		case 10:
			subtype = IFM_10_T;
			break;
		case 100:
			subtype = IFM_100_TX;
			break;
		case 1000:
			subtype = IFM_1000_T;
			break;
		case 2500:
			subtype = IFM_2500_T;
			break;
		case 5000:
			subtype = IFM_5000_T;
			break;
		case 10000:
			subtype = IFM_10G_T;
			break;
		default:
			subtype = IFM_AUTO;
			break;
		}
		bool full = subtype != IFM_AUTO;
		char duplex[16] = "";
		char path[256];
		snprintf(path, sizeof(path), "/sys/class/net/%s/duplex", name);
		FILE *file = fopen(path, "r");
		if (file != NULL) {
			full = fscanf(file, "%15s", duplex) == 1
					&& strcmp(duplex, "full") == 0;
			fclose(file);
		}
		media->ifm_current = IFM_ETHER | IFM_AUTO;
		media->ifm_mask = 0;
		media->ifm_status = IFM_AVALID
				| (read_sys_number(name, "carrier", 0) == 1
								? IFM_ACTIVE
								: 0);
		media->ifm_active = IFM_ETHER | subtype | (full ? IFM_FDX : 0);
		if (media->ifm_count > 0 && media->ifm_ulist != NULL) {
			media->ifm_ulist[0] = IFM_ETHER | IFM_AUTO;
		}
		media->ifm_count = 1;
		return 0;
	}
	default:
		if (!(command & xnu_IOC_OUT)) {
			return 0;
		}
#ifdef ENABLE_STRACE
		fprintf(stderr, "  ioctl: no interface ioctl %#llx\n",
				(unsigned long long)command);
#endif
		return _EOPNOTSUPP;
	}
}

static int
bpf_ioctl(int fd, uint64_t command, void *data)
{
	struct bpf_device *device = &bpf_devices[fd];
	switch (command) {
	case xnu_BIOCGBLEN:
		*(uint32_t *)data = device->buffer_size;
		return 0;
	case xnu_BIOCSBLEN: {
		uint32_t size = *(uint32_t *)data;
		if (size < 32) {
			size = 32;
		} else if (size > BPF_MAX_BUFSIZE) {
			size = BPF_MAX_BUFSIZE;
		}
		device->buffer_size = size;
		*(uint32_t *)data = size;
		return 0;
	}
	case xnu_BIOCSETIF: {
		char name[IFNAMSIZ + 1] = {0};
		memcpy(name, data, IFNAMSIZ);
		unsigned int index = if_nametoindex(name);
		if (index == 0) {
			return _ENXIO;
		}
		struct sockaddr_ll address = {
				.sll_family = AF_PACKET,
				.sll_protocol = htons(ETH_P_ALL),
				.sll_ifindex = (int)index,
		};
		if (bind(fd, (struct sockaddr *)&address, sizeof(address))
				== -1) {
			return err_map(errno);
		}
		memcpy(device->interface, name, IFNAMSIZ);
		return 0;
	}
	case xnu_BIOCGETIF:
		if (device->interface[0] == '\0') {
			return _EINVAL;
		}
		memset(data, 0, 32);
		memcpy(data, device->interface, IFNAMSIZ);
		return 0;
	case xnu_BIOCSETF: {
		const struct xnu_bpf_program *program = data;
		struct sock_fprog host = {
				.len = (unsigned short)program->bf_len,
				.filter = program->bf_insns,
		};
		if (program->bf_insns == NULL) {
			setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
			return 0;
		}
		return errno_map(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
				&host, sizeof(host)));
	}
	case xnu_BIOCGDLT:
		if (device->interface[0] == '\0') {
			return _EINVAL;
		}
		*(uint32_t *)data = DLT_EN10MB;
		return 0;
	case xnu_BIOCVERSION:
		((uint16_t *)data)[0] = 1;
		((uint16_t *)data)[1] = 1;
		return 0;
	case xnu_BIOCGSEESENT: {
		int ignore = 0;
		socklen_t length = sizeof(ignore);
		getsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore,
				&length);
		*(uint32_t *)data = !ignore;
		return 0;
	}
	case xnu_BIOCSSEESENT: {
		int ignore = *(uint32_t *)data == 0;
		return errno_map(setsockopt(fd, SOL_PACKET,
				PACKET_IGNORE_OUTGOING, &ignore,
				sizeof(ignore)));
	}
	case xnu_BIOCFLUSH: {
		uint8_t discard[64];
		while (recv(fd, discard, sizeof(discard), MSG_DONTWAIT) >= 0) {
		}
		return 0;
	}
	case xnu_BIOCPROMISC:
		return 0;
	default:
		if (!(command & xnu_IOC_OUT)) {
			return 0;
		}
#ifdef ENABLE_STRACE
		fprintf(stderr, "  ioctl: no BPF ioctl %#llx\n",
				(unsigned long long)command);
#endif
		return _EINVAL;
	}
}

static int
host_interface_ioctl(unsigned long command, const char *name, struct ifreq *out)
{
	memset(out, 0, sizeof(*out));
	snprintf(out->ifr_name, sizeof(out->ifr_name), "%s", name);
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		return err_map(errno);
	}
	int result = ioctl(fd, command, out);
	int error = errno;
	close(fd);
	if (result == -1) {
		return error == ENODEV ? _ENXIO : err_map(error);
	}
	return 0;
}

static unsigned int
read_ipv6_number(const char *directory, const char *name, const char *setting,
		unsigned int fallback)
{
	char path[256];
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/%s/%s/%s", directory,
			name, setting);
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		return fallback;
	}
	unsigned int value = fallback;
	if (fscanf(file, "%u", &value) != 1) {
		value = fallback;
	}
	fclose(file);
	return value;
}

static bool
interface_address(const char *name, int family,
		bool (*pick)(const struct ifaddrs *), struct sockaddr *out,
		bool netmask)
{
	struct ifaddrs *list;
	if (getifaddrs(&list) == -1) {
		return false;
	}
	bool found = false;
	for (struct ifaddrs *entry = list; entry != NULL && !found;
			entry = entry->ifa_next) {
		if (entry->ifa_addr != NULL
				&& entry->ifa_addr->sa_family == family
				&& strcmp(entry->ifa_name, name) == 0
				&& pick(entry)) {
			const struct sockaddr *source = netmask
					? entry->ifa_netmask
					: entry->ifa_addr;
			memcpy(out, source,
					family == AF_INET
							? sizeof(struct sockaddr_in)
							: sizeof(struct sockaddr_in6));
			found = true;
		}
	}
	freeifaddrs(list);
	return found;
}

static bool
is_primary(const struct ifaddrs *entry)
{
	(void)entry;
	return true;
}

bool
net_is_bpf_path(const char *path)
{
	if (strncmp(path, "/dev/bpf", 8) != 0 || path[8] == '\0') {
		return false;
	}
	for (const char *digit = path + 8; *digit != '\0'; digit++) {
		if (!isdigit((unsigned char)*digit)) {
			return false;
		}
	}
	return true;
}

int
net_bpf_open(bool nonblocking, bool cloexec)
{
	if (geteuid() != 0) {
		return _EACCES;
	}
	int fd = socket(AF_PACKET,
			SOCK_RAW | (nonblocking ? SOCK_NONBLOCK : 0)
					| (cloexec ? SOCK_CLOEXEC : 0),
			0);
	if (fd == -1) {
		return err_map(errno);
	}
	if ((size_t)fd >= sizeof(bpf_devices) / sizeof(*bpf_devices)) {
		close(fd);
		return _EMFILE;
	}
	bpf_devices[fd] = (struct bpf_device){
			.open = true,
			.buffer_size = BPF_DEFAULT_BUFSIZE,
	};
	return fd;
}

bool
net_is_bpf(int fd)
{
	return fd >= 0
			&& (size_t)fd
			< sizeof(bpf_devices) / sizeof(*bpf_devices)
			&& bpf_devices[fd].open;
}

void
net_close(int fd)
{
	if (net_is_bpf(fd)) {
		bpf_devices[fd].open = false;
	}
}

long
net_bpf_read(int fd, void *buffer, size_t size)
{
	struct bpf_device *device = &bpf_devices[fd];
	if (size < device->buffer_size) {
		return _EINVAL;
	}
	uint8_t *out = buffer;
	size_t used = 0;
	for (;;) {
		size_t header = BPF_HEADER_SIZE;
		if (used + header >= size) {
			break;
		}
		ssize_t length = recv(fd, out + used + header,
				size - used - header,
				MSG_TRUNC | (used != 0 ? MSG_DONTWAIT : 0));
		if (length < 0) {
			if (used != 0) {
				break;
			}
			return err_map(errno);
		}
		size_t captured = (size_t)length < size - used - header
				? (size_t)length
				: size - used - header;
		struct timeval now;
		gettimeofday(&now, NULL);
		struct xnu_bpf_hdr record = {
				.bh_tstamp
				= {(int32_t)now.tv_sec, (int32_t)now.tv_usec},
				.bh_caplen = (uint32_t)captured,
				.bh_datalen = (uint32_t)length,
				.bh_hdrlen = (uint16_t)header,
		};
		memcpy(out + used, &record, header);
		used += BPF_WORDALIGN(header + captured);
	}
	return (long)(used < size ? used : size);
}
