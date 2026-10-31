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
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "codesign.h"
#include "necp.h"
#include "route.h"
#include "sha.h"
#include "xnu-errno.h"

#define xnu_AF_INET  2
#define xnu_AF_INET6 30

#define NECP_CLIENT_ACTION_ADD                       1
#define NECP_CLIENT_ACTION_REMOVE                    2
#define NECP_CLIENT_ACTION_COPY_PARAMETERS           3
#define NECP_CLIENT_ACTION_COPY_RESULT               4
#define NECP_CLIENT_ACTION_COPY_LIST                 5
#define NECP_CLIENT_ACTION_AGENT                     7
#define NECP_CLIENT_ACTION_COPY_AGENT                8
#define NECP_CLIENT_ACTION_AGENT_USE                 12
#define NECP_CLIENT_ACTION_COPY_CLIENT_UPDATE        15
#define NECP_CLIENT_ACTION_SIGN                      20
#define NECP_CLIENT_ACTION_GET_INTERFACE_ADDRESS     21
#define NECP_CLIENT_ACTION_ACQUIRE_AGENT_TOKEN       22
#define NECP_CLIENT_ACTION_VALIDATE                  23
#define NECP_CLIENT_ACTION_COPY_INTERFACE            9
#define NECP_CLIENT_ACTION_COPY_ROUTE_STATISTICS     11
#define NECP_CLIENT_ACTION_UPDATE_CACHE              14
#define NECP_CLIENT_ACTION_ADD_FLOW                  17
#define NECP_CLIENT_ACTION_REMOVE_FLOW               18
#define NECP_CLIENT_ACTION_COPY_UPDATED_RESULT       16
#define NECP_CLIENT_ACTION_CLAIM                     19
#define NECP_CLIENT_ACTION_COPY_UPDATED_RESULT_FINAL 26

#define NECP_CLIENT_PARAMETER_BOUND_INTERFACE 9
#define NECP_CLIENT_PARAMETER_REMOTE_ENDPOINT 201
#define NECP_CLIENT_PARAMETER_FLAGS           250
#define NECP_CLIENT_PARAMETER_FLAG_LISTENER   0x0008

#define NECP_CLIENT_RESULT_CLIENT_ID       1
#define NECP_CLIENT_RESULT_POLICY_RESULT   2
#define NECP_CLIENT_RESULT_INTERFACE_INDEX 5
#define NECP_CLIENT_RESULT_FLAGS           7
#define NECP_CLIENT_RESULT_INTERFACE       8
#define NECP_CLIENT_RESULT_EFFECTIVE_MTU   10
#define NECP_CLIENT_RESULT_GATEWAY         212

#define NECP_CLIENT_RESULT_FLAG_IS_LOCAL  0x0001
#define NECP_CLIENT_RESULT_FLAG_IS_DIRECT 0x0002
#define NECP_CLIENT_RESULT_FLAG_HAS_IPV4  0x0004
#define NECP_CLIENT_RESULT_FLAG_HAS_IPV6  0x0008
#define NECP_CLIENT_RESULT_FLAG_SATISFIED 0x0020

#define NECP_KERNEL_POLICY_RESULT_NONE 0

#define NECP_INTERFACE_FLAG_HAS_NETMASK        0x0080
#define NECP_INTERFACE_FLAG_HAS_BROADCAST      0x0100
#define NECP_INTERFACE_FLAG_SUPPORTS_MULTICAST 0x0200
#define NECP_INTERFACE_FLAG_IPV4_ROUTABLE      0x1000
#define NECP_INTERFACE_FLAG_IPV6_ROUTABLE      0x2000

#define IFRTYPE_FUNCTIONAL_UNKNOWN  0
#define IFRTYPE_FUNCTIONAL_LOOPBACK 1
#define IFRTYPE_FUNCTIONAL_WIRED    2

#define NECP_MAX_CLIENT_PARAMETERS_SIZE 8192

#define NECP_OPEN_FLAG_OBSERVER      0x01
#define NECP_OPEN_FLAG_PUSH_OBSERVER 0x04

#define NECP_SESSION_ACTION_POLICY_ADD                1
#define NECP_SESSION_ACTION_POLICY_GET                2
#define NECP_SESSION_ACTION_POLICY_DELETE             3
#define NECP_SESSION_ACTION_POLICY_APPLY_ALL          4
#define NECP_SESSION_ACTION_POLICY_LIST_ALL           5
#define NECP_SESSION_ACTION_POLICY_DELETE_ALL         6
#define NECP_SESSION_ACTION_SET_SESSION_PRIORITY      7
#define NECP_SESSION_ACTION_LOCK_SESSION_TO_PROC      8
#define NECP_SESSION_ACTION_REGISTER_SERVICE          9
#define NECP_SESSION_ACTION_UNREGISTER_SERVICE        10
#define NECP_SESSION_ACTION_POLICY_DUMP_ALL           11
#define NECP_SESSION_ACTION_ADD_DOMAIN_FILTER         12
#define NECP_SESSION_ACTION_REMOVE_DOMAIN_FILTER      13
#define NECP_SESSION_ACTION_REMOVE_ALL_DOMAIN_FILTERS 14
#define NECP_SESSION_ACTION_ADD_DOMAIN_TRIE           15
#define NECP_SESSION_ACTION_REMOVE_DOMAIN_TRIE        16
#define NECP_SESSION_ACTION_REMOVE_ALL_DOMAIN_TRIES   17
#define NECP_SESSION_ACTION_TRIE_DUMP_ALL             18
#define NECP_TLV_POLICY_ID                            5

#define NECP_CLIENT_SIGN_TYPE_RESOLVER_ANSWER                1
#define NECP_CLIENT_SIGN_TYPE_BROWSE_RESULT                  2
#define NECP_CLIENT_SIGN_TYPE_SERVICE_RESOLVER_ANSWER        3
#define NECP_CLIENT_SIGN_TYPE_SYSTEM_RESOLVER_ANSWER         4
#define NECP_CLIENT_SIGN_TYPE_SYSTEM_BROWSE_RESULT           5
#define NECP_CLIENT_SIGN_TYPE_SYSTEM_SERVICE_RESOLVER_ANSWER 6
#define NECP_CLIENT_ACTION_SIGN_MAX_STRING_LENGTH            1024
#define NECP_CLIENT_ACTION_SIGN_TAG_LENGTH                   32
#define NECP_CLIENT_ACTION_SIGN_MAX_TOTAL_LENGTH             4096
#define NECP_SIGNABLE_HEADER_SIZE                            20

struct __attribute__((packed)) necp_tlv_header {
	uint8_t type;
	uint32_t length;
};

struct necp_interface_signature {
	uint8_t signature[20];
	uint8_t signature_len;
};

struct necp_interface_details {
	char name[24];
	uint32_t index;
	uint32_t generation;
	uint32_t functional_type;
	uint32_t delegate_index;
	uint32_t flags;
	uint32_t mtu;
	struct necp_interface_signature ipv4_signature;
	struct necp_interface_signature ipv6_signature;
	uint32_t ipv4_netmask;
	uint32_t ipv4_broadcast;
	uint32_t tso_max_segment_size_v4;
	uint32_t tso_max_segment_size_v6;
	uint32_t hwcsum_flags;
	uint8_t radio_type;
	uint8_t radio_channel;
	uint8_t l4s_mode;
};

_Static_assert(sizeof(struct necp_interface_details) == 116,
		"necp_interface_details");

struct route {
	unsigned int interface;
	unsigned char type;
	int family;
	uint8_t gateway[16];
	bool has_gateway;
};

struct client {
	struct client *next;
	uint8_t id[16];
	uint8_t *parameters;
	size_t parameters_length;
	uint8_t result[512];
	size_t result_length;
	bool result_read;
};

struct policy {
	struct policy *next;
	uint32_t id;
	uint8_t *tlvs;
	size_t length;
};

static struct necp_fd {
	bool open;
	int flags;
	struct client *clients;
	bool session;
	struct policy *policies;
	uint32_t priority;
	uint32_t next_id;
} necp_fds[1024];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void network_changed(void);
static void compute_result(struct client *client);
static bool route_get(int family, const void *destination,
		unsigned int interface, struct route *out);
static bool interface_has_family(unsigned int index, int family);
static uint8_t *write_tlv(uint8_t *cursor, uint8_t *end, uint8_t type,
		const void *value, uint32_t length);
static unsigned int interface_mtu(unsigned int index);
static void update_readable(int fd);
static bool is_necp(int fd);
static struct client *find_client(struct necp_fd *necp, const uint8_t *id);
static long copy_interface(uint32_t index, uint8_t *buffer, size_t size);
static long interface_address(const uint8_t *index_buffer, size_t index_length,
		uint8_t *buffer, size_t size);
static long sign_answer(const uint8_t *signable, size_t length, uint8_t *tag,
		size_t size);
static size_t signable_length(const uint8_t *signable, size_t length);
static void sign_tag(const uint8_t *signable, size_t length,
		uint8_t tag[SHA256_DIGEST_LENGTH]);
static void signing_key(uint8_t key[SHA256_DIGEST_LENGTH]);
static long validate_answer(const uint8_t *validatable, size_t length);
static long reply_id(uint8_t *out, size_t out_length, uint32_t id);
static struct policy **find_policy(struct necp_fd *session, uint32_t id);

int
necp_open(int flags)
{
	if ((flags & (NECP_OPEN_FLAG_OBSERVER | NECP_OPEN_FLAG_PUSH_OBSERVER))
			&& geteuid() != 0
			&& !codesign_entitled(getpid(),
					"com.apple.private.network."
					"statistics")) {
		return _EACCES;
	}
	int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fd == -1) {
		return err_map(errno);
	}
	if ((size_t)fd >= sizeof(necp_fds) / sizeof(*necp_fds)) {
		close(fd);
		return _EMFILE;
	}
	pthread_mutex_lock(&lock);
	necp_fds[fd] = (struct necp_fd){.open = true, .flags = flags};
	pthread_mutex_unlock(&lock);
	static bool watching;
	if (!__atomic_exchange_n(&watching, true, __ATOMIC_RELAXED)) {
		route_watch(network_changed);
	}
	return fd;
}

static void
network_changed(void)
{
	pthread_mutex_lock(&lock);
	for (size_t fd = 0; fd < sizeof(necp_fds) / sizeof(*necp_fds); fd++) {
		struct necp_fd *necp = &necp_fds[fd];
		if (!necp->open || necp->session) {
			continue;
		}
		for (struct client *client = necp->clients; client != NULL;
				client = client->next) {
			uint8_t previous[sizeof(client->result)];
			size_t previous_length = client->result_length;
			bool read = client->result_read;
			memcpy(previous, client->result, previous_length);
			compute_result(client);
			client->result_read = read
					&& previous_length
							== client->result_length
					&& memcmp(previous, client->result,
							   previous_length)
							== 0;
		}
		update_readable((int)fd);
	}
	pthread_mutex_unlock(&lock);
}

static void
compute_result(struct client *client)
{
	uint32_t flags = 0;
	uint32_t client_flags = 0;
	unsigned int bound = 0;
	int family = 0;
	uint8_t destination[16] = {0};
	uint16_t port = 0;

	for (size_t offset = 0; offset + sizeof(struct necp_tlv_header)
			<= client->parameters_length;) {
		struct necp_tlv_header header;
		memcpy(&header, client->parameters + offset, sizeof(header));
		const uint8_t *value
				= client->parameters + offset + sizeof(header);
		if (offset + sizeof(header) + header.length
				> client->parameters_length) {
			break;
		}
		if (header.type == NECP_CLIENT_PARAMETER_FLAGS
				&& header.length >= sizeof(uint32_t)) {
			memcpy(&client_flags, value, sizeof(client_flags));
		} else if (header.type == NECP_CLIENT_PARAMETER_BOUND_INTERFACE
				&& header.length > 0) {
			char name[IF_NAMESIZE + 1] = {0};
			memcpy(name, value,
					header.length < IF_NAMESIZE
							? header.length
							: IF_NAMESIZE);
			bound = if_nametoindex(name);
		} else if (header.type == NECP_CLIENT_PARAMETER_REMOTE_ENDPOINT
				&& header.length >= 8) {
			memcpy(&port, value + 2, sizeof(port));
			if (value[1] == xnu_AF_INET && header.length >= 8) {
				family = AF_INET;
				memcpy(destination, value + 4, 4);
			} else if (value[1] == xnu_AF_INET6
					&& header.length >= 24) {
				family = AF_INET6;
				memcpy(destination, value + 8, 16);
			}
		}
		offset += sizeof(header) + header.length;
	}

	struct route route = {0};
	bool routed = false;
	if (family != 0) {
		routed = route_get(family, destination, bound, &route);
	} else {
		static const uint8_t v4[4] = {192, 0, 2, 1};
		static const uint8_t v6[16]
				= {0x20, 0x01, 0x0d, 0xb8, [15] = 1};
		routed = route_get(AF_INET, v4, bound, &route)
				|| route_get(AF_INET6, v6, bound, &route);
	}
	if (routed) {
		if (interface_has_family(route.interface, AF_INET)) {
			flags |= NECP_CLIENT_RESULT_FLAG_HAS_IPV4;
		}
		if (interface_has_family(route.interface, AF_INET6)) {
			flags |= NECP_CLIENT_RESULT_FLAG_HAS_IPV6;
		}
		if (family != 0 && route.type == RTN_LOCAL) {
			flags |= NECP_CLIENT_RESULT_FLAG_IS_LOCAL;
		} else if (family != 0 && !route.has_gateway) {
			flags |= NECP_CLIENT_RESULT_FLAG_IS_DIRECT;
		}
	}
	if ((client_flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) || routed) {
		flags |= NECP_CLIENT_RESULT_FLAG_SATISFIED;
	}

	uint8_t *cursor = client->result;
	uint8_t *end = client->result + sizeof(client->result);
	cursor = write_tlv(cursor, end, NECP_CLIENT_RESULT_FLAGS, &flags,
			sizeof(flags));
	cursor = write_tlv(cursor, end, NECP_CLIENT_RESULT_CLIENT_ID,
			client->id, sizeof(client->id));
	uint32_t policy = NECP_KERNEL_POLICY_RESULT_NONE;
	cursor = write_tlv(cursor, end, NECP_CLIENT_RESULT_POLICY_RESULT,
			&policy, sizeof(policy));
	if (routed) {
		uint32_t index = route.interface;
		cursor = write_tlv(cursor, end,
				NECP_CLIENT_RESULT_INTERFACE_INDEX, &index,
				sizeof(index));
		uint32_t mtu = interface_mtu(route.interface);
		if (mtu != 0) {
			cursor = write_tlv(cursor, end,
					NECP_CLIENT_RESULT_EFFECTIVE_MTU, &mtu,
					sizeof(mtu));
		}
		if (family != 0 && route.has_gateway) {
			uint8_t gateway[28] = {0};
			if (route.family == AF_INET) {
				gateway[0] = 16;
				gateway[1] = xnu_AF_INET;
				memcpy(gateway + 4, route.gateway, 4);
				cursor = write_tlv(cursor, end,
						NECP_CLIENT_RESULT_GATEWAY,
						gateway, 16);
			} else {
				gateway[0] = 28;
				gateway[1] = xnu_AF_INET6;
				memcpy(gateway + 8, route.gateway, 16);
				cursor = write_tlv(cursor, end,
						NECP_CLIENT_RESULT_GATEWAY,
						gateway, 28);
			}
		}
		uint32_t interface[2] = {route.interface, route.interface};
		cursor = write_tlv(cursor, end, NECP_CLIENT_RESULT_INTERFACE,
				interface, sizeof(interface));
	}
	client->result_length = (size_t)(cursor - client->result);
	client->result_read = false;
#ifdef ENABLE_STRACE
	char text[INET6_ADDRSTRLEN] = "-";
	if (family != 0) {
		inet_ntop(family, destination, text, sizeof(text));
	}
	fprintf(stderr,
			"  necp: client for %s port %u: flags %#x, interface "
			"%u\n",
			text, ntohs(port), flags, routed ? route.interface : 0);
#endif
}

static bool
route_get(int family, const void *destination, unsigned int interface,
		struct route *out)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd == -1) {
		return false;
	}
	struct {
		struct nlmsghdr header;
		struct rtmsg message;
		uint8_t attributes[64];
	} request = {0};
	size_t address_length = family == AF_INET ? 4 : 16;
	request.header.nlmsg_type = RTM_GETROUTE;
	request.header.nlmsg_flags = NLM_F_REQUEST;
	request.header.nlmsg_seq = 1;
	request.message.rtm_family = (unsigned char)family;
	request.message.rtm_dst_len = (unsigned char)(address_length * 8);
	struct rtattr *attribute = (struct rtattr *)request.attributes;
	attribute->rta_type = RTA_DST;
	attribute->rta_len = (unsigned short)RTA_LENGTH(address_length);
	memcpy(RTA_DATA(attribute), destination, address_length);
	size_t length = RTA_ALIGN(attribute->rta_len);
	if (interface != 0) {
		attribute = (struct rtattr *)(request.attributes + length);
		attribute->rta_type = RTA_OIF;
		attribute->rta_len = RTA_LENGTH(sizeof(uint32_t));
		uint32_t index = interface;
		memcpy(RTA_DATA(attribute), &index, sizeof(index));
		length += RTA_ALIGN(attribute->rta_len);
	}
	request.header.nlmsg_len
			= (uint32_t)(NLMSG_LENGTH(sizeof(request.message))
					+ length);

	bool found = false;
	uint8_t reply[4096] __attribute__((aligned(4)));
	ssize_t received = -1;
	if (send(fd, &request, request.header.nlmsg_len, 0) != -1) {
		received = recv(fd, reply, sizeof(reply), 0);
	}
	close(fd);
	if (received <= 0) {
		return false;
	}
	struct nlmsghdr *header = (struct nlmsghdr *)reply;
	if (!NLMSG_OK(header, (size_t)received)
			|| header->nlmsg_type != RTM_NEWROUTE) {
		return false;
	}
	struct rtmsg *message = NLMSG_DATA(header);
	*out = (struct route){.family = family, .type = message->rtm_type};
	size_t remaining = RTM_PAYLOAD(header);
	for (struct rtattr *a = RTM_RTA(message); RTA_OK(a, remaining);
			a = RTA_NEXT(a, remaining)) {
		if (a->rta_type == RTA_OIF) {
			uint32_t index;
			memcpy(&index, RTA_DATA(a), sizeof(index));
			out->interface = index;
			found = true;
		} else if (a->rta_type == RTA_GATEWAY
				&& RTA_PAYLOAD(a) == address_length) {
			memcpy(out->gateway, RTA_DATA(a), address_length);
			out->has_gateway = true;
		}
	}
	return found && message->rtm_type != RTN_UNREACHABLE;
}

static bool
interface_has_family(unsigned int index, int family)
{
	struct ifaddrs *list;
	if (getifaddrs(&list) == -1) {
		return false;
	}
	bool found = false;
	for (struct ifaddrs *entry = list; entry != NULL;
			entry = entry->ifa_next) {
		if (entry->ifa_addr == NULL
				|| entry->ifa_addr->sa_family != family
				|| if_nametoindex(entry->ifa_name) != index) {
			continue;
		}
		if (family == AF_INET6
				&& IN6_IS_ADDR_LINKLOCAL(&(
						(struct sockaddr_in6 *)
								entry->ifa_addr)
								->sin6_addr)) {
			continue;
		}
		found = true;
	}
	freeifaddrs(list);
	return found;
}

static uint8_t *
write_tlv(uint8_t *cursor, uint8_t *end, uint8_t type, const void *value,
		uint32_t length)
{
	if (cursor + sizeof(struct necp_tlv_header) + length > end) {
		return cursor;
	}
	struct necp_tlv_header header = {.type = type, .length = length};
	memcpy(cursor, &header, sizeof(header));
	memcpy(cursor + sizeof(header), value, length);
	return cursor + sizeof(header) + length;
}

static unsigned int
interface_mtu(unsigned int index)
{
	char name[IF_NAMESIZE];
	if (if_indextoname(index, name) == NULL) {
		return 0;
	}
	char path[64];
	snprintf(path, sizeof(path), "/sys/class/net/%s/mtu", name);
	FILE *file = fopen(path, "r");
	unsigned int mtu = 0;
	if (file != NULL) {
		if (fscanf(file, "%u", &mtu) != 1) {
			mtu = 0;
		}
		fclose(file);
	}
	return mtu;
}

static void
update_readable(int fd)
{
	bool unread = false;
	for (struct client *client = necp_fds[fd].clients; client != NULL;
			client = client->next) {
		unread |= !client->result_read;
	}
	eventfd_t value;
	if (unread) {
		eventfd_write(fd, 1);
	} else {
		eventfd_read(fd, &value);
	}
}

void
necp_close(int fd)
{
	pthread_mutex_lock(&lock);
	if (is_necp(fd)) {
		struct client *client = necp_fds[fd].clients;
		while (client != NULL) {
			struct client *next = client->next;
			free(client->parameters);
			free(client);
			client = next;
		}
		struct policy *policy = necp_fds[fd].policies;
		while (policy != NULL) {
			struct policy *next = policy->next;
			free(policy->tlvs);
			free(policy);
			policy = next;
		}
		necp_fds[fd] = (struct necp_fd){0};
	}
	pthread_mutex_unlock(&lock);
}

static bool
is_necp(int fd)
{
	return fd >= 0 && (size_t)fd < sizeof(necp_fds) / sizeof(*necp_fds)
			&& necp_fds[fd].open;
}

long
necp_client_action(int fd, uint32_t action, uint8_t *client_id,
		size_t client_id_length, uint8_t *buffer, size_t buffer_size)
{
	pthread_mutex_lock(&lock);
	if (!is_necp(fd) || necp_fds[fd].session) {
		pthread_mutex_unlock(&lock);
		return _EBADF;
	}
	struct necp_fd *necp = &necp_fds[fd];
	long result = 0;
	switch (action) {
	case NECP_CLIENT_ACTION_ADD: {
		if (necp->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
			result = _EINVAL;
			break;
		}
		if (client_id == NULL || client_id_length != 16
				|| buffer == NULL || buffer_size == 0
				|| buffer_size > NECP_MAX_CLIENT_PARAMETERS_SIZE) {
			result = _EINVAL;
			break;
		}
		struct client *client = calloc(1, sizeof(*client));
		getrandom(client->id, sizeof(client->id), 0);
		client->id[9] &= ~0x01;
		client->parameters = malloc(buffer_size);
		memcpy(client->parameters, buffer, buffer_size);
		client->parameters_length = buffer_size;
		compute_result(client);
		client->next = necp->clients;
		necp->clients = client;
		memcpy(client_id, client->id, 16);
		break;
	}
	case NECP_CLIENT_ACTION_CLAIM:
		result = find_client(necp, client_id) != NULL ? 0 : _ENOENT;
		break;
	case NECP_CLIENT_ACTION_REMOVE: {
		result = _ENOENT;
		for (struct client **link = &necp->clients; *link != NULL;
				link = &(*link)->next) {
			if (client_id != NULL
					&& memcmp((*link)->id, client_id, 16)
							== 0) {
				struct client *client = *link;
				*link = client->next;
				free(client->parameters);
				free(client);
				result = 0;
				break;
			}
		}
		break;
	}
	case NECP_CLIENT_ACTION_COPY_PARAMETERS:
	case NECP_CLIENT_ACTION_COPY_RESULT:
	case NECP_CLIENT_ACTION_COPY_UPDATED_RESULT:
	case NECP_CLIENT_ACTION_COPY_UPDATED_RESULT_FINAL: {
		if (buffer == NULL || buffer_size == 0) {
			result = _EINVAL;
			break;
		}
		static const uint8_t wildcard[16];
		bool any = client_id == NULL
				|| memcmp(client_id, wildcard, 16) == 0;
		struct client *client = NULL;
		if (any && action != NECP_CLIENT_ACTION_COPY_PARAMETERS) {
			for (client = necp->clients;
					client != NULL && client->result_read;
					client = client->next) {
			}
		} else if (!any) {
			client = find_client(necp, client_id);
		}
		if (client == NULL) {
			result = any ? 0 : _ENOENT;
			break;
		}
		if (action == NECP_CLIENT_ACTION_COPY_PARAMETERS) {
			if (buffer_size < client->parameters_length) {
				result = _EINVAL;
				break;
			}
			memcpy(buffer, client->parameters,
					client->parameters_length);
			result = (long)client->parameters_length;
			break;
		}
		if (action != NECP_CLIENT_ACTION_COPY_RESULT
				&& client->result_read) {
			result = 0;
			break;
		}
		if (buffer_size < client->result_length) {
			if (action == NECP_CLIENT_ACTION_COPY_UPDATED_RESULT_FINAL) {
				client->result_read = true;
			}
			result = _EINVAL;
			break;
		}
		memcpy(buffer, client->result, client->result_length);
		client->result_read = true;
		result = (long)client->result_length;
		break;
	}
	case NECP_CLIENT_ACTION_COPY_LIST: {
		uint32_t count = 0;
		for (struct client *client = necp->clients; client != NULL;
				client = client->next) {
			count++;
		}
		size_t needed = sizeof(uint32_t) + 16 * (size_t)count;
		if (buffer == NULL || buffer_size < needed) {
			result = _EINVAL;
			break;
		}
		memcpy(buffer, &count, sizeof(count));
		size_t offset = sizeof(count);
		for (struct client *client = necp->clients; client != NULL;
				client = client->next) {
			memcpy(buffer + offset, client->id, 16);
			offset += 16;
		}
		result = (long)needed;
		break;
	}
	case NECP_CLIENT_ACTION_COPY_INTERFACE: {
		uint32_t index = 0;
		if (client_id == NULL || client_id_length != sizeof(index)) {
			result = _EINVAL;
			break;
		}
		memcpy(&index, client_id, sizeof(index));
		result = copy_interface(index, buffer, buffer_size);
		break;
	}
	case NECP_CLIENT_ACTION_UPDATE_CACHE:
		break;
	case NECP_CLIENT_ACTION_ADD_FLOW: {
		if (client_id == NULL || client_id_length != 16
				|| buffer == NULL || buffer_size < 36) {
			result = _EINVAL;
			break;
		}
		if (find_client(necp, client_id) == NULL) {
			result = _ENOENT;
			break;
		}
		static const uint8_t none[16];
		if (memcmp(buffer, none, 16) != 0) {
			result = _ENOTSUP;
			break;
		}
		uint8_t *registration = buffer + 16;
		getrandom(registration, 16, 0);
		registration[9] |= 0x01;
		break;
	}
	case NECP_CLIENT_ACTION_REMOVE_FLOW:
		break;
	case NECP_CLIENT_ACTION_COPY_ROUTE_STATISTICS:
		if (buffer == NULL) {
			result = _EINVAL;
			break;
		}
		memset(buffer, 0, buffer_size);
		break;
	case NECP_CLIENT_ACTION_AGENT:
	case NECP_CLIENT_ACTION_AGENT_USE:
		if (client_id == NULL || client_id_length != 16
				|| buffer == NULL || buffer_size == 0) {
			result = _EINVAL;
		} else {
			result = _ENOENT;
		}
		break;
	case NECP_CLIENT_ACTION_COPY_AGENT:
	case NECP_CLIENT_ACTION_ACQUIRE_AGENT_TOKEN:
		result = client_id == NULL || client_id_length != 16
						|| buffer == NULL
						|| buffer_size == 0
				? _EINVAL
				: _ENOENT;
		break;
	case NECP_CLIENT_ACTION_COPY_CLIENT_UPDATE:
		if (!(necp->flags & NECP_OPEN_FLAG_PUSH_OBSERVER)) {
			result = _EINVAL;
		} else if (client_id == NULL || client_id_length != 16
				|| buffer == NULL || buffer_size == 0) {
			result = _EINVAL;
		} else {
			result = _ENOENT;
		}
		break;
	case NECP_CLIENT_ACTION_GET_INTERFACE_ADDRESS:
		result = interface_address(client_id, client_id_length, buffer,
				buffer_size);
		break;
	case NECP_CLIENT_ACTION_SIGN:
		result = sign_answer(client_id, client_id_length, buffer,
				buffer_size);
		break;
	case NECP_CLIENT_ACTION_VALIDATE:
		result = validate_answer(client_id, client_id_length);
		break;
	default:
#ifdef ENABLE_STRACE
		fprintf(stderr,
				"  necp: no action %u, id %zu bytes, buffer "
				"%zu:",
				action, client_id_length, buffer_size);
		for (size_t i = 0; buffer != NULL && i < buffer_size && i < 160;
				i++) {
			fprintf(stderr, " %02x", buffer[i]);
		}
		fprintf(stderr, "\n");
#endif
		result = _ENOTSUP;
		break;
	}
	update_readable(fd);
	pthread_mutex_unlock(&lock);
	return result;
}

static struct client *
find_client(struct necp_fd *necp, const uint8_t *id)
{
	if (id == NULL) {
		return NULL;
	}
	for (struct client *client = necp->clients; client != NULL;
			client = client->next) {
		if (memcmp(client->id, id, 16) == 0) {
			return client;
		}
	}
	return NULL;
}

static long
copy_interface(uint32_t index, uint8_t *buffer, size_t size)
{
	struct necp_interface_details details = {0};
	if (buffer == NULL || size < sizeof(details)) {
		return _EINVAL;
	}
	if (index == 0) {
		return _ENOENT;
	}
	char name[IF_NAMESIZE];
	if (if_indextoname(index, name) != NULL) {
		snprintf(details.name, sizeof(details.name), "%s", name);
		details.index = index;
		details.generation = index;
		details.mtu = interface_mtu(index);

		static const uint8_t v4[4] = {192, 0, 2, 1};
		static const uint8_t v6[16]
				= {0x20, 0x01, 0x0d, 0xb8, [15] = 1};
		struct route route;
		if (route_get(AF_INET, v4, index, &route)
				&& route.interface == index) {
			details.flags |= NECP_INTERFACE_FLAG_IPV4_ROUTABLE;
		}
		if (route_get(AF_INET6, v6, index, &route)
				&& route.interface == index) {
			details.flags |= NECP_INTERFACE_FLAG_IPV6_ROUTABLE;
		}

		struct ifaddrs *list;
		if (getifaddrs(&list) == 0) {
			for (struct ifaddrs *entry = list; entry != NULL;
					entry = entry->ifa_next) {
				if (strcmp(entry->ifa_name, name) != 0) {
					continue;
				}
				if (entry->ifa_flags & IFF_MULTICAST) {
					details.flags |= NECP_INTERFACE_FLAG_SUPPORTS_MULTICAST;
				}
				if (entry->ifa_flags & IFF_LOOPBACK) {
					details.functional_type
							= IFRTYPE_FUNCTIONAL_LOOPBACK;
				}
				if (entry->ifa_addr == NULL
						|| entry->ifa_addr->sa_family
								!= AF_INET) {
					continue;
				}
				details.flags |= NECP_INTERFACE_FLAG_HAS_NETMASK;
				details.ipv4_netmask = ((struct sockaddr_in *)entry
									->ifa_netmask)
								       ->sin_addr
								       .s_addr;
				if ((entry->ifa_flags & IFF_BROADCAST)
						&& entry->ifa_broadaddr
								!= NULL) {
					details.flags |= NECP_INTERFACE_FLAG_HAS_BROADCAST;
					details.ipv4_broadcast
							= ((struct sockaddr_in *)entry->ifa_broadaddr)
									  ->sin_addr
									  .s_addr;
				}
			}
			freeifaddrs(list);
		}
		if (details.functional_type != IFRTYPE_FUNCTIONAL_LOOPBACK) {
			char path[64];
			snprintf(path, sizeof(path), "/sys/class/net/%s/type",
					name);
			FILE *file = fopen(path, "r");
			unsigned int type = 0;
			if (file != NULL) {
				if (fscanf(file, "%u", &type) != 1) {
					type = 0;
				}
				fclose(file);
			}
			details.functional_type = type == 1
					? IFRTYPE_FUNCTIONAL_WIRED
					: IFRTYPE_FUNCTIONAL_UNKNOWN;
		}
	}
	memcpy(buffer, &details, sizeof(details));
	return 0;
}

static long
interface_address(const uint8_t *index_buffer, size_t index_length,
		uint8_t *buffer, size_t size)
{
	uint32_t index = 0;
	if (index_buffer == NULL || index_length != sizeof(index)
			|| buffer == NULL || size < 16 || size > 128) {
		return _EINVAL;
	}
	memcpy(&index, index_buffer, sizeof(index));
	if (index == 0) {
		return _ENOENT;
	}
	int family;
	if (buffer[1] == xnu_AF_INET) {
		family = AF_INET;
	} else if (buffer[1] == xnu_AF_INET6) {
		family = AF_INET6;
	} else {
		return _EINVAL;
	}
	if (buffer[0] != size) {
		return _EINVAL;
	}
	char name[IF_NAMESIZE];
	if (if_indextoname(index, name) == NULL) {
		return _ENOENT;
	}
	int s = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s == -1) {
		return err_map(errno);
	}
	setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, name,
			(socklen_t)strlen(name));
	struct sockaddr_storage remote = {0};
	socklen_t length;
	if (family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)&remote;
		in->sin_family = AF_INET;
		memcpy(&in->sin_port, buffer + 2, 2);
		memcpy(&in->sin_addr, buffer + 4, 4);
		if (in->sin_port == 0) {
			in->sin_port = htons(9);
		}
		length = sizeof(*in);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&remote;
		in6->sin6_family = AF_INET6;
		memcpy(&in6->sin6_port, buffer + 2, 2);
		memcpy(&in6->sin6_addr, buffer + 8, 16);
		if (in6->sin6_port == 0) {
			in6->sin6_port = htons(9);
		}
		if (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
			in6->sin6_scope_id = index;
		}
		length = sizeof(*in6);
	}
	struct sockaddr_storage local;
	socklen_t local_length = sizeof(local);
	if (connect(s, (struct sockaddr *)&remote, length) == -1
			|| getsockname(s, (struct sockaddr *)&local,
					   &local_length)
					== -1) {
		close(s);
		return _EINVAL;
	}
	close(s);
	memset(buffer, 0, size);
	if (family == AF_INET) {
		if (size < 16) {
			return _EMSGSIZE;
		}
		buffer[0] = 16;
		buffer[1] = xnu_AF_INET;
		memcpy(buffer + 4, &((struct sockaddr_in *)&local)->sin_addr,
				4);
	} else {
		if (size < 28) {
			return _EMSGSIZE;
		}
		buffer[0] = 28;
		buffer[1] = xnu_AF_INET6;
		memcpy(buffer + 8, &((struct sockaddr_in6 *)&local)->sin6_addr,
				16);
		memcpy(buffer + 24,
				&((struct sockaddr_in6 *)&local)->sin6_scope_id,
				4);
	}
	return 0;
}

static long
sign_answer(const uint8_t *signable, size_t length, uint8_t *tag, size_t size)
{
	if (!codesign_entitled(
			    getpid(), "com.apple.private.validated-resolver")) {
		return _EPERM;
	}
	if (signable == NULL || length < NECP_SIGNABLE_HEADER_SIZE
			|| length > NECP_CLIENT_ACTION_SIGN_MAX_TOTAL_LENGTH
			|| tag == NULL
			|| size != NECP_CLIENT_ACTION_SIGN_TAG_LENGTH
			|| signable_length(signable, length) != length) {
		return _EINVAL;
	}
	sign_tag(signable, length, tag);
	return 0;
}

static size_t
signable_length(const uint8_t *signable, size_t length)
{
	uint32_t type;
	memcpy(&type, signable + 16, sizeof(type));
	switch (type) {
	case NECP_CLIENT_SIGN_TYPE_RESOLVER_ANSWER:
	case NECP_CLIENT_SIGN_TYPE_SYSTEM_RESOLVER_ANSWER: {
		if (length < NECP_SIGNABLE_HEADER_SIZE + 36) {
			return 0;
		}
		uint32_t hostname;
		memcpy(&hostname, signable + NECP_SIGNABLE_HEADER_SIZE + 32,
				sizeof(hostname));
		return hostname > NECP_CLIENT_ACTION_SIGN_MAX_STRING_LENGTH
				? 0
				: NECP_SIGNABLE_HEADER_SIZE + 36 + hostname;
	}
	case NECP_CLIENT_SIGN_TYPE_BROWSE_RESULT:
	case NECP_CLIENT_SIGN_TYPE_SYSTEM_BROWSE_RESULT: {
		if (length < NECP_SIGNABLE_HEADER_SIZE + 6) {
			return 0;
		}
		uint16_t service;
		memcpy(&service, signable + NECP_SIGNABLE_HEADER_SIZE + 4,
				sizeof(service));
		return service > NECP_CLIENT_ACTION_SIGN_MAX_STRING_LENGTH
				? 0
				: NECP_SIGNABLE_HEADER_SIZE + 6 + service;
	}
	case NECP_CLIENT_SIGN_TYPE_SERVICE_RESOLVER_ANSWER:
	case NECP_CLIENT_SIGN_TYPE_SYSTEM_SERVICE_RESOLVER_ANSWER: {
		if (length < NECP_SIGNABLE_HEADER_SIZE + 10) {
			return 0;
		}
		uint16_t service, hostname;
		memcpy(&service, signable + NECP_SIGNABLE_HEADER_SIZE + 4,
				sizeof(service));
		memcpy(&hostname, signable + NECP_SIGNABLE_HEADER_SIZE + 8,
				sizeof(hostname));
		return service > NECP_CLIENT_ACTION_SIGN_MAX_STRING_LENGTH
						|| hostname > NECP_CLIENT_ACTION_SIGN_MAX_STRING_LENGTH
				? 0
				: NECP_SIGNABLE_HEADER_SIZE + 10 + service
						+ hostname;
	}
	default:
		return 0;
	}
}

static void
sign_tag(const uint8_t *signable, size_t length,
		uint8_t tag[SHA256_DIGEST_LENGTH])
{
	uint8_t key[SHA256_DIGEST_LENGTH];
	signing_key(key);
	hmac_sha256(key, sizeof(key), signable, length, tag);
}

static void
signing_key(uint8_t key[SHA256_DIGEST_LENGTH])
{
	char seed[64] = "limbo necp signing ";
	size_t used = strlen(seed);
	FILE *file = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (file != NULL) {
		size_t n = fread(seed + used, 1, sizeof(seed) - used - 1, file);
		used += n;
		fclose(file);
	}
	sha256(seed, used, key);
}

static long
validate_answer(const uint8_t *validatable, size_t length)
{
	if (!codesign_entitled(
			    getpid(), "com.apple.private.validated-resolver")) {
		return _EPERM;
	}
	if (validatable == NULL
			|| length < NECP_CLIENT_ACTION_SIGN_TAG_LENGTH
							+ NECP_SIGNABLE_HEADER_SIZE
			|| length > NECP_CLIENT_ACTION_SIGN_MAX_TOTAL_LENGTH
							+ NECP_CLIENT_ACTION_SIGN_TAG_LENGTH) {
		return _EINVAL;
	}
	uint8_t tag[SHA256_DIGEST_LENGTH];
	sign_tag(validatable + NECP_CLIENT_ACTION_SIGN_TAG_LENGTH,
			length - NECP_CLIENT_ACTION_SIGN_TAG_LENGTH, tag);
	uint8_t difference = 0;
	for (size_t i = 0; i < sizeof(tag); i++) {
		difference |= tag[i] ^ validatable[i];
	}
	return difference == 0 ? 0 : _EAUTH;
}

int
necp_session_open(int flags)
{
	if (geteuid() != 0
			&& !codesign_entitled(getpid(),
					"com.apple.private.necp.policies")) {
		return _EACCES;
	}
	int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fd == -1) {
		return err_map(errno);
	}
	if ((size_t)fd >= sizeof(necp_fds) / sizeof(*necp_fds)) {
		close(fd);
		return _EMFILE;
	}
	pthread_mutex_lock(&lock);
	necp_fds[fd] = (struct necp_fd){
			.open = true,
			.flags = flags,
			.session = true,
			.next_id = 1,
	};
	pthread_mutex_unlock(&lock);
	return fd;
}

long
necp_session_action(int fd, uint32_t action, const uint8_t *in,
		size_t in_length, uint8_t *out, size_t out_length)
{
	pthread_mutex_lock(&lock);
	if (!is_necp(fd) || !necp_fds[fd].session) {
		pthread_mutex_unlock(&lock);
		return _EINVAL;
	}
	struct necp_fd *session = &necp_fds[fd];
	long result = 0;
	switch (action) {
	case NECP_SESSION_ACTION_POLICY_ADD: {
		if (in == NULL || in_length == 0 || out == NULL
				|| out_length < sizeof(uint32_t)) {
			result = _EINVAL;
			break;
		}
		struct policy *policy = calloc(1, sizeof(*policy));
		policy->id = session->next_id++;
		policy->tlvs = malloc(in_length);
		memcpy(policy->tlvs, in, in_length);
		policy->length = in_length;
		policy->next = session->policies;
		session->policies = policy;
		result = reply_id(out, out_length, policy->id);
		break;
	}
	case NECP_SESSION_ACTION_POLICY_GET:
	case NECP_SESSION_ACTION_POLICY_DELETE: {
		uint32_t id;
		if (in == NULL || in_length < sizeof(id)) {
			result = _EINVAL;
			break;
		}
		memcpy(&id, in, sizeof(id));
		struct policy **link = find_policy(session, id);
		if (link == NULL) {
			result = _ENOENT;
			break;
		}
		struct policy *policy = *link;
		if (action == NECP_SESSION_ACTION_POLICY_DELETE) {
			*link = policy->next;
			free(policy->tlvs);
			free(policy);
			break;
		}
		if (out == NULL || out_length < policy->length) {
			result = _EINVAL;
			break;
		}
		memcpy(out, policy->tlvs, policy->length);
		break;
	}
	case NECP_SESSION_ACTION_POLICY_LIST_ALL: {
		size_t needed = 0;
		for (struct policy *policy = session->policies; policy != NULL;
				policy = policy->next) {
			needed += sizeof(struct necp_tlv_header)
					+ sizeof(uint32_t);
		}
		if (needed != 0 && (out == NULL || out_length < needed)) {
			result = _EINVAL;
			break;
		}
		uint8_t *cursor = out;
		for (struct policy *policy = session->policies; policy != NULL;
				policy = policy->next) {
			cursor = write_tlv(cursor, out + out_length,
					NECP_TLV_POLICY_ID, &policy->id,
					sizeof(policy->id));
		}
		break;
	}
	case NECP_SESSION_ACTION_POLICY_DELETE_ALL: {
		struct policy *policy = session->policies;
		while (policy != NULL) {
			struct policy *next = policy->next;
			free(policy->tlvs);
			free(policy);
			policy = next;
		}
		session->policies = NULL;
		break;
	}
	case NECP_SESSION_ACTION_SET_SESSION_PRIORITY:
		if (in == NULL || in_length < sizeof(uint32_t)) {
			result = _EINVAL;
			break;
		}
		memcpy(&session->priority, in, sizeof(uint32_t));
		break;
	case NECP_SESSION_ACTION_POLICY_APPLY_ALL:
	case NECP_SESSION_ACTION_LOCK_SESSION_TO_PROC:
	case NECP_SESSION_ACTION_REGISTER_SERVICE:
	case NECP_SESSION_ACTION_UNREGISTER_SERVICE:
	case NECP_SESSION_ACTION_REMOVE_DOMAIN_FILTER:
	case NECP_SESSION_ACTION_REMOVE_ALL_DOMAIN_FILTERS:
	case NECP_SESSION_ACTION_REMOVE_DOMAIN_TRIE:
	case NECP_SESSION_ACTION_REMOVE_ALL_DOMAIN_TRIES:
		break;
	case NECP_SESSION_ACTION_ADD_DOMAIN_FILTER:
	case NECP_SESSION_ACTION_ADD_DOMAIN_TRIE:
		result = reply_id(out, out_length, session->next_id++);
		break;
	case NECP_SESSION_ACTION_POLICY_DUMP_ALL:
		result = reply_id(out, out_length, 0);
		break;
	case NECP_SESSION_ACTION_TRIE_DUMP_ALL:
		if (out == NULL || out_length < 1) {
			result = _EINVAL;
			break;
		}
		out[0] = 0;
		break;
	default:
		result = _EINVAL;
		break;
	}
#ifdef ENABLE_STRACE
	fprintf(stderr, "  necp: session action %u: %ld\n", action, result);
#endif
	pthread_mutex_unlock(&lock);
	return result;
}

static long
reply_id(uint8_t *out, size_t out_length, uint32_t id)
{
	if (out == NULL || out_length < sizeof(id)) {
		return _EINVAL;
	}
	memcpy(out, &id, sizeof(id));
	return 0;
}

static struct policy **
find_policy(struct necp_fd *session, uint32_t id)
{
	for (struct policy **link = &session->policies; *link != NULL;
			link = &(*link)->next) {
		if ((*link)->id == id) {
			return link;
		}
	}
	return NULL;
}
