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
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "check.h"

extern int necp_open(int flags);
extern int necp_client_action(int fd, uint32_t action, uuid_t client_id,
		size_t client_id_len, uint8_t *buffer, size_t buffer_size);
extern int necp_session_open(int flags);

#define NECP_OPEN_FLAG_OBSERVER                  0x01
#define NECP_CLIENT_ACTION_ADD                   1
#define NECP_CLIENT_ACTION_REMOVE                2
#define NECP_CLIENT_ACTION_COPY_RESULT           4
#define NECP_CLIENT_ACTION_COPY_AGENT            8
#define NECP_CLIENT_ACTION_COPY_CLIENT_UPDATE    15
#define NECP_CLIENT_ACTION_SIGN                  20
#define NECP_CLIENT_ACTION_GET_INTERFACE_ADDRESS 21
#define NECP_CLIENT_ACTION_VALIDATE              23
#define NECP_CLIENT_PARAMETER_REMOTE_ENDPOINT    201
#define NECP_CLIENT_RESULT_INTERFACE_INDEX       5
#define NECP_CLIENT_RESULT_FLAGS                 7
#define NECP_CLIENT_RESULT_FLAG_SATISFIED        0x0020

struct __attribute__((packed)) tlv {
	uint8_t type;
	uint32_t length;
};

static const uint8_t *
find_tlv(const uint8_t *buffer, size_t length, uint8_t type, uint32_t *size)
{
	for (size_t offset = 0; offset + sizeof(struct tlv) <= length;) {
		struct tlv header;
		memcpy(&header, buffer + offset, sizeof(header));
		if (header.type == type) {
			*size = header.length;
			return buffer + offset + sizeof(header);
		}
		offset += sizeof(header) + header.length;
	}
	return NULL;
}

int
main(void)
{
	int fd = necp_open(0);
	CHECK(fd != -1);

	struct __attribute__((packed)) {
		struct tlv header;
		struct sockaddr_in address;
	} parameters = {
		.header = {NECP_CLIENT_PARAMETER_REMOTE_ENDPOINT,
				sizeof(struct sockaddr_in)},
		.address = {
			.sin_len = sizeof(struct sockaddr_in),
			.sin_family = AF_INET,
			.sin_port = htons(80),
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		},
	};
	uuid_t client;
	CHECK(necp_client_action(fd, NECP_CLIENT_ACTION_ADD, client,
			      sizeof(client), (uint8_t *)&parameters,
			      sizeof(parameters))
			== 0);
	uint8_t result[1024];
	int length = necp_client_action(fd, NECP_CLIENT_ACTION_COPY_RESULT,
			client, sizeof(client), result, sizeof(result));
	CHECK(length > 0);
	uint32_t size;
	const uint8_t *value = find_tlv(result, (size_t)length,
			NECP_CLIENT_RESULT_FLAGS, &size);
	CHECK(value != NULL && size == sizeof(uint32_t));
	uint32_t flags;
	memcpy(&flags, value, sizeof(flags));
	CHECK(flags & NECP_CLIENT_RESULT_FLAG_SATISFIED);
	value = find_tlv(result, (size_t)length,
			NECP_CLIENT_RESULT_INTERFACE_INDEX, &size);
	CHECK(value != NULL && size == sizeof(uint32_t));
	uint32_t index;
	memcpy(&index, value, sizeof(index));
	CHECK(index != 0);

	struct sockaddr_in address = parameters.address;
	CHECK(necp_client_action(fd, NECP_CLIENT_ACTION_GET_INTERFACE_ADDRESS,
			      (uint8_t *)&index, sizeof(index),
			      (uint8_t *)&address, sizeof(address))
			== 0);
	CHECK(address.sin_family == AF_INET);
	CHECK(address.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
	address = parameters.address;
	address.sin_len = 8;
	errno = 0;
	CHECK(necp_client_action(fd, NECP_CLIENT_ACTION_GET_INTERFACE_ADDRESS,
			      (uint8_t *)&index, sizeof(index),
			      (uint8_t *)&address, sizeof(address))
					== -1
			&& errno == EINVAL);

	uuid_t agent;
	uuid_generate(agent);
	uint8_t content[512];
	CHECK(necp_client_action(fd, NECP_CLIENT_ACTION_COPY_AGENT, agent,
			      sizeof(agent), content, sizeof(content))
					== -1
			&& errno == ENOENT);

	uint8_t signable[64] = {0};
	uint8_t tag[32];
	CHECK(necp_client_action(fd, NECP_CLIENT_ACTION_SIGN, signable,
			      sizeof(signable), tag, sizeof(tag))
					== -1
			&& errno == EPERM);
	CHECK(necp_client_action(fd, NECP_CLIENT_ACTION_VALIDATE, signable,
			      sizeof(signable), NULL,
			      0) == -1
			&& errno == EPERM);

	CHECK(necp_client_action(fd, NECP_CLIENT_ACTION_COPY_CLIENT_UPDATE,
			      client, sizeof(client), content, sizeof(content))
					== -1
			&& errno == EINVAL);

	CHECK(necp_client_action(fd, NECP_CLIENT_ACTION_REMOVE, client,
			      sizeof(client), NULL, 0)
			== 0);
	CHECK(close(fd) == 0);

	if (geteuid() != 0) {
		CHECK(necp_open(NECP_OPEN_FLAG_OBSERVER) == -1
				&& errno == EACCES);
		CHECK(necp_session_open(0) == -1 && errno == EACCES);
	}

	printf("necp: ok\n");
	return 0;
}
