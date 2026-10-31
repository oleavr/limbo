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
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bsd/hostuuid.h"
#include "sysroot.h"

#define HOST_UUID_PATH "/private/var/db/limbo/host-uuid"

static pthread_once_t once = PTHREAD_ONCE_INIT;
static bool found;
static uint8_t bytes[16];
static char string[37];

static void find(void);
static bool parse_hex(const char *text, uint8_t uuid[16]);
static bool read_file(const char *path, uint8_t uuid[16]);
static bool sysroot_uuid(uint8_t uuid[16]);
static void format(const uint8_t uuid[16], char text[37]);

bool
host_uuid(uint8_t uuid[16])
{
	pthread_once(&once, find);
	if (found) {
		memcpy(uuid, bytes, 16);
	}
	return found;
}

static void
find(void)
{
	const char *given = getenv("LIMBO_PLATFORM_UUID");
	found = (given != NULL && parse_hex(given, bytes))
			|| read_file("/etc/machine-id", bytes)
			|| sysroot_uuid(bytes);
	if (found) {
		format(bytes, string);
	}
}

static bool
parse_hex(const char *text, uint8_t uuid[16])
{
	int digits = 0;
	int value = 0;
	for (; *text != '\0' && *text != '\n'; text++) {
		if (*text == '-') {
			continue;
		}
		if (!isxdigit((unsigned char)*text) || digits == 32) {
			return false;
		}
		int digit = isdigit((unsigned char)*text)
				? *text - '0'
				: tolower((unsigned char)*text) - 'a' + 10;
		value = (value << 4) | digit;
		if (digits % 2 == 1) {
			uuid[digits / 2] = (uint8_t)value;
			value = 0;
		}
		digits++;
	}
	return digits == 32;
}

static bool
read_file(const char *path, uint8_t uuid[16])
{
	char text[80];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return false;
	}
	ssize_t length = read(fd, text, sizeof(text) - 1);
	close(fd);
	if (length <= 0) {
		return false;
	}
	text[length] = '\0';
	return parse_hex(text, uuid);
}

static bool
sysroot_uuid(uint8_t uuid[16])
{
	char buffer[PATH_MAX];
	const char *path = sysroot_host_path(HOST_UUID_PATH, 0, buffer);
	if (path == NULL) {
		return false;
	}
	if (read_file(path, uuid)) {
		return true;
	}
	uint8_t fresh[16];
	if (getrandom(fresh, sizeof(fresh), 0) != (ssize_t)sizeof(fresh)) {
		return false;
	}
	fresh[6] = (fresh[6] & 0x0f) | 0x40;
	fresh[8] = (fresh[8] & 0x3f) | 0x80;
	char text[38];
	format(fresh, text);
	text[36] = '\n';
	text[37] = '\0';
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd != -1) {
		if (write(fd, text, 37) != 37) {
			close(fd);
			unlink(path);
			return false;
		}
		close(fd);
	}
	return read_file(path, uuid);
}

static void
format(const uint8_t uuid[16], char text[37])
{
	snprintf(text, 37,
			"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%"
			"02X%02X%02X%02X",
			uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5],
			uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11],
			uuid[12], uuid[13], uuid[14], uuid[15]);
}

const char *
host_uuid_string(void)
{
	pthread_once(&once, find);
	return found ? string : NULL;
}
