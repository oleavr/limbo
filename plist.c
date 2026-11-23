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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "plist.h"

struct bplist {
	const uint8_t *bytes;
	size_t size;
	uint8_t offset_size, ref_size;
	uint64_t count, table;
	FILE *out;
	int depth;
};

static char *bplist_to_xml(const uint8_t *bytes, size_t size);
static bool bplist_object(struct bplist *p, uint64_t ref);
static bool bplist_offset(
		const struct bplist *p, uint64_t ref, uint64_t *offset);
static bool bplist_count(const struct bplist *p, uint64_t *at, uint8_t marker,
		uint64_t *count);
static void bplist_base64(FILE *out, const uint8_t *at, uint64_t size);
static void bplist_utf16(FILE *out, const uint8_t *at, uint64_t units);
static void bplist_escaped(FILE *out, const char *text, size_t length);
static bool bplist_refs(
		struct bplist *p, uint64_t at, uint64_t count, uint64_t *refs);
static uint64_t bplist_uint(const uint8_t *at, size_t size);

char *
plist_read(const char *host_path)
{
	FILE *file = fopen(host_path, "r");
	if (file == NULL) {
		return NULL;
	}
	char *contents = NULL;
	size_t length = 0;
	FILE *out = open_memstream(&contents, &length);
	char chunk[4096];
	size_t n;
	while ((n = fread(chunk, 1, sizeof(chunk), file)) > 0) {
		fwrite(chunk, 1, n, out);
	}
	fclose(out);
	fclose(file);
	if (contents != NULL && length >= 8
			&& memcmp(contents, "bplist00", 8) == 0) {
		char *xml = bplist_to_xml((const uint8_t *)contents, length);
		free(contents);
		return xml;
	}
	return contents;
}

static char *
bplist_to_xml(const uint8_t *bytes, size_t size)
{
	if (size < 8 + 32 || memcmp(bytes, "bplist00", 8) != 0) {
		return NULL;
	}
	const uint8_t *trailer = bytes + size - 32;
	struct bplist p = {
			.bytes = bytes,
			.size = size,
			.offset_size = trailer[6],
			.ref_size = trailer[7],
			.count = bplist_uint(trailer + 8, 8),
			.table = bplist_uint(trailer + 24, 8),
	};
	if (p.offset_size == 0 || p.offset_size > 8 || p.ref_size == 0
			|| p.ref_size > 8 || p.table >= size
			|| p.count > size) {
		return NULL;
	}
	char *xml = NULL;
	size_t length = 0;
	p.out = open_memstream(&xml, &length);
	if (p.out == NULL) {
		return NULL;
	}
	fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist "
	      "version=\"1.0\">\n",
			p.out);
	bool ok = bplist_object(&p, bplist_uint(trailer + 16, 8));
	fputs("\n</plist>\n", p.out);
	fclose(p.out);
	if (!ok) {
		free(xml);
		return NULL;
	}
	return xml;
}

static bool
bplist_object(struct bplist *p, uint64_t ref)
{
	uint64_t at;
	if (p->depth > 64 || !bplist_offset(p, ref, &at)) {
		return false;
	}
	uint8_t marker = p->bytes[at];
	uint64_t count;
	switch (marker >> 4) {
	case 0x0:
		fputs(marker == 0x09 ? "<true/>"
						: marker == 0x08
						? "<false/>"
						: "<string></string>",
				p->out);
		return true;
	case 0x1: {
		size_t size = (size_t)1 << (marker & 0xf);
		if (size > 16 || at + 1 + size > p->size) {
			return false;
		}
		const uint8_t *value
				= p->bytes + at + 1 + (size > 8 ? size - 8 : 0);
		uint64_t v = bplist_uint(value, size > 8 ? 8 : size);
		if (size == 8) {
			fprintf(p->out, "<integer>%lld</integer>",
					(long long)v);
		} else {
			fprintf(p->out, "<integer>%llu</integer>",
					(unsigned long long)v);
		}
		return true;
	}
	case 0x2:
	case 0x3: {
		size_t size = (marker >> 4) == 0x3
				? 8
				: (size_t)1 << (marker & 0xf);
		if ((size != 4 && size != 8) || at + 1 + size > p->size) {
			return false;
		}
		uint64_t bits = bplist_uint(p->bytes + at + 1, size);
		double value;
		if (size == 4) {
			uint32_t b = (uint32_t)bits;
			float f;
			memcpy(&f, &b, sizeof(f));
			value = f;
		} else {
			memcpy(&value, &bits, sizeof(value));
		}
		if ((marker >> 4) == 0x3) {
			time_t t = (time_t)(value + 978307200.0);
			struct tm tm;
			char text[32];
			gmtime_r(&t, &tm);
			strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &tm);
			fprintf(p->out, "<date>%s</date>", text);
		} else {
			fprintf(p->out, "<real>%.17g</real>", value);
		}
		return true;
	}
	case 0x4:
		if (!bplist_count(p, &at, marker, &count)
				|| at + count > p->size) {
			return false;
		}
		fputs("<data>", p->out);
		bplist_base64(p->out, p->bytes + at, count);
		fputs("</data>", p->out);
		return true;
	case 0x5:
	case 0x7:
		if (!bplist_count(p, &at, marker, &count)
				|| at + count > p->size) {
			return false;
		}
		fputs("<string>", p->out);
		bplist_escaped(p->out, (const char *)p->bytes + at, count);
		fputs("</string>", p->out);
		return true;
	case 0x6:
		if (!bplist_count(p, &at, marker, &count)
				|| at + 2 * count > p->size) {
			return false;
		}
		fputs("<string>", p->out);
		bplist_utf16(p->out, p->bytes + at, count);
		fputs("</string>", p->out);
		return true;
	case 0x8: {
		size_t size = (size_t)(marker & 0xf) + 1;
		if (at + 1 + size > p->size) {
			return false;
		}
		fprintf(p->out,
				"<dict><key>CF$UID</key><integer>%llu</"
				"integer></dict>",
				(unsigned long long)bplist_uint(
						p->bytes + at + 1, size));
		return true;
	}
	case 0xa:
	case 0xc:
	case 0xd: {
		bool dictionary = (marker >> 4) == 0xd;
		if (!bplist_count(p, &at, marker, &count) || count > p->count) {
			return false;
		}
		uint64_t total = dictionary ? 2 * count : count;
		uint64_t *refs = calloc(total ? total : 1, sizeof(*refs));
		if (refs == NULL || !bplist_refs(p, at, total, refs)) {
			free(refs);
			return false;
		}
		bool ok = true;
		p->depth++;
		fputs(dictionary ? "<dict>" : "<array>", p->out);
		for (uint64_t i = 0; i < count && ok; i++) {
			if (dictionary) {
				uint64_t key_at;
				if (!bplist_offset(p, refs[i], &key_at)) {
					ok = false;
					break;
				}
				char *key = NULL;
				size_t key_length = 0;
				FILE *saved = p->out;
				p->out = open_memstream(&key, &key_length);
				ok = bplist_object(p, refs[i]);
				fclose(p->out);
				p->out = saved;
				if (ok && key_length >= 17
						&& strncmp(key, "<string>", 8)
								== 0) {
					fputs("<key>", p->out);
					fwrite(key + 8, 1, key_length - 17,
							p->out);
					fputs("</key>", p->out);
				} else {
					ok = false;
				}
				free(key);
				if (ok) {
					ok = bplist_object(p, refs[count + i]);
				}
			} else {
				ok = bplist_object(p, refs[i]);
			}
		}
		fputs(dictionary ? "</dict>" : "</array>", p->out);
		p->depth--;
		free(refs);
		return ok;
	}
	default:
		return false;
	}
}

static bool
bplist_offset(const struct bplist *p, uint64_t ref, uint64_t *offset)
{
	if (ref >= p->count) {
		return false;
	}
	uint64_t at = p->table + ref * p->offset_size;
	if (at + p->offset_size > p->size) {
		return false;
	}
	*offset = bplist_uint(p->bytes + at, p->offset_size);
	return *offset < p->size;
}

static bool
bplist_count(const struct bplist *p, uint64_t *at, uint8_t marker,
		uint64_t *count)
{
	*count = marker & 0xf;
	*at += 1;
	if (*count != 0xf) {
		return true;
	}
	if (*at >= p->size || (p->bytes[*at] & 0xf0) != 0x10) {
		return false;
	}
	size_t size = (size_t)1 << (p->bytes[*at] & 0xf);
	if (*at + 1 + size > p->size || size > 8) {
		return false;
	}
	*count = bplist_uint(p->bytes + *at + 1, size);
	*at += 1 + size;
	return true;
}

static void
bplist_base64(FILE *out, const uint8_t *at, uint64_t size)
{
	static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"
				     "pqrstuvwxyz0123456789+/";
	for (uint64_t i = 0; i < size; i += 3) {
		uint32_t v = (uint32_t)at[i] << 16;
		if (i + 1 < size) {
			v |= (uint32_t)at[i + 1] << 8;
		}
		if (i + 2 < size) {
			v |= at[i + 2];
		}
		fputc(digits[(v >> 18) & 0x3f], out);
		fputc(digits[(v >> 12) & 0x3f], out);
		fputc(i + 1 < size ? digits[(v >> 6) & 0x3f] : '=', out);
		fputc(i + 2 < size ? digits[v & 0x3f] : '=', out);
	}
}

static void
bplist_utf16(FILE *out, const uint8_t *at, uint64_t units)
{
	for (uint64_t i = 0; i < units; i++) {
		uint32_t c = ((uint32_t)at[2 * i] << 8) | at[2 * i + 1];
		if (c >= 0xd800 && c < 0xdc00 && i + 1 < units) {
			uint32_t low = ((uint32_t)at[2 * i + 2] << 8)
					| at[2 * i + 3];
			c = 0x10000 + ((c - 0xd800) << 10) + (low - 0xdc00);
			i++;
		}
		char buffer[4];
		size_t n;
		if (c < 0x80) {
			buffer[0] = (char)c;
			n = 1;
		} else if (c < 0x800) {
			buffer[0] = (char)(0xc0 | (c >> 6));
			buffer[1] = (char)(0x80 | (c & 0x3f));
			n = 2;
		} else if (c < 0x10000) {
			buffer[0] = (char)(0xe0 | (c >> 12));
			buffer[1] = (char)(0x80 | ((c >> 6) & 0x3f));
			buffer[2] = (char)(0x80 | (c & 0x3f));
			n = 3;
		} else {
			buffer[0] = (char)(0xf0 | (c >> 18));
			buffer[1] = (char)(0x80 | ((c >> 12) & 0x3f));
			buffer[2] = (char)(0x80 | ((c >> 6) & 0x3f));
			buffer[3] = (char)(0x80 | (c & 0x3f));
			n = 4;
		}
		bplist_escaped(out, buffer, n);
	}
}

static void
bplist_escaped(FILE *out, const char *text, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		switch (text[i]) {
		case '&':
			fputs("&amp;", out);
			break;
		case '<':
			fputs("&lt;", out);
			break;
		case '>':
			fputs("&gt;", out);
			break;
		default:
			fputc(text[i], out);
		}
	}
}

static bool
bplist_refs(struct bplist *p, uint64_t at, uint64_t count, uint64_t *refs)
{
	if (at + count * p->ref_size > p->size) {
		return false;
	}
	for (uint64_t i = 0; i < count; i++) {
		refs[i] = bplist_uint(
				p->bytes + at + i * p->ref_size, p->ref_size);
	}
	return true;
}

static uint64_t
bplist_uint(const uint8_t *at, size_t size)
{
	uint64_t value = 0;
	for (size_t i = 0; i < size; i++) {
		value = (value << 8) | at[i];
	}
	return value;
}

bool
plist_bool(const char *start, const char *end, const char *key)
{
	char tag[160];
	snprintf(tag, sizeof(tag), "<key>%s</key>", key);
	const char *found = strstr(start, tag);
	if (found == NULL || found >= end) {
		return false;
	}
	const char *text = plist_skip(found + strlen(tag), end);
	return strncmp(text, "<true/>", 7) == 0;
}

size_t
plist_variables(const char *start, const char *end, const char *key, char **out,
		size_t max)
{
	const char *variables_end;
	const char *variables
			= plist_dictionary(start, end, key, &variables_end);
	if (variables == NULL) {
		return 0;
	}
	size_t count = 0;
	const char *scan = variables + strlen("<dict>");
	while (count < max) {
		const char *name = strstr(scan, "<key>");
		if (name == NULL || name >= variables_end) {
			break;
		}
		name += strlen("<key>");
		const char *name_end = strstr(name, "</key>");
		if (name_end == NULL) {
			break;
		}
		char variable[128], value[1024];
		snprintf(variable, sizeof(variable), "%.*s",
				(int)(name_end - name), name);
		if (plist_string(name - strlen("<key>"), variables_end,
				    variable, value, sizeof(value))) {
			asprintf(&out[count++], "%s=%s", variable, value);
		}
		scan = name_end;
	}
	return count;
}

const char *
plist_dictionary(const char *start, const char *end, const char *key,
		const char **dictionary_end)
{
	char tag[160];
	snprintf(tag, sizeof(tag), "<key>%s</key>", key);
	const char *found = strstr(start, tag);
	if (found == NULL || found >= end) {
		return NULL;
	}
	const char *value = plist_skip(found + strlen(tag), end);
	if (strncmp(value, "<dict>", 6) != 0) {
		return NULL;
	}
	*dictionary_end = plist_value_end(value, end);
	return value;
}

const char *
plist_value_end(const char *value, const char *end)
{
	int depth = 0;
	const char *scan = value;
	while (scan < end) {
		const char *tag = strchr(scan, '<');
		if (tag == NULL || tag >= end) {
			return end;
		}
		if (strncmp(tag, "<!--", 4) == 0) {
			const char *comment_end = strstr(tag + 4, "-->");
			if (comment_end == NULL) {
				return end;
			}
			scan = comment_end + 3;
			continue;
		}
		const char *close = strchr(tag, '>');
		if (close == NULL) {
			return end;
		}
		bool closing = tag[1] == '/';
		bool empty = close[-1] == '/';
		bool container = strncmp(tag + (closing ? 2 : 1), "dict", 4)
						== 0
				|| strncmp(tag + (closing ? 2 : 1), "array", 5)
						== 0;
		if (container && !empty) {
			depth += closing ? -1 : 1;
		}
		scan = close + 1;
		if (depth <= 0 && (closing || empty || !container)) {
			if (!container && !closing && !empty) {
				const char *next = strchr(scan, '>');
				return (next != NULL) ? next + 1 : end;
			}
			return scan;
		}
	}
	return end;
}

bool
plist_string(const char *start, const char *end, const char *key, char *value,
		size_t size)
{
	char tag[160];
	snprintf(tag, sizeof(tag), "<key>%s</key>", key);
	const char *found = strstr(start, tag);
	if (found == NULL || found >= end) {
		return false;
	}
	const char *text = plist_skip(found + strlen(tag), end);
	if (strncmp(text, "<string>", 8) != 0) {
		return false;
	}
	text += 8;
	const char *text_end = strstr(text, "</string>");
	if (text_end == NULL) {
		return false;
	}
	snprintf(value, size, "%.*s", (int)(text_end - text), text);
	return true;
}

const char *
plist_skip(const char *scan, const char *end)
{
	for (;;) {
		while (scan < end && strchr(" \t\r\n", *scan) != NULL
				&& *scan != '\0') {
			scan++;
		}
		if (scan + 4 > end || strncmp(scan, "<!--", 4) != 0) {
			return scan;
		}
		const char *comment_end = strstr(scan + 4, "-->");
		if (comment_end == NULL || comment_end + 3 > end) {
			return end;
		}
		scan = comment_end + 3;
	}
}
