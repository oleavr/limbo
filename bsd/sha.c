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

#include <string.h>

#include "sha.h"

static void for_each_block(const uint8_t *data, size_t length,
		void (*compress)(uint32_t *state, const uint8_t *block),
		uint32_t *state);
static void sha1_compress(uint32_t *state, const uint8_t *block);
static void sha256_compress(uint32_t *state, const uint8_t *block);
static uint32_t load_big(const uint8_t *bytes);
static void store_big(uint8_t *bytes, uint32_t value);
static uint32_t rotl(uint32_t x, int n);
static uint32_t rotr(uint32_t x, int n);

static const uint32_t sha256_k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
		0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
		0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
		0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
		0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
		0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
		0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void
sha1(const void *data, size_t length, uint8_t digest[SHA1_DIGEST_LENGTH])
{
	uint32_t state[5] = {
			0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
			0xc3d2e1f0};
	for_each_block(data, length, sha1_compress, state);
	for (int i = 0; i < 5; i++) {
		store_big(digest + i * 4, state[i]);
	}
}

void
sha256(const void *data, size_t length, uint8_t digest[SHA256_DIGEST_LENGTH])
{
	uint32_t state[8] = {
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	for_each_block(data, length, sha256_compress, state);
	for (int i = 0; i < 8; i++) {
		store_big(digest + i * 4, state[i]);
	}
}

static void
for_each_block(const uint8_t *data, size_t length,
		void (*compress)(uint32_t *state, const uint8_t *block),
		uint32_t *state)
{
	size_t whole = length & ~(size_t)63;
	for (size_t offset = 0; offset < whole; offset += 64) {
		compress(state, data + offset);
	}

	uint8_t tail[128] = {0};
	size_t rest = length - whole;
	memcpy(tail, data + whole, rest);
	tail[rest] = 0x80;
	size_t tail_length = (rest < 56) ? 64 : 128;
	uint64_t bits = (uint64_t)length * 8;
	store_big(tail + tail_length - 8, (uint32_t)(bits >> 32));
	store_big(tail + tail_length - 4, (uint32_t)bits);
	compress(state, tail);
	if (tail_length == 128) {
		compress(state, tail + 64);
	}
}

static void
sha1_compress(uint32_t *state, const uint8_t *block)
{
	uint32_t w[80];
	for (int i = 0; i < 16; i++) {
		w[i] = load_big(block + i * 4);
	}
	for (int i = 16; i < 80; i++) {
		w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}

	uint32_t a = state[0], b = state[1], c = state[2], d = state[3],
		 e = state[4];
	for (int i = 0; i < 80; i++) {
		uint32_t f, k;
		if (i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5a827999;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ed9eba1;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8f1bbcdc;
		} else {
			f = b ^ c ^ d;
			k = 0xca62c1d6;
		}
		uint32_t t = rotl(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rotl(b, 30);
		b = a;
		a = t;
	}
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

static void
sha256_compress(uint32_t *state, const uint8_t *block)
{
	uint32_t w[64];
	for (int i = 0; i < 16; i++) {
		w[i] = load_big(block + i * 4);
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18)
				^ (w[i - 15] >> 3);
		uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19)
				^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t v[8];
	memcpy(v, state, sizeof(v));
	for (int i = 0; i < 64; i++) {
		uint32_t s1 = rotr(v[4], 6) ^ rotr(v[4], 11) ^ rotr(v[4], 25);
		uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
		uint32_t t1 = v[7] + s1 + ch + sha256_k[i] + w[i];
		uint32_t s0 = rotr(v[0], 2) ^ rotr(v[0], 13) ^ rotr(v[0], 22);
		uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
		uint32_t t2 = s0 + maj;
		memmove(v + 1, v, 7 * sizeof(uint32_t));
		v[4] += t1;
		v[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++) {
		state[i] += v[i];
	}
}

static uint32_t
load_big(const uint8_t *bytes)
{
	return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16
			| (uint32_t)bytes[2] << 8 | bytes[3];
}

static void
store_big(uint8_t *bytes, uint32_t value)
{
	bytes[0] = value >> 24;
	bytes[1] = value >> 16;
	bytes[2] = value >> 8;
	bytes[3] = value;
}

static uint32_t
rotl(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

static uint32_t
rotr(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}
