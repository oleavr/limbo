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

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "check.h"

#define THREADS 4
#define ROUNDS  10
#define BLOCKS  32

static void *
churn(void *argument)
{
	uintptr_t seed = (uintptr_t)argument;
	for (int round = 0; round < ROUNDS; round++) {
		uint8_t *blocks[BLOCKS];
		size_t sizes[BLOCKS];
		for (int i = 0; i < BLOCKS; i++) {
			seed = seed * 6364136223846793005u
					+ 1442695040888963407u;
			sizes[i] = (size_t)16384 << ((seed >> 33) % 11);
			blocks[i] = malloc(sizes[i]);
			CHECK(blocks[i] != NULL);
			memset(blocks[i], (int)(i + round), sizes[i]);
		}
		for (int i = 0; i < BLOCKS; i++) {
			CHECK(blocks[i][0] == (uint8_t)(i + round));
			CHECK(blocks[i][sizes[i] / 2] == (uint8_t)(i + round));
			CHECK(blocks[i][sizes[i] - 1] == (uint8_t)(i + round));
			free(blocks[i]);
		}
		if (round % 2 == 1) {
			usleep(600000);
		}
	}
	return NULL;
}

int
main(void)
{
	pthread_t threads[THREADS];
	for (uintptr_t i = 0; i < THREADS; i++) {
		CHECK(pthread_create(&threads[i], NULL, churn, (void *)(i + 1))
				== 0);
	}
	for (int i = 0; i < THREADS; i++) {
		CHECK(pthread_join(threads[i], NULL) == 0);
	}
	puts("ok");
	return 0;
}
