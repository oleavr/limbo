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

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdio.h>
#include <unistd.h>

#include "check.h"

int
main(void)
{
	char name[32];
	snprintf(name, sizeof(name), "/limbo.test.%d", getpid());

	sem_t *first = sem_open(name, O_CREAT | O_EXCL, 0600, 1);
	CHECK(first != SEM_FAILED);
	CHECK(sem_open(name, O_CREAT | O_EXCL, 0600, 1) == SEM_FAILED);
	CHECK(errno == EEXIST);

	sem_t *second = sem_open(name, 0);
	CHECK(second != SEM_FAILED);
	CHECK(sem_wait(first) == 0);
	CHECK(sem_trywait(second) == -1 && errno == EAGAIN);
	CHECK(sem_post(second) == 0);
	CHECK(sem_trywait(first) == 0);

	CHECK(sem_close(second) == 0);
	CHECK(sem_close(first) == 0);
	CHECK(sem_unlink(name) == 0);
	CHECK(sem_open(name, 0) == SEM_FAILED && errno == ENOENT);
	return 0;
}
