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
#include <stdio.h>
#include <unistd.h>

#include "check.h"

#define NOGROUP 0xffffffffu

int
main(void)
{
	if (getuid() != 0) {
		printf("nogroup: skipped (not root)\n");
		return 77;
	}
	if (setgroups(1, (gid_t[]){NOGROUP}) != 0) {
		CHECK(errno == EINVAL);
		printf("nogroup: skipped (the host has no id for it here)\n");
		return 77;
	}
	gid_t groups[4];
	CHECK(getgroups(4, groups) == 1 && groups[0] == NOGROUP);
	CHECK(setegid(NOGROUP) == 0 && getegid() == NOGROUP);
	CHECK(setgid(NOGROUP) == 0);
	CHECK(getgid() == NOGROUP && getegid() == NOGROUP);
	CHECK(setgid(0) == 0 && getgid() == 0 && getegid() == 0);
	printf("nogroup: ok\n");
	return 0;
}
