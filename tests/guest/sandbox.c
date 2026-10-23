/*
 * Copyright © 2026 Ole André Vadla Ravnås
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "check.h"

extern const char *const APP_SANDBOX_READ_WRITE;
extern char *sandbox_extension_issue_file(
		const char *extension_class, const char *path, uint32_t flags);
extern char *sandbox_extension_issue_mach(
		const char *extension_class, const char *name, uint32_t flags);
extern int64_t sandbox_extension_consume(const char *token);
extern int sandbox_extension_release(int64_t handle);

int
main(void)
{
	char *token = sandbox_extension_issue_file(
			APP_SANDBOX_READ_WRITE, "/tmp", 0);
	CHECK(token != NULL);
	CHECK(strstr(token, ";com.apple.app-sandbox.read-write;") != NULL);
	size_t length = strlen(token);
	CHECK(length > 4 && strcmp(token + length - 4, "/tmp") == 0);
	int64_t handle = sandbox_extension_consume(token);
	CHECK(handle >= 0);
	CHECK(sandbox_extension_release(handle) == 0);
	free(token);

	token = sandbox_extension_issue_mach(
			"com.apple.app-sandbox.mach", "com.apple.lsd.mapdb", 0);
	CHECK(token != NULL);
	CHECK(strstr(token, ";com.apple.lsd.mapdb") != NULL);
	free(token);

	CHECK(sandbox_extension_issue_file(APP_SANDBOX_READ_WRITE,
			      "/nonexistent/limbo", 0)
			== NULL);
	return 0;
}
