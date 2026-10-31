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

#include <mach/mach_types.h>
#include <mach/mach_voucher.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bsd/codesign.h"
#include "ipc.h"

#define BANK_ORIGINATOR_PID    0x1
#define BANK_PERSONA_ADOPT_ANY 0x4

static bool is_voucher(ipc_voucher_t voucher);

kern_return_t
mach_voucher_extract_attr_content(ipc_voucher_t voucher,
		mach_voucher_attr_key_t key,
		mach_voucher_attr_content_t content,
		mach_msg_type_number_t *contentCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_voucher_extract_attr_content(%p, %p, %p, %p)\n",
			(void *)(uintptr_t)voucher, (void *)(uintptr_t)key,
			(void *)content, (void *)contentCnt);
#endif
	if (!is_voucher(voucher)) {
		return KERN_INVALID_ARGUMENT;
	}
	*contentCnt = 0;
	return KERN_SUCCESS;
}

static bool
is_voucher(ipc_voucher_t voucher)
{
	return voucher == ipc_kobject_name(IPC_KOBJECT_VOUCHER);
}

kern_return_t
_kernelrpc_mach_voucher_extract_attr_recipe(ipc_voucher_t voucher,
		mach_voucher_attr_key_t key,
		mach_voucher_attr_raw_recipe_t recipe,
		mach_msg_type_number_t *recipeCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_voucher_extract_attr_recipe(%p, %p, "
			"%p, "
			"%p)\n",
			(void *)(uintptr_t)voucher, (void *)(uintptr_t)key,
			(void *)recipe, (void *)recipeCnt);
#endif
	if (!is_voucher(voucher)) {
		return KERN_INVALID_ARGUMENT;
	}
	*recipeCnt = 0;
	return KERN_SUCCESS;
}

kern_return_t
mach_voucher_extract_all_attr_recipes(ipc_voucher_t voucher,
		mach_voucher_attr_raw_recipe_array_t recipes,
		mach_msg_type_number_t *recipesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_voucher_extract_all_attr_recipes(%p, %p, %p)\n",
			(void *)(uintptr_t)voucher, (void *)recipes,
			(void *)recipesCnt);
#endif
	if (!is_voucher(voucher)) {
		return KERN_INVALID_ARGUMENT;
	}
	*recipesCnt = 0;
	return KERN_SUCCESS;
}

kern_return_t
mach_voucher_attr_command(ipc_voucher_t voucher, mach_voucher_attr_key_t key,
		mach_voucher_attr_command_t command,
		mach_voucher_attr_content_t in_content,
		mach_msg_type_number_t in_contentCnt,
		mach_voucher_attr_content_t out_content,
		mach_msg_type_number_t *out_contentCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_voucher_attr_command(%p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)(uintptr_t)voucher, (void *)(uintptr_t)key,
			(void *)(uintptr_t)command, (void *)in_content,
			(void *)(uintptr_t)in_contentCnt, (void *)out_content,
			(void *)out_contentCnt);
#endif
	if (!is_voucher(voucher)) {
		return KERN_INVALID_ARGUMENT;
	}
	uint32_t answer;
	if (key == MACH_VOUCHER_ATTR_KEY_BANK
			&& command == BANK_ORIGINATOR_PID) {
		answer = (uint32_t)getpid();
	} else if (key == MACH_VOUCHER_ATTR_KEY_BANK
			&& command == BANK_PERSONA_ADOPT_ANY) {
		answer = codesign_entitled(getpid(),
				"com.apple.private.persona.adopt.any");
	} else {
		return KERN_INVALID_ARGUMENT;
	}
	if (*out_contentCnt < sizeof(answer)) {
		*out_contentCnt = 0;
		return KERN_NO_SPACE;
	}
	memcpy(out_content, &answer, sizeof(answer));
	*out_contentCnt = sizeof(answer);
	return KERN_SUCCESS;
}

kern_return_t
mach_voucher_debug_info(ipc_space_read_t task, mach_port_name_t voucher_name,
		mach_voucher_attr_raw_recipe_array_t recipes,
		mach_msg_type_number_t *recipesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_voucher_debug_info(%p, %p, %p, %p)\n",
			(void *)(uintptr_t)task,
			(void *)(uintptr_t)voucher_name, (void *)recipes,
			(void *)recipesCnt);
#endif
	return KERN_NOT_SUPPORTED;
}
