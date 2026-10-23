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

#pragma once

#include <stdint.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#define DARWIN_FSTYPE_APFS 0x1a

#define DARWIN_MNT_LOCAL      0x00001000
#define DARWIN_MNT_ROOTFS     0x00004000
#define DARWIN_MNT_DOVOLFS    0x00008000
#define DARWIN_MNT_JOURNALED  0x00800000
#define DARWIN_MNT_MULTILABEL 0x04000000
#define DARWIN_MNT_SNAPSHOT   0x40000000

#define DARWIN_MOUNT_FLAGS                                                     \
	(DARWIN_MNT_LOCAL | DARWIN_MNT_ROOTFS | DARWIN_MNT_DOVOLFS             \
			| DARWIN_MNT_JOURNALED | DARWIN_MNT_MULTILABEL         \
			| DARWIN_MNT_SNAPSHOT)

static inline int32_t
darwin_device(dev_t dev)
{
	return (major(dev) << 24) | minor(dev);
}
