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

#pragma once

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <ucontext.h>

enum signal_context {

	SIGNAL_IN_GUEST,

	SIGNAL_IN_LIMBO,

	SIGNAL_ON_LIMBO_THREAD,
};

void signals_init(void);
void signals_handle(int sig, siginfo_t *info, ucontext_t *uc,
		enum signal_context context);
bool signals_trap_enter(ucontext_t *uc);
bool signals_restart(unsigned long number);
void signals_trap_exit(ucontext_t *uc);
void signals_fork_child(void);
int signals_kick_signal(void);
int signals_mask(int how, const uint32_t *set, uint32_t *oset);
int signals_suspend(uint32_t mask);
bool signals_wait_begin(uint32_t mask, sigset_t *previous, sigset_t *set);
void signals_watch(int sig, bool watch);
