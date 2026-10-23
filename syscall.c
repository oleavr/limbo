/*
 * Copyright © 2021 Keegan Saunders
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef __x86_64__
#include <asm/processor-flags.h>
#endif
#include <elf.h>
#include <errno.h>
#ifndef __x86_64__
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/mman.h>
#endif
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <ucontext.h>
#include <unistd.h>

#include "bsd/handler.h"
#include "bsd/xnu-errno.h"
#include "mdep/handler.h"
#include "osfmk/handler.h"
#include "syscall.h"

/* Never allow system calls from outside our binary region */
static const uint8_t selector = SYSCALL_DISPATCH_FILTER_BLOCK;

static void handle_syscall(int sig, siginfo_t *info, void *ucontext);
static bool returns_raw_result(unsigned long syscall, uint64_t arg1);
#ifndef __x86_64__
static int filter_install(const Elf64_Phdr *phdrs, unsigned long e_phnum);
static int signal_stack_install(void);
static void signal_stack_create_key(void);
static void signal_stack_free(void *base);

static bool filter_installed;
#endif

#ifdef __x86_64__
static void set_bsd_result(greg_t *regs, int64_t result);

static __thread bool rdx_pending;
static __thread uint64_t rdx_value;
#else
#define PSTATE_C (1u << 29)
#define MRS_OPCODE 0xd53
static void emulate_system_register(int sig, siginfo_t *info, void *ucontext);
static void dispatch_syscall(mcontext_t *mc);
static void set_bsd_result(mcontext_t *mc, int64_t result);
#define SIGNAL_STACK_SIZE (1UL << 20)

struct signal_stack {
	uint64_t thread_pointer;
};

static pthread_key_t signal_stack_key;
static pthread_once_t signal_stack_once = PTHREAD_ONCE_INIT;
static __thread uint64_t guest_thread_pointer;
static __thread bool x1_pending;
static __thread uint64_t x1_value;
#endif

#ifndef __x86_64__
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif
void limbo_rt_sigreturn(void);
asm(".text\n"
    ".globl limbo_rt_sigreturn\n"
    ".type limbo_rt_sigreturn, %function\n"
    "limbo_rt_sigreturn:\n"
    "	mov x8, #139\n" /* __NR_rt_sigreturn */
    "	svc #0\n");
#endif

int
syscall_handler_install(void)
{
	signal(SIGPIPE, SIG_IGN);

	struct sigaction act;
	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_sigaction = handle_syscall;
	act.sa_flags = SA_SIGINFO | SA_NODEFER;
#ifndef __x86_64__
	act.sa_flags |= SA_ONSTACK | SA_RESTORER;
	act.sa_restorer = limbo_rt_sigreturn;
#endif

	if (sigaction(SIGSYS, &act, NULL) == -1) {
		perror("sigaction");
		return 1;
	}
#ifndef __x86_64__
	struct sigaction ill = {0};
	ill.sa_sigaction = emulate_system_register;
	ill.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK | SA_RESTORER;
	ill.sa_restorer = limbo_rt_sigreturn;
	if (sigaction(SIGILL, &ill, NULL) == -1) {
		perror("sigaction");
		return 1;
	}
#endif
	return 0;
}

#ifndef __x86_64__
__attribute__((no_stack_protector)) static void
emulate_system_register(int sig, siginfo_t *info, void *ucontext)
{
	mcontext_t *mc = &((ucontext_t *)ucontext)->uc_mcontext;
	uint32_t instruction = *(uint32_t *)mc->pc;
	if ((instruction >> 20) == MRS_OPCODE) {
		unsigned destination = instruction & 0x1f;
		if (destination != 31) {
			mc->regs[destination] = 0;
		}
		mc->pc += 4;
		return;
	}
	abort();
}
#endif

/*
 * System calls in Darwin are split into classes, as follows:
 * SYSCALL_CLASS_NONE  0   Invalid
 * SYSCALL_CLASS_MACH  1   Mach
 * SYSCALL_CLASS_UNIX  2   Unix/BSD
 * SYSCALL_CLASS_MDEP  3   Machine-dependent
 * SYSCALL_CLASS_DIAG  4   Diagnostics
 *
 * The system call number is the 24-bit left shift: (2 << 24) is to call
 * SYSCALL_CLASS_UNIX
 */

#define SYSCALL_CLASS_NONE 0
#define SYSCALL_CLASS_MACH (1 << 24)
#define SYSCALL_CLASS_UNIX (2 << 24)
#define SYSCALL_CLASS_MDEP (3 << 24)
#define SYSCALL_CLASS_DIAG (4 << 24)

#define SYSCALL_CLASS_MDEP_ARM64 0x80000000
#define SVC_LINUX 0xd4000001

#define BSD_SYS_ulock_wait  515
#define BSD_SYS_ulock_wake  516
#define BSD_SYS_ulock_wait2 544

#ifdef __x86_64__
static void
handle_syscall(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *context = (ucontext_t *)ucontext;
	greg_t *regs = context->uc_mcontext.gregs;

	/*
	 * RDI, RSI, RDX, R10, R8, R9 and then spilling to the stack
	 *
	 * Presumably due to how the Linux system call trapping is implemented,
	 * the 7th argument lands on the 2nd slot of the stack (1st is LR)
	 *
	 * Returns in RAX
	 */

	uint64_t arg1 = regs[REG_RDI];
	uint64_t arg2 = regs[REG_RSI];
	uint64_t arg3 = regs[REG_RDX];
	uint64_t arg4 = regs[REG_R10];
	uint64_t arg5 = regs[REG_R8];
	uint64_t arg6 = regs[REG_R9];
	uint64_t *sp = (uint64_t *)regs[REG_RSP];

	unsigned long syscall = info->si_syscall;
	if (syscall >= SYSCALL_CLASS_MACH && syscall < SYSCALL_CLASS_UNIX) {
		regs[REG_RAX] = sys_osfmk(syscall - SYSCALL_CLASS_MACH, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else if (syscall >= SYSCALL_CLASS_UNIX
			&& syscall < SYSCALL_CLASS_MDEP) {
		int64_t result = sys_bsd(syscall - SYSCALL_CLASS_UNIX, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
		if (returns_raw_result(syscall - SYSCALL_CLASS_UNIX, arg1)) {
			regs[REG_EFL] &= ~X86_EFLAGS_CF;
			regs[REG_RAX] = result;
		} else {
			set_bsd_result(regs, result);
		}
		if (rdx_pending) {
			regs[REG_RDX] = rdx_value;
			rdx_pending = false;
		}
	} else if (syscall >= SYSCALL_CLASS_MDEP
			&& syscall < SYSCALL_CLASS_DIAG) {
		regs[REG_RAX] = sys_mdep(syscall - SYSCALL_CLASS_MDEP, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else {
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> Missing system call: %#lx", syscall);
#endif
		abort();
	}
}
#else /* __arm64__ */
__attribute__((no_stack_protector)) static void
handle_syscall(int sig, siginfo_t *info, void *ucontext)
{
	mcontext_t *mc = &((ucontext_t *)ucontext)->uc_mcontext;

	if (((uint32_t *)mc->pc)[-1] == SVC_LINUX) {
		dispatch_syscall(mc);
		return;
	}

	uint64_t entry_pointer, stack_pointer;
	asm volatile("mrs %0, tpidr_el0" : "=r"(entry_pointer));
	asm volatile("mov %0, sp" : "=r"(stack_pointer));
	const struct signal_stack *stack = (const void *)(stack_pointer
			& ~(SIGNAL_STACK_SIZE - 1));
	asm volatile("msr tpidr_el0, %0" ::"r"(stack->thread_pointer));
	uint64_t outer_pointer = guest_thread_pointer;
	guest_thread_pointer = entry_pointer;

	dispatch_syscall(mc);

	uint64_t resume_pointer = guest_thread_pointer;
	guest_thread_pointer = outer_pointer;
	asm volatile("msr tpidr_el0, %0" ::"r"(resume_pointer));
}

void
syscall_set_guest_thread_pointer(uint64_t pointer)
{
	guest_thread_pointer = pointer;
}

static void
dispatch_syscall(mcontext_t *mc)
{
	unsigned long long *regs = mc->regs;
	uint64_t arg1 = regs[0];
	uint64_t arg2 = regs[1];
	uint64_t arg3 = regs[2];
	uint64_t arg4 = regs[3];
	uint64_t arg5 = regs[4];
	uint64_t arg6 = regs[5];

	if (((uint32_t *)mc->pc)[-1] == SVC_LINUX) {
		regs[0] = syscall(regs[8], regs[0], regs[1], regs[2], regs[3],
				regs[4], regs[5]);
		return;
	}

	uint64_t *overflow = (uint64_t *)mc->sp;
	uint64_t sp[] = {0, regs[6], regs[7], overflow[0], overflow[1]};

	int64_t number = (int64_t)regs[16];
	if (number < 0) {
		regs[0] = sys_osfmk((unsigned long)-number, arg1, arg2, arg3,
				arg4, arg5, arg6, sp);
	} else if ((uint64_t)number & SYSCALL_CLASS_MDEP_ARM64) {
		regs[0] = sys_mdep((unsigned long)number, arg1, arg2, arg3,
				arg4, arg5, arg6, sp);
	} else {
		int64_t result = sys_bsd((unsigned long)number, arg1, arg2,
				arg3, arg4, arg5, arg6, sp);
		if (returns_raw_result((unsigned long)number, arg1)) {
			mc->pstate &= ~PSTATE_C;
			regs[0] = result;
		} else {
			set_bsd_result(mc, result);
		}
		if (x1_pending) {
			regs[1] = x1_value;
			x1_pending = false;
		}
	}
}
#endif

static bool
returns_raw_result(unsigned long syscall, uint64_t arg1)
{
	switch (syscall) {
	case BSD_SYS_ulock_wait:
	case BSD_SYS_ulock_wake:
	case BSD_SYS_ulock_wait2:
		return arg1 & ULF_NO_ERRNO;
	default:
		return false;
	}
}

#ifdef __x86_64__
static void
set_bsd_result(greg_t *regs, int64_t result)
{
	if (result < 0 && result >= _ELAST) {
		regs[REG_EFL] |= X86_EFLAGS_CF;
		regs[REG_RAX] = -result;
	} else {
		regs[REG_EFL] &= ~X86_EFLAGS_CF;
		regs[REG_RAX] = result;
	}
}

void
syscall_set_rdx(uint64_t value)
{
	rdx_value = value;
	rdx_pending = true;
}
#else
static void
set_bsd_result(mcontext_t *mc, int64_t result)
{
	if (result < 0 && result >= _ELAST) {
		mc->pstate |= PSTATE_C;
		mc->regs[0] = -result;
	} else {
		mc->pstate &= ~PSTATE_C;
		mc->regs[0] = result;
	}
}

void
syscall_set_rdx(uint64_t value)
{
	x1_value = value;
	x1_pending = true;
}
#endif

int
syscall_dispatch_enable(void)
{
#ifndef __x86_64__
	if (signal_stack_install()) {
		return 1;
	}
	if (filter_installed) {
		return 0;
	}
#endif

	/* Enumerate the program headers of the executable to determine the
	 * region for which we should NOT trap all system calls */
	Elf64_Phdr *phdrs = (Elf64_Phdr *)getauxval(AT_PHDR);
	unsigned long e_phnum = getauxval(AT_PHNUM);

	for (uint32_t i = 0; i < e_phnum; i++) {
		Elf64_Phdr phdr = phdrs[i];
		if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
			if (prctl(PR_SET_SYSCALL_USER_DISPATCH,
					    PR_SYS_DISPATCH_ON, phdr.p_vaddr,
					    phdr.p_memsz, &selector)) {
#ifndef __x86_64__
				if (errno == EINVAL) {
					return filter_install(phdrs, e_phnum);
				}
#endif
				perror("prctl");
				return 1;
			}
		}
	}
	return 0;
}

#ifndef __x86_64__
#define IP_LOW  offsetof(struct seccomp_data, instruction_pointer)
#define IP_HIGH (IP_LOW + sizeof(uint32_t))

static int
filter_install(const Elf64_Phdr *phdrs, unsigned long e_phnum)
{
	struct sock_filter program[6 * e_phnum + 1];
	unsigned short length = 0;

	for (uint32_t i = 0; i < e_phnum; i++) {
		const Elf64_Phdr *phdr = &phdrs[i];
		if (phdr->p_type != PT_LOAD || !(phdr->p_flags & PF_X)) {
			continue;
		}

		uint64_t start = phdr->p_vaddr;
		uint64_t end = phdr->p_vaddr + phdr->p_memsz;
		if (start >> 32 != end >> 32) {
			fprintf(stderr, "limbo: segment spans 4 GiB\n");
			return 1;
		}

		struct sock_filter range[] = {
				BPF_STMT(BPF_LD | BPF_W | BPF_ABS, IP_HIGH),
				BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						(uint32_t)(start >> 32), 0, 4),
				BPF_STMT(BPF_LD | BPF_W | BPF_ABS, IP_LOW),
				BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
						(uint32_t)start, 0, 2),
				BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K,
						(uint32_t)end, 1, 0),
				BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		};
		memcpy(&program[length], range, sizeof(range));
		length += sizeof(range) / sizeof(range[0]);
	}
	program[length++] = (struct sock_filter)BPF_STMT(
			BPF_RET | BPF_K, SECCOMP_RET_TRAP);

	struct sock_fprog fprog = {.len = length, .filter = program};
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
			|| prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog)) {
		perror("seccomp");
		return 1;
	}
	filter_installed = true;
	return 0;
}

static int
signal_stack_install(void)
{
	stack_t current;
	if (sigaltstack(NULL, &current) == 0
			&& !(current.ss_flags & SS_DISABLE)) {
		return 0;
	}

	uint8_t *region = mmap(NULL, 2 * SIGNAL_STACK_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	uint8_t *base = (uint8_t *)(((uintptr_t)region + SIGNAL_STACK_SIZE - 1)
			& ~(SIGNAL_STACK_SIZE - 1));
	if (base != region) {
		munmap(region, base - region);
	}
	munmap(base + SIGNAL_STACK_SIZE, region + SIGNAL_STACK_SIZE - base);

	struct signal_stack *stack = (struct signal_stack *)base;
	asm volatile("mrs %0, tpidr_el0" : "=r"(stack->thread_pointer));

	stack_t ss = {
			.ss_sp = base + sizeof(*stack),
			.ss_size = SIGNAL_STACK_SIZE - sizeof(*stack),
	};
	sigaltstack(&ss, NULL);

	pthread_once(&signal_stack_once, signal_stack_create_key);
	pthread_setspecific(signal_stack_key, base);
	return 0;
}

static void
signal_stack_create_key(void)
{
	pthread_key_create(&signal_stack_key, signal_stack_free);
}

static void
signal_stack_free(void *base)
{
	stack_t ss = {.ss_flags = SS_DISABLE};
	sigaltstack(&ss, NULL);
	munmap(base, SIGNAL_STACK_SIZE);
}
#endif
