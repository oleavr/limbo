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
#include <stddef.h>
#endif
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <ucontext.h>
#include <unistd.h>

#include "bsd/credentials.h"
#include "bsd/handler.h"
#include "bsd/signals.h"
#include "bsd/xnu-errno.h"
#include "mdep/handler.h"
#include "osfmk/handler.h"
#include "syscall.h"
#include "thread.h"

/* Never allow system calls from outside our binary region */
static const uint8_t selector = SYSCALL_DISPATCH_FILTER_BLOCK;

static void handle_syscall(int sig, siginfo_t *info, void *ucontext);
static bool returns_raw_result(unsigned long syscall, uint64_t arg1);
static int signal_stack_install(void);
static void signal_stack_create_key(void);
static void signal_stack_free(void *base);
#ifndef __x86_64__
static int filter_install(const Elf64_Phdr *phdrs, unsigned long e_phnum);

static bool filter_installed;
#endif

#define SIGNAL_STACK_SIZE (1UL << 20)

struct signal_stack {
	uint64_t thread_pointer;
};

static pthread_key_t signal_stack_key;
static pthread_once_t signal_stack_once = PTHREAD_ONCE_INIT;

#ifdef __x86_64__
static void set_bsd_result(greg_t *regs, int64_t result);

static __thread bool rdx_pending;
static __thread uint64_t rdx_value;
static __thread ucontext_t *trap_context;
static __thread bool context_kept;
static __thread bool guest_thread;
#else
#define PSTATE_C (1u << 29)
#define MRS_OPCODE 0xd53
static void emulate_system_register(int sig, siginfo_t *info, void *ucontext);
static void dispatch_syscall(mcontext_t *mc);
static void set_bsd_result(mcontext_t *mc, int64_t result);
static __thread uint64_t guest_thread_pointer;
static __thread bool x1_pending;
static __thread uint64_t x1_value;
static __thread ucontext_t *trap_context;
static __thread bool context_kept;
#endif
static uintptr_t limbo_text_start, limbo_text_end;
static uintptr_t vdso_start, vdso_end;
static void find_limbo_text(void);
static bool in_limbo(uint64_t pc);
static void handle_suspend(int sig, siginfo_t *info, void *ucontext);

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

#ifdef __x86_64__
void
syscall_report_fault(int sig, siginfo_t *info, void *context)
{
	const greg_t *gregs = ((ucontext_t *)context)->uc_mcontext.gregs;
	fprintf(stderr,
			"limbo: fatal signal %d (code %d) at %llx, address "
			"%p\n",
			sig, info->si_code, (unsigned long long)gregs[REG_RIP],
			info->si_addr);
	fprintf(stderr, "  thread %d, sp %llx (%llx), bp %llx\n", (int)gettid(),
			(unsigned long long)gregs[REG_RSP],
			(unsigned long long)*(const uint64_t *)gregs[REG_RSP],
			(unsigned long long)gregs[REG_RBP]);
	FILE *maps = fopen("/proc/self/maps", "re");
	char line[256], previous[256] = "";
	uint64_t near[] = {(uint64_t)info->si_addr, (uint64_t)gregs[REG_RSP]};
	while (maps != NULL && fgets(line, sizeof(line), maps) != NULL) {
		unsigned long long start, end;
		if (sscanf(line, "%llx-%llx", &start, &end) != 2) {
			continue;
		}
		for (int i = 0; i != 2; i++) {
			if (near[i] >= start && near[i] < end) {
				fprintf(stderr, "  map before: %s  map %s: %s",
						previous, i ? "sp" : "address",
						line);
			}
		}
		snprintf(previous, sizeof(previous), "%s", line);
	}
	if (maps != NULL) {
		fclose(maps);
	}
	uint64_t address = (uint64_t)gregs[REG_RIP];
	const uint64_t *frame = (const uint64_t *)gregs[REG_RBP];
	for (int i = 0; i < 64 && address != 0; i++) {
		Dl_info found;
		if (dladdr((void *)address, &found)
				&& found.dli_sname != NULL) {
			fprintf(stderr, "  %llx %s+%#llx\n",
					(unsigned long long)address,
					found.dli_sname,
					(unsigned long long)(address
							- (uint64_t)found
									.dli_saddr));
		} else {
			fprintf(stderr, "  %llx\n",
					(unsigned long long)address);
		}
		if (frame == NULL || ((uintptr_t)frame & 7) != 0) {
			break;
		}
		address = frame[1];
		frame = (const uint64_t *)frame[0];
	}
	signal(sig, SIG_DFL);
	if (info->si_code <= 0 || sig == SIGTRAP) {
		raise(sig);
	}
}

void
syscall_signal_handler(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *uc = ucontext;
	if (!guest_thread) {
		signals_handle(sig, info, uc, SIGNAL_ON_LIMBO_THREAD);
		return;
	}
	signals_handle(sig, info, uc,
			in_limbo(uc->uc_mcontext.gregs[REG_RIP])
					? SIGNAL_IN_LIMBO
					: SIGNAL_IN_GUEST);
}

static void
handle_suspend(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *uc = ucontext;
	if (!in_limbo(uc->uc_mcontext.gregs[REG_RIP])) {
		thread_stop_if_suspended(uc);
	}
}
#endif

int
syscall_handler_install(void)
{
	signal(SIGPIPE, SIG_IGN);

	struct sigaction act;
	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_sigaction = handle_syscall;
	act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
#ifndef __x86_64__
	act.sa_flags |= SA_RESTORER;
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
	find_limbo_text();
	signals_init();

	struct sigaction suspend = {0};
	suspend.sa_sigaction = handle_suspend;
	suspend.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART | SA_RESTORER;
	suspend.sa_restorer = limbo_rt_sigreturn;
	sigaction(thread_suspend_signal(), &suspend, NULL);
#endif
#ifdef __x86_64__

	find_limbo_text();
	signals_init();
	struct sigaction suspend = {0};
	suspend.sa_sigaction = handle_suspend;
	suspend.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
	sigaction(thread_suspend_signal(), &suspend, NULL);
#endif
	credentials_init();
	return 0;
}

#ifndef __x86_64__

__attribute__((always_inline)) static inline uint64_t
enter_limbo(void)
{
	uint64_t entry_pointer, stack_pointer;
	asm volatile("mrs %0, tpidr_el0" : "=r"(entry_pointer));
	asm volatile("mov %0, sp" : "=r"(stack_pointer));
	const struct signal_stack *stack = (const void *)(stack_pointer
			& ~(SIGNAL_STACK_SIZE - 1));
	asm volatile("msr tpidr_el0, %0" ::"r"(stack->thread_pointer));
	return entry_pointer;
}

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
	syscall_signal_handler(sig, info, ucontext);
}

__attribute__((no_stack_protector)) void
syscall_signal_handler(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *uc = ucontext;
	stack_t ss;
	register uint64_t x0 asm("x0") = 0;
	register uint64_t x1 asm("x1") = (uint64_t)&ss;
	register uint64_t x8 asm("x8") = 132;
	asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
	if (x0 != 0 || !(ss.ss_flags & SS_ONSTACK)) {
		signals_handle(sig, info, uc, SIGNAL_ON_LIMBO_THREAD);
		return;
	}

	uint64_t entry_pointer = enter_limbo();
	signals_handle(sig, info, uc,
			in_limbo(uc->uc_mcontext.pc) ? SIGNAL_IN_LIMBO
						     : SIGNAL_IN_GUEST);
	asm volatile("msr tpidr_el0, %0" ::"r"(entry_pointer));
}

__attribute__((no_stack_protector)) static void
handle_suspend(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *uc = ucontext;
	uint64_t entry_pointer = enter_limbo();
	if (!in_limbo(uc->uc_mcontext.pc)) {
		thread_stop_if_suspended(uc);
	}
	asm volatile("msr tpidr_el0, %0" ::"r"(entry_pointer));
}
#endif

#ifndef __x86_64__
#endif

static void
find_limbo_text(void)
{
	Elf64_Phdr *phdrs = (Elf64_Phdr *)getauxval(AT_PHDR);
	unsigned long e_phnum = getauxval(AT_PHNUM);
	limbo_text_start = UINTPTR_MAX;
	for (unsigned long i = 0; i < e_phnum; i++) {
		if (phdrs[i].p_type == PT_LOAD && (phdrs[i].p_flags & PF_X)) {
			uintptr_t end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
			if (phdrs[i].p_vaddr < limbo_text_start) {
				limbo_text_start = phdrs[i].p_vaddr;
			}
			if (end > limbo_text_end) {
				limbo_text_end = end;
			}
		}
	}

	const Elf64_Ehdr *vdso = (const void *)getauxval(AT_SYSINFO_EHDR);
	if (vdso == NULL) {
		return;
	}
	const Elf64_Phdr *vphdrs
			= (const void *)((const uint8_t *)vdso + vdso->e_phoff);
	for (int i = 0; i < vdso->e_phnum; i++) {
		if (vphdrs[i].p_type == PT_LOAD) {
			vdso_start = (uintptr_t)vdso;
			vdso_end = (uintptr_t)vdso + vphdrs[i].p_offset
					+ vphdrs[i].p_memsz;
		}
	}
}

static bool
in_limbo(uint64_t pc)
{
	return (pc >= limbo_text_start && pc < limbo_text_end)
			|| (pc >= vdso_start && pc < vdso_end);
}

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

#define BSD_SYS___pthread_kill 328
#define BSD_SYS_abort_with_payload 521
#define BSD_SYS_ulock_wait  515
#define BSD_SYS_ulock_wake  516
#define BSD_SYS_ulock_wait2 544

#ifdef __x86_64__
/*
 * The guest's return addresses, from its frame pointers, for a guest that
 * aborts: a system call's stub makes no frame, so its caller's address is
 * the one at the stack pointer
 */
void
syscall_print_guest_chain(const mcontext_t *mc)
{
	const uint64_t *sp = (const uint64_t *)mc->gregs[REG_RSP];
	fprintf(stderr, "  guest chain: %llx %llx",
			(unsigned long long)mc->gregs[REG_RIP],
			(unsigned long long)sp[0]);
	const uint64_t *frame = (const uint64_t *)mc->gregs[REG_RBP];
	for (int i = 0; i < 64 && frame != NULL && ((uintptr_t)frame & 7) == 0;
			i++) {
		fprintf(stderr, " %llx", (unsigned long long)frame[1]);
		frame = (const uint64_t *)frame[0];
	}
	fprintf(stderr, "\n");
}

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
	ucontext_t *outer_context = trap_context;
	trap_context = context;
	asm volatile("limbo_syscall_entered:" ::: "memory");
	void *outer_trap;
	thread_enter_trap(context, &outer_trap);

	unsigned long syscall = info->si_syscall;
	if (signals_trap_enter(context)) {
		regs[REG_RIP] -= 2;
		regs[REG_RAX] = (greg_t)syscall;
	} else if (syscall >= SYSCALL_CLASS_MACH
			&& syscall < SYSCALL_CLASS_UNIX) {
		regs[REG_RAX] = sys_osfmk(syscall - SYSCALL_CLASS_MACH, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else if (syscall >= SYSCALL_CLASS_UNIX
			&& syscall < SYSCALL_CLASS_MDEP) {
		/* SIGABRT, which Darwin numbers as Linux does */
		unsigned long number = syscall - SYSCALL_CLASS_UNIX;
		if ((number == BSD_SYS___pthread_kill && arg2 == SIGABRT)
				|| number == BSD_SYS_abort_with_payload) {
			syscall_print_guest_chain(&context->uc_mcontext);
		}
		int64_t result = sys_bsd(syscall - SYSCALL_CLASS_UNIX, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
		if (context_kept) {
			context_kept = false;
			rdx_pending = false;
		} else if (result == _EINTR
				&& signals_restart(
						syscall - SYSCALL_CLASS_UNIX)) {
			regs[REG_RIP] -= 2;
			regs[REG_RAX] = (greg_t)syscall;
			rdx_pending = false;
		} else if (returns_raw_result(syscall - SYSCALL_CLASS_UNIX,
					   arg1)) {
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
		fprintf(stderr, "limbo: missing system call %#lx\n", syscall);
		abort();
	}
	signals_trap_exit(context);
	thread_leave_trap(context, outer_trap);
	trap_context = outer_context;
}

ucontext_t *
syscall_trap_context(void)
{
	return trap_context;
}

/* A thread that leaves a system call for good, as a parked workqueue thread
 * does, is in none */
void
syscall_trap_reset(void)
{
	trap_context = NULL;
}

/* The system call replaced the context it returns to */
void
syscall_keep_context(void)
{
	context_kept = true;
}
#else
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
	ucontext_t *outer_context = trap_context;
	trap_context = ucontext;
	asm volatile("limbo_syscall_entered:" ::: "memory");
	void *outer_trap;
	thread_enter_trap(ucontext, &outer_trap);

	if (signals_trap_enter(ucontext)) {
		mc->pc -= 4;
	} else {
		dispatch_syscall(mc);
	}
	signals_trap_exit(ucontext);
	thread_leave_trap(ucontext, outer_trap);

	trap_context = outer_context;
	uint64_t resume_pointer = guest_thread_pointer;
	guest_thread_pointer = outer_pointer;
	asm volatile("msr tpidr_el0, %0" ::"r"(resume_pointer));
}

void
syscall_set_guest_thread_pointer(uint64_t pointer)
{
	guest_thread_pointer = pointer;
}

ucontext_t *
syscall_trap_context(void)
{
	return trap_context;
}

void
syscall_trap_reset(void)
{
	trap_context = NULL;
}

void
syscall_keep_context(void)
{
	context_kept = true;
}

void
syscall_print_guest_chain(const mcontext_t *mc)
{
	fprintf(stderr, "  guest chain: %llx %llx", mc->pc & 0x7fffffffffULL,
			mc->regs[30] & 0x7fffffffffULL);
	const uint64_t *frame = (const uint64_t *)mc->regs[29];
	for (int i = 0; i < 64 && frame != NULL && ((uintptr_t)frame & 7) == 0;
			i++) {
		fprintf(stderr, " %llx",
				(unsigned long long)(frame[1]
						& 0x7fffffffffULL));
		frame = (const uint64_t *)frame[0];
	}
	fprintf(stderr, "\n");
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
		/* SIGABRT, which Darwin numbers as Linux does */
		if ((number == BSD_SYS___pthread_kill && arg2 == SIGABRT)
				|| number == BSD_SYS_abort_with_payload) {
			syscall_print_guest_chain(mc);
		}
		int64_t result = sys_bsd((unsigned long)number, arg1, arg2,
				arg3, arg4, arg5, arg6, sp);
		if (context_kept) {
			context_kept = false;
			x1_pending = false;
		} else if (result == _EINTR
				&& signals_restart((unsigned long)number)) {
			regs[0] = arg1;
			regs[1] = arg2;
			mc->pc -= 4;
			x1_pending = false;
		} else if (returns_raw_result((unsigned long)number, arg1)) {
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

bool
syscall_entering(const ucontext_t *uc)
{
	extern const char limbo_syscall_entered[];
#ifdef __x86_64__
	uintptr_t pc = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
#else
	uintptr_t pc = (uintptr_t)uc->uc_mcontext.pc;
#endif
	return pc >= (uintptr_t)handle_syscall
			&& pc < (uintptr_t)limbo_syscall_entered;
}

/* The guest's call chain into the system call the thread is in, which
 * names the code that wanted what limbo lacks */
void
syscall_print_trap_chain(void)
{
	if (trap_context != NULL) {
		syscall_print_guest_chain(&trap_context->uc_mcontext);
	}
}

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
#else
	if (signal_stack_install()) {
		return 1;
	}
	guest_thread = true;
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
#endif

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
#ifndef __x86_64__
	asm volatile("mrs %0, tpidr_el0" : "=r"(stack->thread_pointer));
#endif

	stack_t ss = {
			.ss_sp = base + sizeof(*stack),
			.ss_size = SIGNAL_STACK_SIZE - sizeof(*stack),
	};
	if (sigaltstack(&ss, NULL) == -1) {
		perror("sigaltstack");
		munmap(base, SIGNAL_STACK_SIZE);
		return 1;
	}

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
