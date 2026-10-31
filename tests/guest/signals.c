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

#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

static volatile sig_atomic_t got;
static volatile sig_atomic_t got_pid;
static volatile sig_atomic_t children;
static int self_pipe[2];
static volatile sig_atomic_t fault_on_altstack;
static volatile sig_atomic_t fault_address_ok;
static sigjmp_buf fault_jump;

static void
on_signal(int sig)
{
	got = sig;
}

static void
on_signal_info(int sig, siginfo_t *info, void *context)
{
	got = sig;
	got_pid = info->si_pid;
}

static void
on_fault(int sig, siginfo_t *info, void *context)
{
	stack_t stack;
	sigaltstack(NULL, &stack);
	fault_on_altstack = (stack.ss_flags & SS_ONSTACK) != 0;
	fault_address_ok = info->si_addr == (void *)0x10;
	siglongjmp(fault_jump, 1);
}

static void
on_trap(int sig, siginfo_t *info, void *context)
{
#ifdef __arm64__
	ucontext_t *uc = context;
	uc->uc_mcontext->__ss.__pc += 4;
#endif
	got = sig;
}

static void
on_alarm(int sig)
{

	volatile double x = 1.5;
	for (int i = 0; i < 100; i++) {
		x = x * 1.0001 + 0.5;
	}
	got = sig;
}

static void
on_child(int sig)
{
	children++;
}

static void
on_child_pipe(int sig)
{
	char byte = 1;
	write(self_pipe[1], &byte, 1);
}

static void
on_blocked(int sig)
{
	static const char message[] = "a SIGCHLD never came to a read\n";
	write(STDERR_FILENO, message, sizeof(message) - 1);
	_exit(1);
}

static void
on_stuck(int sig)
{
	static const char message[] = "a SIGCHLD never woke sigsuspend\n";
	write(STDERR_FILENO, message, sizeof(message) - 1);
	_exit(1);
}

static void
check_handlers(void)
{
	signal(SIGUSR1, on_signal);
	got = 0;
	raise(SIGUSR1);
	CHECK(got == SIGUSR1);

	got = 0;
	kill(getpid(), SIGUSR1);
	CHECK(got == SIGUSR1);

	struct sigaction action = {0};
	action.sa_sigaction = on_signal_info;
	action.sa_flags = SA_SIGINFO;
	sigaction(SIGUSR2, &action, NULL);
	got = 0;
	kill(getpid(), SIGUSR2);
	CHECK(got == SIGUSR2 && got_pid == getpid());

	struct sigaction old;
	sigaction(SIGUSR1, NULL, &old);
	CHECK(old.sa_handler == on_signal);

	got = 0;
	pthread_kill(pthread_self(), SIGUSR1);
	CHECK(got == SIGUSR1);
}

static void
check_mask(void)
{
	sigset_t set, old, pending;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, &old);
	got = 0;
	raise(SIGUSR1);
	sigpending(&pending);
	CHECK(got == 0 && sigismember(&pending, SIGUSR1));
	sigprocmask(SIG_SETMASK, &old, NULL);
	CHECK(got == SIGUSR1);
}

static void
check_faults(void)
{
	stack_t stack = {.ss_sp = malloc(65536), .ss_size = 65536};
	CHECK(sigaltstack(&stack, NULL) == 0);
	struct sigaction action = {0};
	action.sa_sigaction = on_fault;
	action.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	if (sigsetjmp(fault_jump, 1) == 0) {
		*(volatile int *)0x10 = 1;
		CHECK(!"no fault");
	}
	CHECK(fault_on_altstack && fault_address_ok);

	action.sa_sigaction = on_trap;
	action.sa_flags = SA_SIGINFO;
	sigaction(SIGTRAP, &action, NULL);
	got = 0;
	__builtin_debugtrap();
	CHECK(got == SIGTRAP);
}

static void
check_alarm(void)
{
	signal(SIGALRM, on_alarm);
	got = 0;
	volatile double acc = 0.25;
	alarm(1);
	while (!got) {
		acc = acc * 1.0 + 0.0;
	}
	CHECK(acc == 0.25);
}

static void
check_child(void)
{
	signal(SIGCHLD, on_child);
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, &old);
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		usleep(100000);
		_exit(7);
	}
	sigset_t wait_mask = old;
	sigdelset(&wait_mask, SIGCHLD);
	while (children == 0) {
		sigsuspend(&wait_mask);
	}
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	sigprocmask(SIG_SETMASK, &old, NULL);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);
}

static void
check_children(void)
{
	signal(SIGCHLD, on_child);
	signal(SIGALRM, on_stuck);
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, &old);
	sigset_t wait_mask = old;
	sigdelset(&wait_mask, SIGCHLD);
	mach_timebase_info_data_t timebase;
	mach_timebase_info(&timebase);
	alarm(60);
	for (int i = 0; i < 4000; i++) {
		children = 0;
		sigprocmask(SIG_UNBLOCK, &set, NULL);
		pid_t pid = fork();
		CHECK(pid >= 0);
		if (pid == 0) {
			_exit(0);
		}
		uint64_t until = mach_absolute_time()
				+ (uint64_t)(i % 1000) * 1000 * timebase.denom
						/ timebase.numer;
		while (mach_absolute_time() < until) {
		}
		sigprocmask(SIG_BLOCK, &set, NULL);
		while (children == 0) {
			sigsuspend(&wait_mask);
		}
		int status;
		CHECK(waitpid(pid, &status, 0) == pid);
	}
	alarm(0);
	sigprocmask(SIG_SETMASK, &old, NULL);
	signal(SIGCHLD, SIG_DFL);
}

static void
on_alarm_pipe(int sig)
{
	char byte = 1;
	write(self_pipe[1], &byte, 1);
}

static void
check_restart(void)
{
	CHECK(pipe(self_pipe) == 0);
	struct sigaction action
			= {.sa_handler = on_alarm_pipe, .sa_flags = SA_RESTART};
	sigemptyset(&action.sa_mask);
	CHECK(sigaction(SIGALRM, &action, NULL) == 0);
	alarm(1);
	char byte;
	CHECK(read(self_pipe[0], &byte, 1) == 1 && byte == 1);
	signal(SIGALRM, SIG_DFL);
	close(self_pipe[0]);
	close(self_pipe[1]);
}

static void
check_self_pipe(void)
{
	CHECK(pipe(self_pipe) == 0);
	signal(SIGCHLD, on_child_pipe);
	signal(SIGALRM, on_blocked);
	mach_timebase_info_data_t timebase;
	mach_timebase_info(&timebase);
	alarm(60);
	for (int i = 0; i < 4000; i++) {
		pid_t pid = fork();
		CHECK(pid >= 0);
		if (pid == 0) {
			_exit(0);
		}
		uint64_t until = mach_absolute_time()
				+ (uint64_t)(i % 1000) * 1000 * timebase.denom
						/ timebase.numer;
		while (mach_absolute_time() < until) {
		}
		char byte;
		CHECK(read(self_pipe[0], &byte, 1) == 1);
		int status;
		CHECK(waitpid(pid, &status, 0) == pid);
	}
	alarm(0);
	signal(SIGCHLD, SIG_DFL);
	close(self_pipe[0]);
	close(self_pipe[1]);
}

static void
check_source(void)
{
	signal(SIGTERM, SIG_IGN);
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	dispatch_source_t source = dispatch_source_create(
			DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0,
			dispatch_get_global_queue(0, 0));
	dispatch_source_set_event_handler(source, ^{
		dispatch_semaphore_signal(done);
	});
	dispatch_resume(source);
	kill(getpid(), SIGTERM);
	CHECK(dispatch_semaphore_wait(done,
			      dispatch_time(DISPATCH_TIME_NOW,
					      5 * NSEC_PER_SEC))
			== 0);
	dispatch_source_cancel(source);
}

int
main(void)
{
	check_handlers();
	check_mask();
	check_faults();
	check_alarm();
	check_child();
	check_children();
	check_restart();
	check_self_pipe();
	check_source();
	return 0;
}
