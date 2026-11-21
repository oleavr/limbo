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
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <os/lock.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
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
	for (int i = 0; i < 4000; i++) {
		alarm(60);
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
check_continued(void)
{
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		for (;;) {
			pause();
		}
	}
	int status;
	CHECK(kill(pid, SIGSTOP) == 0);
	CHECK(waitpid(pid, &status, WUNTRACED) == pid);
	CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
	CHECK(kill(pid, SIGCONT) == 0);
	CHECK(waitpid(pid, &status, WUNTRACED | WCONTINUED) == pid);
	CHECK(WIFCONTINUED(status));
	CHECK(kill(pid, SIGKILL) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
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
	for (int i = 0; i < 4000; i++) {
		alarm(60);
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

static void *
send_hangup(void *arg)
{
	usleep(100000);
	pthread_kill(*(pthread_t *)arg, SIGHUP);
	return NULL;
}

static void
check_sigwait(void)
{
	sigset_t set, old;
	int sig = 0;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, &old);
	got = 0;
	raise(SIGUSR1);
	CHECK(sigwait(&set, &sig) == 0 && sig == SIGUSR1 && got == 0);
	sigprocmask(SIG_SETMASK, &old, NULL);
	CHECK(got == 0);

	signal(SIGHUP, SIG_DFL);
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	sigprocmask(SIG_BLOCK, &set, &old);
	pthread_t self = pthread_self(), sender;
	pthread_create(&sender, NULL, send_hangup, &self);
	sig = 0;
	CHECK(sigwait(&set, &sig) == 0 && sig == SIGHUP);
	pthread_join(sender, NULL);
	sigprocmask(SIG_SETMASK, &old, NULL);

	sigset_t *no_set = NULL;
	CHECK(sigwait(no_set, &sig) == EINVAL);
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

static mach_port_t waited_port;
static volatile sig_atomic_t handled_in_receive;

static void
send_nothing(int sig)
{
}

static void
send_from_handler(int sig)
{
	(void)sig;
	handled_in_receive = 1;
	mach_msg_header_t message = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0),
			.msgh_size = sizeof(message),
			.msgh_remote_port = waited_port,
			.msgh_id = 0x4e7,
	};
	mach_msg(&message, MACH_SEND_MSG, sizeof(message), 0, MACH_PORT_NULL, 0,
			MACH_PORT_NULL);
}

static void
check_receive_interrupted(void)
{
	CHECK(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
			      &waited_port)
			== KERN_SUCCESS);
	signal(SIGALRM, send_nothing);
	struct {
		mach_msg_header_t header;
		mach_msg_trailer_t trailer;
	} received;
	mach_msg_return_t result = MACH_RCV_TIMED_OUT;
	for (int tries = 0; tries < 5 && result == MACH_RCV_TIMED_OUT;
			tries++) {
		ualarm(100000, 0);
		result = mach_msg(&received.header,
				MACH_RCV_MSG | MACH_RCV_INTERRUPT
						| MACH_RCV_TIMEOUT,
				0, sizeof(received), waited_port, 1000,
				MACH_PORT_NULL);
	}
	CHECK(result == MACH_RCV_INTERRUPTED);

	signal(SIGALRM, send_from_handler);
	ualarm(100000, 0);
	CHECK(mach_msg(&received.header, MACH_RCV_MSG, 0, sizeof(received),
			      waited_port, 0, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(handled_in_receive && received.header.msgh_id == 0x4e7);
	signal(SIGALRM, SIG_DFL);
	mach_port_mod_refs(mach_task_self(), waited_port,
			MACH_PORT_RIGHT_RECEIVE, -1);
}

enum wait_kind {
	WAIT_CONDITION,
	WAIT_MUTEX,
	WAIT_UNFAIR_LOCK,
	WAIT_KINDS,
};

static volatile sig_atomic_t interruptions;
static volatile sig_atomic_t wait_ended;
static volatile sig_atomic_t interrupted_during_wait;
static pthread_mutex_t late_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t late_cond = PTHREAD_COND_INITIALIZER;
static bool late_ready;
static os_unfair_lock late_lock = OS_UNFAIR_LOCK_INIT;
static dispatch_semaphore_t late_held;

static void
count_interruption(int sig)
{
	(void)sig;
	interruptions++;
	interrupted_during_wait = !wait_ended;
}

static void *
end_wait_late(void *arg)
{
	enum wait_kind kind = (enum wait_kind)(intptr_t)arg;
	if (kind == WAIT_MUTEX) {
		pthread_mutex_lock(&late_mutex);
		dispatch_semaphore_signal(late_held);
	} else if (kind == WAIT_UNFAIR_LOCK) {
		os_unfair_lock_lock(&late_lock);
		dispatch_semaphore_signal(late_held);
	}
	usleep(300000);
	wait_ended = 1;
	switch (kind) {
	case WAIT_CONDITION:
		pthread_mutex_lock(&late_mutex);
		late_ready = true;
		pthread_cond_signal(&late_cond);
		pthread_mutex_unlock(&late_mutex);
		break;
	case WAIT_MUTEX:
		pthread_mutex_unlock(&late_mutex);
		break;
	case WAIT_UNFAIR_LOCK:
		os_unfair_lock_unlock(&late_lock);
		break;
	case WAIT_KINDS:
		break;
	}
	return NULL;
}

static void
check_waits_interrupted(void)
{
	signal(SIGALRM, count_interruption);
	late_held = dispatch_semaphore_create(0);
	for (enum wait_kind kind = 0; kind != WAIT_KINDS; kind++) {
		interruptions = 0;
		interrupted_during_wait = 0;
		wait_ended = 0;
		pthread_t ender;
		CHECK(pthread_create(&ender, NULL, end_wait_late,
				      (void *)(intptr_t)kind)
				== 0);
		if (kind != WAIT_CONDITION) {
			dispatch_semaphore_wait(
					late_held, DISPATCH_TIME_FOREVER);
		}
		ualarm(100000, 0);
		switch (kind) {
		case WAIT_CONDITION:
			pthread_mutex_lock(&late_mutex);
			while (!late_ready) {
				pthread_cond_wait(&late_cond, &late_mutex);
			}
			pthread_mutex_unlock(&late_mutex);
			break;
		case WAIT_MUTEX:
			pthread_mutex_lock(&late_mutex);
			pthread_mutex_unlock(&late_mutex);
			break;
		case WAIT_UNFAIR_LOCK:
			os_unfair_lock_lock(&late_lock);
			os_unfair_lock_unlock(&late_lock);
			break;
		case WAIT_KINDS:
			break;
		}
		pthread_join(ender, NULL);
		CHECK(interruptions == 1 && interrupted_during_wait);
	}
	signal(SIGALRM, SIG_DFL);
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
	check_continued();
	check_restart();
	check_self_pipe();
	check_sigwait();
	check_source();
	check_receive_interrupted();
	check_waits_interrupted();
	return 0;
}
