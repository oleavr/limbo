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

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "check.h"

static int file;
static char text[] = "asynchronous";
static volatile sig_atomic_t signals;

static void check_transfer(void);
static void check_terminal(void);
static void check_append(void);
static void check_waiters(void);
static void check_refused(void);
static void check_suspend(void);
static void check_cancel(void);
static void check_fsync(void);
static void check_signal(void);
static void check_limit(void);
static void wait_for(struct aiocb *cb);
static void on_signal(int sig);
static void *wait_for_own(void *arg);

int
main(void)
{
	char path[] = "/tmp/aio.XXXXXX";
	file = mkstemp(path);
	CHECK(file != -1 && unlink(path) == 0);
	check_suspend();
	check_cancel();
	check_transfer();
	check_terminal();
	check_append();
	check_waiters();
	check_refused();
	check_fsync();
	check_signal();
	check_limit();
	printf("aio: ok\n");
	return 0;
}

static void
check_suspend(void)
{
	struct aiocb never = {.aio_fildes = file};
	const struct aiocb *list[2] = {&never, NULL};
	struct timespec shortly = {.tv_nsec = 20000000};
	CHECK(aio_suspend(list, 1, &shortly) == -1 && errno == EINVAL);

	struct aiocb cb = {.aio_fildes = file,
			.aio_buf = text,
			.aio_nbytes = sizeof(text)};
	CHECK(aio_write(&cb) == 0);
	wait_for(&cb);
	CHECK(aio_suspend(list, 1, &shortly) == -1 && errno == EAGAIN);
	list[1] = &cb;
	CHECK(aio_suspend(list, 2, &shortly) == 0);
	list[0] = NULL;
	CHECK(aio_suspend(list, 2, NULL) == 0);
	CHECK(aio_suspend(list, 0, NULL) == -1 && errno == EINVAL);
	struct timespec invalid = {.tv_nsec = 1000000000};
	CHECK(aio_suspend(list, 2, &invalid) == -1 && errno == EINVAL);
	invalid = (struct timespec){.tv_sec = -1};
	CHECK(aio_suspend(list, 2, &invalid) == -1 && errno == EINVAL);
	CHECK(aio_return(&cb) == (ssize_t)sizeof(text));
}

static void
check_cancel(void)
{
	struct aiocb never = {.aio_fildes = file};
	CHECK(aio_cancel(file, NULL) == AIO_ALLDONE);
	CHECK(aio_cancel(file, &never) == AIO_ALLDONE);
	CHECK(aio_cancel(-1, NULL) == -1 && errno == EBADF);
	int ends[2];
	CHECK(pipe(ends) == 0);
	CHECK(aio_cancel(ends[0], NULL) == -1 && errno == EBADF);
	CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);

	struct aiocb cb = {.aio_fildes = file,
			.aio_buf = text,
			.aio_nbytes = sizeof(text)};
	CHECK(aio_write(&cb) == 0);
	wait_for(&cb);
	CHECK(aio_cancel(file, NULL) == AIO_ALLDONE);
	CHECK(aio_cancel(file, &cb) == AIO_ALLDONE);
	CHECK(aio_cancel(file, &never) == -1 && errno == EBADF);
	CHECK(aio_cancel(STDERR_FILENO, &cb) == -1 && errno == EBADF);
	CHECK(aio_return(&cb) == (ssize_t)sizeof(text));
}

static void
check_transfer(void)
{
	struct aiocb never = {.aio_fildes = file};
	CHECK(aio_error(&never) == -1 && errno == EINVAL);
	CHECK(aio_return(&never) == -1 && errno == EINVAL);

	struct aiocb write_cb = {.aio_fildes = file,
			.aio_offset = 4,
			.aio_buf = text,
			.aio_nbytes = sizeof(text)};
	CHECK(aio_write(&write_cb) == 0);
	CHECK(aio_write(&write_cb) == -1 && errno == EAGAIN);
	wait_for(&write_cb);
	CHECK(aio_error(&write_cb) == 0);
	CHECK(aio_return(&write_cb) == (ssize_t)sizeof(text));
	CHECK(aio_return(&write_cb) == -1 && errno == EINVAL);
	CHECK(aio_error(&write_cb) == -1 && errno == EINVAL);

	char back[sizeof(text)] = {0};
	struct aiocb read_cb = {.aio_fildes = file,
			.aio_offset = 4,
			.aio_buf = back,
			.aio_nbytes = sizeof(back)};
	CHECK(aio_read(&read_cb) == 0);
	wait_for(&read_cb);
	CHECK(aio_error(&read_cb) == 0);
	CHECK(aio_return(&read_cb) == (ssize_t)sizeof(back));
	CHECK(memcmp(back, text, sizeof(text)) == 0);

	read_cb.aio_offset = 1000;
	CHECK(aio_read(&read_cb) == 0);
	wait_for(&read_cb);
	CHECK(aio_error(&read_cb) == 0 && aio_return(&read_cb) == 0);

	int folder = open("/tmp", O_RDONLY);
	CHECK(folder != -1);
	read_cb.aio_fildes = folder;
	CHECK(aio_read(&read_cb) == 0);
	wait_for(&read_cb);
	CHECK(aio_error(&read_cb) == EISDIR && aio_return(&read_cb) == 0);
	CHECK(close(folder) == 0);
}

static void
check_terminal(void)
{
	int master, slave;
	CHECK(openpty(&master, &slave, NULL, NULL, NULL) == 0);
	char byte = 'x';
	int ends[2] = {slave, master};
	for (int i = 0; i < 2; i++) {
		struct aiocb cb = {.aio_fildes = ends[i],
				.aio_buf = &byte,
				.aio_nbytes = 1};
		CHECK(aio_write(&cb) == 0);
		wait_for(&cb);
		CHECK(aio_error(&cb) == ENXIO && aio_return(&cb) == 0);
		CHECK(aio_read(&cb) == 0);
		wait_for(&cb);
		CHECK(aio_error(&cb) == ENXIO && aio_return(&cb) == 0);
	}
	CHECK(close(slave) == 0 && close(master) == 0);
}

static void
check_append(void)
{
	char path[] = "/tmp/aio.XXXXXX";
	int made = mkstemp(path);
	CHECK(made != -1 && write(made, "0123456789", 10) == 10);
	int appending = open(path, O_WRONLY | O_APPEND);
	CHECK(appending != -1 && unlink(path) == 0);
	CHECK(lseek(appending, 2, SEEK_SET) == 2);
	struct aiocb cb = {.aio_fildes = appending,
			.aio_offset = 4,
			.aio_buf = text,
			.aio_nbytes = 3};
	CHECK(aio_write(&cb) == 0);
	wait_for(&cb);
	CHECK(aio_error(&cb) == 0 && aio_return(&cb) == 3);
	CHECK(lseek(appending, 0, SEEK_CUR) == 13);
	char written[13];
	CHECK(pread(made, written, sizeof(written), 0) == 13);
	CHECK(memcmp(written, "0123456789asy", sizeof(written)) == 0);

	CHECK(lseek(made, 2, SEEK_SET) == 2);
	cb.aio_fildes = made;
	CHECK(aio_write(&cb) == 0);
	wait_for(&cb);
	CHECK(aio_return(&cb) == 3 && lseek(made, 0, SEEK_CUR) == 2);
	CHECK(pread(made, written, sizeof(written), 0) == 13);
	CHECK(memcmp(written, "0123asy789asy", sizeof(written)) == 0);
	CHECK(close(appending) == 0 && close(made) == 0);
}

enum { WAITERS = 8, WAITER_ROUNDS = 16 };

static struct waiter {
	struct aiocb cb;
	atomic_bool waiting, done;
} waiters[WAITERS];

static void
check_waiters(void)
{
	struct aiocb kept = {
			.aio_fildes = file, .aio_buf = text, .aio_nbytes = 1};
	CHECK(aio_write(&kept) == 0);
	wait_for(&kept);
	for (int round = 0; round < WAITER_ROUNDS; round++) {
		pthread_t threads[WAITERS];
		for (int i = 0; i < WAITERS; i++) {
			waiters[i].cb = (struct aiocb){.aio_fildes = file,
					.aio_buf = text,
					.aio_nbytes = 1};
			atomic_store(&waiters[i].waiting, false);
			atomic_store(&waiters[i].done, false);
			CHECK(pthread_create(&threads[i], NULL, wait_for_own,
					      &waiters[i])
					== 0);
		}
		for (int i = 0; i < WAITERS; i++) {
			while (!atomic_load(&waiters[i].waiting)) {
				usleep(1000);
			}
		}
		usleep(20000);
		struct waiter *first = &waiters[round % WAITERS];
		CHECK(aio_write(&first->cb) == 0);
		for (int tries = 0; tries < 2000 && !atomic_load(&first->done);
				tries++) {
			usleep(1000);
		}
		CHECK(atomic_load(&first->done));
		for (int i = 0; i < WAITERS; i++) {
			if (&waiters[i] != first) {
				CHECK(aio_write(&waiters[i].cb) == 0);
			}
		}
		for (int i = 0; i < WAITERS; i++) {
			CHECK(pthread_join(threads[i], NULL) == 0);
		}
	}
	CHECK(aio_return(&kept) == 1);
}

static void *
wait_for_own(void *arg)
{
	struct waiter *waiter = arg;
	const struct aiocb *list[1] = {&waiter->cb};
	atomic_store(&waiter->waiting, true);
	while (aio_suspend(list, 1, NULL) == -1) {
		CHECK(errno == EINTR);
	}
	CHECK(aio_return(&waiter->cb) == 1);
	atomic_store(&waiter->done, true);
	return NULL;
}

static void
check_refused(void)
{
	char byte;
	int read_only = open("/dev/null", O_RDONLY);
	int write_only = open("/dev/null", O_WRONLY);
	int ends[2];
	CHECK(read_only != -1 && write_only != -1 && pipe(ends) == 0);
	struct aiocb cb = {.aio_fildes = read_only,
			.aio_buf = text,
			.aio_nbytes = 1};
	CHECK(aio_write(&cb) == -1 && errno == EBADF);
	cb.aio_fildes = write_only;
	cb.aio_buf = &byte;
	CHECK(aio_read(&cb) == -1 && errno == EBADF);
	cb.aio_fildes = ends[1];
	CHECK(aio_write(&cb) == -1 && errno == ESPIPE);
	CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
	cb.aio_fildes = ends[1];
	CHECK(aio_write(&cb) == -1 && errno == EBADF);
	CHECK(close(read_only) == 0 && close(write_only) == 0);

	cb.aio_fildes = file;
	cb.aio_buf = NULL;
	CHECK(aio_write(&cb) == -1 && errno == EINVAL);
	cb.aio_buf = text;
	cb.aio_offset = -1;
	CHECK(aio_write(&cb) == -1 && errno == EINVAL);
	cb.aio_offset = 0;
	cb.aio_nbytes = (size_t)INT_MAX + 1;
	CHECK(aio_write(&cb) == -1 && errno == EINVAL);
	cb.aio_nbytes = 1;
	cb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	CHECK(aio_write(&cb) == -1 && errno == EINVAL);
	cb.aio_sigevent.sigev_signo = SIGSTOP;
	CHECK(aio_write(&cb) == -1 && errno == EINVAL);
	cb.aio_sigevent.sigev_signo = NSIG;
	CHECK(aio_write(&cb) == -1 && errno == EINVAL);
	cb.aio_sigevent.sigev_notify = SIGEV_THREAD;
	CHECK(aio_write(&cb) == -1 && errno == EINVAL);
	CHECK(aio_error(&cb) == -1 && errno == EINVAL);
}

static void
check_fsync(void)
{
	struct aiocb cb = {.aio_fildes = file};
	int ops[] = {0, O_SYNC, O_DSYNC};
	for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
		CHECK(aio_fsync(ops[i], &cb) == 0);
		wait_for(&cb);
		CHECK(aio_error(&cb) == 0 && aio_return(&cb) == 0);
	}
	CHECK(aio_fsync(O_NONBLOCK, &cb) == -1 && errno == EINVAL);
	cb.aio_fildes = open("/dev/null", O_RDONLY);
	CHECK(cb.aio_fildes != -1);
	CHECK(aio_fsync(O_SYNC, &cb) == -1 && errno == EBADF);
	CHECK(close(cb.aio_fildes) == 0);
}

static void
check_signal(void)
{
	CHECK(signal(SIGUSR1, on_signal) != SIG_ERR);
	struct aiocb cb = {.aio_fildes = file,
			.aio_buf = text,
			.aio_nbytes = 2,
			.aio_sigevent = {.sigev_notify = SIGEV_SIGNAL,
					.sigev_signo = SIGUSR1}};
	CHECK(aio_write(&cb) == 0);
	wait_for(&cb);
	for (int i = 0; signals == 0 && i < 5000; i++) {
		usleep(1000);
	}
	CHECK(signals == 1 && aio_return(&cb) == 2);
}

static void
check_limit(void)
{
	enum { PROCESS_MAX = 256 };
	static struct aiocb cbs[PROCESS_MAX + 1];
	for (int i = 0; i <= PROCESS_MAX; i++) {
		cbs[i] = (struct aiocb){.aio_fildes = file,
				.aio_buf = text,
				.aio_nbytes = 1};
		CHECK(aio_write(&cbs[i]) == (i == PROCESS_MAX ? -1 : 0));
	}
	CHECK(errno == EAGAIN);
	for (int i = 0; i < PROCESS_MAX; i++) {
		wait_for(&cbs[i]);
		CHECK(aio_return(&cbs[i]) == 1);
	}
}

static void
wait_for(struct aiocb *cb)
{
	const struct aiocb *list[1] = {cb};
	while (aio_suspend(list, 1, NULL) == -1) {
		CHECK(errno == EINTR);
	}
}

static void
on_signal(int sig)
{
	(void)sig;
	signals++;
}
