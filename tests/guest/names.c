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

#include <mach/mach.h>
#include <poll.h>
#include <servers/bootstrap.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"

#define ANSWER_MS    20000
#define FORGET_MS    10
#define FORGET_TRIES 500
#define DEADLINE_S   120

typedef struct {
	pid_t pid;
	int commands;
	int answers;
} server_t;

static const char UNKNOWN_NAME[] = "com.limbo.test.names.unknown";
static const char DOOMED_NAME[] = "com.limbo.test.names.doomed";

static server_t start_server(const char *name);
static void serve(const char *name, int commands, int answers);
static void tell(const server_t *server, char command);
static void stop_server(server_t *server);
static char read_within(int fd);
static kern_return_t look_up_until_forgotten(const char *name);

static void
check_unknown_name(void)
{
	mach_port_t port = MACH_PORT_NULL;
	CHECK(bootstrap_look_up(bootstrap_port, UNKNOWN_NAME, &port)
			== BOOTSTRAP_UNKNOWN_SERVICE);
	CHECK(port == MACH_PORT_NULL);
}

static void
check_dead_port_forgotten(void)
{
	server_t server = start_server(DOOMED_NAME);
	mach_port_t port = MACH_PORT_NULL;
	CHECK(bootstrap_look_up(bootstrap_port, DOOMED_NAME, &port)
			== KERN_SUCCESS);
	tell(&server, 'd');
	CHECK(look_up_until_forgotten(DOOMED_NAME)
			== BOOTSTRAP_UNKNOWN_SERVICE);
	stop_server(&server);
	mach_port_deallocate(mach_task_self(), port);
}

int
main(void)
{
	alarm(DEADLINE_S);
	check_unknown_name();
	check_dead_port_forgotten();
	return 0;
}

static server_t
start_server(const char *name)
{
	int commands[2];
	int answers[2];
	CHECK(pipe(commands) == 0 && pipe(answers) == 0);
	pid_t pid = fork();
	CHECK(pid != -1);
	if (pid == 0) {
		close(commands[1]);
		close(answers[0]);
		serve(name, commands[0], answers[1]);
		_exit(0);
	}
	close(commands[0]);
	close(answers[1]);
	server_t server = {
			.pid = pid,
			.commands = commands[1],
			.answers = answers[0],
	};
	CHECK(read_within(server.answers) == 'r');
	return server;
}

static void
serve(const char *name, int commands, int answers)
{
	mach_port_t port = MACH_PORT_NULL;
	if (bootstrap_check_in(bootstrap_port, name, &port) != KERN_SUCCESS) {
		_exit(1);
	}
	write(answers, "r", 1);
	char command;
	while (read(commands, &command, 1) == 1) {
		if (command == 'd') {
			mach_port_mod_refs(mach_task_self(), port,
					MACH_PORT_RIGHT_RECEIVE, -1);
		}
		write(answers, &command, 1);
	}
}

static void
tell(const server_t *server, char command)
{
	CHECK(write(server->commands, &command, 1) == 1);
	CHECK(read_within(server->answers) == command);
}

static void
stop_server(server_t *server)
{
	close(server->commands);
	close(server->answers);
	int status;
	CHECK(waitpid(server->pid, &status, 0) == server->pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static char
read_within(int fd)
{
	struct pollfd polled = {.fd = fd, .events = POLLIN};
	char byte = 0;
	CHECK(poll(&polled, 1, ANSWER_MS) == 1);
	CHECK(read(fd, &byte, 1) == 1);
	return byte;
}

static kern_return_t
look_up_until_forgotten(const char *name)
{
	kern_return_t kr = KERN_SUCCESS;
	for (int i = 0; i != FORGET_TRIES && kr == KERN_SUCCESS; i++) {
		mach_port_t port = MACH_PORT_NULL;
		kr = bootstrap_look_up(bootstrap_port, name, &port);
		if (kr == KERN_SUCCESS) {
			mach_port_deallocate(mach_task_self(), port);
			usleep(FORGET_MS * 1000);
		}
	}
	return kr;
}
