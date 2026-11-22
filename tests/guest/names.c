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
#include <stdlib.h>
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
static const char TAKEN_NAME[] = "com.limbo.test.names.taken";
static const char COUNTED_NAME[] = "com.limbo.test.names.counted";
static const char ALONE_NAME[] = "com.limbo.test.names.alone";

static server_t start_server(const char *name);
static void serve(const char *name, int commands, int answers);
static void tell(const server_t *server, char command);
static void stop_server(server_t *server);
static char read_within(int fd);
static kern_return_t look_up_until_forgotten(const char *name);
static int in_child(int (*role)(void));
static int check_in_taken(void);

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

static void
check_taken_names(void)
{
	mach_port_t port = MACH_PORT_NULL;
	CHECK(bootstrap_check_in(bootstrap_port, TAKEN_NAME, &port)
			== KERN_SUCCESS);
	mach_port_t again = MACH_PORT_NULL;
	CHECK(bootstrap_check_in(bootstrap_port, TAKEN_NAME, &again)
			== BOOTSTRAP_SERVICE_ACTIVE);
	CHECK(again == MACH_PORT_NULL);
	CHECK(in_child(check_in_taken) == 0);
	mach_port_t found = MACH_PORT_NULL;
	CHECK(bootstrap_look_up(bootstrap_port, TAKEN_NAME, &found)
			== KERN_SUCCESS);
	CHECK(found == port);

	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static void
check_looked_up_right_counted(void)
{
	server_t server = start_server(COUNTED_NAME);
	mach_port_t port = MACH_PORT_NULL;
	CHECK(bootstrap_look_up(bootstrap_port, COUNTED_NAME, &port)
			== KERN_SUCCESS);
	mach_port_t notify = MACH_PORT_NULL;
	CHECK(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
			      &notify)
			== KERN_SUCCESS);
	mach_port_t previous;
	CHECK(mach_port_request_notification(mach_task_self(), port,
			      MACH_NOTIFY_DEAD_NAME, 0, notify,
			      MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous)
			== KERN_SUCCESS);

	tell(&server, 'd');
	struct {
		mach_dead_name_notification_t notification;
		mach_msg_trailer_t trailer;
	} message;
	CHECK(mach_msg(&message.notification.not_header,
			      MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(message), notify, ANSWER_MS,
			      MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(message.notification.not_header.msgh_id == MACH_NOTIFY_DEAD_NAME);
	CHECK(message.notification.not_port == port);
	mach_msg_header_t request = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = sizeof(request),
			.msgh_remote_port = port,
	};
	CHECK(mach_msg(&request, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
			      sizeof(request), 0, MACH_PORT_NULL, ANSWER_MS,
			      MACH_PORT_NULL)
			== MACH_SEND_INVALID_DEST);

	stop_server(&server);
	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_DEAD_NAME, -2)
			== KERN_SUCCESS);
	CHECK(mach_port_mod_refs(mach_task_self(), notify,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
}

static int
check_alone(void)
{
	mach_port_t port = MACH_PORT_NULL;
	CHECK(bootstrap_check_in(bootstrap_port, ALONE_NAME, &port)
			== KERN_SUCCESS);
	mach_port_t again = MACH_PORT_NULL;
	CHECK(bootstrap_check_in(bootstrap_port, ALONE_NAME, &again)
			== BOOTSTRAP_SERVICE_ACTIVE);
	mach_port_t found = MACH_PORT_NULL;
	CHECK(bootstrap_look_up(bootstrap_port, ALONE_NAME, &found)
			== KERN_SUCCESS);
	CHECK(found == port);

	mach_msg_header_t sent = {
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.msgh_size = sizeof(sent),
			.msgh_remote_port = found,
			.msgh_id = 1,
	};
	CHECK(mach_msg(&sent, MACH_SEND_MSG, sizeof(sent), 0, MACH_PORT_NULL,
			      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	struct {
		mach_msg_header_t header;
		mach_msg_trailer_t trailer;
	} received;
	CHECK(mach_msg(&received.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
			      sizeof(received), port, ANSWER_MS, MACH_PORT_NULL)
			== MACH_MSG_SUCCESS);
	CHECK(received.header.msgh_id == 1);

	CHECK(mach_port_mod_refs(mach_task_self(), port,
			      MACH_PORT_RIGHT_RECEIVE, -1)
			== KERN_SUCCESS);
	CHECK(bootstrap_look_up(bootstrap_port, ALONE_NAME, &found)
			== BOOTSTRAP_UNKNOWN_SERVICE);
	return 0;
}

static void
check_without_broker(const char *program)
{
	pid_t pid = fork();
	CHECK(pid != -1);
	if (pid == 0) {
		setenv("LIMBO_BROKER", "", 1);
		execl(program, program, "alone", NULL);
		_exit(1);
	}
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int
main(int argc, char *argv[])
{
	alarm(DEADLINE_S);
	if (argc == 2 && strcmp(argv[1], "alone") == 0) {
		return check_alone();
	}
	check_unknown_name();
	check_dead_port_forgotten();
	check_taken_names();
	check_looked_up_right_counted();
	check_without_broker(argv[0]);
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

static int
in_child(int (*role)(void))
{
	pid_t pid = fork();
	CHECK(pid != -1);
	if (pid == 0) {
		_exit(role());
	}
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status));
	return WEXITSTATUS(status);
}

static int
check_in_taken(void)
{
	mach_port_t port = MACH_PORT_NULL;
	return bootstrap_check_in(bootstrap_port, TAKEN_NAME, &port)
			!= BOOTSTRAP_NOT_PRIVILEGED;
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
