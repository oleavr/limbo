/*
 * Copyright © 2026 Ole André Vadla Ravnås
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

#include <bsm/audit.h>
#include <dispatch/dispatch.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xpc/xpc.h>

#include "check.h"

typedef struct _xpc_event_publisher_s *xpc_event_publisher_t;
xpc_event_publisher_t xpc_event_publisher_create(
		const char *stream, dispatch_queue_t queue);
void xpc_event_publisher_set_handler(xpc_event_publisher_t publisher,
		void (^handler)(int action, uint64_t token,
				xpc_object_t event));
void xpc_event_publisher_set_error_handler(
		xpc_event_publisher_t publisher, void (^handler)(int error));
void xpc_event_publisher_activate(xpc_event_publisher_t publisher);
int xpc_event_publisher_create_subscription(xpc_event_publisher_t publisher,
		const char *stream, const char *name, xpc_object_t descriptor,
		pid_t subscriber, uint64_t *token);
xpc_object_t xpc_event_publisher_copy_event(xpc_event_publisher_t publisher,
		uint64_t token, pid_t subscriber);
int xpc_event_publisher_fire(xpc_event_publisher_t publisher, uint64_t token,
		xpc_object_t details);
int xpc_event_publisher_get_subscriber_asid(
		xpc_event_publisher_t publisher, uint64_t token);
void xpc_set_event(
		const char *stream, const char *name, xpc_object_t descriptor);
void *vproc_swap_integer(void *vp, int key, int64_t *inval, int64_t *outval);

static void check_event_publisher(const char *self);
static int subscribe(void);
static void check_job_events(void);
static void check_peruser_suspend(void);
static int subscribe_as_job(const char *marker);

void *_vprocmgr_switch_to_session(const char *session, uint64_t flags);
extern char **environ;

int
main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "subscribe") == 0) {
		return subscribe();
	}
	if (argc > 2 && strcmp(argv[1], "job-subscriber") == 0) {
		return subscribe_as_job(argv[2]);
	}
	check_event_publisher(argv[0]);
	check_job_events();
	check_peruser_suspend();
	return 0;
}

static void
check_peruser_suspend(void)
{
	int64_t uid = 501;
	bool root = geteuid() == 0;
	CHECK((vproc_swap_integer(NULL, 0x16, &uid, NULL) == NULL) == root);
	CHECK((vproc_swap_integer(NULL, 0x17, &uid, NULL) == NULL) == root);
	int64_t keep_alive = 1;
	CHECK(vproc_swap_integer(NULL, 7, &keep_alive, NULL) == NULL);
	keep_alive = 0;
	CHECK(vproc_swap_integer(NULL, 7, &keep_alive, NULL) == NULL);
	CHECK(_vprocmgr_switch_to_session("Background", 0) == NULL);
}

static void
check_event_publisher(const char *self)
{
	const char *stream = "com.limbo.test.events";
	dispatch_queue_t queue = dispatch_queue_create("limbo.events", NULL);
	dispatch_semaphore_t added = dispatch_semaphore_create(0);
	__block uint64_t added_token = 0;
	__block int errors = 0;
	xpc_event_publisher_t publisher
			= xpc_event_publisher_create(stream, queue);
	xpc_event_publisher_set_handler(publisher,
			^(int action, uint64_t token, xpc_object_t event) {
			  if (action == 0 && event != NULL
					  && xpc_dictionary_get_string(
							     event, "key")
							  != NULL) {
				  added_token = token;
				  dispatch_semaphore_signal(added);
			  }
			});
	xpc_event_publisher_set_error_handler(publisher, ^(int error) {
	  errors++;
	});
	xpc_event_publisher_activate(publisher);

	xpc_object_t descriptor = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(descriptor, "key", "value");
	uint64_t token = 0;
	CHECK(xpc_event_publisher_create_subscription(publisher, stream,
			      "limbo-event", descriptor, getpid(), &token)
			== 0);
	CHECK(token != 0);
	CHECK(dispatch_semaphore_wait(added,
			      dispatch_time(DISPATCH_TIME_NOW,
					      5 * NSEC_PER_SEC))
			== 0);
	CHECK(added_token == token);

	xpc_object_t event = xpc_event_publisher_copy_event(
			publisher, token, getpid());
	CHECK(event != NULL);
	CHECK(strcmp(xpc_dictionary_get_string(event, "key"), "value") == 0);

	dispatch_semaphore_t fired = dispatch_semaphore_create(0);
	__block int64_t fired_value = 0;
	xpc_set_event_stream_handler(stream, queue, ^(xpc_object_t details) {
	  fired_value = xpc_dictionary_get_int64(details, "fired");
	  dispatch_semaphore_signal(fired);
	});
	xpc_object_t details = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_int64(details, "fired", 7);
	CHECK(xpc_event_publisher_fire(publisher, token, details) == 0);
	CHECK(dispatch_semaphore_wait(fired,
			      dispatch_time(DISPATCH_TIME_NOW,
					      5 * NSEC_PER_SEC))
			== 0);
	CHECK(fired_value == 7);

	pid_t child;
	char *child_argv[] = {(char *)self, "subscribe", NULL};
	CHECK(posix_spawn(&child, self, NULL, NULL, child_argv, environ) == 0);
	sleep(2);
	uint64_t child_token = 0;
	CHECK(xpc_event_publisher_create_subscription(publisher, stream,
			      "limbo-child", descriptor, child, &child_token)
			== 0);
	fired_value = 0;
	xpc_dictionary_set_int64(details, "fired", 9);
	CHECK(xpc_event_publisher_fire(publisher, child_token, details) == 0);
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(fired_value == 0);
	CHECK(errors == 0);
}

static int
subscribe(void)
{
	dispatch_queue_t queue
			= dispatch_queue_create("limbo.subscriber", NULL);
	dispatch_semaphore_t fired = dispatch_semaphore_create(0);
	__block int64_t value = 0;
	xpc_set_event_stream_handler("com.limbo.test.events", queue,
			^(xpc_object_t details) {
			  value = xpc_dictionary_get_int64(details, "fired");
			  dispatch_semaphore_signal(fired);
			});
	if (dispatch_semaphore_wait(fired,
			    dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC))
			!= 0) {
		return 1;
	}
	return value == 9 ? 0 : 2;
}

static void
check_job_events(void)
{
	const char *marker = getenv("LIMBO_TEST_JOB_EVENT");
	if (marker == NULL) {
		return;
	}
	const char *stream = "com.limbo.test.jobevents";
	dispatch_queue_t queue = dispatch_queue_create("limbo.jobevents", NULL);
	dispatch_semaphore_t added = dispatch_semaphore_create(0);
	dispatch_semaphore_t set = dispatch_semaphore_create(0);
	__block uint64_t token = 0;
	xpc_event_publisher_t publisher
			= xpc_event_publisher_create(stream, queue);
	xpc_event_publisher_set_handler(publisher,
			^(int action, uint64_t added_token,
					xpc_object_t event) {
			  const char *key = event != NULL
					  ? xpc_dictionary_get_string(
							    event, "key")
					  : NULL;
			  if (action == 0 && key != NULL
					  && strcmp(key, "job") == 0) {
				  token = added_token;
				  dispatch_semaphore_signal(added);
			  } else if (action == 0 && key != NULL
					  && strcmp(key, "set") == 0) {
				  dispatch_semaphore_signal(set);
			  }
			});
	xpc_event_publisher_set_error_handler(publisher,
			^(int error){
			});
	xpc_event_publisher_activate(publisher);
	CHECK(dispatch_semaphore_wait(added,
			      dispatch_time(DISPATCH_TIME_NOW,
					      5 * NSEC_PER_SEC))
			== 0);

	int asid = xpc_event_publisher_get_subscriber_asid(publisher, token);

	xpc_object_t details = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_int64(details, "fired", 11);
	CHECK(xpc_event_publisher_fire(publisher, token, details) == 0);
	char text[32] = "";
	for (int i = 0; i < 200 && text[0] == '\0'; i++) {
		usleep(50000);
		FILE *file = fopen(marker, "r");
		if (file != NULL) {
			if (fgets(text, sizeof(text), file) == NULL) {
				text[0] = '\0';
			}
			fclose(file);
		}
	}
	long long value = 0, job_asid = -1;
	CHECK(sscanf(text, "%lld %lld", &value, &job_asid) == 2);
	CHECK(value == 11);
	CHECK(asid == (int)job_asid);
	if (geteuid() != 0) {
		auditinfo_addr_t self;
		CHECK(getaudit_addr(&self, sizeof(self)) == 0);
		CHECK(asid == (int)self.ai_asid);
	}
	CHECK(dispatch_semaphore_wait(set,
			      dispatch_time(DISPATCH_TIME_NOW,
					      20 * NSEC_PER_SEC))
			== 0);
}

static int
subscribe_as_job(const char *marker)
{
	dispatch_queue_t queue = dispatch_queue_create("limbo.job", NULL);
	dispatch_semaphore_t fired = dispatch_semaphore_create(0);
	__block int64_t value = 0;
	xpc_set_event_stream_handler("com.limbo.test.jobevents", queue,
			^(xpc_object_t details) {
			  value = xpc_dictionary_get_int64(details, "fired");
			  dispatch_semaphore_signal(fired);
			});
	if (dispatch_semaphore_wait(fired,
			    dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC))
			!= 0) {
		return 1;
	}
	FILE *file = fopen(marker, "w");
	if (file == NULL) {
		return 2;
	}
	auditinfo_addr_t self = {0};
	getaudit_addr(&self, sizeof(self));
	fprintf(file, "%lld %d", (long long)value, (int)self.ai_asid);
	fclose(file);

	xpc_object_t descriptor = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(descriptor, "key", "set");
	xpc_set_event("com.limbo.test.jobevents", "limbo-set-event",
			descriptor);
	sleep(25);
	return 0;
}
