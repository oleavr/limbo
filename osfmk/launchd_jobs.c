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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bsd/persona.h"
#include "bsd/process.h"
#include "launchd.h"
#include "launchd_engine.h"
#include "launchd_jobs.h"
#include "osfmk/broker_client.h"
#include "osfmk/ipc.h"
#include "sysroot.h"
#include "xpc_service.h"
#include "xpc_services.h"

#define DOMAIN_TYPE_USER 2
#define DOMAIN_TYPE_PID  5
#define DOMAIN_TYPE_GUI  8

#define GROUPS_MAX 32

struct identity {
	uid_t uid;
	gid_t gid;
	gid_t groups[GROUPS_MAX];
	int group_count;
};

#define SERVICE_LABEL_VARIABLE      "LIMBO_LAUNCHD_SERVICE_LABEL"
#define SERVICE_DICTIONARY_VARIABLE "LIMBO_LAUNCHD_SERVICE_DICTIONARY"

#define DOMAIN_ENVIRONMENT_VARIABLE "LIMBO_LAUNCHD_DOMAIN_ENVIRONMENT"

struct job {
	struct job *next;
	uint8_t handle[16];
	char *label;
	char *program;
	pid_t pid;
	int service_type;
	void *plist;
	size_t plist_size;
	pid_t host;
	uid_t uid;
	uint64_t domain;
	char *broker_name;
	uint8_t instance[16];
	bool has_instance;
	void *variables;
	size_t variables_size;
	mach_port_name_t monitor;
	bool exit_told;
	bool exited;
	int status;
};

struct strings {
	char **items;
	size_t count;
};

static void reply_error(mach_msg_header_t *request, int64_t error);
static uid_t domain_user(uint64_t type, uint64_t handle);
static uid_t user_named(const char *name);
static void *copy_object(const struct xpc_object *object, size_t *size);
static bool start(struct job *job);
static pid_t broker_job_pid(const char *command, const char *name,
		char *program, size_t size);
static char *control(const char *const *words, size_t count, uint32_t *status);
static bool collect_argument(void *context, const char *argument);
static void strings_add(struct strings *strings, char *item);
static void strings_free(struct strings *strings);
static void collect_variable(void *context, const char *key, const char *value);
static bool identity_for(uid_t uid, struct identity *identity);
static pid_t spawn(const struct identity *identity, uint32_t persona,
		const char *label, const char *program, char **argv, char **env,
		bool suspended);
static bool become(const struct identity *identity);
static void add_job(struct job *job);
static void reply_info(mach_msg_header_t *request, struct job *job);
static void encode_info(struct xpc_encoder *encoder, struct job *job,
		mach_port_name_t monitor);
static bool collect_status(struct job *job);
static void reply_handle(mach_msg_header_t *request, const struct job *job);
static bool running(pid_t pid);
static struct job *job_for_handle(const uint8_t handle[16]);
static struct job *job_for_pid(pid_t pid);
static void tell_exit(struct job *job);
static bool reply_own_properties(mach_msg_header_t *request);
static bool parse_uuid_text(const char *text, uint8_t *out);
static void reply_properties(mach_msg_header_t *request, struct job *job);
static bool broker_job_plist(pid_t pid, char *path, size_t size);

enum {
	JOB_STATE_WAITING = 0,
	JOB_STATE_RUNNING = 1,
	JOB_STATE_SPAWN_FAILED = 2,
	JOB_STATE_EXITED = 3,
};

enum {
	SERVICE_TYPE_DAEMON = 1,
	SERVICE_TYPE_APP = 4,
	SERVICE_TYPE_EXTENSION = 6,
};

static struct job *jobs;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static const char *own_label;
static uint8_t *own_dictionary;
static size_t own_dictionary_size;

bool
launchd_jobs_submit_and_start(mach_msg_header_t *request)
{
	struct xpc_object message, plist;
	if (!xpc_message_payload(request, &message)
			|| !xpc_dictionary_get_dictionary(
					&message, "plist", &plist)) {
		reply_error(request, EINVAL);
		return true;
	}
	const char *label = xpc_dictionary_get_string(&plist, "Label");
	const char *program = xpc_dictionary_get_string(&plist, "Program");
	if (label == NULL) {
		reply_error(request, EINVAL);
		return true;
	}
	const char *type = xpc_dictionary_get_string(&plist, "ProcessType");
	uint64_t domain = 0, handle = 0;
	xpc_dictionary_get_uint64(&message, "type", &domain);
	xpc_dictionary_get_uint64(&message, "handle", &handle);
	struct job *job = calloc(1, sizeof(*job));
	getrandom(job->handle, sizeof(job->handle), 0);
	job->uid = domain_user(domain, handle);
	const char *user_name = xpc_dictionary_get_string(&plist, "UserName");
	if (job->uid == (uid_t)-1 && user_name != NULL) {
		job->uid = user_named(user_name);
	}
	job->domain = domain;
	job->label = strdup(label);
	job->program = program != NULL ? strdup(program) : NULL;
	job->service_type = type != NULL && strcmp(type, "App") == 0
			? SERVICE_TYPE_APP
			: SERVICE_TYPE_DAEMON;
	job->plist = copy_object(&plist, &job->plist_size);
	if (!start(job)) {
		free(job->label);
		free(job->program);
		free(job->plist);
		free(job);
		reply_error(request, ENOEXEC);
		return true;
	}
	add_job(job);
	reply_info(request, job);
	return true;
}

static void
reply_error(mach_msg_header_t *request, int64_t error)
{
	uint8_t buffer[64];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_int64(&encoder, "error", error);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
}

static uid_t
domain_user(uint64_t type, uint64_t handle)
{
	struct process process;
	switch (type) {
	case DOMAIN_TYPE_USER:
	case DOMAIN_TYPE_GUI:
		return (uid_t)handle;
	case DOMAIN_TYPE_PID:
		return process_lookup((int32_t)handle, &process) == 0
				? (uid_t)process.uid[1]
				: (uid_t)-1;
	default:
		return (uid_t)-1;
	}
}

static uid_t
user_named(const char *name)
{
	char path[PATH_MAX];
	FILE *file = fopen(sysroot_host_path("/etc/passwd", 0, path), "re");
	uid_t uid = (uid_t)-1;
	for (struct passwd *pw; file != NULL && (pw = fgetpwent(file));) {
		if (strcmp(pw->pw_name, name) == 0) {
			uid = pw->pw_uid;
			break;
		}
	}
	if (file != NULL) {
		fclose(file);
	}
	return uid;
}

static void *
copy_object(const struct xpc_object *object, size_t *size)
{
	*size = xpc_object_size(object);
	void *copy = malloc(*size ? *size : 1);
	memcpy(copy, object->data, *size);
	return copy;
}

static bool
start(struct job *job)
{
	if (job->broker_name != NULL) {
		pid_t pid = broker_job_pid("start", job->broker_name, NULL, 0);
		if (pid <= 0) {
			return false;
		}
		job->pid = pid;
		job->exit_told = false;
		job->exited = false;
		return true;
	}
	struct xpc_object plist = {
			.data = job->plist,
			.end = (const uint8_t *)job->plist + job->plist_size,
	};
	struct strings arguments = {0};
	struct xpc_object array;
	if (xpc_dictionary_get_array(&plist, "ProgramArguments", &array)) {
		xpc_array_apply_strings(&array, collect_argument, &arguments);
	}
	if (job->program == NULL && arguments.count != 0) {
		job->program = strdup(arguments.items[0]);
	}
	if (job->program == NULL) {
		strings_free(&arguments);
		return false;
	}
	if (arguments.count == 0) {
		strings_add(&arguments, strdup(job->program));
	}
	bool suspended = false;
	xpc_dictionary_get_bool(&plist, "WaitForDebugger", &suspended);

	struct strings env = {0};
	struct xpc_object variables;
	if (xpc_dictionary_get_dictionary(
			    &plist, "EnvironmentVariables", &variables)) {
		xpc_dictionary_apply_strings(
				&variables, collect_variable, &env);
	}
	if (job->variables != NULL) {
		struct xpc_object instance = {
				.data = job->variables,
				.end = (const uint8_t *)job->variables
						+ job->variables_size,
		};
		xpc_dictionary_apply_strings(&instance, collect_variable, &env);
	}
	extern char **environ;
	for (char **variable = environ; *variable != NULL; variable++) {
		if (strncmp(*variable, "LIMBO_", 6) == 0
				&& (strncmp(*variable, "LIMBO_LAUNCHD_", 14)
								!= 0
						|| strncmp(*variable,
								   DOMAIN_ENVIRONMENT_VARIABLE
								   "=",
								   strlen(DOMAIN_ENVIRONMENT_VARIABLE)
										   + 1)
								== 0)
				&& strncmp(*variable, "LIMBO_XPC_", 10) != 0) {
			strings_add(&env, strdup(*variable));
		}
	}
	if (job->service_type == SERVICE_TYPE_EXTENSION) {
		char *variable;
		asprintf(&variable, SERVICE_LABEL_VARIABLE "=%s", job->label);
		strings_add(&env, variable);
		if (job->host != 0) {
			asprintf(&variable,
					XPC_SERVICES_HOST_PID_VARIABLE "=%d",
					(int)job->host);
			strings_add(&env, variable);
		}
		if (job->host != 0 && job->has_instance) {
			char text[37];
			xpc_services_uuid_text(job->instance, text);
			asprintf(&variable,
					XPC_SERVICES_INSTANCE_VARIABLE "=%s",
					text);
			strings_add(&env, variable);
		}
		size_t prefix = strlen(SERVICE_DICTIONARY_VARIABLE "=");
		variable = malloc(prefix + job->plist_size * 2 + 1);
		memcpy(variable, SERVICE_DICTIONARY_VARIABLE "=", prefix);
		const uint8_t *bytes = job->plist;
		for (size_t i = 0; i < job->plist_size; i++) {
			snprintf(variable + prefix + i * 2, 3, "%02x",
					bytes[i]);
		}
		variable[prefix + job->plist_size * 2] = '\0';
		strings_add(&env, variable);
	}
	char *name;
	asprintf(&name, "XPC_SERVICE_NAME=%s", job->label);
	strings_add(&env, name);
	strings_add(&env, strdup("XPC_FLAGS=1"));

	struct identity identity;
	if (!identity_for(job->uid, &identity)) {
		strings_free(&env);
		strings_free(&arguments);
		return false;
	}
	uint64_t persona = (uint32_t)-1;
	xpc_dictionary_get_uint64(&plist, "PersonaEnterprise", &persona);
	if (persona == (uint32_t)-1
			&& job->service_type == SERVICE_TYPE_EXTENSION
			&& job->host != 0) {
		persona = persona_of(job->host);
	}
	pid_t pid = spawn(&identity, (uint32_t)persona, job->label,
			job->program, arguments.items, env.items, suspended);
	strings_free(&env);
	strings_free(&arguments);
	if (pid <= 0) {
		return false;
	}
	job->pid = pid;
	job->exit_told = false;
	job->exited = false;
	if (job->domain == DOMAIN_TYPE_GUI) {
		char number[24];
		snprintf(number, sizeof(number), "%d", (int)pid);
		const char *const words[] = {"session", number};
		uint32_t status = 0;
		free(control(words, 2, &status));
	}
	return true;
}

static pid_t
broker_job_pid(const char *command, const char *name, char *program,
		size_t size)
{
	const char *const words[] = {command, name};
	uint32_t status = 0;
	char *text = control(words, 2, &status);
	if (text == NULL || status != 0) {
		free(text);
		return -1;
	}
	pid_t pid = (pid_t)strtol(text, NULL, 10);
	const char *line = strstr(text, "\tprogram: ");
	if (line != NULL && program != NULL) {
		line += strlen("\tprogram: ");
		size_t length = strcspn(line, "\n");
		char host[PATH_MAX];
		snprintf(host, sizeof(host), "%.*s", (int)length, line);
		snprintf(program, size, "%s", sysroot_guest_path(host));
	}
	free(text);
	return pid;
}

static char *
control(const char *const *words, size_t count, uint32_t *status)
{
	char *argv[8];
	size_t argc = 0;
	for (; argc != count && argc != 8; argc++) {
		argv[argc] = strdup(words[argc]);
	}
	char *text = launchd_command(argv, argc, 0, status);
	for (size_t i = 0; i != argc; i++) {
		free(argv[i]);
	}
	return text;
}

static bool
collect_argument(void *context, const char *argument)
{
	strings_add(context, strdup(argument));
	return true;
}

static void
strings_add(struct strings *strings, char *item)
{
	strings->items = reallocarray(
			strings->items, strings->count + 2, sizeof(char *));
	strings->items[strings->count++] = item;
	strings->items[strings->count] = NULL;
}

static void
strings_free(struct strings *strings)
{
	for (size_t i = 0; i < strings->count; i++) {
		free(strings->items[i]);
	}
	free(strings->items);
}

static void
collect_variable(void *context, const char *key, const char *value)
{
	if (strncmp(key, "LIMBO_", 6) == 0
			|| strcmp(key, "DYLD_INSERT_LIBRARIES") == 0
			|| strcmp(key, "XPC_SERVICE_NAME") == 0
			|| strcmp(key, "XPC_FLAGS") == 0) {
		return;
	}
	char *variable;
	asprintf(&variable, "%s=%s", key, value);
	strings_add(context, variable);
}

static bool
identity_for(uid_t uid, struct identity *identity)
{
	identity->uid = (uid_t)-1;
	identity->group_count = 0;
	if (uid == (uid_t)-1 || uid == geteuid() || geteuid() != 0) {
		return true;
	}
	char path[PATH_MAX];
	FILE *file = fopen(sysroot_host_path("/etc/passwd", 0, path), "re");
	char name[256] = "";
	for (struct passwd *pw; file != NULL && (pw = fgetpwent(file));) {
		if (pw->pw_uid == uid) {
			snprintf(name, sizeof(name), "%s", pw->pw_name);
			identity->gid = pw->pw_gid;
			break;
		}
	}
	if (file != NULL) {
		fclose(file);
	}
	if (name[0] == '\0') {
		return false;
	}
	identity->uid = uid;
	identity->groups[identity->group_count++] = identity->gid;
	file = fopen(sysroot_host_path("/etc/group", 0, path), "re");
	for (struct group *gr; file != NULL && (gr = fgetgrent(file))
			&& identity->group_count != GROUPS_MAX;) {
		for (char **member = gr->gr_mem; *member != NULL; member++) {
			if (strcmp(*member, name) == 0
					&& gr->gr_gid != identity->gid) {
				identity->groups[identity->group_count++]
						= gr->gr_gid;
				break;
			}
		}
	}
	if (file != NULL) {
		fclose(file);
	}
	struct stat st;
	if (stat(sysroot_host_path("/", 0, path), &st) == 0 && st.st_uid == uid
			&& identity->group_count != GROUPS_MAX) {
		identity->groups[identity->group_count++] = st.st_gid;
	}
	return true;
}

static pid_t
spawn(const struct identity *identity, uint32_t persona, const char *label,
		const char *program, char **argv, char **env, bool suspended)
{
	char buffer[PATH_MAX];
	const char *host = sysroot_host_path(program, 0, buffer);
	size_t argc = 0;
	while (argv[argc] != NULL) {
		argc++;
	}
	char **limbo_argv = calloc(argc + 3, sizeof(char *));
	limbo_argv[0] = "limbo";
	limbo_argv[1] = (char *)host;
	memcpy(limbo_argv + 2, argv, argc * sizeof(char *));

	int exec_fds[2];
	if (pipe2(exec_fds, O_CLOEXEC) == -1) {
		free(limbo_argv);
		return -1;
	}
	pid_t child = fork();
	if (child == 0) {
		broker_client_fork_child();
		close(exec_fds[0]);
		sigset_t mask;
		sigemptyset(&mask);
		sigprocmask(SIG_SETMASK, &mask, NULL);
		setsid();
		size_t envc = 0;
		while (env[envc] != NULL) {
			envc++;
		}
		char **job_env = calloc(envc + 2, sizeof(char *));
		if (job_env == NULL) {
			_exit(127);
		}
		memcpy(job_env, env, envc * sizeof(char *));
		if (suspended) {
			job_env[envc++] = "LIMBO_START_SUSPENDED=1";
		}
		if (persona != (uint32_t)-1) {
			int error = persona_spawn_check(persona);
			if (error == 0) {
				error = persona_adopt(getpid(), persona);
			}
		}
		const char *name = strrchr(program, '/');
		int output = jobs_open_log(name != NULL ? name + 1 : program,
				argv[0] != NULL ? argv + 1 : argv,
				identity->uid, identity->gid);
		if (output == -1) {
			output = open("/dev/null", O_WRONLY);
		}
		int input = open("/dev/null", O_RDONLY);
		if (output != -1 && input != -1) {
			dup2(input, STDIN_FILENO);
			dup2(output, STDOUT_FILENO);
			dup2(output, STDERR_FILENO);
		}
		if (!become(identity)) {
			(void)!write(exec_fds[1], "u", 1);
			_exit(126);
		}
		execve("/proc/self/exe", limbo_argv, job_env);
		(void)!write(exec_fds[1], "e", 1);
		_exit(127);
	}
	close(exec_fds[1]);
	free(limbo_argv);
	if (child < 0) {
		close(exec_fds[0]);
		return -1;
	}
	char failed;
	ssize_t got;
	while ((got = read(exec_fds[0], &failed, 1)) == -1 && errno == EINTR) {
	}
	close(exec_fds[0]);
	int status = 0;
	if (got != 0) {
		waitpid(child, &status, 0);
		return -1;
	}
	if (suspended) {
		pid_t waited;
		while ((waited = waitpid(child, &status, WUNTRACED)) == -1
				&& errno == EINTR) {
		}
		if (waited != child || !WIFSTOPPED(status)) {
			return -1;
		}
	}
	return child;
}

static bool
become(const struct identity *identity)
{
	if (identity->uid == (uid_t)-1) {
		return true;
	}
	if (setgroups(identity->group_count, identity->groups) != 0
			&& errno != EPERM) {
		return false;
	}
	return setresgid(identity->gid, identity->gid, identity->gid) == 0
			&& setresuid(identity->uid, identity->uid,
					   identity->uid)
			== 0;
}

static void
add_job(struct job *job)
{
	pthread_mutex_lock(&lock);
	job->next = jobs;
	jobs = job;
	pthread_mutex_unlock(&lock);
}

static void
reply_info(mach_msg_header_t *request, struct job *job)
{
	size_t capacity = 512 + strlen(job->program) + job->plist_size;
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	encode_info(&encoder, job, MACH_PORT_NULL);
	xpc_launchd_reply(request, &encoder);
	free(buffer);
}

static void
encode_info(struct xpc_encoder *encoder, struct job *job,
		mach_port_name_t monitor)
{
	if (job->pid > 0) {
		collect_status(job);
	}
	struct xpc_object plist = {
			.data = job->plist,
			.end = (const uint8_t *)job->plist + job->plist_size,
	};
	xpc_encoder_begin_dictionary(encoder, NULL);
	xpc_encoder_uuid(encoder, "job-handle", job->handle);
	if (job->pid <= 0) {
		xpc_encoder_uint64(encoder, "job-state", JOB_STATE_WAITING);
	} else if (!job->exited) {
		xpc_encoder_uint64(encoder, "job-state", JOB_STATE_RUNNING);
		xpc_encoder_int64(encoder, "pid", job->pid);
	} else {
		xpc_encoder_uint64(encoder, "job-state", JOB_STATE_EXITED);
		xpc_encoder_int64(encoder, "wait4-status", job->status);
		xpc_encoder_uint64(encoder, "os-reason-ns", 0);
		xpc_encoder_uint64(encoder, "os-reason-code", 0);
		xpc_encoder_uint64(encoder, "os-reason-flags", 0);
	}
	xpc_encoder_string(encoder, "program", job->program);
	struct xpc_object additional;
	if (xpc_dictionary_get_dictionary(
			    &plist, "_AdditionalProperties", &additional)) {
		xpc_encoder_object(encoder, "additional-properties",
				additional.data, xpc_object_size(&additional));
	}
	if (job->has_instance) {
		xpc_encoder_uuid(encoder, "instance", job->instance);
	}
	if (monitor != MACH_PORT_NULL) {
		xpc_encoder_mach_recv(encoder, "monitor", monitor);
	}
	xpc_encoder_end_dictionary(encoder);
}

static bool
collect_status(struct job *job)
{
	return job->exited;
}

bool
launchd_jobs_copy_with_label(mach_msg_header_t *request)
{
	struct xpc_object message;
	const char *label;
	if (!xpc_message_payload(request, &message)
			|| (label = xpc_dictionary_get_string(
					    &message, "label"))
					== NULL) {
		reply_error(request, EINVAL);
		return true;
	}
	uint64_t domain = 0;
	xpc_dictionary_get_uint64(&message, "type", &domain);
	char name[300];
	snprintf(name, sizeof(name), "%s/%s",
			domain == DOMAIN_TYPE_GUI                    ? "gui"
					: domain == DOMAIN_TYPE_USER ? "user"
								     : "system",
			label);
	pthread_mutex_lock(&lock);
	struct job *job = jobs;
	while (job != NULL
			&& (job->broker_name == NULL
					|| strcmp(job->broker_name, name)
							!= 0)) {
		job = job->next;
	}
	pthread_mutex_unlock(&lock);
	if (job != NULL) {
		reply_handle(request, job);
		return true;
	}
	char program[PATH_MAX] = "";
	pid_t pid = broker_job_pid("print", name, program, sizeof(program));
	if (pid < 0 || program[0] == '\0') {
		reply_error(request, ESRCH);
		return true;
	}
	job = calloc(1, sizeof(*job));
	getrandom(job->handle, sizeof(job->handle), 0);
	job->uid = (uid_t)-1;
	job->label = strdup(label);
	job->program = strdup(program);
	job->broker_name = strdup(name);
	job->service_type = SERVICE_TYPE_DAEMON;
	job->pid = pid;
	add_job(job);
	reply_handle(request, job);
	return true;
}

static void
reply_handle(mach_msg_header_t *request, const struct job *job)
{
	uint8_t buffer[128];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_uuid(&encoder, "job-handle", job->handle);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
}

static bool
running(pid_t pid)
{
	struct process process;
	return process_lookup((int32_t)pid, &process) == 0
			&& !process_exited(&process);
}

static struct job *
job_for_handle(const uint8_t handle[16])
{
	for (struct job *job = jobs; job != NULL; job = job->next) {
		if (memcmp(job->handle, handle, 16) == 0) {
			return job;
		}
	}
	return NULL;
}

bool
launchd_jobs_start(mach_msg_header_t *request)
{
	struct xpc_object message;
	uint8_t handle[16];
	if (!xpc_message_payload(request, &message)
			|| !xpc_dictionary_get_uuid(
					&message, "job-handle", handle)) {
		return false;
	}
	pthread_mutex_lock(&lock);
	struct job *job = job_for_handle(handle);
	pthread_mutex_unlock(&lock);
	if (job == NULL) {
		reply_error(request, ESRCH);
		return true;
	}
	if ((job->pid <= 0 || collect_status(job)) && !start(job)) {
		reply_error(request, ENOEXEC);
		return true;
	}
	reply_info(request, job);
	return true;
}

bool
launchd_jobs_info(mach_msg_header_t *request)
{
	struct xpc_object message;
	uint8_t handle[16];
	if (!xpc_message_payload(request, &message)
			|| !xpc_dictionary_get_uuid(
					&message, "job-handle", handle)) {
		return false;
	}
	pthread_mutex_lock(&lock);
	struct job *job = job_for_handle(handle);
	pthread_mutex_unlock(&lock);
	if (job == NULL) {
		reply_error(request, ESRCH);
	} else {
		reply_info(request, job);
	}
	return true;
}

bool
launchd_jobs_remove(mach_msg_header_t *request)
{
	struct xpc_object message;
	uint8_t handle[16];
	if (!xpc_message_payload(request, &message)
			|| !xpc_dictionary_get_uuid(
					&message, "job-handle", handle)) {
		return false;
	}
	pthread_mutex_lock(&lock);
	struct job *job = NULL;
	for (struct job **link = &jobs; *link != NULL; link = &(*link)->next) {
		if (memcmp((*link)->handle, handle, sizeof(handle)) == 0) {
			job = *link;
			*link = job->next;
			break;
		}
	}
	pthread_mutex_unlock(&lock);
	if (job == NULL) {
		reply_error(request, ESRCH);
		return true;
	}
	if (job->pid > 0 && running(job->pid)) {
		kill(job->pid, SIGKILL);
	}
	if (job->monitor != MACH_PORT_NULL) {
		ipc_port_deallocate(job->monitor);
	}
	free(job->label);
	free(job->program);
	free(job->plist);
	free(job->variables);
	free(job->broker_name);
	free(job);

	uint8_t buffer[64];
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, sizeof(buffer));
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	return true;
}

bool
launchd_jobs_managed(mach_msg_header_t *request)
{
	pthread_mutex_lock(&lock);
	size_t count = 0;
	for (struct job *job = jobs; job != NULL; job = job->next) {
		count++;
	}
	size_t capacity = 128 + count * 24;
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_begin_array(&encoder, "handles");
	for (struct job *job = jobs; job != NULL; job = job->next) {
		if (job->broker_name == NULL) {
			xpc_encoder_element_uuid(&encoder, job->handle);
		}
	}
	xpc_encoder_end_array(&encoder);
	xpc_encoder_end_dictionary(&encoder);
	pthread_mutex_unlock(&lock);
	xpc_launchd_reply(request, &encoder);
	free(buffer);
	return true;
}

bool
launchd_jobs_handle_for_pid(mach_msg_header_t *request, pid_t pid)
{
	pthread_mutex_lock(&lock);
	struct job *job = job_for_pid(pid);
	pthread_mutex_unlock(&lock);
	if (job == NULL) {
		return false;
	}
	reply_info(request, job);
	return true;
}

static struct job *
job_for_pid(pid_t pid)
{
	for (struct job *job = jobs; job != NULL; job = job->next) {
		if (job->pid == pid) {
			return job;
		}
	}
	return NULL;
}

bool
launchd_jobs_monitor(mach_msg_header_t *request)
{
	struct xpc_object message;
	uint8_t handle[16];
	if (!xpc_message_payload(request, &message)
			|| !xpc_dictionary_get_uuid(
					&message, "job-handle", handle)) {
		return false;
	}
	pthread_mutex_lock(&lock);
	struct job *job = job_for_handle(handle);
	pthread_mutex_unlock(&lock);
	if (job == NULL) {
		reply_error(request, ESRCH);
		return true;
	}
	mach_port_name_t port;
	if (ipc_port_allocate(MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS
			|| ipc_port_insert_right(port, port,
					   MACH_MSG_TYPE_MAKE_SEND_ONCE)
					!= KERN_SUCCESS) {
		reply_error(request, ENOMEM);
		return true;
	}
	pthread_mutex_lock(&lock);
	job->monitor = port;
	job->exit_told = false;
	tell_exit(job);
	pthread_mutex_unlock(&lock);

	size_t capacity = 512 + strlen(job->program) + job->plist_size;
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	encode_info(&encoder, job, port);
	xpc_launchd_reply(request, &encoder);
	free(buffer);
	return true;
}

static void
tell_exit(struct job *job)
{
	if (job->monitor == MACH_PORT_NULL || job->exit_told || job->pid <= 0
			|| !job->exited) {
		return;
	}
	size_t capacity = 512 + strlen(job->program) + job->plist_size;
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	encode_info(&encoder, job, MACH_PORT_NULL);
	xpc_launchd_send(job->monitor, MACH_MSG_TYPE_MOVE_SEND_ONCE, &encoder);
	free(buffer);
	job->monitor = MACH_PORT_NULL;
	job->exit_told = true;
}

bool
launchd_jobs_monitor_poll(mach_msg_header_t *request)
{
	struct xpc_object message;
	uint8_t handle[16];
	if (!xpc_message_payload(request, &message)
			|| !xpc_dictionary_get_uuid(
					&message, "job-handle", handle)
			|| !(request->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return false;
	}
	mach_msg_body_t *body = (mach_msg_body_t *)(request + 1);
	mach_msg_port_descriptor_t *descriptors = (void *)(body + 1);
	mach_port_name_t next = MACH_PORT_NULL;
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		if (descriptors[i].type == MACH_MSG_PORT_DESCRIPTOR
				&& descriptors[i].disposition
						== MACH_MSG_TYPE_PORT_SEND_ONCE) {
			next = descriptors[i].name;
			descriptors[i].name = MACH_PORT_NULL;
		}
	}
	pthread_mutex_lock(&lock);
	struct job *job = job_for_handle(handle);
	if (job != NULL && next != MACH_PORT_NULL) {
		if (job->monitor != MACH_PORT_NULL) {
			ipc_port_deallocate(job->monitor);
		}
		job->monitor = next;
		tell_exit(job);
	}
	pthread_mutex_unlock(&lock);
	return true;
}

void
launchd_jobs_exited(pid_t pid, int status)
{
	pthread_mutex_lock(&lock);
	for (struct job *job = jobs; job != NULL; job = job->next) {
		if (job->pid == pid && !job->exited) {
			job->exited = true;
			job->status = status;
			tell_exit(job);
		}
	}
	pthread_mutex_unlock(&lock);
}

bool
launchd_jobs_reply_properties(mach_msg_header_t *request, pid_t pid)
{
	pthread_mutex_lock(&lock);
	struct job *job = job_for_pid(pid);
	pthread_mutex_unlock(&lock);
	if (job == NULL) {
		return pid == getpid() && reply_own_properties(request);
	}
	reply_properties(request, job);
	return true;
}

static bool
reply_own_properties(mach_msg_header_t *request)
{
	if (own_dictionary == NULL) {
		return false;
	}
	char path[PATH_MAX];
	const char *host = getenv(XPC_SERVICES_HOST_PID_VARIABLE);
	struct job job = {
			.label = (char *)own_label,
			.program = process_executable_path(getpid(), path)
					? (char *)sysroot_guest_path(path)
					: (char *)own_label,
			.service_type = SERVICE_TYPE_EXTENSION,
			.host = host != NULL ? (pid_t)atoi(host) : 0,
			.plist = own_dictionary,
			.plist_size = own_dictionary_size,
			.pid = getpid(),
	};
	const char *instance = getenv(XPC_SERVICES_INSTANCE_VARIABLE);
	job.has_instance = instance != NULL
			&& parse_uuid_text(instance, job.instance);
	reply_properties(request, &job);
	return true;
}

static bool
parse_uuid_text(const char *text, uint8_t *out)
{
	int count = 0;
	for (const char *p = text; *p != '\0' && count != 32; p++) {
		int digit = (*p >= '0' && *p <= '9')       ? *p - '0'
				: (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10
				: (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10
							   : -1;
		if (digit < 0) {
			if (*p != '-') {
				return false;
			}
			continue;
		}
		if (count % 2 == 0) {
			out[count / 2] = (uint8_t)(digit << 4);
		} else {
			out[count / 2] |= (uint8_t)digit;
		}
		count++;
	}
	return count == 32;
}

static void
reply_properties(mach_msg_header_t *request, struct job *job)
{
	struct xpc_object plist = {
			.data = job->plist,
			.end = (const uint8_t *)job->plist + job->plist_size,
	};
	size_t capacity = 4096 + job->plist_size;
	uint8_t *buffer = malloc(capacity);
	struct xpc_encoder encoder;
	xpc_encoder_init(&encoder, buffer, (uint32_t)capacity);
	xpc_encoder_begin_dictionary(&encoder, NULL);
	xpc_encoder_uint64(&encoder, "rec_execcnt", 10);
	const mach_msg_audit_trailer_t *trailer = (const mach_msg_audit_trailer_t
					*)((const uint8_t *)request
			+ request->msgh_size);
	xpc_encoder_uint64(&encoder, "req_pid",
			(uint64_t)(pid_t)trailer->msgh_audit.val[5]);
	xpc_encoder_begin_dictionary(&encoder, "attrs");
	xpc_encoder_string(&encoder, "label", job->label);
	xpc_encoder_string(&encoder, "program", job->program);
	char path[PATH_MAX];
	if (job->broker_name != NULL
			&& broker_job_plist(job->pid, path, sizeof(path))) {
		xpc_encoder_string(&encoder, "path", path);
	}
	xpc_encoder_uint64(&encoder, "service-type", job->service_type);
	struct xpc_object additional;
	if (xpc_dictionary_get_dictionary(
			    &plist, "_AdditionalProperties", &additional)) {
		xpc_encoder_object(&encoder, "additional-properties",
				additional.data, xpc_object_size(&additional));
	}
	if (job->has_instance) {
		xpc_encoder_uuid(&encoder, "instance", job->instance);
	}
	xpc_encoder_end_dictionary(&encoder);
	xpc_encoder_end_dictionary(&encoder);
	xpc_launchd_reply(request, &encoder);
	free(buffer);
}

static bool
broker_job_plist(pid_t pid, char *path, size_t size)
{
	if (pid <= 0) {
		return false;
	}
	char number[24];
	snprintf(number, sizeof(number), "%d", (int)pid);
	const char *const words[] = {"pid", number};
	uint32_t status = 0;
	char *text = control(words, 2, &status);
	char *tab = text != NULL && status == 0 ? strchr(text, '\t') : NULL;
	if (tab != NULL) {
		tab++;
		snprintf(path, size, "%.*s", (int)strcspn(tab, "\n"), tab);
	}
	free(text);
	return tab != NULL;
}

bool
launchd_jobs_properties(mach_msg_header_t *request)
{
	struct xpc_object message;
	uint8_t handle[16];
	if (!xpc_message_payload(request, &message)
			|| !xpc_dictionary_get_uuid(
					&message, "job-handle", handle)) {
		return false;
	}
	pthread_mutex_lock(&lock);
	struct job *job = job_for_handle(handle);
	pthread_mutex_unlock(&lock);
	if (job == NULL) {
		reply_error(request, ESRCH);
	} else {
		reply_properties(request, job);
	}
	return true;
}

void
launchd_jobs_init(void)
{
	own_label = getenv(SERVICE_LABEL_VARIABLE);
	const char *hex = getenv(SERVICE_DICTIONARY_VARIABLE);
	if (own_label == NULL || hex == NULL) {
		return;
	}
	own_dictionary_size = strlen(hex) / 2;
	own_dictionary = malloc(own_dictionary_size ? own_dictionary_size : 1);
	for (size_t i = 0; i < own_dictionary_size; i++) {
		unsigned int byte;
		sscanf(hex + i * 2, "%2x", &byte);
		own_dictionary[i] = (uint8_t)byte;
	}
}

bool
launchd_jobs_own_variable(const char *variable)
{
	if (own_dictionary == NULL) {
		return false;
	}
	struct xpc_object dictionary = {
			.data = own_dictionary,
			.end = own_dictionary + own_dictionary_size,
	};
	struct xpc_object variables;
	if (!xpc_dictionary_get_dictionary(
			    &dictionary, "EnvironmentVariables", &variables)) {
		return false;
	}
	char name[256];
	size_t length = strcspn(variable, "=");
	if (length >= sizeof(name)) {
		return false;
	}
	memcpy(name, variable, length);
	name[length] = '\0';
	return xpc_dictionary_get_string(&variables, name) != NULL;
}
