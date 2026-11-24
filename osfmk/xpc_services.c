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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "broker.h"
#include "bsd/persona.h"
#include "bsd/signo.h"
#include "launchd_jobs.h"
#include "osfmk/broker_client.h"
#include "osfmk/task.h"
#include "plist.h"
#include "sysroot.h"
#include "xpc_services.h"

#define SERVICE_VARIABLE   "LIMBO_XPC_SERVICE"
#define BUNDLE_VARIABLE    "LIMBO_XPC_BUNDLE"
#define INSTANCE_VARIABLE  XPC_SERVICES_INSTANCE_VARIABLE
#define BOOTSTRAP_VARIABLE "LIMBO_XPC_BOOTSTRAP"
#define CREATOR_VARIABLE   "LIMBO_XPC_BOOTSTRAP_CREATOR"

#define MAX_FOLDERS 512

struct service {
	char *identifier;
	char *bundle;
	char *executable;
	bool shared;
	bool multiple;
};

struct folder {
	char *path;
	bool read;
	struct service *services;
	size_t service_count;
};

struct started {
	struct started *next;
	char *name;
	int process;
};

struct bootstrap {
	struct bootstrap *next;
	char *name;
	uint8_t *dictionary;
	size_t size;
};

static void add_folder(const char *folder);
static void *watch_host(void *arg);
static bool find_service(const char *name, struct service *out);
static void add_system_folders(void);
static void add_framework_folders(const char *framework, bool inner);
static void read_folder(struct folder *folder);
static char *read_info_plist(const char *bundle);
static pid_t spawn(const struct service *service, const char *instance);
static char *bootstrap_variable(const char *name);
static char *hex_variable(const char *name, const void *data, size_t size);
static void remember_started(
		const char *identifier, const char *instance, pid_t pid);

extern char **environ;

static struct folder folders[MAX_FOLDERS * 4];
static size_t folder_count;
static bool system_added;

static const char *const system_frameworks[] = {
		"/System/Library/Frameworks",
		"/System/Library/PrivateFrameworks",
		"/System/iOSSupport/System/Library/Frameworks",
		"/System/iOSSupport/System/Library/PrivateFrameworks",
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct started *started;
static struct bootstrap *bootstraps;
static pthread_mutex_t bootstraps_lock = PTHREAD_MUTEX_INITIALIZER;

void
xpc_services_init(const char *executable)
{
	char guest[PATH_MAX];
	char real[PATH_MAX];
	if (realpath(executable, real) != NULL) {
		snprintf(guest, sizeof(guest), "%s", sysroot_guest_path(real));
		xpc_services_add_binary(guest);
	}

	const char *host = getenv(XPC_SERVICES_HOST_PID_VARIABLE);
	if (host != NULL) {
		sigset_t all, old;
		sigfillset(&all);
		pthread_sigmask(SIG_SETMASK, &all, &old);
		pthread_t thread;
		if (pthread_create(&thread, NULL, watch_host,
				    (void *)(intptr_t)atoi(host))
				== 0) {
			pthread_detach(thread);
		}
		pthread_sigmask(SIG_SETMASK, &old, NULL);
	}
}

void
xpc_services_add_binary(const char *path)
{
	char folder[PATH_MAX];
	snprintf(folder, sizeof(folder), "%s", path);
	char *slash = strrchr(folder, '/');
	if (slash == NULL) {
		return;
	}
	*slash = '\0';
	size_t length = strlen(folder);
	if (length > 6 && strcmp(folder + length - 6, "/MacOS") == 0) {
		folder[length - 6] = '\0';
	}
	strncat(folder, "/XPCServices", sizeof(folder) - strlen(folder) - 1);
	add_folder(folder);
}

static void
add_folder(const char *folder)
{
	pthread_mutex_lock(&lock);
	for (size_t i = 0; i < folder_count; i++) {
		if (strcmp(folders[i].path, folder) == 0) {
			pthread_mutex_unlock(&lock);
			return;
		}
	}
	if (folder_count < sizeof(folders) / sizeof(folders[0])) {
		char buffer[PATH_MAX];
		const char *host = sysroot_host_path(folder, 0, buffer);
		if (access(host, F_OK) == 0) {
			folders[folder_count++].path = strdup(folder);
		}
	}
	pthread_mutex_unlock(&lock);
}

static void *
watch_host(void *arg)
{
	int pidfd = syscall(SYS_pidfd_open, (pid_t)(intptr_t)arg, 0);
	if (pidfd != -1) {
		struct pollfd pfd = {.fd = pidfd, .events = POLLIN};
		while (poll(&pfd, 1, -1) == -1 && errno == EINTR) {
		}
	}
	_exit(0);
}

void
xpc_services_uuid_text(const uint8_t *uuid, char *out)
{
	static const char digits[] = "0123456789ABCDEF";
	char *p = out;
	for (int i = 0; i != 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10) {
			*p++ = '-';
		}
		*p++ = digits[uuid[i] >> 4];
		*p++ = digits[uuid[i] & 0xf];
	}
	*p = '\0';
}

void
xpc_services_host_name(const char *name, pid_t host, char *out, size_t size)
{
	snprintf(out, size, "%s#%d", name, (int)host);
}

void
xpc_services_instance_name(const char *name, pid_t host,
		const uint8_t *instance, char *out, size_t size)
{
	if (instance == NULL) {
		xpc_services_host_name(name, host, out, size);
		return;
	}
	char text[37];
	xpc_services_uuid_text(instance, text);
	snprintf(out, size, "%s#%d#%s", name, (int)host, text);
}

const char *
xpc_services_check_in_name(const char *name, char *buffer, size_t size)
{
	const char *service = getenv(SERVICE_VARIABLE);
	const char *host = getenv(XPC_SERVICES_HOST_PID_VARIABLE);
	if (host == NULL || (service != NULL && strcmp(service, name) != 0)) {
		return name;
	}
	const char *instance = getenv(INSTANCE_VARIABLE);
	if (instance != NULL) {
		snprintf(buffer, size, "%s#%d#%s", name, atoi(host), instance);
	} else {
		xpc_services_host_name(name, atoi(host), buffer, size);
	}
	return buffer;
}

bool
xpc_services_is_service(const char *name)
{
	const char *service = getenv(SERVICE_VARIABLE);
	return service != NULL && strcmp(service, name) == 0;
}

bool
xpc_services_multiple_instances(const char *name)
{
	struct service found;
	return find_service(name, &found) && found.multiple;
}

static bool
find_service(const char *name, struct service *out)
{
	if (!system_added) {
		system_added = true;
		add_system_folders();
	}
	pthread_mutex_lock(&lock);
	for (size_t i = 0; i < folder_count; i++) {
		struct folder *folder = &folders[i];
		if (!folder->read) {
			read_folder(folder);
		}
		for (size_t j = 0; j < folder->service_count; j++) {
			struct service *service = &folder->services[j];
			if (strcmp(service->identifier, name) == 0) {
				*out = *service;
				pthread_mutex_unlock(&lock);
				return true;
			}
		}
	}
	pthread_mutex_unlock(&lock);
	return false;
}

static void
add_system_folders(void)
{
	for (size_t i = 0; i < sizeof(system_frameworks)
					/ sizeof(system_frameworks[0]);
			i++) {
		char buffer[PATH_MAX];
		DIR *dir = opendir(sysroot_host_path(
				system_frameworks[i], 0, buffer));
		if (dir == NULL) {
			continue;
		}
		struct dirent *entry;
		while ((entry = readdir(dir)) != NULL) {
			if (strstr(entry->d_name, ".framework") == NULL) {
				continue;
			}
			char framework[PATH_MAX];
			snprintf(framework, sizeof(framework), "%s/%s",
					system_frameworks[i], entry->d_name);
			add_framework_folders(framework, true);
		}
		closedir(dir);
	}
}

static void
add_framework_folders(const char *framework, bool inner)
{
	char folder[PATH_MAX];
	snprintf(folder, sizeof(folder), "%s/Versions/Current/XPCServices",
			framework);
	add_folder(folder);
	snprintf(folder, sizeof(folder), "%s/XPCServices", framework);
	char host[PATH_MAX];
	struct stat st;
	if (lstat(sysroot_host_path(folder, 0, host), &st) == 0
			&& S_ISDIR(st.st_mode)) {
		add_folder(folder);
	}
	if (!inner) {
		return;
	}
	snprintf(folder, sizeof(folder), "%s/Versions/Current/Frameworks",
			framework);
	DIR *dir = opendir(sysroot_host_path(folder, 0, host));
	if (dir == NULL) {
		return;
	}
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strstr(entry->d_name, ".framework") == NULL) {
			continue;
		}
		char inner_framework[PATH_MAX];
		snprintf(inner_framework, sizeof(inner_framework), "%s/%s",
				folder, entry->d_name);
		add_framework_folders(inner_framework, false);
	}
	closedir(dir);
}

static void
read_folder(struct folder *folder)
{
	folder->read = true;
	char buffer[PATH_MAX];
	DIR *dir = opendir(sysroot_host_path(folder->path, 0, buffer));
	if (dir == NULL) {
		return;
	}
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		size_t length = strlen(entry->d_name);
		if (length < 5
				|| strcmp(entry->d_name + length - 4, ".xpc")
						!= 0) {
			continue;
		}
		char bundle[PATH_MAX];
		snprintf(bundle, sizeof(bundle), "%s/%s", folder->path,
				entry->d_name);
		char *plist = read_info_plist(bundle);
		if (plist == NULL) {
			continue;
		}
		char identifier[256];
		char executable[NAME_MAX + 1];
		char type[32] = "Application";
		bool multiple = false;
		const char *end = plist + strlen(plist);
		const char *service_end;
		const char *service = plist_dictionary(
				plist, end, "XPCService", &service_end);
		if (service != NULL) {
			plist_string(service, service_end, "ServiceType", type,
					sizeof(type));
			multiple = plist_bool(service, service_end,
					"_MultipleInstances");
		}
		bool shared = strcmp(type, "Application") != 0;
		if (plist_string(plist, end, "CFBundleIdentifier", identifier,
				    sizeof(identifier))
				&& plist_string(plist, end,
						"CFBundleExecutable",
						executable,
						sizeof(executable))) {
			folder->services = realloc(folder->services,
					(folder->service_count + 1)
							* sizeof(*folder->services));
			folder->services[folder->service_count++]
					= (struct service){
							.identifier
							= strdup(identifier),
							.bundle
							= strdup(bundle),
							.executable
							= strdup(executable),
							.shared = shared,
							.multiple = multiple,
			};
		}
		free(plist);
	}
	closedir(dir);
}

static char *
read_info_plist(const char *bundle)
{
	char guest[PATH_MAX];
	snprintf(guest, sizeof(guest), "%s/Contents/Info.plist", bundle);
	char buffer[PATH_MAX];
	char *plist = plist_read(sysroot_host_path(guest, 0, buffer));
	if (plist == NULL) {
		snprintf(guest, sizeof(guest), "%s/Info.plist", bundle);
		plist = plist_read(sysroot_host_path(guest, 0, buffer));
	}
	return plist;
}

bool
xpc_services_start(const char *name, const uint8_t *instance, bool *shared,
		pid_t *pid)
{
	struct service found;
	if (!find_service(name, &found)) {
		return false;
	}
	*shared = found.shared;
	*pid = 0;
	char text[37];
	if (instance != NULL && found.multiple && !found.shared) {
		xpc_services_uuid_text(instance, text);
	}
	bool own_instance = instance != NULL && found.multiple && !found.shared;
	*pid = spawn(&found, own_instance ? text : NULL);
	remember_started(found.identifier, own_instance ? text : NULL, *pid);
	return true;
}

static pid_t
spawn(const struct service *service, const char *instance)
{
	const char *name = service->identifier;
	char guest[PATH_MAX];
	char buffer[PATH_MAX];
	struct stat st;
	snprintf(guest, sizeof(guest), "%s/Contents/MacOS/%s", service->bundle,
			service->executable);
	if (stat(sysroot_host_path(guest, 0, buffer), &st) != 0) {
		snprintf(guest, sizeof(guest), "%s/%s", service->bundle,
				service->executable);
	}
	char *path = strdup(sysroot_host_path(guest, 0, buffer));

	char *plist = read_info_plist(service->bundle);
	size_t own_count = 0;
	char *own[64];
	if (plist != NULL) {
		const char *end = plist + strlen(plist);
		const char *service_end;
		const char *dictionary = plist_dictionary(
				plist, end, "XPCService", &service_end);
		if (dictionary != NULL) {
			own_count = plist_variables(dictionary, service_end,
					"EnvironmentVariables", own, 64);
		}
		free(plist);
	}

	size_t count = 0;
	while (environ[count] != NULL) {
		count++;
	}
	char **env = calloc(count + own_count + 10, sizeof(*env));
	size_t used = 0;
	for (size_t i = 0; i < count; i++) {
		size_t length = strcspn(environ[i], "=");
		bool overridden = false;
		for (size_t j = 0; j < own_count; j++) {
			overridden |= strncmp(own[j], environ[i], length + 1)
					== 0;
		}
		if (overridden
				|| strncmp(environ[i],
						   "DYLD_INSERT_LIBRARIES=", 22)
						== 0
				|| strncmp(environ[i], "LIMBO_LAUNCHD_", 14)
						== 0
				|| strncmp(environ[i], "LIMBO_XPC_", 10) == 0
				|| strncmp(environ[i],
						   BROKER_INSTANCE_VARIABLE "=",
						   strlen(BROKER_INSTANCE_VARIABLE)
								   + 1)
						== 0
				|| strncmp(environ[i], "XPC_SERVICE_NAME=", 17)
						== 0
				|| strncmp(environ[i], "XPC_FLAGS=", 10) == 0
				|| launchd_jobs_own_variable(environ[i])) {
			continue;
		}
		env[used++] = environ[i];
	}
	size_t first_own = used;
	for (size_t j = 0; j < own_count; j++) {
		env[used++] = own[j];
	}
	asprintf(&env[used++], SERVICE_VARIABLE "=%s", name);
	asprintf(&env[used++], BUNDLE_VARIABLE "=%s", service->bundle);
	if (!service->shared) {
		asprintf(&env[used++], XPC_SERVICES_HOST_PID_VARIABLE "=%d",
				(int)getpid());
	}
	if (instance != NULL) {
		asprintf(&env[used++], INSTANCE_VARIABLE "=%s", instance);
	}
	asprintf(&env[used++], "XPC_SERVICE_NAME=%s", name);
	char *bootstrap = bootstrap_variable(name);
	if (bootstrap != NULL) {
		env[used++] = bootstrap;
		audit_token_t token;
		task_audit_token_self(&token);
		env[used++] = hex_variable(
				CREATOR_VARIABLE, &token, sizeof(token));
	}
	env[used++] = strdup("XPC_FLAGS=1");

	char *argv[] = {"limbo", path, (char *)service->executable, NULL};
	int pids[2];
	if (pipe2(pids, O_CLOEXEC) == -1) {
		pids[0] = pids[1] = -1;
	}
	pid_t host = getpid();
	pid_t child = fork();
	if (child == 0) {
		broker_client_fork_child();
		pid_t grandchild = fork();
		if (grandchild == 0) {
			persona_inherit(getpid(), host);
			execve("/proc/self/exe", argv, env);
			_exit(127);
		}
		if (pids[1] != -1) {
			(void)!write(pids[1], &grandchild, sizeof(grandchild));
		}
		_exit(0);
	}
	pid_t service_pid = 0;
	if (pids[1] != -1) {
		close(pids[1]);
	}
	if (child > 0) {
		waitpid(child, NULL, 0);
		if (pids[0] != -1
				&& read(pids[0], &service_pid,
						   sizeof(service_pid))
						!= sizeof(service_pid)) {
			service_pid = 0;
		}
	}
	if (pids[0] != -1) {
		close(pids[0]);
	}
	if (service_pid < 0) {
		service_pid = 0;
	}
	for (size_t i = first_own; i < used; i++) {
		free(env[i]);
	}
	free(env);
	free(path);
	return service_pid;
}

static char *
bootstrap_variable(const char *name)
{
	char *variable = NULL;
	pthread_mutex_lock(&bootstraps_lock);
	for (struct bootstrap *b = bootstraps; b != NULL; b = b->next) {
		if (strcmp(b->name, name) == 0) {
			variable = hex_variable(BOOTSTRAP_VARIABLE,
					b->dictionary, b->size);
			break;
		}
	}
	pthread_mutex_unlock(&bootstraps_lock);
	return variable;
}

static char *
hex_variable(const char *name, const void *data, size_t size)
{
	size_t prefix = strlen(name) + 1;
	char *variable = malloc(prefix + size * 2 + 1);
	snprintf(variable, prefix + 1, "%s=", name);
	const uint8_t *bytes = data;
	for (size_t i = 0; i < size; i++) {
		snprintf(variable + prefix + i * 2, 3, "%02x", bytes[i]);
	}
	variable[prefix + size * 2] = '\0';
	return variable;
}

static void
remember_started(const char *identifier, const char *instance, pid_t pid)
{
	int process = (pid > 0) ? (int)syscall(SYS_pidfd_open, pid, 0) : -1;
	pthread_mutex_lock(&lock);
	for (struct started **link = &started; *link != NULL;) {
		struct started *entry = *link;
		struct pollfd fd = {.fd = entry->process, .events = POLLIN};
		if (poll(&fd, 1, 0) == 1) {
			*link = entry->next;
			close(entry->process);
			free(entry->name);
			free(entry);
		} else {
			link = &entry->next;
		}
	}
	if (process != -1) {
		struct started *entry = calloc(1, sizeof(*entry));
		if (instance != NULL) {
			asprintf(&entry->name, "%s.%s", identifier, instance);
		} else {
			entry->name = strdup(identifier);
		}
		entry->process = process;
		entry->next = started;
		started = entry;
	}
	pthread_mutex_unlock(&lock);
}

int
xpc_services_kill(const char *name, int signo)
{
	int linux_signo = signo_to_linux(signo);
	int error = ESRCH;
	pthread_mutex_lock(&lock);
	for (struct started *entry = started; entry != NULL;
			entry = entry->next) {
		if (strcasecmp(entry->name, name) != 0) {
			continue;
		}
		if (linux_signo != 0
				&& syscall(SYS_pidfd_send_signal,
						   entry->process, linux_signo,
						   NULL, 0)
						== 0) {
			error = 0;
		}
		break;
	}
	pthread_mutex_unlock(&lock);
	return error;
}
