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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "broker.h"
#include "launchd_engine.h"
#include "plist.h"

#define DEFAULT_THROTTLE   10
#define OTHER_PERSONA_TYPE 6
#define STOP_TIMEOUT_MS    LIMBO_LAUNCHD_STOP_MS

#define LOGS_VARIABLE "LIMBO_JOB_LOGS"

enum job_state {
	JOB_UNLOADED,
	JOB_IDLE,
	JOB_WAITING,
	JOB_RUNNING,
	JOB_STOPPED,
};

enum job_session {
	SESSION_BOOT,
	SESSION_BOOT_TASK,
};

struct keepalive {
	bool always;
	int successful_exit;
	int crashed;
	bool after_initial_demand;
};

struct job {
	char *name;
	char *label;
	char *plist;
	char *environment;
	bool root;
	char *account;
	uid_t account_uid;
	gid_t account_gid;
	char *account_home;
	enum job_session session;
	bool run_at_load;
	bool required;
	bool system_session;
	int persona_type;
	struct keepalive keepalive;
	unsigned throttle;
	char **services;
	size_t service_count;
	char *executable;
	char **argv;
	char *log;
	char **variables;
	size_t variable_count;

	enum job_state state;
	pid_t pid;
	int64_t started;
	int64_t start_at;
	int64_t kill_at;
	bool stopping;
	bool restart;
	bool demanded;
	bool has_status;
	int status;
	char *reason;
	unsigned runs;
};

static void handle_signals(void);
static void find_account(struct job *job);
#define ACCOUNT_GROUPS_MAX 64
static size_t account_groups(const char *name, gid_t gid, gid_t *groups);
static void load_user_groups(void);
static void add_user_group(gid_t gid);
static void set_state(struct job *job, enum job_state state);
static void load_session(enum job_session session);
static bool load_into(struct job *job);
static void load_start(struct job *job);
static void next_boot_task(void);
static bool starts_at_load(const struct job *job);
static void job_exited(struct job *job, int status);
static bool crashed(int status);
static char *exit_reason(const char *log);
static int open_log(struct job *job);
static bool kept_alive(const struct job *job, int status);
static void schedule(struct job *job);
static void start(struct job *job);
static char **make_environment(const struct job *job);
static void stop(struct job *job);
static struct job *parse_job(char *line);
static bool parse_keepalive(const char *text, struct keepalive *keepalive);
static char *find_executable(const char *program);
static const char *program_name(const char *path);
static char *program_argv0(const char *executable, const char *program);
static char *log_path(
		const char *prefix, const char *program, char **arguments);
static bool job_matches(const struct job *job, const char *word);

static void describe(FILE *out, const struct job *job, bool details);
static int shell_status(int status);
static int64_t now_ms(void);
static char *optional(const char *text);
static void say(const char *format, ...);

static struct job **jobs;
static size_t job_count;

static int signal_fd = -1;
static pid_t broker;
static bool shutting_down;
static bool booted;

static uid_t user_uid;
static gid_t user_gid;
static gid_t user_groups[16];
static size_t user_group_count;
static char user_name[64] = "root";
static char user_home[PATH_MAX];
static char log_directory[PATH_MAX] = "/tmp";
static char sysroot[PATH_MAX];
static char limbo[PATH_MAX];

void
jobs_init(pid_t broker_pid)
{
	broker = broker_pid;
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, NULL);
	signal_fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
}

void
jobs_load(const char *path)
{
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		perror(path);
		return;
	}

	const char *root = getenv("LIMBO_SYSROOT");
	struct stat st;
	if (root == NULL || realpath(root, sysroot) == NULL
			|| stat(sysroot, &st) != 0) {
		say("no sysroot (LIMBO_SYSROOT), so no jobs");
		fclose(file);
		return;
	}
	user_uid = st.st_uid;
	user_gid = st.st_gid;
	FILE *passwd = fopen("/etc/passwd", "re");
	for (struct passwd *pw; passwd != NULL && (pw = fgetpwent(passwd));) {
		if (pw->pw_uid == user_uid) {
			snprintf(log_directory, sizeof(log_directory), "%s",
					pw->pw_dir);
			break;
		}
	}
	if (passwd != NULL) {
		fclose(passwd);
	}
	char sysroot_passwd[PATH_MAX];
	snprintf(sysroot_passwd, sizeof(sysroot_passwd),
			"%s/private/etc/passwd", sysroot);
	FILE *guest_passwd = fopen(sysroot_passwd, "re");
	user_groups[user_group_count++] = user_gid;
	for (struct passwd *pw; guest_passwd != NULL
			&& (pw = fgetpwent(guest_passwd));) {
		if (pw->pw_uid == user_uid) {
			snprintf(user_name, sizeof(user_name), "%s",
					pw->pw_name);
			snprintf(user_home, sizeof(user_home), "%s",
					pw->pw_dir);
			user_groups[0] = pw->pw_gid;
			break;
		}
	}
	if (guest_passwd != NULL) {
		fclose(guest_passwd);
	}
	if (user_home[0] == '\0') {
		say("no account for uid %u in %s, so no user jobs run",
				(unsigned)user_uid, sysroot_passwd);
	} else {
		load_user_groups();
	}
	const char *logs = getenv(LOGS_VARIABLE);
	if (logs != NULL) {
		snprintf(log_directory, sizeof(log_directory), "%s", logs);
	}
	char self[PATH_MAX];
	ssize_t length = readlink("/proc/self/exe", self, sizeof(self) - 1);
	self[length > 0 ? length : 0] = '\0';
	snprintf(limbo, sizeof(limbo), "%s/limbo", dirname(self));

	char *line = NULL;
	size_t capacity = 0;
	while (getline(&line, &capacity, file) != -1) {
		line[strcspn(line, "\r\n")] = '\0';
		for (char *c = line; *c != '\0'; c++) {
			if (*c == '#'
					&& (c == line || c[-1] == ' '
							|| c[-1] == '\t')) {
				*c = '\0';
				break;
			}
		}
		struct job *job = parse_job(line);
		if (job == NULL) {
			continue;
		}
		jobs = reallocarray(jobs, job_count + 1, sizeof(*jobs));
		jobs[job_count++] = job;
	}
	free(line);
	fclose(file);

	next_boot_task();
}

static void
next_boot_task(void)
{
	if (booted || shutting_down) {
		return;
	}
	for (size_t i = 0; i != job_count; i++) {
		struct job *job = jobs[i];
		if (job->session == SESSION_BOOT_TASK
				&& job->state == JOB_UNLOADED) {
			say("boot task %s", job->name);
			start(job);
			if (job->state == JOB_RUNNING) {
				return;
			}
		}
	}
	booted = true;
	load_session(SESSION_BOOT);
}

static size_t
account_groups(const char *name, gid_t gid, gid_t *groups)
{
	size_t count = 0;
	groups[count++] = gid;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/private/etc/group", sysroot);
	FILE *file = fopen(path, "re");
	for (struct group *gr; file != NULL && (gr = fgetgrent(file))
			&& count != ACCOUNT_GROUPS_MAX;) {
		bool listed = false;
		for (char **member = gr->gr_mem; *member != NULL; member++) {
			listed = listed || strcmp(*member, name) == 0;
		}
		bool known = false;
		for (size_t i = 0; i != count; i++) {
			known = known || groups[i] == gr->gr_gid;
		}
		if (listed && !known) {
			groups[count++] = gr->gr_gid;
		}
	}
	if (file != NULL) {
		fclose(file);
	}
	return count;
}

static void
load_user_groups(void)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/private/etc/group", sysroot);
	FILE *file = fopen(path, "re");
	for (struct group *gr; file != NULL && (gr = fgetgrent(file));) {
		for (char **member = gr->gr_mem; *member != NULL; member++) {
			if (strcmp(*member, user_name) == 0) {
				add_user_group(gr->gr_gid);
				break;
			}
		}
	}
	if (file != NULL) {
		fclose(file);
	}
	add_user_group(user_gid);
}

static void
add_user_group(gid_t gid)
{
	for (size_t i = 0; i != user_group_count; i++) {
		if (user_groups[i] == gid) {
			return;
		}
	}
	if (user_group_count != sizeof(user_groups) / sizeof(*user_groups)) {
		user_groups[user_group_count++] = gid;
	}
}

static void
set_state(struct job *job, enum job_state state)
{
	job->state = state;
}

static void
load_session(enum job_session session)
{
	struct job **loaded = calloc(
			job_count != 0 ? job_count : 1, sizeof(*loaded));
	size_t count = 0;
	for (size_t i = 0; i != job_count; i++) {
		struct job *job = jobs[i];
		if (job->session != session) {
			continue;
		}
		if (load_into(job)) {
			loaded[count++] = job;
		}
	}
	for (size_t i = 0; i != count; i++) {
		load_start(loaded[i]);
	}
	free(loaded);
}

static bool
load_into(struct job *job)
{
	if (job->root && geteuid() != 0) {
		say("%s runs as root, and the broker doesn't", job->name);
		set_state(job, JOB_STOPPED);
		return false;
	}
	if (!job->root
			&& (job->account != NULL ? job->account_uid == (uid_t)-1
						 : user_home[0] == '\0')) {
		say("%s: its user has no account", job->name);
		set_state(job, JOB_STOPPED);
		return false;
	}
	set_state(job, JOB_IDLE);
	return true;
}

static void
load_start(struct job *job)
{
	if (job->state != JOB_IDLE) {
		return;
	}
	if (starts_at_load(job)) {
		job->demanded = true;
		start(job);
	}
}

static bool
starts_at_load(const struct job *job)
{
	const struct keepalive *k = &job->keepalive;
	return job->run_at_load || k->always
			|| (k->successful_exit != -1
					&& !k->after_initial_demand);
}

size_t
jobs_poll_count(void)
{
	return (signal_fd != -1) ? 1 : 0;
}

void
jobs_poll_fill(struct pollfd *fds)
{
	if (signal_fd != -1) {
		fds[0] = (struct pollfd){.fd = signal_fd, .events = POLLIN};
	}
}

void
jobs_poll_handle(const struct pollfd *fds, size_t count)
{
	for (size_t n = 0; n != count; n++) {
		if (!(fds[n].revents & POLLIN)) {
			continue;
		}
		if (fds[n].fd == signal_fd) {
			handle_signals();
			continue;
		}
	}

	int64_t now = now_ms();
	for (size_t i = 0; i != job_count; i++) {
		struct job *job = jobs[i];
		if (job->state == JOB_WAITING && job->start_at <= now) {
			start(job);
		} else if (job->state == JOB_RUNNING && job->stopping
				&& job->kill_at <= now) {
			say("%s, pid %d, didn't stop: killed", job->name,
					(int)job->pid);
			kill(-job->pid, SIGKILL);
			kill(job->pid, SIGKILL);
			job->kill_at = INT64_MAX;
		}
	}
}

int
jobs_poll_timeout(void)
{
	int64_t next = INT64_MAX;
	for (size_t i = 0; i != job_count; i++) {
		const struct job *job = jobs[i];
		if (job->state == JOB_WAITING && job->start_at < next) {
			next = job->start_at;
		}
		if (job->state == JOB_RUNNING && job->stopping
				&& job->kill_at < next) {
			next = job->kill_at;
		}
	}
	int64_t now = now_ms();
	int64_t wait = next == INT64_MAX ? -1 : next - now;
	if (wait < 0 && next != INT64_MAX) {
		wait = 0;
	}
	return wait > INT32_MAX ? INT32_MAX : (int)wait;
}

static char *control(char **argv, size_t argc, uint32_t *status);

char *
jobs_control(char **argv, size_t argc, uint32_t *status)
{
	char *text = control(argv, argc, status);
	return text;
}

static char *
control(char **argv, size_t argc, uint32_t *status)
{
	char *text = NULL;
	size_t length = 0;
	FILE *out = open_memstream(&text, &length);
	*status = 0;

	const char *command = argc > 0 ? argv[0] : "list";
	if (strcmp(command, "list") == 0) {
		fprintf(out, "PID\tStatus\tState\tName\n");
		for (size_t i = 0; i != job_count; i++) {
			describe(out, jobs[i], false);
		}
		fclose(out);
		return text;
	}
	if (strcmp(command, "pid") == 0) {
		pid_t pid = argc > 1 ? (pid_t)strtol(argv[1], NULL, 10) : 0;
		struct job *job = NULL;
		for (size_t i = 0; i != job_count && job == NULL; i++) {
			if (jobs[i]->state == JOB_RUNNING && jobs[i]->pid == pid
					&& pid > 0 && jobs[i]->label != NULL) {
				job = jobs[i];
			}
		}
		if (job != NULL) {
			fprintf(out, "%s\t/%s\n", job->label,
					job->plist != NULL ? job->plist : "");
		} else {
			*status = 1;
		}
		fclose(out);
		return text;
	}
	if (strcmp(command, "print") != 0 && strcmp(command, "start") != 0
			&& strcmp(command, "stop") != 0
			&& strcmp(command, "restart") != 0) {
		fprintf(out, "unknown command %s\n", command);
		*status = 1;
		fclose(out);
		return text;
	}

	size_t names_end = argc;
	while (names_end > 1 && strchr(argv[names_end - 1], '=') != NULL) {
		names_end--;
	}
	size_t matched = 0;
	for (size_t i = 0; i != job_count; i++) {
		struct job *job = jobs[i];
		bool match = false;
		for (size_t a = 1; a < names_end && !match; a++) {
			match = job_matches(job, argv[a]);
		}
		if (!match) {
			continue;
		}
		matched++;
		if (job->state == JOB_UNLOADED
				&& strcmp(command, "print") != 0) {
			fprintf(out, "%s: not loaded, as its session isn't\n",
					job->name);
			*status = 1;
			continue;
		}
		if (names_end != argc) {
			for (size_t v = 0; v != job->variable_count; v++) {
				free(job->variables[v]);
			}
			job->variable_count = argc - names_end;
			job->variables = reallocarray(job->variables,
					job->variable_count, sizeof(char *));
			for (size_t v = 0; v != job->variable_count; v++) {
				job->variables[v] = strdup(argv[names_end + v]);
			}
		}
		if (strcmp(command, "print") == 0) {
			describe(out, job, true);
		} else if (strcmp(command, "start") == 0) {
			if (job->state != JOB_RUNNING) {
				job->demanded = true;
				start(job);
			}
			describe(out, job, false);
		} else if (strcmp(command, "stop") == 0) {
			if (job->state == JOB_RUNNING) {
				stop(job);
			}
			job->restart = false;
			set_state(job,
					job->state == JOB_RUNNING
							? JOB_RUNNING
							: JOB_STOPPED);
			job->demanded = false;
			describe(out, job, false);
		} else {
			if (job->state == JOB_RUNNING) {
				stop(job);
				job->restart = true;
			} else {
				job->demanded = true;
				start(job);
			}
			describe(out, job, false);
		}
	}
	if (matched == 0) {
		fprintf(out, "no such job\n");
		*status = 1;
	}
	fclose(out);
	return text;
}

bool
jobs_done(void)
{
	if (!shutting_down) {
		return false;
	}
	for (size_t i = 0; i != job_count; i++) {
		if (jobs[i]->state == JOB_RUNNING) {
			return false;
		}
	}
	return true;
}

void
jobs_shut_down(void)
{
	if (shutting_down) {
		return;
	}
	say("stopping every job");
	shutting_down = true;
	for (size_t i = 0; i != job_count; i++) {
		if (jobs[i]->state == JOB_RUNNING) {
			stop(jobs[i]);
		}
	}
}

static void
handle_signals(void)
{
	struct signalfd_siginfo info;
	while (read(signal_fd, &info, sizeof(info)) == sizeof(info)) {
	}
	int status;
	pid_t pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		for (size_t i = 0; i != job_count; i++) {
			if (jobs[i]->state == JOB_RUNNING
					&& jobs[i]->pid == pid) {
				job_exited(jobs[i], status);
			}
		}
	}
}

void
jobs_broker_gone(void)
{
	jobs_shut_down();
}

static void
job_exited(struct job *job, int status)
{
	job->has_status = true;
	job->status = status;
	pid_t group = job->pid;
	job->pid = 0;
	bool stopped = job->stopping;
	job->stopping = false;
	free(job->reason);
	job->reason = crashed(status) ? exit_reason(job->log) : NULL;
	if (job->reason != NULL) {
		say("%s exited with %d: %s", job->name, shell_status(status),
				job->reason);
	} else {
		say("%s exited with %d", job->name, shell_status(status));
	}
	if (group > 0 && shutting_down) {
		kill(-group, SIGKILL);
	}

	if (job->session == SESSION_BOOT_TASK) {
		set_state(job, JOB_STOPPED);
		if (job->required && status != 0) {
			say("%s: launchd requires the boot task to succeed",
					job->name);
		}
		next_boot_task();
		return;
	}

	if (shutting_down) {
		set_state(job, JOB_STOPPED);
	} else if (job->restart) {
		job->restart = false;
		set_state(job, JOB_IDLE);
		job->demanded = true;
		start(job);
	} else if (job->state == JOB_STOPPED || stopped) {
		set_state(job, JOB_STOPPED);
	} else if (kept_alive(job, status)) {
		set_state(job, JOB_IDLE);
		schedule(job);
	} else {
		set_state(job, JOB_IDLE);
	}
}

static bool
crashed(int status)
{
	if (!WIFSIGNALED(status)) {
		return false;
	}
	switch (WTERMSIG(status)) {
	case SIGABRT:
	case SIGSEGV:
	case SIGBUS:
	case SIGILL:
	case SIGTRAP:
		return true;
	default:
		return false;
	}
}

static char *
exit_reason(const char *log)
{
	static const char *const prefixes[] = {
			"not implemented: ",
			"limbo: fatal signal ",
			"limbo: missing system call ",
	};
	enum { TAIL_SIZE = 1 << 20 };
	int fd = open(log, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return NULL;
	}
	char *tail = malloc(TAIL_SIZE);
	off_t size = lseek(fd, 0, SEEK_END);
	ssize_t length = -1;
	if (tail != NULL && size != -1) {
		length = pread(fd, tail, TAIL_SIZE,
				size > TAIL_SIZE ? size - TAIL_SIZE : 0);
	}
	close(fd);

	const char *found = NULL;
	size_t found_length = 0;
	const char *end = tail + (length > 0 ? length : 0);
	for (const char *line = tail; line < end;) {
		const char *next = memchr(line, '\n', end - line);
		size_t line_length = (next != NULL ? next : end) - line;
		for (size_t i = 0; i != sizeof(prefixes) / sizeof(*prefixes);
				i++) {
			size_t prefix_length = strlen(prefixes[i]);
			if (line_length >= prefix_length
					&& memcmp(line, prefixes[i],
							   prefix_length)
							== 0) {
				found = line;
				found_length = line_length;
			}
		}
		line += line_length + 1;
	}
	char *reason = found != NULL ? strndup(found, found_length) : NULL;
	free(tail);
	return reason;
}

static bool
kept_alive(const struct job *job, int status)
{
	const struct keepalive *k = &job->keepalive;
	if (k->always) {
		return true;
	}
	if (k->after_initial_demand && !job->demanded) {
		return false;
	}
	if (k->successful_exit != -1
			&& (status == 0) == (k->successful_exit != 0)) {
		return true;
	}
	if (k->crashed != -1) {
		int signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
		bool crashed = signal == SIGILL || signal == SIGTRAP
				|| signal == SIGABRT || signal == SIGFPE
				|| signal == SIGBUS || signal == SIGSEGV
				|| signal == SIGSYS;
		if (crashed == (k->crashed != 0)) {
			return true;
		}
	}
	return false;
}

static void
schedule(struct job *job)
{
	int64_t at = job->started + (int64_t)job->throttle * 1000;
	if (job->runs == 0 || at <= now_ms()) {
		start(job);
		return;
	}
	say("%s starts in %lld ms", job->name, (long long)(at - now_ms()));
	set_state(job, JOB_WAITING);
	job->start_at = at;
}

static void
start(struct job *job)
{
	if (job->state == JOB_RUNNING || shutting_down) {
		return;
	}
	if (job->root && geteuid() != 0) {
		say("%s runs as root, and the broker doesn't", job->name);
		set_state(job, JOB_STOPPED);
		return;
	}
	if (!job->root
			&& (job->account != NULL ? job->account_uid == (uid_t)-1
						 : user_home[0] == '\0')) {
		say("%s: its user has no account", job->name);
		set_state(job, JOB_STOPPED);
		return;
	}
	if (job->executable == NULL) {
		say("%s: no program", job->name);
		set_state(job, JOB_STOPPED);
		return;
	}
	int log = open_log(job);
	uid_t uid = job->account != NULL ? job->account_uid : user_uid;
	gid_t gid = job->account != NULL ? job->account_gid : user_gid;
	gid_t own_groups[ACCOUNT_GROUPS_MAX];
	size_t own_group_count = job->account != NULL
			? account_groups(job->account, gid, own_groups)
			: 0;
	char **env = make_environment(job);
	size_t argc = 0;
	while (job->argv[argc] != NULL) {
		argc++;
	}
	char **argv = calloc(argc + 3, sizeof(char *));
	argv[0] = "limbo";
	argv[1] = job->executable;
	memcpy(argv + 2, job->argv, argc * sizeof(char *));

	int limbo_fd = open(limbo, O_PATH | O_CLOEXEC);

	pid_t pid = fork();
	if (pid == 0) {
		sigset_t mask;
		sigemptyset(&mask);
		sigprocmask(SIG_SETMASK, &mask, NULL);
		setsid();
		int null = open("/dev/null", O_RDWR);
		dup2(null, STDIN_FILENO);
		dup2(null, STDOUT_FILENO);
		dup2(log != -1 ? log : null, STDERR_FILENO);
		bool own = job->account != NULL;
		if (!job->root && geteuid() == 0
				&& ((own ? setgroups(own_group_count,
							   own_groups)
					 : setgroups(user_group_count,
							   user_groups))
								!= 0
						|| setgid(own ? gid
							      : user_groups[0])
								!= 0
						|| setuid(uid) != 0)) {
			_exit(126);
		}
		if (chdir("/") != 0) {
			_exit(126);
		}
		syscall(SYS_execveat, limbo_fd, "", argv, env, AT_EMPTY_PATH);
		_exit(127);
	}
	if (limbo_fd != -1) {
		close(limbo_fd);
	}
	if (log != -1) {
		close(log);
	}
	for (size_t i = 0; env[i] != NULL; i++) {
		free(env[i]);
	}
	free(env);
	free(argv);
	if (pid < 0) {
		say("%s didn't start: %s", job->name, strerror(errno));
		set_state(job, JOB_IDLE);
		return;
	}
	job->pid = pid;
	set_state(job, JOB_RUNNING);
	job->stopping = false;
	job->started = now_ms();
	job->runs++;
	say("%s started, pid %d", job->name, (int)pid);
}

static char **
make_environment(const struct job *job)
{
	static const char *const dropped[] = {
			"HOME",
			"USER",
			"LOGNAME",
			"DYLD_INSERT_LIBRARIES",
			"LIMBO_LAUNCHD_ENVIRONMENT",
			"LIMBO_LAUNCHD_PERSONA_TYPE",
			"LIMBO_SYSROOT",
	};
	extern char **environ;
	size_t count = 0;
	while (environ[count] != NULL) {
		count++;
	}
	char **env = calloc(count + job->variable_count + 16, sizeof(char *));
	size_t n = 0;
	for (size_t i = 0; i != count; i++) {
		size_t length = strcspn(environ[i], "=");
		bool drop = false;
		for (size_t d = 0; d != sizeof(dropped) / sizeof(*dropped);
				d++) {
			drop = drop
					|| (strlen(dropped[d]) == length
							&& strncmp(environ[i],
									   dropped[d],
									   length)
									== 0);
		}
		if (!drop) {
			env[n++] = strdup(environ[i]);
		}
	}
	asprintf(&env[n++], "LIMBO_SYSROOT=%s", sysroot);
	if (job->root) {
		env[n++] = strdup("HOME=/var/root");
		env[n++] = strdup("USER=root");
		env[n++] = strdup("LOGNAME=root");
	} else if (job->account != NULL) {
		asprintf(&env[n++], "HOME=%s", job->account_home);
		asprintf(&env[n++], "USER=%s", job->account);
		asprintf(&env[n++], "LOGNAME=%s", job->account);
	} else {
		asprintf(&env[n++], "HOME=%s", user_home);
		asprintf(&env[n++], "USER=%s", user_name);
		asprintf(&env[n++], "LOGNAME=%s", user_name);
	}
	if (job->environment != NULL) {
		asprintf(&env[n++], "LIMBO_LAUNCHD_ENVIRONMENT=%s",
				job->environment);
	}
	if (job->persona_type > 0) {
		uid_t domain_uid = strncmp(job->name, "system/", 7) != 0
				? (job->account != NULL ? job->account_uid
							: user_uid)
				: job->system_session ? (uid_t)-1
						      : user_uid;
		asprintf(&env[n++], "LIMBO_LAUNCHD_PERSONA_TYPE=%d:%u",
				job->persona_type, (unsigned)domain_uid);
	}

	for (size_t v = 0; v != job->variable_count; v++) {
		const char *variable = job->variables[v];
		size_t length = strcspn(variable, "=");
		for (size_t i = 0; i != n;) {
			if (strncmp(env[i], variable, length + 1) == 0) {
				free(env[i]);
				memmove(&env[i], &env[i + 1],
						(n - i) * sizeof(*env));
				n--;
			} else {
				i++;
			}
		}
		if (variable[length + 1] != '\0') {
			env[n++] = strdup(variable);
		}
	}
	env[n] = NULL;
	return env;
}

static void
stop(struct job *job)
{
	say("stopping %s, pid %d", job->name, (int)job->pid);
	job->stopping = true;
	job->kill_at = now_ms() + STOP_TIMEOUT_MS;
	kill(-job->pid, SIGTERM);
	kill(job->pid, SIGTERM);
}

static void
find_account(struct job *job)
{
	job->account_uid = (uid_t)-1;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/private/etc/passwd", sysroot);
	FILE *file = fopen(path, "re");
	for (struct passwd *pw; file != NULL && (pw = fgetpwent(file));) {
		if (strcmp(pw->pw_name, job->account) == 0) {
			job->account_uid = pw->pw_uid;
			job->account_gid = pw->pw_gid;
			job->account_home = strdup(pw->pw_dir);
			break;
		}
	}
	if (file != NULL) {
		fclose(file);
	}
}

static struct job *
parse_job(char *line)
{
	char *words[74];
	size_t count = 0;
	char *save = NULL;
	for (char *word = strtok_r(line, " \t", &save);
			word != NULL && count != 73;
			word = strtok_r(NULL, " \t", &save)) {
		words[count++] = word;
	}
	if (count < 11) {
		return NULL;
	}
	words[count] = NULL;
	char **fields = words;
	char **arguments = words + 10;
	size_t argc = count - 10;

	struct job *job = calloc(1, sizeof(*job));
	job->name = strdup(fields[0]);
	job->session = strncmp(fields[0], "boot/", 5) == 0 ? SESSION_BOOT_TASK
							   : SESSION_BOOT;
	job->root = strcmp(fields[1], "root") == 0;
	if (!job->root && strcmp(fields[1], "user") != 0) {
		job->account = strdup(fields[1]);
		find_account(job);
	}
	job->plist = optional(fields[2]);
	job->label = optional(fields[3]);

	job->run_at_load = strstr(fields[5], "runatload") != NULL;
	job->required = strstr(fields[5], "required") != NULL;
	job->system_session = strstr(fields[5], "systemsession") != NULL;
	const char *persona = strstr(fields[5], "persona=");
	job->persona_type = persona != NULL
			? (int)strtol(persona + strlen("persona="), NULL, 10)
			: 0;
	job->environment = optional(fields[6]);
	if (!parse_keepalive(fields[7], &job->keepalive)) {
		say("%s: KeepAlive %s, taken as false", job->name, fields[7]);
	}
	job->throttle = strcmp(fields[8], "-") == 0
			? DEFAULT_THROTTLE
			: (unsigned)strtoul(fields[8], NULL, 10);
	if (strcmp(fields[9], "-") != 0) {
		for (char *name = strtok_r(fields[9], ";", &save); name != NULL;
				name = strtok_r(NULL, ";", &save)) {
			job->services = reallocarray(job->services,
					job->service_count + 1, sizeof(char *));
			job->services[job->service_count++] = strdup(name);
		}
	}

	char program[PATH_MAX];
	size_t length = 0;
	for (const char *c = arguments[0];
			*c != '\0' && length + 1 < sizeof(program); c++) {
		if (strncmp(c, "%20", 3) == 0) {
			program[length++] = ' ';
			c += 2;
		} else {
			program[length++] = *c;
		}
	}
	program[length] = '\0';
	job->executable = find_executable(program);
	job->argv = calloc(argc + 1, sizeof(char *));
	job->argv[0] = program_argv0(job->executable, program);
	for (size_t i = 1; i != argc; i++) {
		job->argv[i] = strdup(arguments[i]);
	}
	job->log = log_path("", program_name(job->argv[0]), arguments + 1);
	return job;
}

static bool
parse_keepalive(const char *text, struct keepalive *keepalive)
{
	*keepalive = (struct keepalive){
			.successful_exit = -1,
			.crashed = -1,
	};
	if (strcmp(text, "-") == 0 || strcmp(text, "false") == 0) {
		return true;
	}
	if (strcmp(text, "true") == 0) {
		keepalive->always = true;
		return true;
	}
	char copy[256];
	snprintf(copy, sizeof(copy), "%s", text);
	bool known = true;
	char *save = NULL;
	for (char *condition = strtok_r(copy, ",", &save); condition != NULL;
			condition = strtok_r(NULL, ",", &save)) {
		char *value = strchr(condition, '=');
		if (value != NULL) {
			*value++ = '\0';
		}
		int wanted = value != NULL && strcmp(value, "true") == 0;
		if (strcmp(condition, "SuccessfulExit") == 0) {
			keepalive->successful_exit = wanted;
		} else if (strcmp(condition, "Crashed") == 0) {
			keepalive->crashed = wanted;
		} else if (strcmp(condition, "AfterInitialDemand") == 0) {
			keepalive->after_initial_demand = true;
		} else {
			known = false;
		}
	}
	return known;
}

static char *
find_executable(const char *program)
{
	char path[PATH_MAX];
	if (program[0] == '/') {
		return strdup(program);
	}
	if (strchr(program, '/') != NULL) {
		snprintf(path, sizeof(path), "%s/%s", sysroot, program);
		return strdup(path);
	}
	static const char *const folders[] = {
			"usr/libexec",
			"usr/sbin",
			"System/Library/CoreServices",
	};
	char *found = NULL;
	for (size_t i = 0; i != sizeof(folders) / sizeof(*folders); i++) {
		snprintf(path, sizeof(path), "%s/%s/%s", sysroot, folders[i],
				program);
		struct stat st;
		if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
			free(found);
			found = strdup(path);
		}
	}
	return found;
}

static const char *
program_name(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash != NULL ? slash + 1 : path;
}

static char *
program_argv0(const char *executable, const char *program)
{
	size_t length = strlen(sysroot);
	if (executable != NULL && strncmp(executable, sysroot, length) == 0
			&& executable[length] == '/') {
		return strdup(executable + length);
	}
	return strdup(program_name(program));
}

static char *
log_path(const char *prefix, const char *program, char **arguments)
{
	char name[300];
	size_t length = (size_t)snprintf(name, 32, "%s", prefix);
	for (const char *c = program; *c != '\0' && length < 200; c++) {
		name[length++] = (isalnum((unsigned char)*c) || *c == '.'
						 || *c == '_' || *c == '-')
				? *c
				: '_';
	}
	size_t taken = 0;
	for (size_t i = 0; arguments[i] != NULL && taken < 16; i++) {
		if (i != 0) {
			name[length++] = '_';
			taken++;
		}
		for (const char *c = arguments[i]; *c != '\0' && taken < 16;
				c++, taken++) {
			name[length++] = isalnum((unsigned char)*c) ? *c : '_';
		}
	}
	if (arguments[0] != NULL) {
		name[length++] = '_';
	}
	name[length] = '\0';
	char *path;
	asprintf(&path, "%s/%s.log", log_directory, name);
	return path;
}

static int
open_log(struct job *job)
{
	char old[PATH_MAX];
	snprintf(old, sizeof(old), "%s.old", job->log);
	rename(job->log, old);
	int log = open(job->log, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
			0644);
	if (log != -1 && geteuid() == 0) {
		(void)!fchown(log, user_uid, user_gid);
	}
	return log;
}

static bool
job_matches(const struct job *job, const char *word)
{
	return strcasecmp(job->name, word) == 0
			|| (job->label != NULL
					&& strcasecmp(job->label, word) == 0)
			|| strcasecmp(program_name(job->argv[0]), word) == 0;
}

static void
describe(FILE *out, const struct job *job, bool details)
{
	static const char *const states[] = {
			[JOB_UNLOADED] = "unloaded",
			[JOB_IDLE] = "idle",
			[JOB_WAITING] = "waiting",
			[JOB_RUNNING] = "running",
			[JOB_STOPPED] = "stopped",
	};
	static const char *const sessions[] = {
			[SESSION_BOOT] = "boot",
			[SESSION_BOOT_TASK] = "boot task",
	};
	char pid[16] = "-", status[16] = "-";
	if (job->state == JOB_RUNNING) {
		snprintf(pid, sizeof(pid), "%d", (int)job->pid);
	}
	if (job->has_status) {
		snprintf(status, sizeof(status), "%d",
				shell_status(job->status));
	}
	fprintf(out, "%s\t%s\t%s%s\t%s%s%s\n", pid, status, states[job->state],
			job->stopping ? ",stopping" : "", job->name,
			job->reason != NULL ? "\t" : "",
			job->reason != NULL ? job->reason : "");
	if (!details) {
		return;
	}
	const struct keepalive *k = &job->keepalive;
	fprintf(out,
			"\tprogram: %s\n\tlog: %s\n\tas: %s\n\tloads: %s\n"
			"\truns: %u\n",
			job->executable != NULL ? job->executable : "-",
			job->log,
			job->root ? "root"
					: job->account != NULL ? job->account
							       : user_name,
			sessions[job->session], job->runs);
	if (!job->root) {
		fprintf(out, "\tgroups:");
		for (size_t i = 0; i != user_group_count; i++) {
			fprintf(out, " %u", (unsigned)user_groups[i]);
		}
		fprintf(out, "\n");
	}
	fprintf(out, "\trun at load: %s\n", starts_at_load(job) ? "yes" : "no");
	fprintf(out, "\tkeepalive: %s", k->always ? "always" : "");
	if (k->successful_exit != -1) {
		fprintf(out, " SuccessfulExit=%s",
				k->successful_exit ? "true" : "false");
	}
	if (k->crashed != -1) {
		fprintf(out, " Crashed=%s", k->crashed ? "true" : "false");
	}
	if (k->after_initial_demand) {
		fprintf(out, " AfterInitialDemand");
	}
	fprintf(out, "\n\tthrottle: %u s\n", job->throttle);
	for (size_t i = 0; i != job->service_count; i++) {
		fprintf(out, "\tservice: %s\n", job->services[i]);
	}
	for (size_t i = 0; i != job->variable_count; i++) {
		fprintf(out, "\tvariable: %s\n", job->variables[i]);
	}
}

static int
shell_status(int status)
{
	if (WIFSIGNALED(status)) {
		return 128 + WTERMSIG(status);
	}
	return WEXITSTATUS(status);
}

static int64_t
now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static char *
optional(const char *text)
{
	return strcmp(text, "-") == 0 ? NULL : strdup(text);
}

static void
say(const char *format, ...)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);
	fprintf(stderr, "%02d:%02d:%02d " LIMBO_LAUNCHD ": ", tm.tm_hour,
			tm.tm_min, tm.tm_sec);
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fputc('\n', stderr);
}
