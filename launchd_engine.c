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
#include <dirent.h>
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
#define SHUTDOWN_POLL_MS   100

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
	SESSION_GUI,
	SESSION_LOGIN_WINDOW,
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
	bool in_account_domain;
	enum job_session session;
	bool run_at_load;
	bool unheld;
	bool names_held;
	bool untold;
	bool for_root;
	bool multiple;
	bool required;
	bool system_session;
	int persona_type;
	char *instance;
	struct keepalive keepalive;
	unsigned throttle;
	char **services;
	bool *services_hidden;
	size_t service_count;
	char *executable;
	char **argv;
	char *log;
	char **variables;
	size_t variable_count;

	enum job_state state;
	pid_t pid;
	bool exit_pending;
	int exit_status;
	int64_t exit_at;
	int64_t started;
	int64_t start_at;
	int64_t kill_at;
	bool stopping;
	bool restart;
	bool unloading;
	bool reload;
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
static void tell_changes(void);
static void forget_name(const char *name);
static void load(struct job *job);
static void load_session(enum job_session session);
static bool load_into(struct job *job);
static void load_start(struct job *job);
static void next_boot_task(void);
static void hold_names(struct job *job);
static bool starts_at_load(const struct job *job);
static void at_login_window(FILE *out);
static void log_in(FILE *out);
static void unload(enum job_session session);
static void log_out(FILE *out);
static void add_session_process(FILE *out, pid_t pid);
static void end_session_processes(void);
static void kill_session_processes(int64_t now);
static unsigned long long process_start_time(pid_t pid);
static bool left_processes_gone(void);
static size_t signal_left_processes(int signo);
static bool descends_from(const pid_t (*parents)[2], size_t count, pid_t pid,
		pid_t ancestor);
static bool process_running(pid_t pid);
static void process_exited(struct job *job, int status);
static void take_exit(struct job *job);
static void job_exited(struct job *job, int status);
static bool crashed(int status);
static char *exit_reason(const char *log);
static int open_log(struct job *job);
static bool kept_alive(const struct job *job, int status);
static bool awaited(const struct job *job);
static void demand(struct job *job, const char *why);
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
static uint32_t job_domain_of(const struct job *job);
static const struct job *account_job_with(const char *name);
static struct job *account_instance(const struct job *template, uid_t uid);
static uint32_t *name_awaited(const char *name);
struct awaited_name {
	char *name;
	uint32_t waiters;
};
static struct awaited_name *awaited_names;
static size_t awaited_count;
static void describe(FILE *out, const struct job *job, bool details);
static int shell_status(int status);
static int64_t now_ms(void);
static char *optional(const char *text);
static void say(const char *format, ...);

static struct job **jobs;
static size_t job_count;
static struct job **account_jobs;
static size_t account_job_count;
static int signal_fd = -1;
static pid_t broker;
static bool shutting_down;
static bool booted;
static int64_t left_kill_at;
static bool logged_in;
static bool login_window;
struct session_process {
	pid_t pid;
	unsigned long long start_time;
	int64_t kill_at;
};
static struct session_process *session_processes;
static size_t session_process_count;
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
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGHUP);
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
		job->untold = true;
		if (strncmp(job->name, "account/", 8) == 0) {
			account_jobs = reallocarray(account_jobs,
					account_job_count + 1,
					sizeof(*account_jobs));
			account_jobs[account_job_count++] = job;
		} else {
			jobs = reallocarray(jobs, job_count + 1, sizeof(*jobs));
			jobs[job_count++] = job;
		}
	}
	free(line);
	fclose(file);

	next_boot_task();
	tell_changes();
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
	for (size_t i = 0; i != account_job_count; i++) {
		hold_names(account_jobs[i]);
	}
	for (size_t i = 0; i != job_count; i++) {
		hold_names(jobs[i]);
	}
	load_session(SESSION_BOOT);
}

static void
hold_names(struct job *job)
{
	if (!job->unheld && !job->names_held) {
		job->names_held = true;
		job->untold = true;
	}
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
	bool loaded = job->state != JOB_UNLOADED;
	bool may_run = loaded && job->state != JOB_STOPPED;
	job->state = state;
	if (loaded != (state != JOB_UNLOADED)
			|| may_run
					!= (state != JOB_UNLOADED
							&& state != JOB_STOPPED)) {
		job->untold = true;
	}
}

static void
load(struct job *job)
{
	if (load_into(job)) {
		load_start(job);
	}
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
		if (job->state == JOB_UNLOADED || session == SESSION_BOOT) {
			job->unloading = false;
			if (load_into(job)) {
				loaded[count++] = job;
			}
		} else if (job->unloading && session == SESSION_GUI) {
			job->reload = true;
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
	} else if (awaited(job)) {
		demand(job, "a guest that waited for it");
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

static void
at_login_window(FILE *out)
{
	if (logged_in || login_window) {
		fprintf(out, "%s\n",
				logged_in ? "someone is logged in"
					  : "at the login window already");
		return;
	}
	say("the login window's session loads");
	login_window = true;
	load_session(SESSION_LOGIN_WINDOW);
	fprintf(out, "at the login window\n");
}

static void
log_in(FILE *out)
{
	if (logged_in) {
		fprintf(out, "%s is logged in already\n", user_name);
		return;
	}
	if (login_window) {
		say("the login window's session unloads");
		login_window = false;
		unload(SESSION_LOGIN_WINDOW);
	}
	say("%s logs in", user_name);
	logged_in = true;
	load_session(SESSION_GUI);
	fprintf(out, "%s logged in\n", user_name);
}

static void
log_out(FILE *out)
{
	if (!logged_in) {
		if (out != NULL) {
			fprintf(out, "no one is logged in\n");
		}
		return;
	}
	say("%s logs out", user_name);
	logged_in = false;
	unload(SESSION_GUI);
	end_session_processes();
	if (out != NULL) {
		fprintf(out, "%s logged out\n", user_name);
	}
}

static void
unload(enum job_session session)
{
	for (size_t i = 0; i != job_count; i++) {
		struct job *job = jobs[i];
		if (job->session != session) {
			continue;
		}
		job->restart = false;
		job->demanded = false;
		if (job->state == JOB_RUNNING) {
			job->unloading = true;
			if (!job->stopping) {
				stop(job);
			}
		} else {
			set_state(job, JOB_UNLOADED);
		}
	}
}

static void
add_session_process(FILE *out, pid_t pid)
{
	unsigned long long start_time = process_start_time(pid);
	if (pid <= 0 || start_time == 0) {
		fprintf(out, "no process %d\n", (int)pid);
		return;
	}
	size_t kept = 0;
	for (size_t i = 0; i != session_process_count; i++) {
		struct session_process *process = &session_processes[i];
		if (process->pid != pid
				&& process_start_time(process->pid)
						== process->start_time) {
			session_processes[kept++] = *process;
		}
	}
	session_process_count = kept;
	struct session_process *grown = realloc(session_processes,
			(kept + 1) * sizeof(*session_processes));
	if (grown == NULL) {
		return;
	}
	session_processes = grown;
	session_processes[session_process_count++] = (struct session_process){
			.pid = pid,
			.start_time = start_time,
			.kill_at = INT64_MAX,
	};
}

static void
end_session_processes(void)
{
	int64_t kill_at = now_ms() + STOP_TIMEOUT_MS;
	size_t kept = 0;
	for (size_t i = 0; i != session_process_count; i++) {
		struct session_process *process = &session_processes[i];
		if (process_start_time(process->pid) != process->start_time) {
			continue;
		}
		say("stopping the session's process %d", (int)process->pid);
		kill(-process->pid, SIGTERM);
		kill(process->pid, SIGTERM);
		process->kill_at = kill_at;
		session_processes[kept++] = *process;
	}
	session_process_count = kept;
}

static void
kill_session_processes(int64_t now)
{
	size_t kept = 0;
	for (size_t i = 0; i != session_process_count; i++) {
		struct session_process *process = &session_processes[i];
		if (process->kill_at > now) {
			session_processes[kept++] = *process;
			continue;
		}
		if (process_start_time(process->pid) == process->start_time) {
			say("the session's process %d didn't stop: killed",
					(int)process->pid);
			kill(-process->pid, SIGKILL);
			kill(process->pid, SIGKILL);
		}
	}
	session_process_count = kept;
}

static unsigned long long
process_start_time(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		return 0;
	}
	char line[1024];
	size_t length = fread(line, 1, sizeof(line) - 1, file);
	fclose(file);
	line[length] = '\0';
	char *field = strrchr(line, ')');
	if (field == NULL) {
		return 0;
	}
	if (field[1] != ' ') {
		return 0;
	}
	char state = field[2];
	long threads = 0;
	for (int n = 3; n <= 22 && field != NULL; n++) {
		field = strchr(field + 1, ' ');
		if (n == 20 && field != NULL) {
			threads = strtol(field + 1, NULL, 10);
		}
	}
	if (state == 'Z' && threads <= 1) {
		return 0;
	}
	return field != NULL ? strtoull(field + 1, NULL, 10) : 0;
}

static bool
left_processes_gone(void)
{
	int64_t now = now_ms();
	if (left_kill_at == 0) {
		left_kill_at = now + STOP_TIMEOUT_MS;
		return signal_left_processes(SIGTERM) == 0;
	}
	if (now < left_kill_at) {
		return signal_left_processes(0) == 0;
	}
	signal_left_processes(SIGKILL);
	return true;
}

static size_t
signal_left_processes(int signo)
{
	DIR *proc = opendir("/proc");
	if (proc == NULL) {
		return 0;
	}
	pid_t(*parents)[2] = NULL;
	size_t count = 0;
	size_t capacity = 0;
	struct dirent *entry;
	while ((entry = readdir(proc)) != NULL) {
		char *end;
		long pid = strtol(entry->d_name, &end, 10);
		if (*end != '\0' || pid <= 0) {
			continue;
		}
		char path[64];
		snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
		FILE *file = fopen(path, "r");
		if (file == NULL) {
			continue;
		}
		char line[1024];
		size_t length = fread(line, 1, sizeof(line) - 1, file);
		fclose(file);
		line[length] = '\0';
		char *field = strrchr(line, ')');
		int parent;
		if (field == NULL
				|| sscanf(field + 1, " %*c %d", &parent) != 1) {
			continue;
		}
		if (count == capacity) {
			capacity = capacity != 0 ? capacity * 2 : 512;
			pid_t(*grown)[2] = reallocarray(
					parents, capacity, sizeof(*parents));
			if (grown == NULL) {
				break;
			}
			parents = grown;
		}
		parents[count][0] = (pid_t)pid;
		parents[count][1] = (pid_t)parent;
		count++;
	}
	closedir(proc);

	pid_t root = getppid() == broker ? broker : getpid();
	size_t signalled = 0;
	for (size_t i = 0; i != count; i++) {
		pid_t pid = parents[i][0];
		if (pid == getpid() || !descends_from(parents, count, pid, root)
				|| !process_running(pid)) {
			continue;
		}
		if (signo != 0) {
			char path[64], name[64] = "";
			snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
			FILE *file = fopen(path, "r");
			if (file != NULL) {
				if (fgets(name, sizeof(name), file) != NULL) {
					name[strcspn(name, "\n")] = '\0';
				}
				fclose(file);
			}
			say(signo == SIGKILL ? "%s, pid %d, which the jobs "
					       "left, "
					       "didn't stop: killed"
					     : "stopping %s, pid %d, which the "
					       "jobs left",
					name, (int)pid);
			kill(pid, signo);
		}
		signalled++;
	}
	free(parents);
	return signalled;
}

static bool
descends_from(const pid_t (*parents)[2], size_t count, pid_t pid,
		pid_t ancestor)
{
	for (size_t depth = 0; depth != count && pid > 1; depth++) {
		pid_t parent = 0;
		for (size_t i = 0; i != count; i++) {
			if (parents[i][0] == pid) {
				parent = parents[i][1];
				break;
			}
		}
		if (parent == ancestor) {
			return true;
		}
		pid = parent;
	}
	return false;
}

static bool
process_running(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
	DIR *tasks = opendir(path);
	if (tasks == NULL) {
		return false;
	}
	bool running = false;
	struct dirent *entry;
	while (!running && (entry = readdir(tasks)) != NULL) {
		if (entry->d_name[0] == '.') {
			continue;
		}
		char stat_path[PATH_MAX];
		snprintf(stat_path, sizeof(stat_path), "%s/%s/stat", path,
				entry->d_name);
		FILE *file = fopen(stat_path, "r");
		if (file == NULL) {
			continue;
		}
		char line[1024];
		size_t length = fread(line, 1, sizeof(line) - 1, file);
		fclose(file);
		line[length] = '\0';
		char *field = strrchr(line, ')');
		running = field != NULL && field[1] == ' ' && field[2] != 'Z'
				&& field[2] != 'X';
	}
	closedir(tasks);
	return running;
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
		} else if (job->state == JOB_RUNNING && job->exit_pending
				&& job->exit_at <= now) {
			if (job->stopping) {
				say("%s stops: its exit is taken", job->name);
			} else {
				say("%s: the broker has not said in %d ms that "
				    "it read what pid %d sent: its exit "
				    "is taken as things are",
						job->name, STOP_TIMEOUT_MS,
						(int)job->pid);
			}
			take_exit(job);
		} else if (job->state == JOB_RUNNING && job->stopping
				&& !job->exit_pending && job->kill_at <= now) {
			say("%s, pid %d, didn't stop: killed", job->name,
					(int)job->pid);
			kill(-job->pid, SIGKILL);
			kill(job->pid, SIGKILL);
			job->kill_at = INT64_MAX;
		}
	}
	kill_session_processes(now);
	tell_changes();
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
				&& !job->exit_pending && job->kill_at < next) {
			next = job->kill_at;
		}
		if (job->state == JOB_RUNNING && job->exit_pending
				&& job->exit_at < next) {
			next = job->exit_at;
		}
	}
	for (size_t i = 0; i != session_process_count; i++) {
		if (session_processes[i].kill_at < next) {
			next = session_processes[i].kill_at;
		}
	}
	int64_t now = now_ms();
	if (shutting_down && (session_process_count != 0 || left_kill_at != 0)
			&& next > now + SHUTDOWN_POLL_MS) {
		next = now + SHUTDOWN_POLL_MS;
	}
	int64_t wait = next == INT64_MAX ? -1 : next - now;
	if (wait < 0 && next != INT64_MAX) {
		wait = 0;
	}
	return wait > INT32_MAX ? INT32_MAX : (int)wait;
}

static bool
jobs_demand(const char *name, uint32_t domain)
{
	struct job *other = NULL;
	bool own = false;
	for (size_t i = 0; i != job_count; i++) {
		struct job *job = jobs[i];
		for (size_t j = 0; j != job->service_count; j++) {
			if (strcmp(job->services[j], name) != 0
					|| job->state == JOB_STOPPED
					|| job->state == JOB_UNLOADED) {
				continue;
			}
			uint32_t job_domain = job_domain_of(job);
			if (job_domain == domain) {
				demand(job, name);
				own = true;
			} else if (other == NULL) {
				other = job;
			}
		}
	}
	const struct job *template = account_job_with(name);
	if (!own && broker_domain_is_account(domain) && template != NULL) {
		struct job *instance = account_instance(
				template, domain & ~BROKER_DOMAIN_ACCOUNT);
		if (instance != NULL) {
			demand(instance, name);
			return true;
		}
	}
	if (!own && other != NULL) {
		demand(other, name);
	}
	return own;
}

static const struct job *
account_job_with(const char *name)
{
	for (size_t i = 0; i != account_job_count; i++) {
		const struct job *job = account_jobs[i];
		for (size_t j = 0; !job->unheld && j != job->service_count;
				j++) {
			if (strcmp(job->services[j], name) == 0) {
				return job;
			}
		}
	}
	return NULL;
}

static struct job *account_job(const struct job *template, uid_t uid);

static struct job *
account_instance(const struct job *template, uid_t uid)
{
	struct job *job = account_job(template, uid);
	if (job != NULL) {
		jobs = reallocarray(jobs, job_count + 1, sizeof(*jobs));
		jobs[job_count++] = job;
		load(job);
	}
	return job;
}

static struct job *
account_job(const struct job *template, uid_t uid)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/private/etc/passwd", sysroot);
	FILE *file = fopen(path, "re");
	struct passwd *found = NULL;
	for (struct passwd *pw; file != NULL && (pw = fgetpwent(file));) {
		if (pw->pw_uid == uid) {
			found = pw;
			break;
		}
	}
	if (found == NULL) {
		if (file != NULL) {
			fclose(file);
		}
		say("%s: no account for uid %u", template->name, (unsigned)uid);
		return NULL;
	}
	struct job *job = calloc(1, sizeof(*job));
	asprintf(&job->name, "user/%u/%s", (unsigned)uid,
			template->name + strlen("account/"));
	job->account = strdup(found->pw_name);
	job->account_uid = found->pw_uid;
	job->account_gid = found->pw_gid;
	job->account_home = strdup(found->pw_dir);
	fclose(file);
	job->in_account_domain = true;
	job->session = SESSION_BOOT;
	job->label = template->label != NULL ? strdup(template->label) : NULL;
	job->plist = template->plist != NULL ? strdup(template->plist) : NULL;
	job->environment = template->environment != NULL
			? strdup(template->environment)
			: NULL;
	job->keepalive = template->keepalive;
	job->throttle = template->throttle;
	job->service_count = template->service_count;
	job->services = calloc(job->service_count, sizeof(char *));
	job->services_hidden = calloc(job->service_count, sizeof(bool));
	for (size_t i = 0; i != job->service_count; i++) {
		job->services[i] = strdup(template->services[i]);
		job->services_hidden[i] = template->services_hidden[i];
	}
	job->executable = template->executable != NULL
			? strdup(template->executable)
			: NULL;
	size_t argc = 0;
	while (template->argv[argc] != NULL) {
		argc++;
	}
	job->argv = calloc(argc + 1, sizeof(char *));
	for (size_t i = 0; i != argc; i++) {
		job->argv[i] = strdup(template->argv[i]);
	}
	char prefix[80];
	snprintf(prefix, sizeof(prefix), "%s-", job->account);
	job->log = log_path(prefix, program_name(job->argv[0]), job->argv + 1);
	job->multiple = template->multiple;
	job->persona_type = template->persona_type;
	return job;
}

static struct job *
copy_job(const struct job *template)
{
	struct job *job = calloc(1, sizeof(*job));
	job->name = strdup(template->name);
	job->root = template->root;
	if (template->account != NULL) {
		job->account = strdup(template->account);
		job->account_home = template->account_home != NULL
				? strdup(template->account_home)
				: NULL;
	}
	job->account_uid = template->account_uid;
	job->account_gid = template->account_gid;
	job->session = template->session;
	job->label = template->label != NULL ? strdup(template->label) : NULL;
	job->plist = template->plist != NULL ? strdup(template->plist) : NULL;
	job->environment = template->environment != NULL
			? strdup(template->environment)
			: NULL;
	job->throttle = template->throttle;
	job->executable = template->executable != NULL
			? strdup(template->executable)
			: NULL;
	size_t argc = 0;
	while (template->argv[argc] != NULL) {
		argc++;
	}
	job->argv = calloc(argc + 1, sizeof(char *));
	for (size_t i = 0; i != argc; i++) {
		job->argv[i] = strdup(template->argv[i]);
	}
	job->log = template->log != NULL ? strdup(template->log) : NULL;
	job->persona_type = template->persona_type;
	return job;
}

static bool
jobs_make_instance(const char *name, uint32_t domain)
{
	const char *mark = strrchr(name, '#');
	if (mark == NULL || mark == name || strlen(mark + 1) != 36) {
		return false;
	}
	for (size_t i = 0; i != job_count; i++) {
		for (size_t j = 0; j != jobs[i]->service_count; j++) {
			if (strcmp(jobs[i]->services[j], name) == 0) {
				return true;
			}
		}
	}
	char base[LIMBO_BROKER_SERVICE_NAME_MAX];
	snprintf(base, sizeof(base), "%.*s", (int)(mark - name), name);
	struct job *job = NULL;
	if (broker_domain_is_account(domain)) {
		const struct job *template = account_job_with(base);
		if (template != NULL && template->multiple) {
			job = account_job(template,
					domain & ~BROKER_DOMAIN_ACCOUNT);
		}
	} else {
		const struct job *template = NULL;
		for (size_t pass = 0; pass != 2 && template == NULL; pass++)
			for (size_t i = 0; i != job_count && template == NULL;
					i++) {
				if (!jobs[i]->multiple
						|| jobs[i]->instance != NULL
						|| jobs[i]->in_account_domain
						|| (pass == 0)
								!= (job_domain_of(jobs[i])
										== domain)) {
					continue;
				}
				for (size_t j = 0; j != jobs[i]->service_count;
						j++) {
					if (strcmp(jobs[i]->services[j], base)
							== 0) {
						template = jobs[i];
						break;
					}
				}
			}
		if (template != NULL) {
			job = copy_job(template);
		}
	}
	if (job == NULL) {
		return false;
	}
	char *named;
	asprintf(&named, "%s#%.8s", job->name, mark + 1);
	free(job->name);
	job->name = named;
	job->instance = strdup(mark + 1);
	for (size_t i = 0; i != job->service_count; i++) {
		free(job->services[i]);
	}
	free(job->services);
	free(job->services_hidden);
	job->service_count = 1;
	job->services = calloc(1, sizeof(char *));
	job->services_hidden = calloc(1, sizeof(bool));
	job->services[0] = strdup(name);
	job->keepalive = (struct keepalive){
			.successful_exit = -1,
			.crashed = -1,
	};
	jobs = reallocarray(jobs, job_count + 1, sizeof(*jobs));
	jobs[job_count++] = job;
	hold_names(job);
	load(job);
	return true;
}

static char *control(char **argv, size_t argc, uint32_t *status);

char *
jobs_control(char **argv, size_t argc, uint32_t *status)
{
	char *text = control(argv, argc, status);
	tell_changes();
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
	if (strcmp(command, "waiting") == 0) {
		for (size_t i = 0; i != awaited_count; i++) {
			if (awaited_names[i].waiters != 0) {
				fprintf(out, "%u\t%s\n",
						awaited_names[i].waiters,
						awaited_names[i].name);
			}
		}
		fclose(out);
		return text;
	}
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
	if (strcmp(command, "session") == 0 && argc > 1) {
		add_session_process(out, (pid_t)strtol(argv[1], NULL, 10));
		fclose(out);
		return text;
	}
	if (strcmp(command, "login") == 0 || strcmp(command, "logout") == 0
			|| strcmp(command, "loginwindow") == 0) {
		if (shutting_down) {
			fprintf(out, "the broker is stopping\n");
			*status = 1;
		} else if (strcmp(command, "loginwindow") == 0) {
			at_login_window(out);
		} else if (strcmp(command, "login") == 0) {
			log_in(out);
		} else {
			log_out(out);
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
	for (size_t i = 0; i != session_process_count; i++) {
		const struct session_process *process = &session_processes[i];
		if (process_start_time(process->pid) == process->start_time) {
			return false;
		}
	}
	if (!left_processes_gone()) {
		return false;
	}
	return true;
}

static bool rebooting;

void
jobs_shut_down(bool reboot)
{
	if (shutting_down) {
		return;
	}
	say(reboot ? "stopping every job, to boot again"
		   : "stopping every job");
	shutting_down = true;
	rebooting = reboot;
	broker_jobs_stopping();
	for (size_t i = 0; i != job_count; i++) {
		if (jobs[i]->state == JOB_RUNNING) {
			stop(jobs[i]);
		}
	}
	end_session_processes();
	tell_changes();
}

bool
jobs_rebooting(void)
{
	return rebooting;
}

static void
handle_signals(void)
{
	struct signalfd_siginfo info;
	bool reap = false;
	while (read(signal_fd, &info, sizeof(info)) == sizeof(info)) {
		if (info.ssi_signo == SIGCHLD) {
			reap = true;
		} else {
			jobs_shut_down(false);
		}
	}
	if (!reap) {
		return;
	}
	int status;
	pid_t pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		for (size_t i = 0; i != job_count; i++) {
			if (jobs[i]->state == JOB_RUNNING && jobs[i]->pid == pid
					&& !jobs[i]->exit_pending) {
				process_exited(jobs[i], status);
			}
		}
	}
}

static bool broker_gone;

static void
process_exited(struct job *job, int status)
{
	if (broker_gone) {
		job_exited(job, status);
		return;
	}
	job->exit_pending = true;
	job->exit_status = status;
	job->exit_at = now_ms() + STOP_TIMEOUT_MS;
	broker_process_exited(job->pid);
}

static void
take_exit(struct job *job)
{
	job->exit_pending = false;
	job_exited(job, job->exit_status);
}

void
jobs_process_exited(pid_t pid)
{
	for (size_t i = 0; i != job_count; i++) {
		struct job *job = jobs[i];
		if (job->state == JOB_RUNNING && job->exit_pending
				&& job->pid == pid) {
			take_exit(job);
		}
	}
	tell_changes();
}

void
jobs_broker_gone(void)
{
	broker_gone = true;
	for (size_t i = 0; i != job_count; i++) {
		if (jobs[i]->exit_pending) {
			take_exit(jobs[i]);
		}
	}
	jobs_shut_down(false);
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
	if (group > 0 && (shutting_down || job->unloading)) {
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

	if (!shutting_down && job->session == SESSION_BOOT && job->label != NULL
			&& strcmp(job->label, "com.apple.loginwindow") == 0) {
		log_out(NULL);
	}

	if (shutting_down) {
		set_state(job, JOB_STOPPED);
	} else if (job->unloading) {
		job->unloading = false;
		set_state(job, JOB_UNLOADED);
		if (job->reload) {
			job->reload = false;
			load(job);
		}
	} else if (job->restart) {
		job->restart = false;
		set_state(job, JOB_IDLE);
		job->demanded = true;
		start(job);
	} else if (job->state == JOB_STOPPED || stopped) {
		set_state(job, JOB_STOPPED);
	} else if (kept_alive(job, status) || awaited(job)) {
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

static bool
awaited(const struct job *job)
{
	for (size_t i = 0; i != job->service_count; i++) {
		const uint32_t *waiters = name_awaited(job->services[i]);
		if (waiters != NULL && *waiters != 0) {
			return true;
		}
	}
	return false;
}

static void
demand(struct job *job, const char *why)
{
	if (job->state != JOB_IDLE || shutting_down) {
		return;
	}
	say("%s demanded by %s", job->name, why);
	job->demanded = true;
	schedule(job);
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
	tell_changes();
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
			LIMBO_LAUNCHD_SESSION_TYPE_ENV,
			BROKER_DOMAIN_VARIABLE,
			BROKER_INSTANCE_VARIABLE,
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
	if (job->in_account_domain || job->account != NULL) {
		asprintf(&env[n++], BROKER_DOMAIN_VARIABLE "=%#x",
				job_domain_of(job));
	}
	if (job->instance != NULL) {
		asprintf(&env[n++], BROKER_INSTANCE_VARIABLE "=%s",
				job->instance);
	}
	if (job->session == SESSION_LOGIN_WINDOW) {
		env[n++] = strdup(
				LIMBO_LAUNCHD_SESSION_TYPE_ENV "=LoginWindow");
	}
	if (job->system_session) {
		env[n++] = strdup(LIMBO_LAUNCHD_SESSION_TYPE_ENV "=System");
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
	if (job->exit_pending) {
		job->exit_at = 0;
		return;
	}
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
	job->session = strncmp(fields[0], "gui/", 4) == 0 ? SESSION_GUI
			: strncmp(fields[0], "loginwindow/", 12) == 0
			? SESSION_LOGIN_WINDOW
			: strncmp(fields[0], "boot/", 5) == 0
			? SESSION_BOOT_TASK
			: SESSION_BOOT;
	job->root = strcmp(fields[1], "root") == 0;
	if (!job->root && strcmp(fields[1], "user") != 0) {
		job->account = strdup(fields[1]);
		find_account(job);
	}
	job->plist = optional(fields[2]);
	job->label = optional(fields[3]);

	job->run_at_load = strstr(fields[5], "runatload") != NULL;
	job->unheld = strstr(fields[5], "unheld") != NULL;
	job->for_root = strstr(fields[5], "forroot") != NULL;
	job->multiple = strstr(fields[5], "multiple") != NULL;
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
			size_t length = strlen(name);
			bool hidden = length > 1 && name[length - 1] == '!';
			if (hidden) {
				name[length - 1] = '\0';
			}
			job->services = reallocarray(job->services,
					job->service_count + 1, sizeof(char *));
			job->services_hidden = reallocarray(
					job->services_hidden,
					job->service_count + 1, sizeof(bool));
			job->services_hidden[job->service_count] = hidden;
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
	job->log = log_path(job->session == SESSION_LOGIN_WINDOW
					? "loginwindow-"
					: "",
			program_name(job->argv[0]), arguments + 1);
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

static uint32_t
job_domain_of(const struct job *job)
{
	if (job->in_account_domain) {
		return broker_domain_account(job->account_uid);
	}
	return (job->root || job->account != NULL) ? BROKER_DOMAIN_SYSTEM
						   : BROKER_DOMAIN_USER;
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
			[SESSION_GUI] = "gui",
			[SESSION_LOGIN_WINDOW] = "loginwindow",
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

static uint32_t *
name_awaited(const char *name)
{
	for (size_t i = 0; i != awaited_count; i++) {
		if (strcmp(awaited_names[i].name, name) == 0) {
			return &awaited_names[i].waiters;
		}
	}
	return NULL;
}

void
jobs_name_awaited(const char *name, uint32_t domain, uint32_t flags,
		uint32_t waiters)
{
	uint32_t *known = name_awaited(name);
	if (known != NULL) {
		*known = waiters;
	} else if (waiters != 0) {
		struct awaited_name *grown = reallocarray(awaited_names,
				awaited_count + 1, sizeof(*awaited_names));
		char *copy = strdup(name);
		if (grown != NULL) {
			awaited_names = grown;
		}
		if (grown != NULL && copy != NULL) {
			awaited_names[awaited_count++]
					= (struct awaited_name){copy, waiters};
		} else {
			free(copy);
		}
	}
	if ((flags & BROKER_NAME_INSTANCE)
			&& !jobs_make_instance(name, domain)) {
		forget_name(name);
	}
	if ((flags & BROKER_NAME_DEMANDED) && !jobs_demand(name, domain)
			&& waiters != 0) {
		broker_no_job(name, domain);
	}
	tell_changes();
}

static struct broker_name **told_names;
static size_t told_count;

static size_t
told_at(const char *name)
{
	size_t low = 0, high = told_count;
	while (low != high) {
		size_t middle = low + (high - low) / 2;
		if (strcmp(told_names[middle]->name, name) < 0) {
			low = middle + 1;
		} else {
			high = middle;
		}
	}
	return low;
}

static size_t
record_size(const struct broker_name *record)
{
	return sizeof(*record) + record->domain_count * sizeof(uint32_t);
}

static void
tell_record(struct broker_name *record)
{
	size_t at = told_at(record->name);
	bool known = at != told_count
			&& strcmp(told_names[at]->name, record->name) == 0;
	if (known ? record_size(told_names[at]) == record_size(record)
							&& memcmp(told_names[at],
									   record,
									   record_size(record))
									== 0
		  : record->flags == 0 && record->domain_count == 0) {
		free(record);
		return;
	}
	if (known) {
		free(told_names[at]);
	} else {
		told_names = reallocarray(told_names, told_count + 1,
				sizeof(*told_names));
		memmove(&told_names[at + 1], &told_names[at],
				(told_count++ - at) * sizeof(*told_names));
	}
	told_names[at] = record;
	broker_name(record);
}

static void
tell_name(const char *name)
{
	static uint32_t *domains;
	static size_t domain_room;
	if (domain_room < job_count) {
		uint32_t *grown = reallocarray(
				domains, job_count, sizeof(*domains));
		if (grown == NULL) {
			return;
		}
		domains = grown;
		domain_room = job_count;
	}
	uint32_t domain_count = 0, flags = 0;
	bool held = false, hides = false;
	const struct job *template = account_job_with(name);
	if (template != NULL) {
		flags |= BROKER_NAME_ACCOUNTS;
		if (template->multiple) {
			flags |= BROKER_NAME_INSTANCES;
		}
		for (size_t j = 0; j != template->service_count; j++) {
			if (template->names_held && !held
					&& strcmp(template->services[j], name)
							== 0) {
				held = true;
				hides = template->services_hidden[j];
			}
		}
	}
	bool found = false, loaded = false, system = false;
	for (size_t i = 0; i != job_count; i++) {
		const struct job *job = jobs[i];
		for (size_t j = 0; j != job->service_count; j++) {
			if (strcmp(job->services[j], name) != 0) {
				continue;
			}
			found = true;
			if (job->names_held && !held) {
				held = true;
				hides = job->services_hidden[j];
			}
			if (job->multiple && job->instance == NULL
					&& !job->in_account_domain) {
				flags |= BROKER_NAME_INSTANCES;
			}
			if (job->state == JOB_UNLOADED) {
				continue;
			}
			loaded = true;
			if (job->state == JOB_STOPPED) {
				continue;
			}
			uint32_t domain = job_domain_of(job);
			system = system || domain == BROKER_DOMAIN_SYSTEM;
			bool listed = false;
			for (uint32_t d = 0; d != domain_count; d++) {
				listed = listed || domains[d] == domain;
			}
			if (!listed) {
				domains[domain_count++] = domain;
			}
		}
	}
	if (held) {
		flags |= BROKER_NAME_HELD | (hides ? BROKER_NAME_HIDES : 0);
	}
	if (found && !loaded) {
		flags |= BROKER_NAME_UNLOADED;
	}
	if (template != NULL && template->for_root && !system) {
		flags |= BROKER_NAME_ROOT_ACCOUNT;
	}
	struct broker_name *record = calloc(
			1, sizeof(*record) + domain_count * sizeof(uint32_t));
	if (record == NULL) {
		return;
	}
	strncpy(record->name, name, sizeof(record->name) - 1);
	record->flags = flags;
	record->domain_count = domain_count;
	if (domain_count != 0) {
		memcpy(record->domains, domains,
				domain_count * sizeof(uint32_t));
	}
	tell_record(record);
}

static void
forget_name(const char *name)
{
	struct broker_name *record = calloc(1, sizeof(*record));
	strncpy(record->name, name, sizeof(record->name) - 1);
	size_t at = told_at(name);
	if (at == told_count || strcmp(told_names[at]->name, name) != 0) {
		broker_name(record);
		free(record);
		return;
	}
	tell_record(record);
}

static void
tell_changes(void)
{
	for (size_t i = 0; i != account_job_count + job_count; i++) {
		struct job *job = i < account_job_count
				? account_jobs[i]
				: jobs[i - account_job_count];
		if (!job->untold) {
			continue;
		}
		job->untold = false;
		for (size_t j = 0; j != job->service_count; j++) {
			tell_name(job->services[j]);
		}
	}
}
