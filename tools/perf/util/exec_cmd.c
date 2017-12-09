#include "cache.h"
#include "exec_cmd.h"
#include "quote.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ARGS	32
#define MAX_BUFF_SIZE 1024
#define MAX_CMD_SIZE 50

static const char *argv_exec_path;
static const char *argv0_path;

const char *system_path(const char *path)
{
	static const char *prefix = PREFIX;
	struct strbuf d = STRBUF_INIT;

	if (is_absolute_path(path))
		return path;

	strbuf_addf(&d, "%s/%s", prefix, path);
	path = strbuf_detach(&d, NULL);
	return path;
}

const char *perf_extract_argv0_path(const char *argv0)
{
	const char *slash;

	if (!argv0 || !*argv0)
		return NULL;
	slash = argv0 + strlen(argv0);

	while (argv0 <= slash && !is_dir_sep(*slash))
		slash--;

	if (slash >= argv0) {
		argv0_path = strndup(argv0, slash - argv0);
		return argv0_path ? slash + 1 : NULL;
	}

	return argv0;
}

void perf_set_argv_exec_path(const char *exec_path)
{
	argv_exec_path = exec_path;
	/*
	 * Propagate this setting to external programs.
	 */
	setenv(EXEC_PATH_ENVIRONMENT, exec_path, 1);
}


/* Returns the highest-priority, location to look for perf programs. */
const char *perf_exec_path(void)
{
	const char *env;

	if (argv_exec_path)
		return argv_exec_path;

	env = getenv(EXEC_PATH_ENVIRONMENT);
	if (env && *env) {
		return env;
	}

	return system_path(PERF_EXEC_PATH);
}

static void add_path(struct strbuf *out, const char *path)
{
	if (path && *path) {
		if (is_absolute_path(path))
			strbuf_addstr(out, path);
		else
			strbuf_addstr(out, make_nonrelative_path(path));

		strbuf_addch(out, PATH_SEP);
	}
}

void setup_path(void)
{
	const char *old_path = getenv("PATH");
	struct strbuf new_path = STRBUF_INIT;

	add_path(&new_path, perf_exec_path());
	add_path(&new_path, argv0_path);

	if (old_path)
		strbuf_addstr(&new_path, old_path);
	else
		strbuf_addstr(&new_path, "/usr/local/bin:/usr/bin:/bin");

	setenv("PATH", new_path.buf, 1);

	strbuf_release(&new_path);
}

static const char **prepare_perf_cmd(const char **argv)
{
	int argc;
	const char **nargv;

	for (argc = 0; argv[argc]; argc++)
		; /* just counting */
	nargv = malloc(sizeof(*nargv) * (argc + 2));

	nargv[0] = "perf";
	for (argc = 0; argv[argc]; argc++)
		nargv[argc + 1] = argv[argc];
	nargv[argc + 1] = NULL;
	return nargv;
}

int execv_perf_cmd(const char **argv) {
	const char **nargv = prepare_perf_cmd(argv);

	/* execvp() can only ever return if it fails */
	execvp("perf", (char **)nargv);

	free(nargv);
	return -1;
}


int execl_perf_cmd(const char *cmd,...)
{
	int argc;
	const char *argv[MAX_ARGS + 1];
	const char *arg;
	va_list param;

	va_start(param, cmd);
	argv[0] = cmd;
	argc = 1;
	while (argc < MAX_ARGS) {
		arg = argv[argc++] = va_arg(param, char *);
		if (!arg)
			break;
	}
	va_end(param);
	if (MAX_ARGS <= argc)
		return error("too many args to run %s", cmd);

	argv[argc] = NULL;
	return execv_perf_cmd(argv);
}

int is_file_exist(const char *path) {
	if(!path)
		return 0;
	if(access(path, F_OK) == 0)
		return 1;
	return 0;
}

char* find_guest_machine_kallsyms_path(int pid) {
	FILE *fstream = NULL;
	char buff[MAX_BUFF_SIZE], *str_pid, *path = NULL, *path_end = NULL;
	str_pid = calloc(MAX_CMD_SIZE, sizeof(char));
	if (!str_pid)
		return path;
	sprintf(str_pid, "ps aux | grep \"libvirt+  %d\"", pid);
	memset(buff, 0, MAX_BUFF_SIZE);
	fstream = popen(str_pid, "r");
	if(!fstream)
		return path;
	while(fgets(buff, MAX_BUFF_SIZE, fstream)) {
		if ((path = strstr(buff, "file=")) && (path_end = strstr(path, ","))) {
			path+=5;
			*path_end = '\0';
			path_end = strrchr(path, '/');
			*(++path_end) = '\0';
			strcat(path, "kallsyms");
			if(!is_file_exist(path)) {
				path = NULL;
				continue;
			}
			break;
		}
	}
	pclose(fstream);
	free(str_pid);
	return path;
}

int get_guest_machine_kallsyms(void) {
/*
	int err;
	if(!is_file_exist("/dev/nbd0")) {
		err = system("modprobe nbd max_part=8");
		if(!err) {
			printf("cmd failed: modprobe nbd max_part=8\n");
			return err;
		}
	}
*/
	return 0;
}













