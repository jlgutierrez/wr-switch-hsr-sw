/* A replacement for TRACE with only run-time conditionals */
#define _GNU_SOURCE /* asprintf */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>

#include <libwr/wrs-msg.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

int wrs_msg_level = WRS_MSG_DEFAULT_LEVEL;

/* We use debug, info, warning, error and "silent" */
static int wrs_msg_used_levels[] = {
	LOG_ALERT, /* more silent then ERR, but "1" not 0 */
	LOG_ERR,
	LOG_WARNING,
	LOG_INFO,
	LOG_DEBUG,
};
static int wrs_msg_pos;

void wrs_msg_sighandler(int sig)
{
	if (sig == SIGUSR1 && wrs_msg_pos < ARRAY_SIZE(wrs_msg_used_levels) - 1)
		wrs_msg_pos++;
	if (sig == SIGUSR2 && wrs_msg_pos > 0)
		wrs_msg_pos--;
	wrs_msg_level = wrs_msg_used_levels[wrs_msg_pos];
	wrs_msg(LOG_INFO, "pos: %i, level %i\n", wrs_msg_pos, wrs_msg_level);
}


static FILE *wrs_msg_f = (FILE *)-1; /* Means "not yet set" */
static char *prgname; /* always print argv[0], or we get lost */

/* This function is optional, up to the user whether to call it or not */
void wrs_msg_init(int argc, char **argv)
{
	int i;
	int max = ARRAY_SIZE(wrs_msg_used_levels) - 1;
	char *e;

	prgname = argv[0];
	wrs_msg_f = stderr;

	e = getenv("WRS_MSG_LEVEL");
	if (e) {
		i = atoi(e);
		if (i) /* not 0 (EMERG) as atoi returns 0 on error */
			wrs_msg_level = i;
	}

	/* Start at this level, then scan for individual "-v" or "-q" */
	for (wrs_msg_pos = 0; wrs_msg_pos < max; wrs_msg_pos++)
		if (wrs_msg_used_levels[wrs_msg_pos] >= wrs_msg_level)
			break;
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-q") && wrs_msg_pos > 0)
			wrs_msg_pos--;
		if (!strcmp(argv[i], "-v") && wrs_msg_pos < max)
			wrs_msg_pos++;
	}

	wrs_msg_level = wrs_msg_used_levels[wrs_msg_pos];

	/* Prepare for run-time changes */
	signal(SIGUSR1, wrs_msg_sighandler);
	signal(SIGUSR2, wrs_msg_sighandler);
}

void wrs_msg_file(FILE *target)
{
	wrs_msg_f = target;
}

void wrs_msg_filename(char *name)
{
	FILE *f = fopen(name, "a");

	if (f)
		wrs_msg_f = f;
}

void __wrs_msg(int level, const char *func, int line, const char *fmt, ...)
{
	va_list args;
	static char *header_string[] = {
		[LOG_ALERT] = "",
		[LOG_ERR] = "Error: ",
		[LOG_WARNING] = "Warning: ",
		[LOG_INFO] = "",
		[LOG_DEBUG] = ""
	};

	/* If the user didn't set the file, nor init, enforce default now */
	if (wrs_msg_f == (FILE *)-1)
		wrs_msg_f = stderr;

	if (level > wrs_msg_level)
		return;

	/* Same for the name: a pid is better than nothing */
	if (!prgname)
		asprintf(&prgname, "<pid-%i>", getpid());

	/* Program name and header, and possibly function and line too */
	fprintf(wrs_msg_f, "%s: %s", prgname, header_string[level]);
	if (level >= WRS_MSG_DETAILS_AT)
		fprintf(wrs_msg_f, "%s:%i: ", func, line);

	/* The actual message */
	va_start(args, fmt);
	vfprintf(wrs_msg_f, fmt, args);
	va_end(args);
	fflush(wrs_msg_f);
}


