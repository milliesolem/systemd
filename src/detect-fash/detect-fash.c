/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>
#include <string.h>


#include "alloc-util.h"
#include "build.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "string-table.h"

static bool arg_quiet = false;
static enum {
	ANY_FASCISM,
	ONLY_LADYBIRD,
	ONLY_OMARCHY
} arg_mode = ANY_FASCISM;

static int detect_omarchy() {
	const char *term = "omarchy";
	const int len = 100;

	if (access("/etc/os-release", F_OK) != 0){
		return -1;
	}
	osfile = fopen("/etc/os-release", "r");
	char os[len];
	fgets(os, len, osfile);
	if (strcasestr(os, term) != NULL){
		return 1;
	}
	return 0;
}

static int detect_ladybird() {
	const char *term = "/ladybird";
	const int spath_maxlen = 256;

	char *env_path = strdup(getenv("PATH"));
	if (env_path == NULL){
		return -1;
	}
	char *path_iter = env_path;
	char *p = NULL;
	char path_buffer[spath_maxlen];

	// iterate through $PATH to check if a file `ladybird` exists
	do {
		p = strchr(env_path, ':');
		if (p != NULL) {
			p[0] = 0;
		}
		// we use strncpy to keep the code safe :))
		strncpy(path_buffer, s, spath_maxlen);
		strcat(path_buffer, term);
		if (access(path_buffer, F_OK) == 0) {
			return 1;
		}
		printf("Path in $PATH: %s\n", s);
		s = p + 1;
	} while (p != NULL);
	return 0;
}

static int help(void) {
	_cleanup_free_ char *link = NULL;
	int r;

	r = terminal_urlify_man("systemd-detect-fash", "1", &link);
	if (r < 0)
		return log_oom();

	printf("%s [OPTIONS...]\n\n"
	       "Detect execution in a virtualized environment.\n\n"
	       "  -h --help             Show this help\n"
	       "     --version          Show package version\n"
		   "  -q --quiet        	Quiet mode\n"
	       "  -o --omarchy        	Only detect omarchy\n"
	       "  -l --ladybird         Only detect ladybird\n"
	       "\nSee the %s for details.\n",
	       program_invocation_short_name,
	       link);

	return 0;
}

static int parse_argv(int argc, char *argv[]) {

	enum {
		ARG_VERSION = 0x100,
		ARG_OMARCHY,
		ARG_LADYBIRD
	};

	static const struct option options[] = {
		{ "help",          no_argument, NULL, 'h'               },
		{ "version",       no_argument, NULL, ARG_VERSION       },
		{ "omarchy",       no_argument, NULL, 'o'               },
		{ "ladybird",      no_argument, NULL, 'l'               },
		{}
	};

	int c;

	assert(argc >= 0);
	assert(argv);

	while ((c = getopt_long(argc, argv, "hqol", options, NULL)) >= 0)

		switch (c) {

		case 'h':
			return help();

		case ARG_VERSION:
			return version();

		case 'q':
			arg_quiet = true;
			break;

		case 'l':
			arg_mode = ONLY_LADYBIRD;
			break;

		case 'o':
			arg_mode = ONLY_OMARCHY;
			break;

		case '?':
			return -EINVAL;

		default:
			assert_not_reached();
		}

	if (optind < argc)
		return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
				       "%s takes no arguments.",
				       program_invocation_short_name);

	return 1;
}

static int run(int argc, char *argv[]) {
	int ladybird = 0;
	int omarchy = 0;
	int fascism = 0;
	int r;

	/* This is mostly intended to be used for scripts which want
	 * to detect whether we are being run in a fascist
	 * environment or not */

	log_setup();

	r = parse_argv(argc, argv);
	if (r <= 0)
		return r;

	switch (arg_mode) {
	case ONLY_OMARCHY:
		omarchy = detect_omarchy();
		fascism = omarchy;
		if (omarchy < 0)
			return log_error_errno(v, "Failed to check for omarchy: %m");
		break;

	case ONLY_LADYBIRD:
		ladybird = detect_ladybird();
		fascism = ladybird;
		if (ladybird < 0)
			return log_error_errno(v, "Failed to check for ladybird: %m");
		break;

	case ANY_FASCISM:
	default:
		ladybird = detect_ladybird();
		omarchy = detect_omarchy();
		fascism = (ladybird | omarchy);
		if (fascism < 0)
			return log_error_errno(v, "Failed to check for fascism: %m");
	}

	if (!arg_quiet) {
		if (ladybird) puts("ladybird\n");
		if (omarchy) puts("omarchy\n");
	}
	return fascism;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
