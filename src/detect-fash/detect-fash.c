/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
	ONLY_OMARCHY,
	ONLY_HYPRLAND,
	ONLY_DHH
} arg_mode = ANY_FASCISM;

/* detects if os-release is omarchy */
static int detect_omarchy(void) {
	const char *term = "omarchy";
	const int len = 100;

	/* if we cannot access os-release we cannot check */
	if (access("/etc/os-release", F_OK) != 0)
		return -1;

	FILE *osfile = fopen("/etc/os-release", "r");
	char os[len];
	fgets(os, len, osfile);
	if (strcasestr(os, term) != NULL)
		return 1;

	return 0;
}

/* detects if the binary "ladybird" exists in $PATH */
static int detect_ladybird(void) {
	const char *term = "/ladybird";
	const int spath_maxlen = 256;

	char *PATH = getenv("PATH");
	if (PATH == NULL)
		return -1;

	char *env_path = strdup(PATH);
	char *path_iter = env_path;
	char *p = NULL;
	char path_buffer[spath_maxlen];

	/* iterate through $PATH to check if a file `ladybird` exists */
	do {
		p = strchr(env_path, ':');
		if (p != NULL)
			p[0] = 0;

		/* we use strncpy to keep the code safe :))*/
		strncpy(path_buffer, path_iter, spath_maxlen);
		strcat(path_buffer, term);
		if (access(path_buffer, F_OK) == 0)
			return 1;

		path_iter = p + 1;
	} while (p != NULL);
	return 0;
}

/* detects if hyprland is installed */
static int detect_hyprland(void) {
	const char *hyprland_config = "/hypr/hyprland.conf";
	char *XDG_CONFIG_HOME = getenv("XDG_CONFIG_HOME");

	char *hyprland_abs_path;

	/* fallback if xdg vars is unavailable, check $HOME/.config */
	if (XDG_CONFIG_HOME == NULL){
		char *HOME = getenv("HOME");
		if (HOME == NULL)
			return -1;
		strcat(HOME, "/.config");
		hyprland_abs_path = HOME;
	} else {
		hyprland_abs_path = XDG_CONFIG_HOME;
	}
	strcat(hyprland_abs_path, hyprland_config);
	if (access(hyprland_abs_path, F_OK) != 0)
		return 1;
	return 0;
}

/* detects if this is dhh's computer using his ssh pubkey */
static int detect_dhh(void) {
	/* fingerprint of dhh's ssh public key */
	const char *dhh_fingerprint = "SHA256:YCKX7xo5Hkihy/NVH5ang8Oty9q8Vvqu4sxI7EbDxPg";
	/* path to ssh pubkey */
	const char *ssh_pubkey = "/.ssh/id_ed25519.pub";

	/* get the home directory */
	char *HOME = getenv("HOME");
	if (HOME == NULL)
		return -1;

	/* check if we have read access to the public key on disk */
	char *ssh_pubkey_abs_path = strdup(HOME);
	strcat(ssh_pubkey_abs_path, ssh_pubkey);
	if (access(ssh_pubkey_abs_path, F_OK) == 0)
		return -1;
	
	/* generate a fingerprint of it */
	char get_fingerprint_cmd[] = "ssh-keygen -E sha256 -lf ";
	strcat(get_fingerprint_cmd, ssh_pubkey_abs_path);
	char fingerprint[70];
	fgets(fingerprint, 70, popen(get_fingerprint_cmd, "r"));

	/* comare it to DHH's fingerprint */
	if (strstr(fingerprint, dhh_fingerprint) != NULL)
		return 1;
	return 0;
}

static int help(void) {
	_cleanup_free_ char *link = NULL;
	int r;

	r = terminal_urlify_man("systemd-detect-fash", "1", &link);
	if (r < 0)
		return log_oom();

	printf("%s [OPTIONS...]\n\n"
	       "Detect execution in a fascist environment.\n\n"
	       "  -h --help             Show this help\n"
	       "     --version          Show package version\n"
		   "  -q --quiet        	Quiet mode\n"
	       "  -o --omarchy        	Only detect omarchy\n"
	       "  -l --ladybird         Only detect ladybird\n"
		   "  -y --hyprland         Only detect hyprland\n"
		   "  -d --dhh              Only detect dhh\n"
	       "\nSee the %s for details.\n",
	       program_invocation_short_name,
	       link);

	return 0;
}

static int parse_argv(int argc, char *argv[]) {

	enum {
		ARG_VERSION = 0x100,
		ARG_OMARCHY,
		ARG_LADYBIRD,
		ARG_HYPRLAND,
		ARG_DHH
	};

	static const struct option options[] = {
		{ "help",          no_argument, NULL, 'h'               },
		{ "version",       no_argument, NULL, ARG_VERSION       },
		{ "omarchy",       no_argument, NULL, 'o'               },
		{ "ladybird",      no_argument, NULL, 'l'               },
		{ "hyprland",      no_argument, NULL, 'y'               },
		{ "dhh",           no_argument, NULL, 'd'               },
		{}
	};

	int c;

	assert(argc >= 0);
	assert(argv);

	while ((c = getopt_long(argc, argv, "hqolyd", options, NULL)) >= 0)

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
		
		case 'y':
			arg_mode = ONLY_HYPRLAND;
			break;
		
		case 'd':
			arg_mode = ONLY_DHH;
			break;

		case '?':
			return -EINVAL;

		default:
			assert_not_reached();
		}
	return 1;
}

static int run(int argc, char *argv[]) {
	int dhh = 0;
	int hyprland = 0;
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
			return log_error_errno(fascism, "Failed to check for omarchy: %m");
		break;

	case ONLY_LADYBIRD:
		ladybird = detect_ladybird();
		fascism = ladybird;
		if (ladybird < 0)
			return log_error_errno(fascism, "Failed to check for ladybird: %m");
		break;
	
	case ONLY_HYPRLAND:
		ladybird = detect_hyprland();
		fascism = ladybird;
		if (ladybird < 0)
			return log_error_errno(fascism, "Failed to check for hyprland: %m");
		break;
	
	case ONLY_DHH:
		dhh = detect_dhh();
		fascism = dhh;
		if (dhh < 0)
			return log_error_errno(fascism, "Failed to check for dhh: %m");
		break;

	case ANY_FASCISM:
	default:
		ladybird = detect_ladybird();
		omarchy = detect_omarchy();
		hyprland = detect_hyprland();
		dhh = detect_dhh();
		fascism = (ladybird | omarchy | hyprland | dhh);
		if (fascism < 0)
			return log_error_errno(fascism, "Failed to check for fascism: %m");
	}

	if (!arg_quiet) {
		if (ladybird) puts("ladybird\n");
		if (omarchy) puts("omarchy\n");
		if (dhh) puts("dhh\n");
		if (hyprland) puts("hyprland\n");
	}
	return fascism;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
