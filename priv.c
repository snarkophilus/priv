/*	$Id: priv.c,v 1.6 1996/03/29 06:54:23 simonb Exp $
 *
 *	priv	run a command as a given user
 *
 *	Loosely based on a command called priv by:
 *		Ron Kuris, Dec 1988.
 *		Dan Busarow, DPC Systems, 22/11/91.
 *
 *	Copyright (c) 1996, Telstra Limited.  All Right Reserved.
 *	Author: Simon Burge, <simonb@telstra.com.au>
 */

/*
 *	One design decision completely different from the original
 *	`priv' is to tell the user what is going wrong.  `priv' has
 *	been redesigned to be used in a production environment as a
 *	substitute for handing out the root password, so I guess it
 *	should be a little bit helpful (but no too much :-).
 */

#ifndef lint
static char rcsid[] = "$Id: priv.c,v 1.6 1996/03/29 06:54:23 simonb Exp $";
#endif /* not lint */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/param.h>

#define PRIVDIR		"/usr/local/etc/priv"	/* database directory */
#define SYSLOGNAME	"priv"			/* name used with syslog */
#define LOGBUFSIZ	120			/* number of characters to log */

#ifdef __svr4__	/* Solaris 2 */
# define index strchr
#endif

#ifdef ultrix
char *strdup();
#endif

static	int check_date __P((const char *));
static	char *build_log_message __P((const char *, char **));

main(argc, argv, envp)
int	argc;
char	**argv, **envp;
{
	struct	passwd *pw;
	FILE	*fp;
	char	userf[MAXPATHLEN];
	char	buffer[BUFSIZ];
	char	*myname, *prog, *newprog;
	char	*expire, *useras, *flags, *cmd;
	int	maxfd, log_malformed, bad_line, i, ok;


	/* Open syslog connection. */
#ifdef LOG_AUTH
	openlog(SYSLOGNAME, 0, LOG_AUTH);
#else
	openlog(SYSLOGNAME);
#endif

	/* Initialisation... */
	ok = log_malformed = 0;
	prog = argv[0];
	newprog = argv[1];
	maxfd = getdtablesize();
	for (i = 3; i < maxfd; i++)
		close(i);

	pw = getpwuid(getuid());
	myname = strdup(pw->pw_name);	/* copy so we can use getpw* later */
	snprintf(userf, MAXPATHLEN, "%s/%s", PRIVDIR, myname);

	/* Check command usage. */
	if (argc < 2)  {
		fprintf(stderr, "usage: %s command args\n", prog);
		syslog(LOG_INFO, "%s: not ok: incorrect usage", myname);
		exit(1);
	}

	/* Try and open the priv database for "myname". */
	if ((fp = fopen(userf, "r")) == NULL) {
		fprintf(stderr, "%s: no access.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: no database", myname);
		exit(1);
	}

	/*
	 * Scan through the file, looking for a blank command or
	 * a command that matches our command line.
	 */
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		buffer[strlen(buffer) - 1] = '\0';	/* zap newline */
		if (!*buffer || *buffer == '#')		/* skip comments */
			continue;
		bad_line = 0;

		expire = strtok(buffer, ":");
		useras = strtok(NULL, ":");
		flags = strtok(NULL, ":");
		cmd = strtok(NULL, ":");

		/*
		 * Check for a bad data line.  The expiry date and flags
		 * should be numeric.  The user name field is checked
		 * later on with getpwnam(), and who gives a damn about
		 * the command name...  If we have a bad line, log an
		 * error to syslog, but only once...
		 */
		if (strspn(expire, "0123456789") != strlen(expire))
			bad_line++;
		if (flags && strspn(flags, "0123456789") != strlen(flags))
			bad_line++;
		if (!useras)
			bad_line++;
		if (bad_line) {
			if (!log_malformed) {
				syslog(LOG_NOTICE,
				    "%s: malformed line in database", myname);
				log_malformed++;
			}
			continue;
		}

		/* If the command is null, we can do anything. */
		if (cmd == NULL || strcmp(cmd, newprog) == 0) {
			ok = 1;
			break;
		}
	}

	/* Check to see if the command was valid, and exit if not. */
	if (!ok) {
		fprintf(stderr, "%s: command not valid.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: command not valid: %s",
		    myname, newprog);
		exit(1);
		/* NOTREACHED */
	}

	/* Check expiry date */
	if (!check_date(expire)) {
		fprintf(stderr, "%s: command expired.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: command expired: %s",
		    myname, newprog);
		exit(1);
		/* NOTREACHED */
	}

	/* Does the user to run the command as exist? */
	if ((pw = getpwnam(useras)) == NULL) {
		fprintf(stderr, "%s: invalid user (%s) to run command as.\n",
		    prog, useras);
		syslog(LOG_NOTICE, "%s: not ok: user name %s not valid",
		    myname, useras);
	}

	/* Set up the permissions */
	if (setgid(pw->pw_gid) < 0) {
		fprintf(stderr, "%s: setgid failed.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: setgid failed: %m", myname);
		exit(1);
	}
	if (initgroups(pw->pw_name, pw->pw_gid) < 0) {
		fprintf(stderr, "%s: initgroups failed.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: initgroups failed: %m", myname);
		exit(1);
	}
	if (setuid(pw->pw_uid) < 0) {
		fprintf(stderr, "%s: setuid failed.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: setuid failed: %m", myname);
		exit(1);
	}

	/* All's well, execute the command. */
	syslog(LOG_INFO, build_log_message(myname, argv + 1));
	execvp(newprog, argv + 1);
	fprintf(stderr,"%s: can't execute %s\n", prog, newprog);
	syslog(LOG_NOTICE, "%s: not ok: could not execute: %s",
	    myname, newprog);
	exit(1);
	/* NOTREACHED */
}

static int
check_date(date)
	const	char *date;
{
	time_t	t;
	struct	tm *tm;
	char	buf[128];

	(void)time(&t);
	tm = localtime(&t);
	snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min);
	return(strcmp(date, buf) > 0);
}


static char *
build_log_message(myname, argv)
	const	char *myname;
	char	**argv;
{
	static	char log[LOGBUFSIZ];
	int	left;

	sprintf(log, "%s:", myname);
	left = LOGBUFSIZ - strlen(log) - 2;
	while (*argv) {
		strcat(log, " ");
		strncat(log, *argv, left);
		left -= strlen(*argv) + 1;
		argv++;
		if (left < 2)
			break;
	}
	return(log);
}
