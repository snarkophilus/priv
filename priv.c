/*	$Id: priv.c,v 1.20 1996/08/09 05:07:20 simonb Exp $
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
 *	should be a little bit helpful (but not too much :-).
 */

#ifndef lint
static char rcsid[] = "$Id: priv.c,v 1.20 1996/08/09 05:07:20 simonb Exp $";
#endif /* not lint */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <paths.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/stat.h>

#define PRIVDIR		"/usr/local/etc/priv"	/* database directory */
#define SYSLOGNAME	"priv"			/* name used with syslog */
#define LOGBUFSIZ	256			/* number of characters to log */
#define MYNAMELEN	20			/* room for user name (+ log name) */
#define EXIT_VAL	255			/* Error exit value */

/* Flags for the "flags" field.  These are spread out for now in the
 * hope of making configuration files not _too_ hard to read...
 */
#define F_SETUID	0000001		/* allow set-{g,u}id programs to run */
#define F_SYMLINK	0000002		/* allow symlink as command run */
#define F_BASENAME	0000004		/* only check basename of command */
#define F_LOGLS		0000010		/* do an 'ls' of the command run */
#define F_LOGCWD	0000020		/* log working directory */
#define F_LOGCMD	0000040		/* log full command name */
#define F_LOGTTY	0000100		/* log user's terminal */
#define F_SU		0100000		/* check su to an account */

#ifdef __svr4__
char *strsep();
#endif

#ifndef S_ISLNK
#define	S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#endif

static	int check_date __P((const char *));
static	char *build_log_message __P((const char *, char **, const char *, unsigned int));
static	char *which __P((const char *));

int
main(argc, argv, envp)
	int		argc;
	char		**argv, **envp;
{
	struct passwd	*pw;
	FILE		*fp;
	char		userf[MAXPATHLEN];
	char		buffer[BUFSIZ];
	char		myfullname[MYNAMELEN];
	char		*myname, *logname;
	char		*prog, *newprog, *realprog, *baseprog;
	char		*expire, *useras, *flags, *cmd;
	char		*tmp, *suuser;
	int		sudash;
	int		maxfd, log_malformed, bad_line, i, ok;
	unsigned int	nflags;


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
	baseprog = NULL;
	if (newprog != NULL && (baseprog = strrchr(newprog, '/')) != NULL)
		baseprog++;
	maxfd = getdtablesize();
	for (i = 3; i < maxfd; i++)
		close(i);

	/* Check if we're running as su-<user> or su<user> */
	suuser = NULL;
	sudash = 0;
	if ((tmp = strrchr(prog, '/')) != NULL)
		tmp++;
	else
		tmp = prog;
	if (strncmp(tmp, "su", 2) == 0) {
		tmp += 2;
		if (*tmp == '-') {
			tmp++;
			sudash++;
		}
		if (*tmp != '\0') {
			suuser = tmp;
		}
		else {
			fprintf(stderr, "priv: invalid su<user> setup\n");
			syslog(LOG_INFO, "priv: invalid su<user> setup");
			exit(EXIT_VAL);
		}
	}

	pw = getpwuid(getuid());
	myname = strdup(pw->pw_name);	/* copy so we can use getpw* later */
	strcpy(myfullname, pw->pw_name);
	if ((logname = getlogin()) != NULL && strcmp(logname, myname)) {
		strcat(myfullname, " (");
		strcat(myfullname, logname);
		strcat(myfullname, ")");
	}
	snprintf(userf, MAXPATHLEN, "%s/%s", PRIVDIR, myname);

	/* Check command usage. */
	if (suuser == NULL && argc < 2)  {
		fprintf(stderr, "usage: %s command args\n", prog);
		syslog(LOG_INFO, "%s: not ok: incorrect usage", myfullname);
		exit(EXIT_VAL);
	}
	if (   suuser != NULL
	    && ! ((argc == 3 && (strcmp(argv[1], "-c") == 0)) || argc == 1) ) {
		fprintf(stderr, "usage: %s [-c command]\n", prog);
		syslog(LOG_INFO, "%s: not ok: incorrect usage", myfullname);
		exit(EXIT_VAL);
	}

	/* Try and open the priv database for "myname". */
	if ((fp = fopen(userf, "r")) == NULL) {
		fprintf(stderr, "%s: no access.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: no database", myname);
		exit(EXIT_VAL);
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
		 * Check for a bad data line.  The expiry date should 
		 * be numeric and the flags octal.  The user name field
		 * is checked later on with getpwnam(), and who gives a
		 * damn about the command name...  If we have a bad
		 * line, log an error to syslog, but only once...
		 */
		if (strspn(expire, "0123456789") != strlen(expire))
			bad_line++;
		if (flags && strspn(flags, "01234567") != strlen(flags))
			bad_line++;
		/* Convert character flags to number */
		nflags = flags ? strtoul(flags, NULL, 8) : 0;
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

		/* If su-ing, check this first */
		if (suuser) {
			if (nflags & F_SU && strcmp(suuser, useras) == 0) {
				ok = 1;
				break;
			}
			/* Try again...  */
			continue;
		}

		/* If the command is null, we can do anything. */
		if (cmd == NULL) {
			ok = 1;
			break;
		}

		/* Check for a full match */
		if (strcmp(cmd, newprog) == 0) {
			ok = 1;
			break;
		}

		/* Check basename if necessary */
		if ((nflags & F_BASENAME) && baseprog &&
		    (strcmp(cmd, baseprog) == 0)) {
			ok = 1;
			break;
		}
	}

	/* Check to see if the command was valid, and exit if not. */
	if (!ok) {
		if (suuser) {
			fprintf(stderr, "%s: user not valid.\n", prog);
			syslog(LOG_NOTICE, "%s: not ok: su to %s",
			    myfullname, useras);
		}
		else {
			fprintf(stderr, "%s: command not valid.\n", prog);
			syslog(LOG_NOTICE, "%s: not ok: command not valid: %s",
			    myfullname, newprog);
		}
		exit(EXIT_VAL);
		/* NOTREACHED */
	}

	/* Check expiry date */
	if (!check_date(expire)) {
		fprintf(stderr, "%s: command expired.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: %s expired: %s",
		    myfullname, suuser ? "su" : "command",
		    suuser ? useras : newprog);
		exit(EXIT_VAL);
		/* NOTREACHED */
	}

	/* Does the user to run the command as exist? */
	if ((pw = getpwnam(useras)) == NULL) {
		fprintf(stderr, "%s: invalid user (%s) to run command as.\n",
		    prog, useras);
		syslog(LOG_NOTICE, "%s: not ok: user name %s not valid",
		    myfullname, useras);
	}

	/* If we're su-ing, now's the time */
	if (suuser != NULL) {
		char	*nargv[7];	/* for su,-,user,-c,cmd,(char *)0 */
		int	nargc;

		nargc = 0;
		nargv[nargc++] = "su";
		if (sudash)
			nargv[nargc++] = "-";
		nargv[nargc++] = suuser;
		if (argc == 3) {
			nargv[nargc++] = argv[1];
			nargv[nargc++] = argv[2];
		}
		nargv[nargc++] = (char *)0;

		setuid(0);	/* Set real & effective uid so "su" will work */
		syslog(LOG_INFO, "su from %s to %s\n", myname, suuser);
		execv("/bin/su", nargv);
		fprintf(stderr,"%s: couldn't run su\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: could not su", myfullname);
		exit(EXIT_VAL);
		/* NOTREACHED */
	}

	/* Set up the permissions */
	if (setgid(pw->pw_gid) < 0) {
		fprintf(stderr, "%s: setgid failed.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: setgid failed: %m", myfullname);
		exit(EXIT_VAL);
	}
	if (initgroups(pw->pw_name, pw->pw_gid) < 0) {
		fprintf(stderr, "%s: initgroups failed.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: initgroups failed: %m",
		    myfullname);
		exit(EXIT_VAL);
	}
	if (setuid(pw->pw_uid) < 0) {
		fprintf(stderr, "%s: setuid failed.\n", prog);
		syslog(LOG_NOTICE, "%s: not ok: setuid failed: %m", myfullname);
		exit(EXIT_VAL);
	}

	realprog = which(newprog);

	/* Check for sym-link */
	if (!(nflags & F_SYMLINK)) {
		struct stat	st;

		if (lstat(realprog, &st) < 0) {
			fprintf(stderr, "%s: internal error\n", prog);
			perror(prog);
			exit(EXIT_VAL);
		}
		if (S_ISLNK(st.st_mode)) {
			fprintf(stderr, "%s: command is sym-link\n", prog);
			syslog(LOG_NOTICE, "%s: not ok: command is symlink: %s",
			    myfullname, realprog);
			exit(EXIT_VAL);
		}
	}

	/* Check for set{u,g}id */
	if (!(nflags & F_SETUID)) {
		struct stat	st;

		if (stat(realprog, &st) < 0) {
			fprintf(stderr, "%s: internal error\n", prog);
			perror(prog);
			exit(EXIT_VAL);
		}
		if (st.st_mode & S_ISUID) {
			fprintf(stderr, "%s: command is setuid\n", prog);
			syslog(LOG_NOTICE, "%s: not ok: command is setuid: %s",
			    myfullname, realprog);
			exit(EXIT_VAL);
		}
		if (st.st_mode & S_ISGID) {
			fprintf(stderr, "%s: command is setgid\n", prog);
			syslog(LOG_NOTICE, "%s: not ok: command is setgid: %s",
			    myfullname, realprog);
			exit(EXIT_VAL);
		}
	}

	/* All's well so far, get ready to execute the command. */
	syslog(LOG_INFO, build_log_message(myfullname, argv + 1, realprog, nflags));
	execve(realprog, argv + 1, envp);
	fprintf(stderr,"%s: can't execute %s\n", prog, newprog);
	syslog(LOG_NOTICE, "%s: not ok: could not execute: %s",
	    myfullname, newprog);
	exit(EXIT_VAL);
	/* NOTREACHED */
}

static int
check_date(date)
	const char	*date;
{
	time_t		t;
	struct tm	*tm;
	char		buf[128];

	(void)time(&t);
	tm = localtime(&t);
	snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min);
	return(strcmp(date, buf) > 0);
}


static char *
build_log_message(myname, argv, prog, flags)
	const char	*myname;
	char		**argv;
	const char	*prog;
	unsigned int	flags;
{
	static char	log[LOGBUFSIZ];
	int		left;

	sprintf(log, "%s", myname);
	if (flags & F_LOGTTY) {
		char	*tty;

		tty = ttyname(0);	/* XXX: stdin filedes */
		if (!tty)
			tty = "NOTTY";
		if (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
		snprintf(log + strlen(log), LOGBUFSIZ - strlen(log) - 2,
		    " (%s)", tty);
	}
	if (flags & F_LOGCWD) {
		char	*pwd;

		pwd = getcwd(NULL, LOGBUFSIZ - strlen(log) - 2);
		snprintf(log + strlen(log), LOGBUFSIZ - strlen(log) - 2,
		    " (pwd=%s)", pwd);
		free(pwd);
	}
	if (flags & F_LOGLS) {
		struct stat	st;

		if (stat(prog, &st) < 0) {
			fprintf(stderr, "%s: internal error\n", prog);
			perror(prog);
			exit(EXIT_VAL);
		}
		snprintf(log + strlen(log), LOGBUFSIZ - strlen(log) - 2,
		    " (ls=%4o:%d:%d:%d:%s)", st.st_mode % 010000,
		    st.st_uid, st.st_gid, st.st_size, prog);
	}
	if (flags & F_LOGCMD) {
		snprintf(log + strlen(log), LOGBUFSIZ - strlen(log) - 2,
		    " (cmd=%s)", prog);
	}
	strcat(log, ":");
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


/* Below code hacked from exec.c (execvp) from NetBSD (April '96) */

static char *
which(name)
	const char	*name;
{
	char		*cur, *p, *path;
	static char	buf[MAXPATHLEN];

	/* If it's an absolute or relative path name, it's too easy. */
	if (strchr(name, '/'))
		return((char *)name);

	/* Get the path we're searching. */
	if (!(path = getenv("PATH")))
		path = _PATH_DEFPATH;
	cur = path = strdup(path);

	while ((p = strsep(&cur, ":")) != NULL) {
		/*
		 * It's a SHELL path -- double, leading and trailing colons
		 * mean the current directory.
		 */
		sprintf(buf, "%s/%s", *p ? p : ".", name);

		if (access(buf, X_OK) == 0) {
			if (path)
				free(path);
			return(buf);
		}
	}
	if (path)
		free(path);
	return (NULL);
}
