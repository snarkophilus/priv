/*	$Id: priv.c,v 1.27 1997/02/04 06:41:44 lukem Exp $
 *
 *	priv	run a command as a given user
 *
 *	Loosely based on a command called priv by:
 *		Ron Kuris, Dec 1988.
 *		Dan Busarow, DPC Systems, 22/11/91.
 */

/*
 * Copyright (c) 1996 Telstra Corporation Limited. All rights reserved.
 * Author: Simon Burge <simonb@telstra.com.au>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Simon Burge, Telstra Corp.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 */

/*
 *	One design decision completely different from the original
 *	`priv' is to tell the user what is going wrong.  `priv' has
 *	been redesigned to be used in a production environment as a
 *	substitute for handing out the root password, so I guess it
 *	should be a little bit helpful (but not too much :-).
 */

#ifndef lint
static char rcsid[] = "$Id: priv.c,v 1.27 1997/02/04 06:41:44 lukem Exp $";
#endif /* not lint */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifndef PRIVDIR
#define PRIVDIR		"/usr/local/etc/priv"	/* database directory */
#endif

#define DEFPATH		"/usr/bin:/bin"
#define SYSLOGNAME	"priv"			/* name used with syslog */
#define LOGBUFSIZ	2048 + 256		/* number of chars to log */
#define MYNAMELEN	20			/* room for username+logname */
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
#define F_BINPATH	0000200		/* allow any in given path */
#define F_GIVEREASON	0000400		/* ask for reason for running priv */
#define F_SU		0100000		/* check su to an account */

#ifndef S_ISLNK
#define	S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#endif

#ifndef __P
#ifdef __STDC__
#define __P(x)	x
#else
#define __P(x)	()
#endif
#endif

int	 check_date __P((const char *));
char	*build_log_message __P((const char *, char **, const char *,
				unsigned int));
void	 getreason __P((const char *, const char *));
void	 splitpath __P((const char *, char **, char **));
char	*which __P((const char *));
char	*strsep __P((char **, const char *));
char	*xstrdup __P((const char *));


char	*progname;


/*
 * main --
 *	main entry point
 */
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
	char		*newprog, *newprogdir, *newprogbase;
	char		*realprog, *realprogdir, *realprogbase;
	char		*expire, *useras, *flags, *cmd;
	char		*tmp, *suuser;
	int		sudash;
	int		maxfd, log_malformed, bad_line, i, ok;
	unsigned int	nflags;


	/* Open syslog connection. */
#ifdef LOG_AUTH
	openlog(SYSLOGNAME, LOG_PID, LOG_AUTH);
#else
	openlog(SYSLOGNAME);
#endif

	/* Initialisation... */
	ok = log_malformed = 0;
	newprog = argv[1];
	if (newprog != NULL) {
		splitpath(newprog, &newprogdir, &newprogbase);
		realprog = which(newprog);
		splitpath(realprog, &realprogdir, &realprogbase);
	}

	maxfd = getdtablesize();
	for (i = 3; i < maxfd; i++)
		close(i);

	/* Check if we're running as su-<user> or su<user> */
	suuser = NULL;
	sudash = 0;
	splitpath(argv[0], &tmp, &progname);
	free(tmp);
	tmp = progname;
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
	myname = xstrdup(pw->pw_name);	/* copy so we can use getpw* later */
	strcpy(myfullname, pw->pw_name);
	if ((logname = getlogin()) != NULL && strcmp(logname, myname)) {
		strcat(myfullname, " (");
		strcat(myfullname, logname);
		strcat(myfullname, ")");
	}
	if (strlen(PRIVDIR) + strlen(myname) >= sizeof(userf)) {
		fprintf(stderr, "%s: database filename too long for user %s",
		    progname, myname);
		syslog(LOG_INFO, "%s: database filename too long", myname);
		exit(EXIT_VAL);
	}
	sprintf(userf, "%s/%s", PRIVDIR, myname);

	/* Check command usage. */
	if (suuser == NULL && argc < 2)  {
		fprintf(stderr, "usage: %s command args\n", progname);
		syslog(LOG_INFO, "%s: not ok: incorrect usage", myfullname);
		exit(EXIT_VAL);
	}
	if (   suuser != NULL
	    && ! ((argc == 3 && (strcmp(argv[1], "-c") == 0)) || argc == 1) ) {
		fprintf(stderr, "usage: %s [-c command]\n", progname);
		syslog(LOG_INFO, "%s: not ok: incorrect usage", myfullname);
		exit(EXIT_VAL);
	}

	/* Try and open the priv database for "myname". */
	if ((fp = fopen(userf, "r")) == NULL) {
		fprintf(stderr, "%s: no access.\n", progname);
		syslog(LOG_NOTICE, "%s: not ok: no database", myname);
		exit(EXIT_VAL);
	}

	expire = NULL;
	useras = NULL;
	nflags = 0;
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

		/* Skip F_SU lines otherwise (i.e, not su-ing) */
		if (nflags & F_SU)
			continue;

		/* If the command is null, we can do anything. */
		if (cmd == NULL) {
			ok = 1;
			break;
		}

		/* Check for a full match */
		if ((strcmp(cmd, newprog) == 0) && !(nflags & F_BINPATH)) {
			ok = 1;
			break;
		}

		/* Check for any command in a given path */
		if (nflags & F_BINPATH) {
			if (strcmp(cmd, (nflags & F_BASENAME) ?
			    realprogdir : newprogdir) == 0) {
				ok = 1;
				break;
			}
		}

		/* Check basename if necessary */
		if ((nflags & F_BASENAME) && (strcmp(cmd, newprogbase) == 0)) {
			ok = 1;
			break;
		}
	}

	/* Check to see if the command was valid, and exit if not. */
	if (!ok) {
		if (suuser) {
			fprintf(stderr, "%s: user not valid.\n", progname);
			syslog(LOG_NOTICE, "%s: not ok: su to %s",
			    myfullname, useras);
		}
		else {
			fprintf(stderr, "%s: command not valid.\n", progname);
			syslog(LOG_NOTICE, "%s: not ok: command not valid: %s",
			    myfullname, newprog);
		}
		exit(EXIT_VAL);
		/* NOTREACHED */
	}

	/* Check expiry date */
	if (!check_date(expire)) {
		fprintf(stderr, "%s: command expired.\n", progname);
		syslog(LOG_NOTICE, "%s: not ok: %s expired: %s",
		    myfullname, suuser ? "su" : "command",
		    suuser ? useras : newprog);
		exit(EXIT_VAL);
		/* NOTREACHED */
	}

	/* Does the user to run the command as exist? */
	if ((pw = getpwnam(useras)) == NULL) {
		fprintf(stderr, "%s: invalid user (%s) to run command as.\n",
		    progname, useras);
		syslog(LOG_NOTICE, "%s: not ok: user name %s not valid",
		    myfullname, useras);
	}

	/* If necessary, ask for a reason for running priv */
	if ((nflags & F_GIVEREASON))
		getreason(myfullname, suuser ? progname : newprogbase);

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
		fprintf(stderr,"%s: couldn't run su\n", progname);
		syslog(LOG_NOTICE, "%s: not ok: could not su", myfullname);
		exit(EXIT_VAL);
		/* NOTREACHED */
	}

	/* Set up the permissions */
	if (setgid(pw->pw_gid) < 0) {
		fprintf(stderr, "%s: setgid failed.\n", progname);
		syslog(LOG_NOTICE, "%s: not ok: setgid failed: %m", myfullname);
		exit(EXIT_VAL);
	}
	if (initgroups(pw->pw_name, pw->pw_gid) < 0) {
		fprintf(stderr, "%s: initgroups failed.\n", progname);
		syslog(LOG_NOTICE, "%s: not ok: initgroups failed: %m",
		    myfullname);
		exit(EXIT_VAL);
	}
	if (setuid(pw->pw_uid) < 0) {
		fprintf(stderr, "%s: setuid failed.\n", progname);
		syslog(LOG_NOTICE, "%s: not ok: setuid failed: %m", myfullname);
		exit(EXIT_VAL);
	}

	/* Check for sym-link */
	if (!(nflags & F_SYMLINK)) {
		struct stat	st;

		if (lstat(realprog, &st) < 0) {
			fprintf(stderr, "%s: internal error\n", progname);
			perror(progname);
			exit(EXIT_VAL);
		}
		if (S_ISLNK(st.st_mode)) {
			fprintf(stderr, "%s: command is sym-link\n", progname);
			syslog(LOG_NOTICE, "%s: not ok: command is symlink: %s",
			    myfullname, realprog);
			exit(EXIT_VAL);
		}
	}

	/* Check for set{u,g}id */
	if (!(nflags & F_SETUID)) {
		struct stat	st;

		if (stat(realprog, &st) < 0) {
			fprintf(stderr, "%s: internal error\n", progname);
			perror(progname);
			exit(EXIT_VAL);
		}
		if (st.st_mode & S_ISUID) {
			fprintf(stderr, "%s: command is setuid\n", progname);
			syslog(LOG_NOTICE, "%s: not ok: command is setuid: %s",
			    myfullname, realprog);
			exit(EXIT_VAL);
		}
		if (st.st_mode & S_ISGID) {
			fprintf(stderr, "%s: command is setgid\n", progname);
			syslog(LOG_NOTICE, "%s: not ok: command is setgid: %s",
			    myfullname, realprog);
			exit(EXIT_VAL);
		}
	}

	/* All's well so far, get ready to execute the command. */
	syslog(LOG_INFO, build_log_message(myfullname, argv + 1, realprog,
	    nflags));
	execve(realprog, argv + 1, envp);
	fprintf(stderr,"%s: can't execute %s\n", progname, newprog);
	syslog(LOG_NOTICE, "%s: not ok: could not execute: %s",
	    myfullname, newprog);
	exit(EXIT_VAL);
	/* NOTREACHED */
}


/*
 * check_date --
 *	Determine if given date (of form "YYYYMMDDhhmm") is after
 *	the current date. Returns 1 for yes, 0 for no
 */
int
check_date(date)
	const char	*date;
{
	time_t		t;
	struct tm	*tm;
	char		buf[128];

	(void)time(&t);
	tm = localtime(&t);
	sprintf(buf, "%04d%02d%02d%02d%02d",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min);
	return(strcmp(date, buf) > 0);
}


/*
 * build_log_message --
 *	Build a log message depending upon the given flags.
 *	Returns a pointer to a static char array
 */
char *
build_log_message(myname, argv, prog, flags)
	const char	*myname;
	char		**argv;
	const char	*prog;
	unsigned int	flags;
{
	static char	log[LOGBUFSIZ];
	int		left;

	sprintf(log, "%.*s", LOGBUFSIZ - 1, myname);
	if (flags & F_LOGTTY) {
		char	*tty;

		tty = ttyname(fileno(stdin));
		if (!tty)
			tty = "NOTTY";
		if (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;

		if (LOGBUFSIZ - strlen(log) - strlen(tty) - 4 > 0)
			sprintf(log + strlen(log), " (%s)", tty);
	}
	if (flags & F_LOGCWD) {
		char	*pwd;

		pwd = getcwd(NULL, LOGBUFSIZ - strlen(log) - 7);
		if (LOGBUFSIZ - strlen(log) - strlen(pwd) - 7 > 0)
			sprintf(log + strlen(log), " (pwd=%s)", pwd);
		free(pwd);
	}
	if (flags & F_LOGLS) {
		struct stat	st;

		if (stat(prog, &st) < 0) {
			fprintf(stderr, "%s: internal error\n", prog);
			perror(prog);
			exit(EXIT_VAL);
		}
		if (LOGBUFSIZ - strlen(log) - strlen(prog) - 66 > 0)
			sprintf(log + strlen(log), " (ls=%4o:%d:%d:%d:%s)",
			    st.st_mode % 010000, st.st_uid, st.st_gid,
			    st.st_size, prog);
	}
	if (flags & F_LOGCMD) {
		if (LOGBUFSIZ - strlen(log) - strlen(prog) - 7 > 0)
			sprintf(log + strlen(log), " (cmd=%s)", prog);
	}
	left = LOGBUFSIZ - strlen(log) - 2;
	if (left > 0)
		strcat(log, ":");
	while (*argv && left > 0) {
		strcat(log, " ");
		strncat(log, *argv, left);
		left -= strlen(*argv) + 1;
		argv++;
	}
	return(log);
}


/*
 * getreason --
 *	Ask user for a reason, and give it
 *	If stdin isn't a terminal, log "NOREASON
 */
void
getreason(user, prog)
	const char	*user;
	const char	*prog;
{
	static const char prompt[] = ">> ";

	char	buf[256];
	int	len;
	int	lines;

	if (! isatty(fileno(stdin)))
		return;
	printf("Enter reason for running %s, "
		"terminated with single '.' or EOF\n%s", prog, prompt);
	lines = 0;
	while (fgets(buf, sizeof(buf), stdin) != NULL) {
		len = strlen(buf);
		if (len == 0)
			break;			/* shouldn't happen! */
		if (buf[len-1] == '\n')
			buf[len-1] = '\0';
		if (strcmp(buf, ".") == 0)
			break;
		syslog(LOG_INFO, "%s: reason: %s", user, buf);
		lines++;
		printf("%s", prompt);
	}
	if (!lines)
		syslog(LOG_INFO, "%s: reason: NON GIVEN", user);
	if (strcmp(buf, ".") != 0)
		putchar('\n');
}


/*
 * splitpath --
 *	Break a path into dirname and basename components. If there
 *	is no leading directory, "" is returned for the directory.
 *	The resultant strings are allocated with malloc(3) and
 *	should be released by the caller with free(3).
 */
void
splitpath(path, dir, base)
	const char	 *path;
	char		**dir;
	char		**base;
{
	char *o;

	o = strrchr(path, '/');
	if (o == NULL) {
		*base = xstrdup(path);
		*dir = xstrdup("");
	} else if (o == path) {
		*base = xstrdup(path + 1);
		*dir = xstrdup("/");
	} else {
		*base = xstrdup(o + 1);
		*dir = xstrdup(path);
		(*dir)[o - path] = '\0';
	}
}


/*
 * xstrdup --
 *	strdup() the given string, and return the result.
 *	If the string is NULL, return NULL.
 *	Prints a message to stderr and exits with a non-zero
 *	return code if the memory couldn't be allocated.
 */
char *
xstrdup(str)
	const char	*str;
{
	char *newstr;

	if (str == NULL)
		return NULL;

	newstr = strdup(str);
	if (newstr == NULL) {
		fprintf(stderr, "%s: can't allocate memory\n", progname);
		exit(EXIT_VAL);
	}
	return newstr;
}


/*
 * which --
 *	Determine the full pathname of the program to execute
 *	from the $PATH if necessary.
 *
 *	Code hacked from exec.c (execvp) from NetBSD (April '96)
 */
char *
which(name)
	const char	*name;
{
	char		*cur, *p, *path;
	static char	buf[MAXPATHLEN * 2 + 1];

	if (name == NULL)
		return(NULL);

	/* If it's an absolute or relative path name, it's too easy. */
	if (strchr(name, '/'))
		return((char *)name);

	/* Get the path we're searching. */
	if (!(path = getenv("PATH")))
		path = DEFPATH;
	cur = path = xstrdup(path);

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
