/*	$Id: priv.c,v 1.33 1997/07/02 23:09:06 simonb Exp $	*/

/*
 *	priv	run a command as a given user
 *
 *	Loosely based on a command called priv by:
 *		Ron Kuris, Dec 1988.
 *		Dan Busarow, DPC Systems, 22/11/91.
 */

/*
 * Copyright (c) 1996, 1997 Werj. All rights reserved.
 * This code was contributed to Werj by Simon Burge <simonb@telstra.com.au>
 * and Luke Mewburn <lukem@connect.com.au>
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
 *	This product includes software developed by Simon Burge, Werj.
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
static char rcsid[] = "$Id: priv.c,v 1.33 1997/07/02 23:09:06 simonb Exp $";
#endif /* not lint */

#include <priv.h>

/*
 * main --
 *	main entry point
 */
int
main(int argc, char **argv, char **envp)
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
	int		log_malformed, bad_line, ok;
	unsigned int	nflags;
	int		sverr;


	/* Open syslog connection. */
#ifdef LOG_AUTH
	openlog(SYSLOGNAME, LOG_PID, LOG_AUTH);
#else
	openlog(SYSLOGNAME);
#endif

	/* Initialisation... */
	if (argv == NULL || argv[0] == NULL)
		errx(EXIT_VAL, "can't determine invocation name");
	ok = log_malformed = 0;
	newprog = argv[1];
	realprog = NULL;

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
			syslog(LOG_INFO, "priv: invalid su<user> setup");
			errx(EXIT_VAL, "invalid su<user> setup");
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
		syslog(LOG_INFO, "%s: database filename too long", myname);
		errx(EXIT_VAL, "database filename too long for user %s",
		    myname);
	}
	sprintf(userf, "%s/%s", PRIVDIR, myname);

	/* Check command usage. */
	if (suuser == NULL && argc < 2)  {
		syslog(LOG_INFO, "%s: not ok: incorrect usage", myfullname);
		fprintf(stderr, "usage: %s command [arg [...]]\n", progname);
		exit(EXIT_VAL);
	}
	if (suuser != NULL) {
		if (argc == 3 && strcmp(argv[1], "-c") == 0) {
			newprog = argv[2];
		} else if (argc != 1) {
			syslog(LOG_INFO, "%s: not ok: incorrect usage",
			    myfullname);
			fprintf(stderr, "usage: %s [-c command]\n", progname);
			exit(EXIT_VAL);
		}
	}

	/*
	 * Determine basename and dirname of invoked program
	 * XXX: realprog & newprog may be NULL if suuser is being used
	 */
	if (newprog != NULL) {
		splitpath(newprog, &newprogdir, &newprogbase);
		realprog = which(newprog);
		if (realprog != NULL)
			splitpath(realprog, &realprogdir, &realprogbase);
	}
	if (suuser == NULL && realprog == NULL) {
		syslog(LOG_NOTICE, "%s: not ok: command not found: %s",
		    myfullname, newprog);
		errx(EXIT_VAL, "command %s not found", newprog);
	}

	/* Try and open the priv database for "myname". */
	if ((fp = fopen(userf, "r")) == NULL) {
		syslog(LOG_NOTICE, "%s: not ok: no database", myname);
		errx(EXIT_VAL, "no access");
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
			warnx("user not valid");
			syslog(LOG_NOTICE, "%s: not ok: su to %s",
			    myfullname, useras);
		}
		else {
			warnx("command not valid");
			syslog(LOG_NOTICE, "%s: not ok: command not valid: %s",
			    myfullname, newprog);
		}
		exit(EXIT_VAL);
	}

	/* Check expiry date */
	if (!check_date(expire)) {
		syslog(LOG_NOTICE, "%s: not ok: %s expired: %s", myfullname,
		    suuser ? "su" : "command", suuser ? useras : newprog);
		errx(EXIT_VAL, "command expired");
	}

	/* Does the user to run the command as exist? */
	if ((pw = getpwnam(useras)) == NULL) {
		syslog(LOG_NOTICE, "%s: not ok: user name %s not valid",
		    myfullname, useras);
		errx(EXIT_VAL, "invalid user (%s) to run command as", useras);
	}

	/* If necessary, ask for a reason for running priv */
	if ((nflags & F_GIVEREASON))
		getreason(myfullname, suuser ? progname : newprogbase);

	/* If we're su-ing, now's the time */
	if (suuser != NULL) {
		StringList	*nargv;

		nargv = sl_init();
		sl_add(nargv, "su");
		if (sudash)
			sl_add(nargv, "-");
		sl_add(nargv, suuser);
		if (argc == 3) {
			sl_add(nargv, argv[1]);
			sl_add(nargv, argv[2]);
		}
		sl_add(nargv, NULL);

		if (argc == 3)
			syslog(LOG_INFO, "su from %s to %s: %s\n",
			    myname, suuser, argv[2]);
		else
			syslog(LOG_INFO, "su from %s to %s\n", myname, suuser);
		envp = lockdown(nflags, realprog, pw, envp);
		setuid(0);	/* Set real & effective uid so "su" will work */
		execve(PATH_SU, nargv->sl_str, envp);
		sverr = errno;
		syslog(LOG_NOTICE, "%s: not ok: could not su", myfullname);
		errno = sverr;
		err(EXIT_VAL, "couldn't run su");
	}

	/* Set up the permissions */
	if (setgid(pw->pw_gid) < 0) {
		sverr = errno;
		syslog(LOG_NOTICE, "%s: not ok: setgid failed: %m", myfullname);
		errno = sverr;
		err(EXIT_VAL, "setgid failed");
	}
	if (initgroups(pw->pw_name, pw->pw_gid) < 0) {
		sverr = errno;
		syslog(LOG_NOTICE, "%s: not ok: initgroups failed: %m",
		    myfullname);
		errno = sverr;
		err(EXIT_VAL, "initgroups failed");
	}
	if (setuid(pw->pw_uid) < 0) {
		sverr = errno;
		syslog(LOG_NOTICE, "%s: not ok: setuid failed: %m", myfullname);
		errno = sverr;
		err(EXIT_VAL, "setuid failed");
	}

	/* Check for sym-link */
	if (!(nflags & F_SYMLINK)) {
		struct stat	st;

		if (lstat(realprog, &st) < 0)
			err(EXIT_VAL, "can't lstat %s", realprog);
		if (S_ISLNK(st.st_mode)) {
			syslog(LOG_NOTICE, "%s: not ok: command is symlink: %s",
			    myfullname, realprog);
			errx(EXIT_VAL, "command is sym-link");
		}
	}

	/* Check for set{u,g}id */
	if (!(nflags & F_SETUID)) {
		struct stat	st;

		if (stat(realprog, &st) < 0)
			err(EXIT_VAL, "can't stat %s", realprog);
		if (st.st_mode & S_ISUID) {
			syslog(LOG_NOTICE, "%s: not ok: command is setuid: %s",
			    myfullname, realprog);
			errx(EXIT_VAL, "command is setuid");
		}
		if (st.st_mode & S_ISGID) {
			syslog(LOG_NOTICE, "%s: not ok: command is setgid: %s",
			    myfullname, realprog);
			errx(EXIT_VAL, "command is setgid");
		}
	}

	/* All's well so far, get ready to execute the command. */
	syslog(LOG_INFO, build_log_message(myfullname, argv + 1, realprog,
	    nflags));
	envp = lockdown(nflags, realprog, pw, envp);
	execve(realprog, argv + 1, envp);
	sverr = errno;
	syslog(LOG_NOTICE, "%s: not ok: could not execute: %s",
	    myfullname, newprog);
	errno = sverr;
	err(EXIT_VAL, "can't execute %s", newprog);
	exit(EXIT_VAL);
	/* NOTREACHED */
}


/*
 * build_log_message --
 *	Build a log message depending upon the given flags.
 *	Returns a pointer to a static char array
 */
char *
build_log_message(const char *myname, char **argv,
		const char *prog, unsigned int flags)
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
#if defined HAVE_GETCWD || defined HAVE_GETWD
	if (flags & F_LOGCWD) {
#ifdef HAVE_GETCWD
		char	*pwd;
#else
		char	 pwd[1024]	/* XXX - clean way of getting PATH_MAX ??? */
#endif

#if defined HAVE_GETCWD
		pwd = getcwd(NULL, LOGBUFSIZ - strlen(log) - 7);
#else
		getwd(pwd);
#endif
		if (LOGBUFSIZ - strlen(log) - strlen(pwd) - 7 > 0)
			sprintf(log + strlen(log), " (pwd=%s)", pwd);
#ifdef HAVE_GETCWD
		free(pwd);
#endif
	}
#endif /* HAVE_GETCWD || HAVE_GETWD */
	if (flags & F_LOGLS) {
		struct stat	st;

		if (stat(prog, &st) < 0)
			err(EXIT_VAL, "can't stat %s", prog);
		if (LOGBUFSIZ - strlen(log) - strlen(prog) - 66 > 0)
			sprintf(log + strlen(log), " (ls=%4o:%d:%d:%d:%s)",
			    (int)(st.st_mode % 010000), (int)st.st_uid,
			    (int)st.st_gid, (int)st.st_size, prog);
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
 * check_date --
 *	Determine if given date (of form "YYYYMMDDhhmm") is after
 *	the current date. 0 always means success.  Returns 1 for yes,
 *	0 for no
 */
int
check_date(const char *date)
{
	time_t		t;
	struct tm	*tm;
	char		buf[128];

	if (strcmp(date, "0") == 0)
		return(1);
	(void)time(&t);
	tm = localtime(&t);
	sprintf(buf, "%04d%02d%02d%02d%02d",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min);
	return(strcmp(date, buf) > 0);
}


/*
 * concatstr --
 *	Take the list of strings, NULL terminated, concatenate them,
 *	and return the result. Caller should release memory with free(3).
 */
char *
concatstr(const char *first, ...)
{
	va_list		 ap;
	size_t		 size;
	const char	*cur;
	char 		*res;

	size = 0;
	va_start(ap, first);
	cur = first;
	while (cur != NULL) {
		size += strlen(cur);
		cur = va_arg(ap, const char *);
	}
	va_end(ap);

	if (size == 0)
		return(xstrdup(""));
	res = malloc(size + 1);
	if (res == NULL)
		err(EXIT_VAL, "can't allocate memory");

	res[0] = '\0';
	va_start(ap, first);
	cur = first;
	while (cur != NULL) {
		strcat(res, cur);
		cur = va_arg(ap, const char *);
	}
	va_end(ap);
	return(res);
}


/*
 * getreason --
 *	Ask user for a reason, and give it
 *	If stdin isn't a terminal, log "NOREASON
 */
void
getreason(const char *user, const char *prog)
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

#ifndef MAXFD
#ifdef HAVE_GETDTABLESIZE
#define MAXFD	getdtablesize()
#else
#define MAXFD	(sysconf(_SC_OPEN_MAX))
#endif
#endif

/*
 * lockdown --
 *	Clean up environment, close any excess file descriptors,
 *	reset signals.
 */
char **
lockdown(int flags, char *prog, struct passwd *user, char **envp)
{
	StringList	*newenv;
	char		*cur;
	int		i;

		/* Close file descriptors */
	for (i = 3; i < MAXFD; i++)
		close(i);

		/* Reset signals */
	for (i = 0; i < NSIG; i++)
		(void) signal(i, SIG_DFL);

		/* Nuke the environment, reset from scratch */
	if (! (flags & F_CLEANENV))
		return(envp);

	newenv = sl_init();
	if ((cur = getenv("COLUMNS")) != NULL &&
	    (cur[strspn(cur, "0123456789")] == '\0'))
		sl_add(newenv, concatstr("COLUMNS=", cur, NULL));
	if ((cur = getenv("LINES")) != NULL &&
	    (cur[strspn(cur, "0123456789")] == '\0'))
		sl_add(newenv, concatstr("LINES=", cur, NULL));
	sl_add(newenv, concatstr("HOME=", user->pw_dir, NULL));
	sl_add(newenv, xstrdup("IFS=\" \t\n\""));
	sl_add(newenv, concatstr("LOGNAME=", user->pw_name, NULL));
	sl_add(newenv, concatstr("USER=", user->pw_name, NULL));
	if ((cur = getenv("HOME")) != NULL)
		sl_add(newenv, concatstr("ORIG_HOME=", cur, NULL));
	if ((cur = getenv("LOGNAME")) != NULL)
		sl_add(newenv, concatstr("ORIG_LOGNAME=", cur, NULL));
	if ((cur = getenv("USER")) != NULL)
		sl_add(newenv, concatstr("ORIG_USER=", cur, NULL));
	sl_add(newenv, xstrdup("PATH=" DEFPATH));
	sl_add(newenv, concatstr("PRIVCMD=", prog, NULL));
	sl_add(newenv, xstrdup("SHELL=/bin/sh"));
	if ((cur = getenv("TERM")) != NULL) {
		for (i = 0; cur[i] != '\0'; i++)
			if (!isalnum(cur[i]) && strchr("-+_.", cur[i]) == NULL)
				break;
		if (cur[i] == '\0')
			sl_add(newenv, concatstr("TERM=", cur, NULL));
	}

	sl_add(newenv, NULL);
	return(newenv->sl_str);
}


/*
 * splitpath --
 *	Break a path into dirname and basename components. If there
 *	is no leading directory, "" is returned for the directory.
 *	The resultant strings are allocated with strdup(3) and
 *	should be released by the caller with free(3).
 */
void
splitpath(const char *path, char **dir, char **base)
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
 * which --
 *	Determine the full pathname of the program to execute
 *	from the $PATH if necessary.
 *
 *	Code hacked from exec.c (execvp) from NetBSD (April '96)
 */
char *
which(const char *name)
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
	return(NULL);
}


/*
 * xstrdup --
 *	strdup() the given string, and return the result.
 *	If the string is NULL, return NULL.
 *	Prints a message to stderr and exits with a non-zero
 *	return code if the memory couldn't be allocated.
 */
char *
xstrdup(const char *str)
{
	char *newstr;

	if (str == NULL)
		return(NULL);

	newstr = strdup(str);
	if (newstr == NULL)
		err(EXIT_VAL, "can't allocate memory");
	return(newstr);
}
