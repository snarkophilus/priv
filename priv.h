/*	$Id$	*/

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

#ifndef _PRIV_H
#define _PRIV_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stringlist.h>
#include <syslog.h>
#include <unistd.h>


#ifndef PRIVDIR
#define PRIVDIR		"/usr/local/etc/priv"	/* database directory */
#endif

#define DEFPATH		"/bin:/usr/bin"
#define PATH_SU		"/bin/su"		/* path to "su" command */
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
#define F_CLEANENV	0001000		/* sanitise environment */
#define F_SU		0100000		/* check su to an account */

#ifndef S_ISLNK
#define	S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#endif

char	*progname;


int	 check_date(const char *);
char	*concatstr(const char *, ...);
char	*build_log_message(const char *, char **, const char *, unsigned int);
void	 getreason(const char *, const char *);
char   **lockdown(int, char *, struct passwd *, char **);
void	 splitpath(const char *, char **, char **);
char	*which(const char *);
char	*xstrdup(const char *);


void	err(int, const char *, ...);
void	errx(int, const char *, ...);
char   *strsep(char **, const char *);
void	warn(const char *, ...);
void	warnx(const char *, ...);

#endif /* _PRIV_H */
