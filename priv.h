/*	$Id: priv.h,v 1.1 1997/02/19 05:04:01 lukem Exp $	*/

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

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <pwd.h>
#include <signal.h>
#if defined __STDC__ || defined HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef HAVE_STRINGLIST_H
#include <stringlist.h>
#else
#include <mystringlist.h>
#endif
#ifdef HAVE_SYSLOG
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
#include <sys/syslog.h>
#endif
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#define DEFPATH		"/bin:/usr/bin"
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

#ifndef HAVE_ERR
void	err(int, const char *, ...);
void	errx(int, const char *, ...);
void	warn(const char *, ...);
void	warnx(const char *, ...);
#endif
#ifndef HAVE_STRDUP
char   *strdup(const char *);
#endif
#ifndef HAVE_STRSEP
char   *strsep(char **, const char *);
#endif
#ifndef HAVE_STRERROR
char   *strerror(int errnum);
#endif
#ifdef HAVE_STRSPN
size_t  strspn(const char *s, const char *charset);
#endif
#ifdef HAVE_STRTOUL
unsigned long strtoul(const char *nptr, char **endptr, int base);
#endif

#endif /* _PRIV_H */
