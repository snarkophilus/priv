/*
 * priv  Run a command as superuser
 * by Ron Kuris, December 1988
 *
 * $Id: priv.c,v 1.3 1996/02/23 14:33:33 simonb Exp $
 */
/*
 *	access list added by Dan Busarow, DPC Systems, 11/22/91
 *
 *	files: /etc/priv.list
 *		a list of authorized user login names, one per line
 *		should be mode 400
 *
 *	/usr/lib/priv/login_name
 *		a list of authorized commands, one per line
 *		this should also be 400
 *
 *	priv should be mode 4111, owned by root
 */

#include <stdio.h>
#include <pwd.h>
#include <syslog.h>

#ifdef __svr4__	/* Solaris 2 */
# define index strchr
#endif

#define PRIVLIST	"/usr/local/etc/priv/priv.list"
#define ACCESSDIR	"/usr/local/etc/priv/"
#define LONGESTNAME	64
#define ERREXIT		1

#define SYSLOGNAME	"priv"		/* name used in syslog entries */

/* If NEWPATH isn't defined, then PATH is taken from calling program.    */
/* If PATHOK appears next to the users login name in the priv.list file, */
/* then the user gets to use their own path.                             */
#define NEWPATH "PATH=/bin:/etc:/usr/bin:/usr/ucb:/usr/local/bin"

extern unsigned short getuid();
extern char *malloc();

main(argc, argv, envp)
char **argv, **envp;
int argc;
{
	struct passwd *pw;
	FILE *fp;
	char aList[64], buffer[LONGESTNAME+1], *lname, *prog;
	short i, j, ok;
#ifdef NEWPATH
	char *p;
	int pathok = 0;
#endif /* ! NEWPATH */

#ifdef LOG_AUTHPRIV
	openlog(SYSLOGNAME, 0, LOG_AUTHPRIV);
#elif defined(LOG_AUTH)
	openlog(SYSLOGNAME, 0, LOG_AUTH);
#else
	openlog(SYSLOGNAME);
#endif

	prog = argv[0]; /* store program name */
	pw = getpwuid(getuid());
	lname = pw->pw_name;

	if (argc < 2)  {
		/***
		fprintf(stderr, "Usage: %s command args\n", prog);
		no error messages, this program is not intended for use
		by the general public, authorized users will know how to
		run it
		***/
		syslog(LOG_NOTICE, "%s: incorrect usage", lname);
		exit(ERREXIT);
	}
	if ((fp = fopen(PRIVLIST, "r")) == NULL) {
		fprintf(stderr, "%s: Can't open database\n", prog);
		syslog(LOG_NOTICE, "%s: can't open database", lname);
		exit(ERREXIT);
	}
	while (fgets(buffer, LONGESTNAME, fp) != NULL) {
		buffer[strlen(buffer)-1] = '\0'; /* zap newline */
		p = (char *)index(buffer, ' ');
#ifdef NEWPATH
		if (p)
			*p++ = '\0';
#endif /* ! NEWPATH */
		if (!strcmp(lname, buffer)) {
			fclose(fp);
#ifdef NEWPATH
			if (p && !strcmp(p, "PATHOK"))
				pathok = 1;
#endif /* ! NEWPATH */
			ok = 0;
			strcpy(aList, ACCESSDIR);
			strcat(aList, lname);
			if ((fp = fopen(aList, "r")) == NULL) {
				/* default, no restriction.  this user is
				   now root so you better trust them! */
				ok = 1;
				syslog(LOG_NOTICE, "%s: full access", lname);
			}
			else {
				while(fgets(buffer, LONGESTNAME, fp) != NULL) {
					buffer[strlen(buffer)-1] = 0;
					if(!strcmp(buffer, argv[1])) {
						ok = 1;
						break;
					}
				}
				if (ok) {
					syslog(LOG_NOTICE,
						"%s: command approved", lname);
				}
				else {
					syslog(LOG_NOTICE,
						"%s: command not valid", lname);
				}
			}
			if (!ok) {	 /* failed access list test */
				fclose(fp);
				exit(ERREXIT);
			}
#ifndef NEWPATH
			if (getenv("PATH") == NULL) {
				syslog(LOG_NOTICE, "%s: no path defined",
					lname);
				fprintf(stderr,"%s: No path.\n", prog);
				exit(ERREXIT);
			}
#else /* NEWPATH */
			if (!(pathok && getenv("PATH"))) {
				for (i=0; envp[i]; i++) {
					if (!strncmp("PATH=", envp[i], 5)) {
						envp[i] = NEWPATH;
						break;
					}
				}
				if (!envp[i]) { /* no PATH, add it to environ */
					extern char **environ;
					char **newenv = (char **)malloc((i + 2)
							* sizeof(char *));
					for (j = 0; j < i; j++)
						newenv[j] = envp[j];
					newenv[j] = NEWPATH;
					newenv[j+1] = NULL;
					environ = newenv;
				}
			}
#endif /* NEWPATH */
			setuid(0);
			setgid(0);
			execvp(argv[1], argv+1);
			syslog(LOG_NOTICE, "%s: couldn't execute program",
				lname);
			fprintf(stderr,"%s: can't execute %s\n", prog, argv[1]);
			exit(ERREXIT);
		}
	}
	/* failed authorization test */
	/* originally there was an error message here saying that the
	   user is not authorized to run priv.  I removed it on the
	   assumption that a program which seems to do nothing is a lot
	   less likely to get hacked on than one which tells you that you
	   are not authorized to run it.
	*/
	fclose(fp);
	syslog(LOG_NOTICE, "%s: failed authorization test", lname);
	exit(ERREXIT);
	/* NOTREACHED */
}
