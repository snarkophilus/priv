PROG=	priv

BINMODE=4555
BINOWN=	root
BINDIR=	/usr/local/bin
MANDIR=	/usr/local/man/cat

# Ultrix compat stuff...
.if exists(/usr/local/lib/libsyslog.a)
CFLAGS+=-I/usr/local/include/local
LDADD+=	-lsyslog
.endif
.if exists(/usr/local/lib/libnetbsd.a)
LDADD+=	-lnetbsd
.endif

.include <bsd.prog.mk>
