#	BSD 4.4 makefile for "priv"

PROG=	priv
.if exists(/usr/local/lib/libsyslog.a)
CFLAGS+=-I/usr/local/include/local
LDADD+=	-lsyslog
.endif
BINMODE=4555
BINOWN=	root
BINDIR=	/usr/local/bin
NOMAN=	no way, man!

.include <bsd.prog.mk>
