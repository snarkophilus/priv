#	$Id: Makefile,v 1.13 1997/02/19 05:04:00 lukem Exp $
#

PROG=	priv
SRCS=	err.c priv.c strdup.c stringlist.c strsep.c
OBJS=	${SRCS:.c=.o}

BINMODE=4555
BINOWN=	root
BINDIR=	/usr/local/bin
PRIVDIR=/usr/local/etc/priv

CC=	cc
CFLAGS=	-I. -O -DPRIVDIR=\"${PRIVDIR}\"

${PROG}:	${OBJS}
	${CC} ${LFLAGS} ${OBJS} -o $@

clean:
	rm -f ${PROG} ${OBJS}
