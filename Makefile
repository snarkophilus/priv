PROG=	priv
SRCS=	priv.c strsep.c
OBJS=	${SRCS:.c=.o}

BINMODE=4555
BINOWN=	root
BINDIR=	/opt/local/bin
PRIVDIR=/opt/local/etc/priv

CC=	gcc
CFLAGS=	-O2 -Wall -DPRIVDIR=\"${PRIVDIR}\"

${PROG}:	${OBJS}
	${CC} ${LFLAGS} ${OBJS} -o $@

clean:
	rm -f ${PROG} ${OBJS}
