PROG=	priv
SRCS=	priv.c strsep.c
OBJS=	${SRCS:.c=.o}

BINMODE=4555
BINOWN=	root
BINDIR=	/usr/local/bin

CC=	gcc
CFLAGS=	-O2 -Wall -DPRIVDIR=\"/opt/local/etc/priv\"

${PROG}:	${OBJS}
	${CC} ${LFLAGS} ${OBJS} -o $@

clean:
	rm -f ${PROG} ${OBJS}
