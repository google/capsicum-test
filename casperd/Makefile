# $FreeBSD: head/sbin/casperd/Makefile 263240 2014-03-16 13:43:06Z jilles $

PROG=	casperd

SRCS=	casperd.c zygote.c

DPADD=	${LIBCASPER} ${LIBCAPSICUM} ${LIBNV} ${LIBPJDLOG} ${LIBUTIL}
LDADD=	-lcasper -lcapsicum -lnv -lpjdlog -lutil

MAN=	casperd.8

CFLAGS+=-I${.CURDIR}
CFLAGS+=-I${.CURDIR}/../../lib/libcapsicum
CFLAGS+=-I${.CURDIR}/../../lib/libcasper
CFLAGS+=-I${.CURDIR}/../../lib/libnv
CFLAGS+=-I${.CURDIR}/../../lib/libpjdlog

.include <bsd.prog.mk>
