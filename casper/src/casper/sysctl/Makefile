# $FreeBSD: head/libexec/casper/sysctl/Makefile 264400 2014-04-13 05:21:56Z imp $

.PATH:	${.CURDIR} ${.CURDIR}/../../../sbin/casper

PROG=	sysctl

SRCS=	sysctl.c

DPADD=	${LIBCAPSICUM} ${LIBCASPER} ${LIBNV} ${LIBPJDLOG} ${LIBUTIL}
LDADD=	-lcapsicum -lcasper -lnv -lpjdlog -lutil

BINDIR=	/libexec/casper

CFLAGS+=-I${.CURDIR}
CFLAGS+=-I${.CURDIR}/../../../lib/libcapsicum
CFLAGS+=-I${.CURDIR}/../../../lib/libcasper
CFLAGS+=-I${.CURDIR}/../../../lib/libpjdlog
CFLAGS+=-I${.CURDIR}/../../../sbin/casper

MAN=

.include <bsd.prog.mk>
