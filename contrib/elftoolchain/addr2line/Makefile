# $Id$

TOP=	..

PROG=	addr2line
SRCS=	addr2line.c

WARNS?=	6

DPADD=	${LIBELF} ${LIBELFTC} ${LIBDWARF}
LDADD=	-lelftc -ldwarf -lelf

MAN1=	addr2line.1

.include "${TOP}/mk/elftoolchain.prog.mk"
