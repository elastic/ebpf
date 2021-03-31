# $Id$

TOP=	..

PROG=	findtextrel
SRCS=	findtextrel.c

WARNS?=	6

DPADD=	${LIBELFTC} ${LIBDWARF} ${LIBELF} 
LDADD=	-lelftc -ldwarf -lelf

MAN1=	findtextrel.1

.include "${TOP}/mk/elftoolchain.prog.mk"
