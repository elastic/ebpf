# $Id$

TOP=	..

INCS=		elfdefinitions.h
INCSDIR=	/usr/include

.PHONY:	all clean clobber depend obj

all depend:

clean clobber:
	rm -f ${CLEANFILES}

cleandepend:
	rm -f ${.OBJDIR}/.depend

.include "${TOP}/mk/elftoolchain.inc.mk"
