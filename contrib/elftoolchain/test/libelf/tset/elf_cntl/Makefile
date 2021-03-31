# $Id$

TOP=	../../../..

TS_SRCS=		cntl.m4
TS_DATA=		a.ar
CLEANFILES+=		a.c a.o

a.c:	.SILENT
	echo "int foobar;" > ${.TARGET}

a.ar:	a.o .SILENT
	rm -f ${.TARGET}
	${AR} crv ${.TARGET} ${.ALLSRC} > /dev/null

.include "${TOP}/mk/elftoolchain.tet.mk"
