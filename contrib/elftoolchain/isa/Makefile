# $Id$

TOP=	..

PROG=	isa
SRCS=	isa.c
LSRC=
YSRC=
LDADD=	-lelftc

ISA=	avr.isa

MAN=	isa.1 isa.5

check-specifications:	.PHONY
.for f in ${ISA}
	${.OBJDIR}/${PROG} -n --query ${f}
.endfor

.include "${TOP}/mk/elftoolchain.prog.mk"
