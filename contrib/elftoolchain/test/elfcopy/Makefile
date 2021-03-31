# $Id$

TOP=		../..

ELFCOPY=	${TOP}/elfcopy/elfcopy

TEST_LOG=	test.log

.MAIN:	all

.PHONY:	clobber execute test

execute test: ${ELFCOPY}
	/bin/sh run.sh

clean clobber:
	rm -f ${TEST_LOG}

SUBDIR=		plugin

.include "${TOP}/mk/elftoolchain.subdir.mk"
