#
# $Id$
#

# Implicit rules for the M4 pre-processor.

.if !defined(TOP)
.error	Make variable \"TOP\" has not been defined.
.endif

.SUFFIXES:	.m4 .c
.m4.c:
	m4 -D SRCDIR=${.CURDIR} ${M4FLAGS} ${.IMPSRC} > ${.TARGET}

