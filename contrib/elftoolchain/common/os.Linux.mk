#
# Build recipes for Linux based operating systems.
#
# $Id$

_NATIVE_ELF_FORMAT = native-elf-format

.if !make(obj)
.BEGIN:	${.OBJDIR}/${_NATIVE_ELF_FORMAT}.h

${.OBJDIR}/${_NATIVE_ELF_FORMAT}.h:
	${.CURDIR}/${_NATIVE_ELF_FORMAT} > ${.TARGET} || rm ${.TARGET}
.endif

CLEANFILES += ${.OBJDIR}/${_NATIVE_ELF_FORMAT}.h
