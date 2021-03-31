# $Id$

#
# Rules for invoking test suites.
#

TEST_DIRECTORY=		test
TEST_TARGET=		test

.if !target(test)
# The special target 'test' runs the test suite associated with a
# utility or library.
test:	all .PHONY
	cd ${TOP}/${TEST_DIRECTORY}/${.CURDIR:T} && \
	${MAKE} all ${TEST_TARGET}
.endif
