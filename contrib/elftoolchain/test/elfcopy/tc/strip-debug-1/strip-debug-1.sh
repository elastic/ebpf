# $Id$
inittest strip-debug-1 tc/strip-debug-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -g -o sections.o.1 sections.o" work true
rundiff true
