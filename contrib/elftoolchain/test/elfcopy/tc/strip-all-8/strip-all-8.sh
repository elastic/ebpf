# $Id$
inittest strip-all-8 tc/strip-all-8
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -o sections.o.debug.1 sections.o.debug" work true
rundiff true
