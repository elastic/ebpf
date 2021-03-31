# $Id$
inittest strip-all-7 tc/strip-all-7
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -o sections.o.1 sections.o" work true
rundiff true
