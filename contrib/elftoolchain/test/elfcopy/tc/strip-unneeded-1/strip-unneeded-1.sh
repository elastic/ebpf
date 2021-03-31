# $Id$
inittest strip-unneeded-1 tc/strip-unneeded-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} --strip-unneeded -o sections.o.1 sections.o" work true
rundiff true
