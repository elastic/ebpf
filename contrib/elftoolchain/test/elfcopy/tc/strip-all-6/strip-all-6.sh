# $Id$
inittest strip-all-6 tc/strip-all-6
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -o mcs.o.1 mcs.o" work true
rundiff true
