# $Id$
inittest strip-all-10 tc/strip-all-10
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -o make.1 make" work true
rundiff true
