# $Id$
inittest strip-all-4 tc/strip-all-4
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} vi" work true
rundiff true
