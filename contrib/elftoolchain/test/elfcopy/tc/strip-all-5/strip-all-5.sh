# $Id$
inittest strip-all-5 tc/strip-all-5
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} pkill" work true
rundiff true
