# $Id$
inittest strip-all-2 tc/strip-all-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} ps" work true
rundiff true
