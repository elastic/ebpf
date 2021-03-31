# $Id$
inittest strip-debug-3 tc/strip-debug-3
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -g -o ls.1 ls" work true
rundiff true
