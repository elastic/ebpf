# $Id$
inittest strip-all-9 tc/strip-all-9
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -o elfcopy.1 elfcopy" work true
rundiff true
