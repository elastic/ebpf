# $Id$
inittest strip-unneeded-2 tc/strip-unneeded-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} --strip-unneeded -o elfcopy.1 elfcopy" work true
rundiff true
