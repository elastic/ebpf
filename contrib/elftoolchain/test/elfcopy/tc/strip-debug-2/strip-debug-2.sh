# $Id$
inittest strip-debug-2 tc/strip-debug-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -g -o symbols.o.1 symbols.o" work true
rundiff true
