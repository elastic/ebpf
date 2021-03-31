# $Id$
inittest strip-K-2 tc/strip-K-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -K foo -o sym.o.1 sym.o" work true
rundiff true
