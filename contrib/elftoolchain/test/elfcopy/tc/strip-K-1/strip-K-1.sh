# $Id$
inittest strip-K-1 tc/strip-K-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -K nosuchsym -o sym.o.1 sym.o" work true
rundiff true
