# $Id$
inittest elfcopy-N-1 tc/elfcopy-N-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} -N bar2 sym.o sym.o.1" work true
rundiff true
