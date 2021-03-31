# $Id$
inittest elfcopy-L-2 tc/elfcopy-L-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} -L _end a.out a.out.1" work true
rundiff true
