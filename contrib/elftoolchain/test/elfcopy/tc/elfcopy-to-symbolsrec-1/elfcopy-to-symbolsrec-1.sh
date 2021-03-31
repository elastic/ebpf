# $Id$
inittest elfcopy-to-symbolsrec-1 tc/elfcopy-to-symbolsrec-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} -O symbolsrec a64.out a64.srec" work true
rundiff true
