# $Id$
inittest elfcopy-to-srec-1 tc/elfcopy-to-srec-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} -O srec a64.out a64.srec" work true
rundiff true
