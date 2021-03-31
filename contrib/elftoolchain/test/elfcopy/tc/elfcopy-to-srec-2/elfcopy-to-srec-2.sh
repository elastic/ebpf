# $Id$
inittest elfcopy-to-srec-2 tc/elfcopy-to-srec-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} -O srec --srec-forceS3 a64.out a64.srec" work true
rundiff true
