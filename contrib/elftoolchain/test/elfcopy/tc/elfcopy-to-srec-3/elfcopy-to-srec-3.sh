# $Id$
inittest elfcopy-to-srec-3 tc/elfcopy-to-srec-3
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} -O srec --srec-forceS3 --srec-len=50 a64.out a64.srec" work true
rundiff true
