# $Id$
inittest elfcopy-noops-6 tc/elfcopy-noops-6
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} mcs.o mcs.o.1" work true
rundiff true
