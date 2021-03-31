# $Id$
inittest elfcopy-noops-1 tc/elfcopy-noops-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} pkill pkill.new" work true
rundiff true
