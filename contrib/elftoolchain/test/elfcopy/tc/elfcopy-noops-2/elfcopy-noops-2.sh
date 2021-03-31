# $Id$
inittest elfcopy-noops-2 tc/elfcopy-noops-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} ls ls.new" work true
rundiff true
