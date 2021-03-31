# $Id$
inittest elfcopy-noops-4 tc/elfcopy-noops-4
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} vi vi.new" work true
rundiff true
