# $Id$
inittest elfcopy-noops-3 tc/elfcopy-noops-3
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} ps ps.new" work true
rundiff true
