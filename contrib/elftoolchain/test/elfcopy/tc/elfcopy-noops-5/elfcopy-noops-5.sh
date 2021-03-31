# $Id$
inittest elfcopy-noops-5 tc/elfcopy-noops-5
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} tcsh tcsh.new" work true
rundiff true
