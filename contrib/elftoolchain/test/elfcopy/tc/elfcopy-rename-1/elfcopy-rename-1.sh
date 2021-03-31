# $Id$
inittest elfcopy-rename-1 tc/elfcopy-rename-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} --rename-section .text=.text.newname sym.o" work true
rundiff true
