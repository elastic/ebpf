# $Id$
inittest arscript-4 tc/arscript-4
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} -M < liba.script.bsd" work true
rundiff true
