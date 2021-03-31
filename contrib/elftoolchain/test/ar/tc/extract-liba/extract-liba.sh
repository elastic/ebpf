# $Id$
inittest extract-liba tc/extract-liba
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} x liba.a" work true
rundiff true
