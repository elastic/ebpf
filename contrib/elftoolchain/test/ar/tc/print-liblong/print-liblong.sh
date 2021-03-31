# $Id$
inittest print-liblong tc/print-liblong
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} p liblong.a" work true
rundiff true
