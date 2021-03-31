# $Id$
inittest extract-liblong tc/extract-liblong
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} x liblong.a" work true
rundiff true
