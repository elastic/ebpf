# $Id$
inittest list-liblong tc/list-liblong
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} t liblong.a" work true
rundiff true
