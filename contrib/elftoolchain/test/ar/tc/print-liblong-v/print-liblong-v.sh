# $Id$
inittest print-liblong-v tc/print-liblong-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} vp liblong.a" work true
rundiff true
