# $Id$
inittest bsd-extract-liblong-v tc/bsd-extract-liblong-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} xv liblong.a" work true
rundiff true
