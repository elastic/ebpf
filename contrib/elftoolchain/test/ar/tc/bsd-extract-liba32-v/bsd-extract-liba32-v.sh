# $Id$
inittest bsd-extract-liba32-v tc/bsd-extract-liba32-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} xv liba.a" work true
rundiff true
