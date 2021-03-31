# $Id$
inittest extract-liba-v tc/extract-liba-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} vx liba.a" work true
rundiff true
