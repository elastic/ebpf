# $Id$
inittest extract-libmix-v tc/extract-libmix-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} xv libmix.a" work true
rundiff true
