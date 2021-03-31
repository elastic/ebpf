# $Id$
inittest list-lib65536 tc/list-lib65536
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} t lib65536.a" work true
rundiff true
