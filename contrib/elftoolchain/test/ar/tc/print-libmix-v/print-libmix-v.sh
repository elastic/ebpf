# $Id$
inittest print-libmix-v tc/print-libmix-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} pv libmix.a" work true
rundiff true
