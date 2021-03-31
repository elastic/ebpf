# $Id$
inittest delete_all-liba-v tc/delete_all-liba-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} dv liba.a a1.o a2.o a3.o a4.o" work true
rundiff true
