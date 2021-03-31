# $Id$
inittest compbase_read-liba tc/compbase_read-liba
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} t liba.a ./a1.o" work true
rundiff true
