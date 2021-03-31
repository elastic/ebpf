# $Id$
inittest optionl-liba tc/optionl-liba
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} cql liba.a a1.o a2.o a3.o a4.o" work true
rundiff false
runcmd "plugin/teraser -c -t optionl-liba liba.a" work false
runcmd "plugin/ardiff -cnlt optionl-liba ${RLTDIR}/liba.a liba.a" work false
