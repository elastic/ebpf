# $Id$
inittest quickadd-liba-v tc/quickadd-liba-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} qcv liba.a a1.o a2.o a3.o a4.o" work true
rundiff false
runcmd "plugin/teraser -c -t quickadd-liba-v liba.a" work false
runcmd "plugin/ardiff -cnlt quickadd-liba-v ${RLTDIR}/liba.a liba.a" work false
