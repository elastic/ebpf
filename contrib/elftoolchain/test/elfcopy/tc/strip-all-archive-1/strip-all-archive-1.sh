# $Id$
inittest strip-all-archive-1 tc/strip-all-archive-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -o liba.a.1 liba.a" work true
rundiff false
runcmd "plugin/teraser -c -t strip-all-archive-1 liba.a.1" work false
runcmd "plugin/ardiff -cnlt strip-all-archive-1 ${RLTDIR}/liba.a.1 liba.a.1" work false
