# $Id$
inittest strip-all-archive-2 tc/strip-all-archive-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} -o liblong.a.1 liblong.a" work true
rundiff false
runcmd "plugin/teraser -c -t strip-all-archive-2 liblong.a.1" work false
runcmd "plugin/ardiff -cnlt strip-all-archive-2 ${RLTDIR}/liblong.a.1 liblong.a.1" work false
