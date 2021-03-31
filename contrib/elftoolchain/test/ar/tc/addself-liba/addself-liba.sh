# $Id$
inittest addself-liba tc/addself-liba
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} cru liba.a liba.a" work true
rundiff false
runcmd "plugin/teraser -c -t addself-liba liba.a" work false
runcmd "plugin/ardiff -cnlt addself-liba ${RLTDIR}/liba.a liba.a" work false
