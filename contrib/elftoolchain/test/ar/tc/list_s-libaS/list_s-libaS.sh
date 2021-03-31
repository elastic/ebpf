# $Id$
inittest list_s-libaS tc/list_s-libaS
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} ts libaS.a" work true
runcmd "plugin/teraser -ce -t list_s-libaS libaS.a" work false
runcmd "plugin/teraser -e libaS.a" result false
rundiff true
