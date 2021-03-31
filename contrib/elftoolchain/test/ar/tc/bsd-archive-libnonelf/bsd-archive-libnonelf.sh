# $Id$
inittest bsd-archive-libnonelf tc/bsd-archive-libnonelf
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} cruF bsd libnonelf.a ne1 ne2 ne3 ne4" work true
rundiff false
runcmd "plugin/teraser -c -t bsd-archive-libnonelf libnonelf.a" work false
runcmd "plugin/ardiff -cnlt bsd-archive-libnonelf ${RLTDIR}/libnonelf.a libnonelf.a" work false
