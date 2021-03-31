# $Id$
inittest elfcopy-noops-archive-2 tc/elfcopy-noops-archive-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} liblong.a liblong.a.1" work true
rundiff false
runcmd "plugin/teraser -c -t elfcopy-noops-archive-2 liblong.a.1" work false
runcmd "plugin/ardiff -cnlt elfcopy-noops-archive-2 ${RLTDIR}/liblong.a.1 liblong.a.1" work false
