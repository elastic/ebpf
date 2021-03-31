# $Id$
inittest arscript-1 tc/arscript-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} -M < kDep.a.ar-script" work true
rundiff false
runcmd "plugin/teraser -c -t arscript-1 kDep.a" work false
runcmd "plugin/ardiff -cnlt arscript-1 ${RLTDIR}/kDep.a kDep.a" work false
