# $Id$
inittest strip-onlydebug-1 tc/strip-onlydebug-1
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${STRIP} --only-keep-debug -o sections.o.1 sections.o" work true
rundiff true
