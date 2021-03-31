# $Id$
inittest extract-libnonelf-v tc/extract-libnonelf-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} xv libnonelf.a" work true
rundiff true
