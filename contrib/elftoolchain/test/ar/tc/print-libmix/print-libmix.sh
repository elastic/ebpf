# $Id$
inittest print-libmix tc/print-libmix
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} p libmix.a" work true
rundiff true
