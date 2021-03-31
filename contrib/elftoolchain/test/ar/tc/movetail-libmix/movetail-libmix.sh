# $Id$
inittest movetail-libmix tc/movetail-libmix
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} m libmix.a a1_has_a_long_file_name.o" work true
runcmd "plugin/teraser -ce -t movetail-libmix libmix.a" work false
runcmd "plugin/teraser -e libmix.a" result false
rundiff true
