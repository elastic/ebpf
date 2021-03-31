# $Id$
inittest delete-liblong tc/delete-liblong
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} d liblong.a a2_is_15_long.o a4_is_16_long_.o" work true
runcmd "plugin/teraser -ce -t delete-liblong liblong.a" work false
runcmd "plugin/teraser -e liblong.a" result false
rundiff true
