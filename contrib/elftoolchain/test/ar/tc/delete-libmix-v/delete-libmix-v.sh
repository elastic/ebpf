# $Id$
inittest delete-libmix-v tc/delete-libmix-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} dv libmix.a a2_non_elf.o" work true
runcmd "plugin/teraser -ce -t delete-libmix-v libmix.a" work false
runcmd "plugin/teraser -e libmix.a" result false
rundiff true
