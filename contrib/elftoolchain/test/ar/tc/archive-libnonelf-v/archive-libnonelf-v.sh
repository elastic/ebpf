# $Id$
inittest archive-libnonelf-v tc/archive-libnonelf-v
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} cruv libnonelf.a a1_ne.o a2_ne.o a3_non_elf_has_a_long_name.o" work true
rundiff false
runcmd "plugin/ardiff -cnlt archive-libnonelf-v ${RLTDIR}/libnonelf.a libnonelf.a" work false
