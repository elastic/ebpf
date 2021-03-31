# $Id$
inittest undefined-libsbrk tc/undefined-libsbrk
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} cru libsbrk.a sbrk.o" work true
runcmd "plugin/teraser -c -t undefined-libsbrk libsbrk.a" work false
runcmd "plugin/ardiff -cnlt undefined-libsbrk ${RLTDIR}/libsbrk.a libsbrk.a" work false

