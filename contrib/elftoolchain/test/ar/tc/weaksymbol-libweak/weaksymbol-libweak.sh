# $Id$
inittest weaksymbol-libweak tc/weaksymbol-libweak
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${AR} cru libweak.a quotactl.o" work true
runcmd "plugin/teraser -c -t weaksymbol-libweak libweak.a" work false
runcmd "plugin/ardiff -cnlt weaksymbol-libweak ${RLTDIR}/libweak.a libweak.a" work false

