# $Id$
inittest usage-bi tc/usage-bi
runcmd "${AR} bi bar.o foo.a bar2.o" work true
rundiff true
