# $Id$
inittest usage-ab tc/usage-ab
runcmd "${AR} mab bar.o foo.a bar2.o" work true
rundiff true
