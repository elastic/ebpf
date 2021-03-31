# $Id$
inittest usage-tx tc/usage-tx
runcmd "${AR} tx foo.a" work true
rundiff true
