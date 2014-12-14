s3eTxmpp
========

Marmalade implementation of txmpp C++ xmpp client

The library is currently under development and thus is not usable. Use it on your own risk.


### Dependencies

 * [expat](https://github.com/marmalade/expat)
 * [openssl](https://github.com/muppetlabs/openssl_marmalade)
 
 To use expat remove the current expat folder from `modules\third_party` and replace with the github library. Now open the mkf and replace 

```
upstream
{
	url="http://source.ideaworks3d.com/upstream/expat-1.95.8.tar.gz"
}```

with 

```
upstream
{
	url="http://source.madewithmarmalade.com/upstream/expat-1.95.8.tar.gz"
}```

## Current Issues

 - An assert mentioning `unimplemented library function: pipe` and crashing at line 646 on physicalsocketserver.cpp