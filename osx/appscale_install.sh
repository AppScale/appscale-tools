#!/bin/sh

cd `dirname $0`/..

# copy tools files
TARGETDIR=/usr/local/appscale-tools
mkdir -p $TARGETDIR
cp -r bin lib templates LICENSE README.md $TARGETDIR || exit 1

# from installpylibs
easy_install termcolor M2Crypto SOAPpy pyyaml boto==2.6 argparse oauth2client google-api-python-client httplib2

# create ssh private key if it does not exist
test -e ~/.ssh/id_rsa || ssh-keygen -q -t rsa -f ~/.ssh/id_rsa -N ""
