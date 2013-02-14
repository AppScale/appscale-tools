#!/bin/sh

cd `dirname $0`/..

# install euca2ools
brew install wget python ssh-copy-id
pip install boto M2Crypto
wget https://github.com/eucalyptus/euca2ools/tarball/2.1.0 -O euca2ools-2.1.0.tar.gz
tar xvf euca2ools-2.1.0.tar.gz
mv eucalyptus-euca2ools-c5c7caa euca2ools-2.1.0
cd euca2ools-2.1.0
python setup.py build
python setup.py install
cd ..
rm -rf euca2ools-2.1.0 euca2ools-2.1.0.tar.gz

# copy tools files
TARGETDIR=/usr/local/appscale-tools
mkdir -p $TARGETDIR
cp -r bin lib templates LICENSE README $TARGETDIR || exit 1

# from installrubylibs
echo 'Please enter your password for the command "gem install json flexmock"'
sudo gem install json flexmock

# from installpylibs
easy_install termcolor M2Crypto SOAPpy pyyaml boto==2.6 argparse

# from installec2ools
brew install ec2-api-tools 

# create ssh private key if it does not exist
test -e ~/.ssh/id_rsa || ssh-keygen -q -t rsa -f ~/.ssh/id_rsa -N ""