#!/bin/sh
# Common functions for build and installer
#
# This should work in bourne shell (/bin/sh)
# The function name should not include non alphabet charactor.
#
# Written by Yoshi <nomura@pobox.com>

set -e

if [ -z "$APPSCALE_TOOLS_HOME" ]; then
    export APPSCALE_TOOLS_HOME=/root/appscale
fi

installexpect()
{
  echo "Installing expect"
  mkdir -pv ${APPSCALE_TOOLS_HOME}/downloads
  cd ${APPSCALE_TOOLS_HOME}/downloads
  curl -o expect5.45.tar.gz http://appscale.cs.ucsb.edu/appscale_files/expect5.45.tar.gz
  tar zxvf expect5.45.tar.gz
  pushd expect5.45
  ./configure
  make
  make install
  if [ -e ./libexpect5.45.so ]; then
    cp libexpect5.45.so /usr/lib || exit 
  fi
  if [ -e ./libexpect5.45.dylib ]; then
    cp libexpect5.45.dylib /usr/local/lib || exit 
  fi 
  popd 
  rm -fr expect5.45*
}

installsshcopyid()
{
  echo "Installing ssh-copy-id if needed."
  set +e
  hash ssh-copy-id > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    set -e
    echo "ssh-copy-id not found - installing."
    cd /usr/bin
    curl -o ssh-copy-id http://appscale.cs.ucsb.edu/appscale_files/ssh-copy-id
    chmod +x ./ssh-copy-id
  fi
  set -e
}

installsetuptools()
{
   echo "Installing setuptools if needed."
   set +e
   hash easy_install > /dev/null 2>&1
   if [ $? -ne 0 ]; then
     set -e
     echo "setuptools not found - installing."
     mkdir -pv ${APPSCALE_TOOLS_HOME}/downloads
     cd ${APPSCALE_TOOLS_HOME}/downloads
     curl -o setuptools-0.6c11.tar.gz http://appscale.cs.ucsb.edu/appscale_files/setuptools-0.6c11.tar.gz
     tar zxvf setuptools-0.6c11.tar.gz
     pushd setuptools-0.6c11
     python setup.py install
     popd
     rm -fr setuptools-0.6c11*
   fi
   set -e
}

installec2ools()
{
  echo "Installing EC2 tools if needed."
  set +e
  hash ec2-describe-instances > /dev/null 2>&1
  if [ $? -ne 0 ] && [ ! -f ${DESTDIR}/usr/local/bin/ec2-run-instances ]; then
    set -e
    echo "EC2 tools not found - installing."
    mkdir -p ${APPSCALE_TOOLS_HOME}/downloads
    cd ${APPSCALE_TOOLS_HOME}/downloads

    curl -o ec2-api-tools.zip http://s3.amazonaws.com/ec2-downloads/ec2-api-tools.zip
    curl -o ec2-ami-tools.zip http://s3.amazonaws.com/ec2-downloads/ec2-ami-tools.zip

    unzip ${APPSCALE_TOOLS_HOME}/downloads/ec2-api-tools*.zip
    unzip ${APPSCALE_TOOLS_HOME}/downloads/ec2-ami-tools*.zip
    rm -rf ${APPSCALE_TOOLS_HOME}/downloads/ec2-api-tools*.zip
    rm -rf ${APPSCALE_TOOLS_HOME}/downloads/ec2-ami-tools*.zip

    mkdir -p ${DESTDIR}/usr/local/bin
    mkdir -p  ${DESTDIR}/usr/local/ec2-api-tools
    mkdir -p  ${DESTDIR}/usr/local/ec2-ami-tools

    rm -fr ${DESTDIR}/usr/local/ec2-ami-tools/*
    rm -fr ${DESTDIR}/usr/local/ec2-api-tools/*

    mv -f ${APPSCALE_TOOLS_HOME}/downloads/ec2-ami-tools*/* ${DESTDIR}/usr/local/ec2-ami-tools
    mv -f ${APPSCALE_TOOLS_HOME}/downloads/ec2-api-tools*/* ${DESTDIR}/usr/local/ec2-api-tools

    rm -fr  ${APPSCALE_TOOLS_HOME}/downloads/ec2-ami-tools*/
    rm -fr  ${APPSCALE_TOOLS_HOME}/downloads/ec2-api-tools*/

    mkdir -p ${DESTDIR}/etc/profile.d
    cat > ${DESTDIR}/etc/profile.d/ec2.sh <<EOF
export PATH=/usr/local/ec2-api-tools/bin:\$PATH
export PATH=/usr/local/ec2-ami-tools/bin:\$PATH
export EC2_HOME=/usr/local/ec2-api-tools
EOF
    cp /usr/local/ec2-api-tools/bin/* ${DESTDIR}/usr/local/bin 
    cp /usr/local/ec2-ami-tools/bin/* ${DESTDIR}/usr/local/bin 
 fi
 set -e
}

installpylibs()
{
  easy_install termcolor
  easy_install M2Crypto
  easy_install SOAPpy
  easy_install pyyaml
  easy_install boto==2.6
  easy_install argparse
}

installgem()
{
  echo "Installing gem if needed."
  set +e
  hash gem > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    set -e
    echo "gem not found - installing."
    cd
    wget http://appscale.cs.ucsb.edu/appscale_files/rubygems-1.3.7.tgz
    tar zxvf rubygems-1.3.7.tgz
    cd rubygems-1.3.7
    ruby setup.rb
    cd
    ln -sf /usr/bin/gem1.8 /usr/bin/gem
    rm -rf rubygems-1.3.7.tgz
    rm -rf rubygems-1.3.7
  fi
  set -e
}

installrubylibs()
{
  echo "Installing specific Ruby gems."
  GEMDEST=${DESTDIR}/var/lib/gems/1.8
  GEMOPT="--no-rdoc --no-ri"
  gem install json flexmock ${GEMOPT}

  # Rake 10.0 depecates rake/rdoctask - upgrade later
  gem install -v=0.9.2.2 rake ${GEMOPT}
}

installappscaletools()
{
    # add to path
    mkdir -p ${DESTDIR}/etc/profile.d
    cat > ${DESTDIR}/etc/profile.d/appscale-tools.sh <<EOF
export TOOLS_PATH=/usr/local/appscale-tools
export PATH=\${PATH}:\${TOOLS_PATH}/bin
EOF

    cat >> ~/.bashrc <<EOF
export TOOLS_PATH=/usr/local/appscale-tools
export PATH=\${PATH}:\${TOOLS_PATH}/bin
EOF
}

keygen()
{
    # create ssh private key if it does not exist
    test -e /root/.ssh/id_rsa || ssh-keygen -q -t rsa -f /root/.ssh/id_rsa -N ""
}
