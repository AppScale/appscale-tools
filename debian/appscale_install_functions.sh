#!/bin/sh
# Common functions for build and installer
#
# This should work in bourne shell (/bin/sh)
# The function name should not include non alphabet charactor.
#
# Written by Yoshi <nomura@pobox.com>

if [ -z "$APPSCALE_HOME_RUNTIME" ]; then
    export APPSCALE_HOME_RUNTIME=/root/appscale
fi

if [ -z "$APPSCALE_HOME" ]; then
    export APPSCALE_HOME=/root/appscale
fi


installexpect()
{
  mkdir -pv ${APPSCALE_HOME}/downloads
  cd ${APPSCALE_HOME}/downloads
  curl -o expect5.45.tar.gz http://appscale.cs.ucsb.edu/appscale_files/expect5.45.tar.gz || exit 1
  tar zxvf expect5.45.tar.gz || exit 1
  pushd expect5.45
  ./configure || exit 1
  make || exit 1
  make install  || exit 1
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
  hash ssh-copy-id > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    cd /usr/bin
    curl -o ssh-copy-id http://appscale.cs.ucsb.edu/appscale_files/ssh-copy-id || exit 1
    chmod +x ./ssh-copy-id
  fi
}
installsetuptools()
{
   mkdir -pv ${APPSCALE_HOME}/downloads
   cd ${APPSCALE_HOME}/downloads
   curl -o setuptools-0.6c11.tar.gz http://appscale.cs.ucsb.edu/appscale_files/setuptools-0.6c11.tar.gz  ||
 ext 1
   tar zxvf setuptools-0.6c11.tar.gz
   pushd setuptools-0.6c11
   python setup.py install  || exit 1
   popd
   rm -fr  setuptools-0.6c11*
}
postinstallsetuptools()
{
  :;
}

# only for the jaunty
installec2ools()
{
# EC2
  hash ec2-describe-instances > /dev/null 2>&1
if [ $? -ne 0 ] && [ ! -f ${DESTDIR}/usr/local/bin/ec2-run-instances ]; then
    mkdir -p ${APPSCALE_HOME}/downloads
    cd ${APPSCALE_HOME}/downloads

    curl -o ec2-api-tools.zip http://s3.amazonaws.com/ec2-downloads/ec2-api-tools.zip || exit 1
    curl -o ec2-ami-tools.zip http://s3.amazonaws.com/ec2-downloads/ec2-ami-tools.zip || exit 1

    unzip ${APPSCALE_HOME}/downloads/ec2-api-tools*.zip || exit 1
    unzip ${APPSCALE_HOME}/downloads/ec2-ami-tools*.zip || exit 1
    rm -rf ${APPSCALE_HOME}/downloads/ec2-api-tools*.zip
    rm -rf ${APPSCALE_HOME}/downloads/ec2-ami-tools*.zip

    mkdir -p ${DESTDIR}/usr/local/bin
    mkdir -p  ${DESTDIR}/usr/local/ec2-api-tools
    mkdir -p  ${DESTDIR}/usr/local/ec2-ami-tools

    rm -fr ${DESTDIR}/usr/local/ec2-ami-tools/*
    rm -fr ${DESTDIR}/usr/local/ec2-api-tools/*

    mv -f ${APPSCALE_HOME}/downloads/ec2-ami-tools*/* ${DESTDIR}/usr/local/ec2-ami-tools || exit 1
    mv -f ${APPSCALE_HOME}/downloads/ec2-api-tools*/* ${DESTDIR}/usr/local/ec2-api-tools || exit 1

    rm -fr  ${APPSCALE_HOME}/downloads/ec2-ami-tools*/ || exit 1
    rm -fr  ${APPSCALE_HOME}/downloads/ec2-api-tools*/ || exit 1    

    mkdir -p ${DESTDIR}/etc/profile.d
    cat > ${DESTDIR}/etc/profile.d/ec2.sh <<EOF
export PATH=/usr/local/ec2-api-tools/bin:\$PATH
export PATH=/usr/local/ec2-ami-tools/bin:\$PATH
export EC2_HOME=/usr/local/ec2-api-tools
EOF
    cp /usr/local/ec2-api-tools/bin/* ${DESTDIR}/usr/local/bin 
    cp /usr/local/ec2-ami-tools/bin/* ${DESTDIR}/usr/local/bin 
 fi
 easy_install boto==2.6
}

installpylibs()
{
  easy_install termcolor
  easy_install paramiko
}

installeuca2ools()
{
# Eucalyptus
  hash euca-run-instances > /dev/null 2>&1
  if [ $? -ne 0 ] && [ ! -f ${DESTDIR}/usr/local/bin/euca-run-instances ]; then
    easy_install -U boto || exit 1
    VERSION="1.3.1"
    cd ${APPSCALE_HOME}/downloads
    
    # Install deps 
    curl -o euca2ools-${VERSION}-src-deps.tar.gz http://appscale.cs.ucsb.edu/appscale_files/euca2ools-${VERSION}-src-deps.tar.gz || exit 1
    tar zvxf euca2ools-$VERSION-src-deps.tar.gz
    cd euca2ools-$VERSION-src-deps
    tar zxvf boto-1.9b.tar.gz
    cd boto-1.9b
    python setup.py install
    cd ..
    tar zxvf M2Crypto-0.20.2.tar.gz
    cd M2Crypto-0.20.2
    python setup.py install
    cd ..

    curl -o euca2ools-${VERSION}.tar.gz http://appscale.cs.ucsb.edu/appscale_files/euca2ools-${VERSION}.tar.gz  || exit 1
    tar zxvf euca2ools-${VERSION}.tar.gz || exit 1
    rm -rf euca2ools-${VERSION}.tar.gz
    cd euca2ools-${VERSION}
    make PREFIX=${DESTDIR}/usr/local
    easy_install euca2ools || exit 1
    
    cd ${APPSCALE_HOME}/downloads
    rm -fr euca2ools-${VERSION}
  fi
}

postinstalleuca2ools()
{
#    cd ${APPSCALE_HOME}/euca2ools-1.0-src-deps/boto-1.8d
#    python setup.py install
#    cd ${APPSCALE_HOME}/euca2ools-1.0
#    make
# just enable eggs
    #easy_install boto
    #easy_install euca2ools
    :;
}

installappscaletools()
{
#    mkdir -p ${DESTDIR}/usr/local
#    cd ${DESTDIR}/usr/local
# tar ball is old right now.
#    wget http://kings.cs.ucsb.edu/appscale_files/appscale-tools-1.3.tar.gz || exit 1
#    rm appscale-tools-1.3.tar.gz
# tools is copied by debian/rule file now.
#    bzr branch lp:appscale/trunk-tools appscale-tools || exit 1
#    rm -r appscale-tools/.bzr || exit 1

    # add to path
    mkdir -p ${DESTDIR}/etc/profile.d
    cat > ${DESTDIR}/etc/profile.d/appscale-tools.sh <<EOF
export TOOLS_PATH=/usr/local/appscale-tools
export PATH=\${PATH}:\${TOOLS_PATH}/bin
EOF
}

postinstallappscaletools()
{
    :;
}

keygen()
{
    # create ssh private key if it is not exists.
    test -e /root/.ssh/id_rsa || ssh-keygen -q -t rsa -f /root/.ssh/id_rsa -N ""
}
