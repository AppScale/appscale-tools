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

# only for the jaunty
installeuca2ools()
{
# EC2
    mkdir -p ${APPSCALE_HOME}/downloads
    cd ${APPSCALE_HOME}/downloads
    wget http://appscale.cs.ucsb.edu/appscale_files/ec2-api-tools-1.3-30349.zip || exit 1
    wget http://appscale.cs.ucsb.edu/appscale_files/ec2-ami-tools-1.3-26357.zip || exit 1

    unzip ec2-api-tools-1.3-30349.zip || exit 1
    unzip ec2-ami-tools-1.3-26357.zip || exit 1
    rm ec2-api-tools-1.3-30349.zip
    rm ec2-ami-tools-1.3-26357.zip

    mv ec2-api-tools-1.3-30349 ec2-api-tools
    mv ec2-ami-tools-1.3-26357/* ec2-api-tools/ # should say directory not empty for bin and lib, that's fine
    mv ec2-ami-tools-1.3-26357/bin/* ec2-api-tools/bin/
    mv ec2-ami-tools-1.3-26357/lib/* ec2-api-tools/lib/
    mkdir -p ${DESTDIR}/usr/local
    mv ec2-api-tools ${DESTDIR}/usr/local/
    rm -r ec2-ami-tools-1.3-26357

# Eucalyptus
#    cd ${APPSCALE_HOME}/downloads
#    wget http://kings.cs.ucsb.edu/appscale_files/euca2ools-1.0-src-deps.tar.gz
#    tar zvxf euca2ools-1.0-src-deps.tar.gz
#    rm euca2ools-1.0-src-deps.tar.gz
#    cd euca2ools-1.0-src-deps
#    tar zxvf boto-1.8d.tar.gz
#    cd boto-1.8d
#    python setup.py bdist_egg
#    python setup.py install --prefix=${DESTDIR}/usr
#    rm -r euca2ools-1.0-src-deps
    easy_install -U boto || exit 1

    cd ${APPSCALE_HOME}/downloads
    wget http://kings.cs.ucsb.edu/appscale_files/euca2ools-1.0.tar.gz || exit 1
    tar zxvf euca2ools-1.0.tar.gz || exit 1
    rm euca2ools-1.0.tar.gz
    cd euca2ools-1.0
    make PREFIX=${DESTDIR}/usr/local
    if [ -n "$DESTDIR" ]; then
	# copy egg
	mkdir -p ${DESTDIR}/usr/local/lib/python2.6/dist-packages/
	cp -v euca2ools/dist/euca2ools-*.egg ${DESTDIR}/usr/local/lib/python2.6/dist-packages/ || exit 1
	cp -rv /usr/local/lib/python2.6/dist-packages/boto-*.egg ${DESTDIR}/usr/local/lib/python2.6/dist-packages/ || exit 1
    fi
    cd ${APPSCALE_HOME}/downloads
    rm -r euca2ools-1.0

    mkdir -p ${DESTDIR}/etc/profile.d
    cat > ${DESTDIR}/etc/profile.d/ec2.sh <<EOF
export PATH=/usr/local/ec2-api-tools/bin:\$PATH
export EC2_HOME=/usr/local/ec2-api-tools
EOF
}

postinstalleuca2ools()
{
#    cd ${APPSCALE_HOME}/euca2ools-1.0-src-deps/boto-1.8d
#    python setup.py install
#    cd ${APPSCALE_HOME}/euca2ools-1.0
#    make
# just enable eggs
    easy_install boto
    easy_install euca2ools
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
