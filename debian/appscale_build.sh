#!/bin/bash

DIST=`lsb_release -c -s`

cd `dirname $0`/..

if [ ! -e ./debian/appscale_install_${DIST}.sh ]; then
    echo "${DIST} is not supported."
    exit 1
fi

echo "Ubuntu ${DIST}"

# install runtime dependency
# for distro
PACKAGES=`find debian -regex ".*\/control\.${DIST}\$" -exec mawk -f debian/package-list.awk {} +`
apt-get update
apt-get install -y ${PACKAGES}
if [ $? -ne 0 ]; then
    echo "Fail to install depending packages for runtime."
    exit 1
fi

# copy tools files
TARGETDIR=/usr/local/appscale-tools
mkdir -p $TARGETDIR
cp -rv bin lib templates $TARGETDIR || exit 1
cp -v CHANGELOG LICENSE README $TARGETDIR || exit 1

# install scripts

bash debian/appscale_install_${DIST}.sh all
if [ $? -ne 0 ]; then
    echo "Unable to complete AppScale tools installation."
    exit 1
fi
echo "AppScale tools installation completed successfully!"
