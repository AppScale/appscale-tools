#!/bin/bash

export DIST=`lsb_release -c -s`

if [ "$DIST" = "n/a" ] ||  [ ! -e ./debian/appscale_install_${DIST}.sh ]; then
    echo "We do not have a build script for ${DIST}."
    echo "You can still install this package from source with 'python setup.py install'."
    exit 1
fi

cd `dirname $0`/..

echo "Installing Ubuntu ${DIST} building environment."

# Install the deb packages specified for this distro.
PACKAGES=`find debian -regex ".*\/control\.${DIST}\$" -exec mawk -f debian/package-list.awk {} +`
apt-get update
apt-get install -y --force-yes ${PACKAGES}
if [ $? -ne 0 ]; then
    echo "Failed to install deb packages for ${DIST}."
    exit 1
fi

# copy tools files
TARGETDIR=/usr/local/appscale-tools
mkdir -p $TARGETDIR
cp -rv bin lib templates $TARGETDIR || exit 1
cp -v LICENSE README.md $TARGETDIR || exit 1

# install scripts
bash debian/appscale_install_${DIST}.sh all
if [ $? -ne 0 ]; then
    echo "Unable to complete AppScale tools installation."
    exit 1
fi
echo "AppScale tools installation completed successfully!"
