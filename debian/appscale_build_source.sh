#!/bin/bash

DIST="source"

cd `dirname $0`/..

if [ ! -e ./debian/appscale_install_${DIST}.sh ]; then
    echo "${DIST} install is not supported."
    exit 1
fi

echo "${DIST} install"

# check runtime dependency
hash ssh 2>&- || { echo >&2 "The tools require ssh but it's not installed.  Aborting."; exit 1; }

hash swig  2>&- || { echo >&2 "The tools require swig but it's not installed.  Aborting."; exit 1; }

hash ruby1.8 2>&- || { echo >&2 "The tools require ruby1.8 but it's not installed or softlinked to ruby. If you have ruby installed and it is version 1.8, run 'ln -s ruby ruby1.8' in the directory the ruby binary resides in. Aborting."; exit 1; }

hash curl 2>&- || { echo >&2 "The tools require curl but it's not installed.  Aborting."; exit 1; }
echo "check"

ruby1.8 -e "require 'openssl'" || { echo >&2 "The tools require the ruby openssl library installed. Aborting." ; exit 1; }
echo "Requirements met. Installing tools"

# copy tools files
TARGETDIR=/usr/local/appscale-tools
mkdir -p $TARGETDIR
cp -rv bin lib templates $TARGETDIR || exit 1
cp -v CHANGELOG LICENSE README $TARGETDIR || exit 1

# CentOS specific 
lsbout=`lsb_release -a`
letter_seq=CentOS
if echo "$lsbout" | grep -q "$letter_seq"
then
  echo "CentOS operating system found. Checking for euca2ools..."
  hash euca-describe-instances > /dev/null 2>&1
  if [ $? -ne 0 ] && [ ! -f /usr/local/bin/euca-run-instances ]; then
    echo "Please install the CentOS euca2ools package (http://open.eucalyptus.com/downloads). Aborting."; exit 1;
  else
    echo "Found euca2ools!"
  fi 
else
  hash help2man 2>&- || { echo >&2 "The tools require help2man but it's not installed.  If you do not need man pages for the euca2ools then you can turn this check off in debian/appscale_build_source.sh. Aborting."; exit 1; }
fi

# install scripts

bash debian/appscale_install_${DIST}.sh all
if [ $? -ne 0 ]; then
    echo "Unable to complete AppScale tools installation."
    exit 1
fi
echo "AppScale tools installation completed successfully!"
