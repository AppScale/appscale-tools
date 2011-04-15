#!/bin/sh

DIST=`lsb_release -c -s`
cd `dirname $0`/..

if [ ! -e ./debian/appscale_install_${DIST}.sh ]; then
  echo "${DIST} is not supported."
  exit 1
fi

RELEASE=$1
if [ -z "$RELEASE" ]; then
    RELEASE="test"
fi

cp -v debian/changelog.${DIST} debian/changelog || exit 1
REVNO=`bzr revno`
sed -i -e s/REVNO/$REVNO/g debian/changelog || exit 1

cp -v debian/control.${DIST} debian/control || exit 1
#cp debian/rules.${DIST} debian/rules || exit 1

if [ -e ./debian/postinst.${DIST} ]; then
    cat debian/appscale_install_functions.sh > debian/postinst
    cat debian/postinst.${DIST} >> debian/postinst
else
    rm -f debian/postinst
fi

DESTDIR=`pwd`/debian/appscale-tools
if [ -e ${DESTDIR} ]; then
    rm -rf ${DESTDIR}
fi

fakeroot make -f debian/rules binary DIST=${DIST} DESTDIR=${DESTDIR}
if [ $? = 0 ]; then
    mkdir -p debian/pool/${DIST}-${RELEASE}
    mv -v ../appscale-tools*.deb debian/pool/${DIST}-${RELEASE} || exit 1
    rm -r ${DESTDIR}
fi
exit $?
