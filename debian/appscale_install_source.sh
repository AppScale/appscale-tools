#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=other

case "$1" in
    tools)
        installpylibs
      	installappscaletools
	postinstallappscaletools
	;;
    all)
        installpylibs
	installappscaletools
	postinstallappscaletools
	;;
esac
