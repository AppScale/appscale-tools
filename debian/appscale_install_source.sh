#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=other

case "$1" in
    tools)
        installsetuptools
        installpylibs
      	installappscaletools
	postinstallappscaletools
	;;
    all)
        installsetuptools
        installpylibs
	installappscaletools
	postinstallappscaletools
	;;
esac
