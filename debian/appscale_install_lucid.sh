#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=lucid

case "$1" in
    tools)
	installappscaletools
        installpylibs
	;;
    all)
	# scratch install of appscale including post script.
	installappscaletools
	postinstallappscaletools
        installsetuptools
        installpylibs
        installec2ools
	keygen
	;;
esac
