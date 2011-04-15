#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=jaunty

case "$1" in
    tools)
	installeuca2ools
	installappscaletools
	;;
    all)
	# scratch install of appscale including post script.
	installeuca2ools
	postinstalleuca2ools
	installappscaletools
	postinstallappscaletools
	keygen
	;;
esac
