#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=other

case "$1" in
    tools)
        #installexpect
        # For mac osx
        installsshcopyid
        installsetuptools
        #postinstallsetuptools

        installeuca2ools
        installec2ools

      	installappscaletools
	      postinstallappscaletools
	;;
    all)
	# scratch install of appscale including post script.
        #installexpect
        # For mac osx
        installsshcopyid
        installsetuptools
        #postinstallsetuptools

        installeuca2ools
        installec2ools

	      installappscaletools
	      postinstallappscaletools
	;;
esac
