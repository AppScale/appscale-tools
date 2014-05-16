#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=wheezy

installpip
installappscaletools
installsetuptools
installpylibs
keygen
