#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=lucid

installappscaletools
installsetuptools
installpylibs
installec2ools
keygen
