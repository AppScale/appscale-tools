#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=trusty

installappscaletools
installsetuptools
installpylibs
keygen
