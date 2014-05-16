#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=n/a

install_pip
installappscaletools
installsetuptools
installpylibs
keygen

