#!/bin/bash

. debian/appscale_install_functions.sh

DESTDIR=$2
DIST=precise

instapp_pip
installappscaletools
installsetuptools
installpylibs
keygen
