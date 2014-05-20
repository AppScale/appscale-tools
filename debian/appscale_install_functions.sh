#!/bin/sh
# Common functions for build and installer
#
# This should work in bourne shell (/bin/sh)
# The function name should not include non alphabet charactor.
#
# Written by Yoshi <nomura@pobox.com>

set -e

if [ -z "$APPSCALE_TOOLS_HOME" ]; then
    export APPSCALE_TOOLS_HOME=/root/appscale
fi

# The command to use to install python packages not belonging to the
# distribution.
export INSTALL_CMD=""

pip_wrapper () 
{
  # pip 1.0 has issues, so we revert to easy_install in this case.
  if [ -z "$INSTALL_CMD" ]; then
    case  $(pip --version|awk '{print $2}') in
    "1.0")
      INSTALL_CMD="$(which easy_install)"
      ;;
    *)
      INSTALL_CMD="$(which pip) install"
      ;;
    esac
  fi
  if [ -z "INSTALL_CMD" ]; then
    echo "Cannot find either pip or easy_install!"
    exit 1
  fi

  # We have seen quite a few network/DNS issues lately, so much so that
  # it takes a couple of tries to install packages with pip. This
  # wrapper ensure that we are a bit more persitent.
  if [ -n "$1" ] ; then
    for x in 1 2 3 4 5 ; do
      if $INSTALL_CMD --upgrade $1 ; then
        return
      else
        echo "Failed to install $1: retrying ..."
        sleep $x
      fi
    done
    echo "Failed to install $1: giving up."
    exit 1
  else
    "Need an argument for $INSTALL_CMD!"
    exit 1
  fi
}

installsetuptools()
{
  pip_wrapper setuptools
}

installpylibs()
{
  pip_wrapper termcolor
  pip_wrapper SOAPpy
  pip_wrapper pyyaml
  pip_wrapper boto
  pip_wrapper oauth2client
  pip_wrapper google-api-python-client
  pip_wrapper argparse
  pip_wrapper python-gflags
}

installappscaletools()
{
    # add to path
    mkdir -p ${DESTDIR}/etc/profile.d
    cat > ${DESTDIR}/etc/profile.d/appscale-tools.sh <<EOF
export TOOLS_PATH=/usr/local/appscale-tools
export PATH=\${PATH}:\${TOOLS_PATH}/bin
EOF

    cat >> ~/.bashrc <<EOF
export TOOLS_PATH=/usr/local/appscale-tools
export PATH=\${PATH}:\${TOOLS_PATH}/bin
EOF
}

keygen()
{
    # create ssh private key if it does not exist
    test -e /root/.ssh/id_rsa || ssh-keygen -q -t rsa -f /root/.ssh/id_rsa -N ""
}
