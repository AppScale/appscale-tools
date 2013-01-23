#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import re
import sys
import unittest


# Third party testing libraries
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from local_state import LocalState
from local_state import LOCAL_APPSCALE_PATH


class TestLocalState(unittest.TestCase):


  def setUp(self):
    # let's say that any python libraries exist
    flexmock(os)
    flexmock(os.path)
    lib = re.compile('/System/.*')
    os.path.should_receive('exists') \
      .with_args(lib) \
      .and_return(True)


  def test_make_appscale_directory_creation(self):
    # let's say that our ~/.appscale directory
    # does not exist
    os.path.should_receive('exists') \
      .with_args(LOCAL_APPSCALE_PATH) \
      .and_return(False) \
      .once()

    # thus, mock out making the appscale dir
    os.should_receive('mkdir') \
      .with_args(LOCAL_APPSCALE_PATH) \
      .and_return()

    LocalState.make_appscale_directory()
