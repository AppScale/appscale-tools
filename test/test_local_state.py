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
import local_state


class TestLocalState(unittest.TestCase):


  def setUp(self):
    """
    # let's say that our ~/.appscale directory
    # already exists
    flexmock(os)
    flexmock(os.path)
    os.path.should_receive('exists') \
      .with_args(local_state.LOCAL_APPSCALE_PATH) \
      .and_return(True)

    # also, let's say that any Python libraries
    # already exist
    lib = re.compile('/System/.*')
    os.path.should_receive('exists') \
      .with_args(lib) \
      .and_return(True)
"""
