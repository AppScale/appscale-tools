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
from custom_exceptions import BadConfigurationException
from local_state import LocalState


class TestLocalState(unittest.TestCase):


  def setUp(self):
    # let's say that any python libraries exist
    flexmock(os)
    flexmock(os.path)
    lib = re.compile('/System/.*')
    os.path.should_receive('exists') \
      .with_args(lib) \
      .and_return(True)

    self.keyname = "booscale"
    self.locations_yaml = LocalState.LOCAL_APPSCALE_PATH + "locations-" + \
      self.keyname + ".yaml"


  def test_make_appscale_directory_creation(self):
    # let's say that our ~/.appscale directory
    # does not exist
    os.path.should_receive('exists') \
      .with_args(LocalState.LOCAL_APPSCALE_PATH) \
      .and_return(False) \
      .once()

    # thus, mock out making the appscale dir
    os.should_receive('mkdir') \
      .with_args(LocalState.LOCAL_APPSCALE_PATH) \
      .and_return()

    LocalState.make_appscale_directory()


  def test_ensure_appscale_isnt_running_but_it_is(self):
    # if there is a locations.yaml file and force isn't set,
    # we should abort
    os.path.should_receive('exists').with_args(self.locations_yaml) \
      .and_return(True)

    self.assertRaises(BadConfigurationException,
      LocalState.ensure_appscale_isnt_running, self.keyname,
      False)


  def test_ensure_appscale_isnt_running_but_it_is_w_force(self):
    # if there is a locations.yaml file and force is set,
    # we shouldn't abort
    os.path.should_receive('exists').with_args(self.locations_yaml) \
      .and_return(True)

    LocalState.ensure_appscale_isnt_running(self.keyname, True)


  def test_ensure_appscale_isnt_running_and_it_isnt(self):
    # if there isn't a locations.yaml file, we're good to go
    os.path.should_receive('exists').with_args(self.locations_yaml) \
      .and_return(False)

    LocalState.ensure_appscale_isnt_running(self.keyname, False)
