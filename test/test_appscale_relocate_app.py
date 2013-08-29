#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import json
import os
import sys
import time
import unittest


# Third party libraries
from flexmock import flexmock
import SOAPpy


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appscale_logger import AppScaleLogger
from appscale_tools import AppScaleTools
from local_state import LocalState
from parse_args import ParseArgs


class TestAppScaleRelocateApp(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-relocate-app"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('success').and_return()
    AppScaleLogger.should_receive('warn').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()


  def test_fails_if_destination_port_invalid(self):
    # If the user wants to relocate their app to port X, X should be a port
    # number that apps can actually be served on (e.g., between 1 and 65535).
    pass


  def test_fails_if_app_isnt_running(self):
    # If the user wants to relocate their app to port X, but their app isn't
    # even running, this should fail.
    argv = [

    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.relocate_app(options)


  def test_fails_if_destination_port_in_use(self):
    pass
