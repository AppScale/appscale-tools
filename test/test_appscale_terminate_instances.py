#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import re
import socket
import subprocess
import sys
import time
import unittest


# Third party libraries
from flexmock import flexmock
import M2Crypto
import SOAPpy


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appcontroller_client import AppControllerClient
from appscale_logger import AppScaleLogger
from appscale_tools import AppScaleTools
from custom_exceptions import AppScaleException
from custom_exceptions import BadConfigurationException
from local_state import LocalState
from parse_args import ParseArgs
from remote_helper import RemoteHelper


class TestAppScaleTerminateInstances(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-terminate-instances"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    fake_output = flexmock(name='out')
    fake_output.should_receive('read').and_return('boo out')
    fake_output.should_receive('close').and_return()

    fake_error = flexmock(name='err')
    fake_error.should_receive('read').and_return('boo err')
    fake_error.should_receive('close').and_return()

    self.success = flexmock(name='success', returncode=0, stdout=fake_output,
      stderr=fake_error)
    self.success.should_receive('wait').and_return(0)

    self.failed = flexmock(name='success', returncode=1)
    self.failed.should_receive('wait').and_return(1)


  def test_terminate_when_not_running(self):
    # let's say that there's no locations.yaml file, which means appscale isn't
    # running, so we should throw up and die
    flexmock(os.path)
    os.path.should_call('exists')  # set up the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_yaml_location(self.keyname)).and_return(False)

    argv = [
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppScaleException, AppScaleTools.terminate_instances,
      options)
