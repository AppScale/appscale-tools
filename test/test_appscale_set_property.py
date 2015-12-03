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


class TestAppScaleSetProperty(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-set-property"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('success').and_return()
    AppScaleLogger.should_receive('warn').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()


  def test_get_property(self):
    # put in a mock for reading the secret file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out finding the shadow node's IP address from the json file
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_secret")
    fake_nodes_json.should_receive('read').and_return(json.dumps([{
      'public_ip' : 'public1',
      'private_ip' : 'private1',
      'jobs' : ['login', 'shadow']
     }]))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out grabbing the userappserver ip from an appcontroller
    property_name = "name"
    property_value = "value"
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('set_property').with_args(property_name,
      property_value, 'the secret').and_return('OK')

    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    argv = [
      "--keyname", self.keyname,
      "--property_name", property_name,
      "--property_value", property_value
    ]
    options = ParseArgs(argv, self.function).args

    result = AppScaleTools.set_property(options)
    self.assertEqual(None, result)
