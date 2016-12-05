#!/usr/bin/env python


# General-purpose Python library imports
import getpass
import json
import os
import sys
import time
import unittest


# Third party libraries
from flexmock import flexmock
import SOAPpy


# AppScale import, the library that we're testing here
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.local_state import LocalState
from appscale.tools.parse_args import ParseArgs


class TestAppScaleResetPassword(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-reset-pwd"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('success').and_return()
    AppScaleLogger.should_receive('warn').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()


  def test_reset_password_for_user_that_exists(self):
    # put in a mock for reading the secret file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out reading the username and new password from the user
    builtins.should_receive('raw_input').and_return('boo@foo.goo')
    flexmock(getpass)
    getpass.should_receive('getpass').and_return('the password')

    # mock out finding the login node's IP address from the json file
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_secret")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        'public_ip': 'public1',
        'private_ip': 'private1',
        'jobs': ['login', 'db_master']
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out grabbing the userappserver ip from an appcontroller
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('nothing interesting here') \
      .and_return('Database is at not-up-yet') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('reset_password').with_args(
      'boo@foo.goo', str, 'the secret').and_return('true')

    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    argv = [
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.reset_password(options)


  def test_reset_password_for_user_that_doesnt_exist(self):
    # put in a mock for reading the secret file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out reading the username and new password from the user
    builtins.should_receive('raw_input').and_return('boo@foo.goo')
    flexmock(getpass)
    getpass.should_receive('getpass').and_return('the password')

    # mock out finding the login node's IP address from the json file
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_secret")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        'public_ip': 'public1',
        'private_ip': 'private1',
        'jobs': ['login', 'db_master']
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out grabbing the userappserver ip from an appcontroller
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('nothing interesting here') \
      .and_return('Database is at not-up-yet') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('reset_password').with_args(
      'boo@foo.goo', str, 'the secret').and_return('false')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    argv = [
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(SystemExit, AppScaleTools.reset_password, options)
