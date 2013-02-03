#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import base64
import httplib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import yaml


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
from local_state import APPSCALE_VERSION
from local_state import LocalState
from node_layout import NodeLayout
from parse_args import ParseArgs
from remote_helper import RemoteHelper
from user_app_client import UserAppClient


class TestAppScaleRemoveApp(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-remove-app"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()
    
    """
    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    self.fake_temp_file = flexmock(name='fake_temp_file')
    self.fake_temp_file.should_receive('read').and_return('boo out')
    self.fake_temp_file.should_receive('close').and_return()

    flexmock(tempfile)
    tempfile.should_receive('TemporaryFile').and_return(self.fake_temp_file)

    self.success = flexmock(name='success', returncode=0)
    self.success.should_receive('wait').and_return(0)

    self.failed = flexmock(name='success', returncode=1)
    self.failed.should_receive('wait').and_return(1)
    """


  def test_remove_app_but_user_cancels_it(self):
    # mock out reading from stdin, and assume the user says 'no'
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_receive('raw_input').and_return('no')

    argv = [
      "--appname", "blargapp"
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppScaleException, AppScaleTools.remove_app, options)


  def test_remove_app_but_app_isnt_running(self):
    # mock out reading from stdin, and assume the user says 'yes'
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_receive('raw_input').and_return('yes')

    # mock out reading the secret key
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('Database is at public1')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(json.dumps([{
      "public_ip" : "public1",
      "private_ip" : "private1",
      "jobs" : ["shadow", "login"]
    }]))
    fake_nodes_json.should_receive('write').and_return()
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out calls to the UserAppServer and presume that calls to create new
    # users succeed
    fake_userappserver = flexmock(name='fake_appcontroller')
    fake_userappserver.should_receive('get_app_data').with_args(
      'blargapp', 'the secret').and_return('Error: app does not exist')
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:4343') \
      .and_return(fake_userappserver)

    argv = [
      "--appname", "blargapp",
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppScaleException, AppScaleTools.remove_app, options)
