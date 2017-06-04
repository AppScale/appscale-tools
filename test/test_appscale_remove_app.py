#!/usr/bin/env python


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
from appscale.tools.admin_client import AdminClient
from appscale.tools.admin_client import AdminError
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.custom_exceptions import AppScaleException
from appscale.tools.local_state import LocalState
from appscale.tools.parse_args import ParseArgs


class TestAppScaleRemoveApp(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-remove-app"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('success').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()
    

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

    flexmock(AdminClient).should_receive('delete_version').\
      and_raise(AdminError)

    # mock out reading the locations.json file, and slip in our own json
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    fake_nodes_json.should_receive('write').and_return()
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    argv = [
      "--appname", "blargapp",
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AdminError, AppScaleTools.remove_app, options)


  def test_remove_app_and_app_is_running(self):
    # mock out reading from stdin, and assume the user says 'YES'
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_receive('raw_input').and_return('YES')

    # mock out reading the secret key
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out reading the locations.json file, and slip in our own json
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    fake_nodes_json.should_receive('write').and_return()
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    operation_id = 'operation-1'
    flexmock(AdminClient).should_receive('delete_version').\
      and_return(operation_id)
    flexmock(AdminClient).should_receive('get_operation').\
      and_return({'done': True})

    argv = [
      "--appname", "blargapp",
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.remove_app(options)
