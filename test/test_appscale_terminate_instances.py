#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import yaml


# Third party libraries
from flexmock import flexmock
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
    AppScaleLogger.should_receive('verbose').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    self.fake_temp_file = flexmock(name='fake_temp_file')
    self.fake_temp_file.should_receive('read').and_return('boo out')
    self.fake_temp_file.should_receive('close').and_return()

    flexmock(tempfile)
    tempfile.should_receive('TemporaryFile').and_return(self.fake_temp_file)

    self.success = flexmock(name='success', returncode=0)
    self.success.should_receive('wait').and_return(0)

    self.failed = flexmock(name='failed', returncode=1)
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


  def test_terminate_in_virtual_cluster_and_succeeds(self):
    # let's say that there is a locations.yaml file, which means appscale is
    # running, so we should terminate the services on each box
    flexmock(os.path)
    os.path.should_call('exists')  # set up the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_yaml_location(self.keyname)).and_return(True)

    # mock out reading the locations.yaml file, and pretend that we're on
    # a virtualized cluster
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')

    fake_yaml_file = flexmock(name='fake_file')
    fake_yaml_file.should_receive('read').and_return(yaml.dump({
      'infrastructure' : 'xen'
    }))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_yaml_location(self.keyname), 'r') \
      .and_return(fake_yaml_file)

    # mock out reading the json file, and pretend that we're running in a
    # two node deployment
    fake_json_file = flexmock(name='fake_file')
    fake_json_file.should_receive('read').and_return(json.dumps([
      {
        'public_ip' : 'public1',
        'jobs' : ['shadow']
      },
      {
        'public_ip' : 'public2',
        'jobs' : ['appengine']
      }
    ]))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_json_file)

    # and slip in a fake secret file
    fake_secret_file = flexmock(name='fake_file')
    fake_secret_file.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(
      LocalState.get_secret_key_location(self.keyname), 'r') \
      .and_return(fake_secret_file)

    # mock out talking to the appcontroller, and assume that it tells us there
    # there are still two machines in this deployment
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return(json.dumps(['public1', 'public2']))

    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # and mock out the ssh call to kill the remote appcontroller, assuming that
    # it fails the first time and passes the second
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('controller stop'),
      shell=True, stdout=self.fake_temp_file, stderr=sys.stdout) \
      .and_return(self.failed).and_return(self.success)

    # next, mock out our checks to see how the stopping process is going and
    # assume that it isn't stopped the first time, and is the second
    still_running = flexmock(name='fake_temp_file')
    still_running.should_receive('read').and_return('service appscale-controller stop')
    still_running.should_receive('close').and_return()

    not_running = flexmock(name='fake_temp_file')
    not_running.should_receive('read').and_return('')
    not_running.should_receive('close').and_return()

    flexmock(tempfile)
    tempfile.should_receive('TemporaryFile').and_return(self.fake_temp_file) \
      .and_return(still_running).and_return(not_running)

    subprocess.should_receive('Popen').with_args(re.compile('ps x'),
      shell=True, stdout=still_running, stderr=sys.stdout) \
      .and_return(self.success)

    subprocess.should_receive('Popen').with_args(re.compile('ps x'),
      shell=True, stdout=not_running, stderr=sys.stdout) \
      .and_return(self.success)

    # finally, mock out removing the yaml file, json file, and secret key from
    # this machine
    flexmock(os)
    os.should_receive('remove').with_args(
      LocalState.get_locations_yaml_location(self.keyname)).and_return()
    os.should_receive('remove').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return()
    os.should_receive('remove').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return()

    argv = [
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.terminate_instances(options)
