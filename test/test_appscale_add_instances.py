#!/usr/bin/env python


# General-purpose Python library imports
import json
import os
import re
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
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.custom_exceptions import BadConfigurationException
from appscale.tools.local_state import LocalState
from appscale.tools.parse_args import ParseArgs


class TestAppScaleAddInstances(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-add-instances"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    self.fake_temp_file = flexmock(name='fake_temp_file')
    self.fake_temp_file.should_receive('seek').with_args(0).and_return()
    self.fake_temp_file.should_receive('read').and_return('boo out')
    self.fake_temp_file.should_receive('close').and_return()

    self.fake_input_file = flexmock(name='fake_input_file')
    self.fake_input_file.should_receive('seek').with_args(0).and_return()
    self.fake_input_file.should_receive('write').and_return()
    self.fake_input_file.should_receive('read').and_return('boo out')
    self.fake_input_file.should_receive('close').and_return()

    flexmock(tempfile)
    tempfile.should_receive('NamedTemporaryFile').and_return(self.fake_temp_file)
    tempfile.should_receive('TemporaryFile').and_return(self.fake_input_file)


    self.success = flexmock(name='success', returncode=0)
    self.success.should_receive('wait').and_return(0)


  def test_add_master_nodes_in_virt_deployment(self):
    # don't use a 192.168.X.Y IP here, since sometimes we set our virtual
    # machines to boot with those addresses (and that can mess up our tests).
    ips_yaml = """
master: 1.2.3.4
database: 1.2.3.4
zookeeper: 1.2.3.4
appengine: 1.2.3.4
    """

    # mock out reading the yaml file, and slip in our own
    fake_yaml_file = flexmock(name='fake_yaml')
    fake_yaml_file.should_receive('read').and_return(ips_yaml)

    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through
    builtins.should_receive('open').with_args('/tmp/boo.yaml', 'r') \
      .and_return(fake_yaml_file)

    argv = [
      "--ips", "/tmp/boo.yaml",
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(BadConfigurationException, AppScaleTools.add_instances,
      options)


  def test_add_nodes_in_virt_deployment(self):
    # don't use a 192.168.X.Y IP here, since sometimes we set our virtual
    # machines to boot with those addresses (and that can mess up our tests).
    ips_yaml = """
database: 1.2.3.4
zookeeper: 1.2.3.4
appengine: 1.2.3.4
    """

    # mock out reading the yaml file, and slip in our own
    fake_yaml_file = flexmock(name='fake_yaml')
    fake_yaml_file.should_receive('read').and_return(ips_yaml)
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through
    builtins.should_receive('open').with_args('/tmp/boo.yaml', 'r') \
      .and_return(fake_yaml_file)

    # and pretend we're on a virtualized cluster
    locations_yaml = yaml.dump({
      "infrastructure" : "xen"
    })

    # say that the ssh key works
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('ssh'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT,
      stdin=self.fake_input_file) \
      .and_return(self.success)

    # mock out reading the locations.json file, and slip in our own json
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(json.dumps({
      "node_info": [{ "public_ip": "public1",
                      "private_ip": "private1",
                      "jobs": ["shadow", "login"] }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out writing the secret key to ~/.appscale, as well as reading it
    # later
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out the SOAP call to the AppController and assume it succeeded
    json_node_info = json.dumps(yaml.safe_load(ips_yaml))
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('start_roles_on_nodes') \
      .with_args(json_node_info, 'the secret').and_return('OK')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    argv = [
      "--ips", "/tmp/boo.yaml",
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.add_instances(options)
