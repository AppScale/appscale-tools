#!/usr/bin/env python

# General-purpose Python library imports
import os
import tempfile
import time
import unittest

# Third party libraries
from flexmock import flexmock

# AppScale import, the library that we're testing here
from appscale.tools.agents.ec2_agent import EC2Agent
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.custom_exceptions import AppScaleException
from appscale.tools.local_state import LocalState
from appscale.tools.parse_args import ParseArgs
from appscale.tools.remote_helper import RemoteHelper


class TestAppScaleTerminateInstances(unittest.TestCase):

  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.group = "bazboogroup"
    self.function = "appscale-terminate-instances"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('verbose').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    local_state = flexmock(LocalState)
    local_state.should_receive('shell').and_return("")

    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    self.fake_temp_file = flexmock(name='fake_temp_file')
    self.fake_temp_file.should_receive('read').and_return('boo out')
    self.fake_temp_file.should_receive('close').and_return()
    self.fake_temp_file.should_receive('seek').with_args(0).and_return()

    flexmock(tempfile)
    tempfile.should_receive('NamedTemporaryFile').and_return(self.fake_temp_file)

    self.success = flexmock(name='success', returncode=0)
    self.success.should_receive('wait').and_return(0)

    self.failed = flexmock(name='failed', returncode=1)
    self.failed.should_receive('wait').and_return(1)

    # throw in some mocks that assume our EC2 environment variables are set
    for credential in EC2Agent.REQUIRED_EC2_CREDENTIALS:
      os.environ[credential] = "baz"

  def tearDown(self):
    # remove the environment variables we set up to not accidentally mess
    # up other unit tests
    for credential in EC2Agent.REQUIRED_EC2_CREDENTIALS:
      os.environ[credential] = ""

  def test_terminate_when_not_running(self):
    # Deployment is configured for a cluster.
    flexmock(LocalState).should_receive('get_infrastructure').and_return('xen')

    # The secret key does not exist.
    flexmock(os.path).should_receive('exists').and_return(False)

    argv = ['--keyname', self.keyname,
            '--test']
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppScaleException, AppScaleTools.terminate_instances,
                      options)

  def test_terminate_in_virtual_cluster_and_succeeds(self):
    # Deployment is running on a cluster.
    flexmock(LocalState).should_receive('get_infrastructure').and_return('xen')

    # The secret key exists.
    flexmock(os.path).should_receive('exists').and_return(True)

    flexmock(RemoteHelper).should_receive('terminate_virtualized_cluster')

    argv = ['--keyname', self.keyname,
            '--test']
    options = ParseArgs(argv, self.function).args
    AppScaleTools.terminate_instances(options)

  def test_terminate_in_cloud_and_succeeds(self):
    # Deployment is running on EC2.
    flexmock(LocalState).should_receive('get_infrastructure').and_return('ec2')

    # The secret key exists.
    flexmock(os.path).should_receive('exists').and_return(True)

    flexmock(RemoteHelper).should_receive('terminate_virtualized_cluster')

    argv = ['--keyname', self.keyname,
            '--test']
    options = ParseArgs(argv, self.function).args
    AppScaleTools.terminate_instances(options)

  def test_terminate_in_gce_and_succeeds(self):
    # Deployment is running on GCE.
    flexmock(LocalState).should_receive('get_infrastructure').and_return('gce')

    # The secret key exists.
    flexmock(os.path).should_receive('exists').and_return(True)

    flexmock(RemoteHelper).should_receive('terminate_virtualized_cluster')

    argv = ['--keyname', self.keyname,
            '--test']
    options = ParseArgs(argv, self.function).args
    AppScaleTools.terminate_instances(options)
