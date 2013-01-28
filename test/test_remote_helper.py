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
import boto
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appscale_logger import AppScaleLogger
from custom_exceptions import AppScaleException
from local_state import APPSCALE_VERSION
from local_state import LocalState
from node_layout import NodeLayout
from remote_helper import RemoteHelper


class TestRemoteHelper(unittest.TestCase):


  def setUp(self):
    # mock out all logging, since it clutters our output
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # mock out all sleeps, as they aren't necessary for unit testing
    flexmock(time)
    time.should_receive('sleep').and_return()

    # set up some fake options so that we don't have to generate them via
    # ParseArgs
    self.options = flexmock(infrastructure='ec2', group='boogroup',
      machine='ami-ABCDEFG', instance_type='m1.large', keyname='bookey',
      table='cassandra')
    self.node_layout = NodeLayout(self.options)

    # mock out calls to EC2
    # begin by assuming that our ssh keypair doesn't exist, and thus that we
    # need to create it
    key_contents = "key contents here"
    fake_key = flexmock(name="fake_key", material=key_contents)

    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_key_pair').with_args('bookey').and_return(None)
    fake_ec2.should_receive('create_key_pair').with_args('bookey') \
      .and_return(fake_key)

    # also, mock out the keypair writing and chmod'ing
    ssh_key_location = LocalState.LOCAL_APPSCALE_PATH + "bookey.key"
    fake_file = flexmock(name="fake_file")
    fake_file.should_receive('write').with_args(key_contents).and_return()

    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through
    builtins.should_receive('open').with_args(ssh_key_location, 'w') \
      .and_return(fake_file)

    flexmock(os)
    os.should_receive('chmod').with_args(ssh_key_location, 0600).and_return()

    # next, assume there are no security groups up yet
    fake_ec2.should_receive('get_all_security_groups').and_return([])

    # and then assume we can create and open our security group fine
    fake_ec2.should_receive('create_security_group').with_args('boogroup',
      'AppScale security group').and_return()
    fake_ec2.should_receive('authorize_security_group').and_return()

    # next, add in mocks for run_instances
    # the first time around, let's say that no machines are running
    # the second time around, let's say that our machine is pending
    # and that it's up the third time around
    fake_pending_instance = flexmock(state='pending')
    fake_pending_reservation = flexmock(instances=fake_pending_instance)

    fake_running_instance = flexmock(state='running', key_name='bookey',
      id='i-12345678', public_dns_name='public1', private_dns_name='private1')
    fake_running_reservation = flexmock(instances=fake_running_instance)

    fake_ec2.should_receive('get_all_instances').and_return([]) \
      .and_return([fake_pending_reservation]) \
      .and_return([fake_running_reservation])

    # next, assume that our run_instances command succeeds
    fake_ec2.should_receive('run_instances').and_return()

    # finally, inject our mocked EC2
    flexmock(boto)
    boto.should_receive('connect_ec2').with_args('baz', 'baz').and_return(fake_ec2)

    # assume that ssh comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      RemoteHelper.SSH_PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)
    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

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

    # and assume that we can ssh in as ubuntu to enable root login, but that
    # it fails the first time
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('ubuntu'), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.failed).and_return(self.success)

    # also assume that we can scp over our ssh keys, but that it fails the first
    # time
    subprocess.should_receive('Popen').with_args(re.compile('/root/.ssh/id_'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).and_return(self.failed).and_return(self.success)


  def test_start_head_node_in_cloud_but_ami_not_appscale(self):
    # mock out our attempts to find /etc/appscale and presume it doesn't exist
    subprocess.should_receive('Popen').with_args(re.compile('/etc/appscale'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).and_return(self.failed)

    self.assertRaises(AppScaleException, RemoteHelper.start_head_node,
      self.options, self.node_layout)


  def test_start_head_node_in_cloud_but_ami_wrong_version(self):
    # mock out our attempts to find /etc/appscale and presume it does exist
    subprocess.should_receive('Popen').with_args(re.compile('/etc/appscale'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    # mock out our attempts to find /etc/appscale/version and presume it doesn't
    # exist
    subprocess.should_receive('Popen').with_args(re.compile(
      '/etc/appscale/{0}'.format(APPSCALE_VERSION)),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.failed)

    self.assertRaises(AppScaleException, RemoteHelper.start_head_node,
      self.options, self.node_layout)


  def test_start_head_node_in_cloud_but_using_unsupported_database(self):
    # mock out our attempts to find /etc/appscale and presume it does exist
    subprocess.should_receive('Popen').with_args(re.compile('/etc/appscale'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    # mock out our attempts to find /etc/appscale/version and presume it does
    # exist
    subprocess.should_receive('Popen').with_args(re.compile(
      '/etc/appscale/{0}'.format(APPSCALE_VERSION)),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    # finally, put in a mock indicating that the database the user wants
    # isn't supported
    subprocess.should_receive('Popen').with_args(re.compile(
      '/etc/appscale/{0}/{1}'.format(APPSCALE_VERSION, 'cassandra')),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.failed)

    self.assertRaises(AppScaleException, RemoteHelper.start_head_node,
      self.options, self.node_layout)
