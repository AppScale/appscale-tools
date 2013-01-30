#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import httplib
import os
import re
import sys
import unittest


# Third party testing libraries
import boto
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appscale_logger import AppScaleLogger
from parse_args import ParseArgs

from agents.ec2_agent import EC2Agent


class TestAppScaleLogger(unittest.TestCase):


  def setUp(self):
    # mock out printing to stdout
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_receive('print').and_return()

    # next, pretend our ec2 credentials are properly set
    for credential in EC2Agent.REQUIRED_CREDENTIALS:
      os.environ[credential] = "baz"

    # finally, pretend that our ec2 image to use exists
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()
    flexmock(boto)
    boto.should_receive('connect_ec2').with_args('baz', 'baz').and_return(fake_ec2)

    # do argument parsing here, since the below tests do it the
    # same way every time
    argv = ["--min", "1", "--max", "1", "--infrastructure",
      "ec2", "--machine", "ami-ABCDEFG"]
    function = "appscale-run-instances"
    self.options = ParseArgs(argv, function).args

    self.expected = {
      "appengine" : 1,
      "autoscale" : True,
      "min" : 1,
      "max" : 1,
      "infrastructure" : "ec2",
      "machine" : "ami-ABCDEFG",
      "force" : False,
      "group" : "appscale",
      "instance_type" : "m1.large",
      "ips" : None,
      "ips_layout" : None,
      "keyname" : "appscale",
      "n" : None,
      "scp" : None,
      "table" : "cassandra",
      "test" : False,
      "version" : False
    }

    # finally, construct a http payload for mocking that the below
    # tests can use
    self.payload = "?boo=baz&min=1&max=1&infrastructure=ec2" + \
      "&machine=ami-ABCDEFG&force=False&group=appscale" + \
      "&instance_type=m1.large&ips=None&keyname=appscale&n=None" + \
      "table=cassandra&test=False&version=False"


  def test_remote_log_tools_state_when_remote_is_up(self):
    # mock out the posting to the remote app
    fake_connection = flexmock(name="fake_connection")
    fake_connection.should_receive('request').with_args('POST',
      '/upload', self.payload, AppScaleLogger.HEADERS) \
      .and_return()
    flexmock(httplib).should_receive('HTTPSConnection') \
      .and_return(fake_connection)

    actual = AppScaleLogger.remote_log_tools_state(self.options, "started")
    self.assertEquals(self.expected, actual)


  def test_remote_log_tools_state_when_remote_is_down(self):
    # mock out the posting to the remote app, which should
    # fail since we're pretending the app is down
    fake_connection = flexmock(name="fake_connection")
    fake_connection.should_receive('request').with_args('POST',
      '/upload', self.payload, AppScaleLogger.HEADERS) \
      .and_raise(Exception)
    flexmock(httplib).should_receive('HTTPSConnection') \
      .and_return(fake_connection)

    actual = AppScaleLogger.remote_log_tools_state(self.options, "started")
    self.assertEquals(self.expected, actual)
