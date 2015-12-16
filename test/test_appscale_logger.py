#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import httplib
import os
import sys
import unittest


# Third party testing libraries
import boto
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from agents.ec2_agent import EC2Agent
from appscale_logger import AppScaleLogger
from parse_args import ParseArgs


class TestAppScaleLogger(unittest.TestCase):


  def setUp(self):
    # mock out printing to stdout
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_receive('print').and_return()

    # next, pretend our ec2 credentials are properly set
    for credential in EC2Agent.REQUIRED_CREDENTIALS:
      os.environ[credential] = "baz"

    # pretend that our credentials are valid.
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_all_instances')

    # Also pretend that the availability zone we want to use exists.
    fake_ec2.should_receive('get_all_zones').with_args('my-zone-1b') \
      .and_return('anything')

    # finally, pretend that our ec2 image to use exists
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()
    flexmock(boto.ec2)
    boto.ec2.should_receive('connect_to_region').with_args('my-zone-1',
      aws_access_key_id='baz', aws_secret_access_key='baz').and_return(fake_ec2)

    # do argument parsing here, since the below tests do it the
    # same way every time
    argv = ["--min", "1", "--max", "1", "--infrastructure", "ec2", "--machine",
      "ami-ABCDEFG", "--group", "blargscale", "--keyname", "appscale", "--zone",
      "my-zone-1b"]
    function = "appscale-run-instances"
    self.options = ParseArgs(argv, function).args
    self.my_id = "12345"

    self.expected = {
      "EC2_ACCESS_KEY" : None,
      "EC2_SECRET_KEY" : None,
      "EC2_URL" : None,
      "admin_pass" : None,
      "admin_user" : None,
      "alter_etc_resolv" : False,
      "appengine" : 1,
      "autoscale" : True,
      "client_secrets" : None,
      "clear_datastore" : False,
      "disks" : None,
      "min" : 1,
      "max" : 1,
      "infrastructure" : "ec2",
      "machine" : "ami-ABCDEFG",
      "flower_password" : ParseArgs.DEFAULT_FLOWER_PASSWORD,
      "force" : False,
      "group" : "blargscale",
      "gce_instance_type" : "n1-standard-1",
      "instance_type" : "m3.medium",
      "ips" : None,
      "ips_layout" : None,
      "keyname" : "appscale",
      "login_host" : None,
      "max_memory" : 400,
      "max_spot_price": None,
      "oauth2_storage" : None,
      "project" : None,
      "replication" : None,
      "scp" : None,
      "static_ip" : None,
      "table" : "cassandra",
      "test" : False,
      "use_spot_instances" : False,
      "user_commands" : [],
      "verbose" : False,
      "version" : False,
      "zone" : "my-zone-1b"
    }

    # finally, construct a http payload for mocking that the below
    # tests can use
    self.payload = "?boo=baz&min=1&max=1&infrastructure=ec2" + \
      "&machine=ami-ABCDEFG&force=False&group=appscale" + \
      "&instance_type=m3.medium&ips=None&keyname=appscale&n=None" + \
      "table=cassandra&test=False&version=False"


  def test_remote_log_tools_state_when_remote_is_up(self):
    # mock out the posting to the remote app
    fake_connection = flexmock(name="fake_connection")
    fake_connection.should_receive('request').with_args('POST',
      '/upload', self.payload, AppScaleLogger.HEADERS) \
      .and_return()
    flexmock(httplib).should_receive('HTTPConnection') \
      .and_return(fake_connection)

    actual = AppScaleLogger.remote_log_tools_state(self.options, self.my_id,
      "started", "X.Y.Z")
    self.assertEquals(self.expected, actual)


  def test_remote_log_tools_state_when_remote_is_down(self):
    # mock out the posting to the remote app, which should
    # fail since we're pretending the app is down
    fake_connection = flexmock(name="fake_connection")
    fake_connection.should_receive('request').with_args('POST',
      '/upload', self.payload, AppScaleLogger.HEADERS) \
      .and_raise(Exception)
    flexmock(httplib).should_receive('HTTPConnection') \
      .and_return(fake_connection)

    actual = AppScaleLogger.remote_log_tools_state(self.options, self.my_id,
    "started", "X.Y.Z")
    self.assertEquals(self.expected, actual)
