# General-purpose Python library imports
import httplib
import sys
import unittest


# Third party testing libraries
import boto
from flexmock import flexmock


# AppScale import, the library that we're testing here
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.parse_args import ParseArgs


class TestAppScaleLogger(unittest.TestCase):

  def setUp(self):
    # mock out printing to stdout
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_receive('print').and_return()

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
    argv = ["--min", "1", "--max", "1", "--infrastructure", "ec2", "--instance_type",
      "m3.medium", "--machine", "ami-ABCDEFG", "--group", "blargscale", "--keyname",
      "appscale", "--zone", "my-zone-1b",  "--EC2_ACCESS_KEY", "baz",
      "--EC2_SECRET_KEY", "baz", "--update", "common"]
    function = "appscale-run-instances"
    self.options = ParseArgs(argv, function).args
    self.my_id = "12345"

    self.expected = {
      "autoscale" : True,
      "infrastructure" : "ec2",
    }

    # finally, construct a http payload for mocking that the below
    # tests can use
    self.payload = ("?boo=baz&my_id=12345&state=started&version=X.Y.Z"
                    "&infrastructure=ec2&autoscale=True")


  def test_remote_log_tools_state_when_remote_is_up(self):
    # mock out the posting to the remote app
    fake_connection = flexmock(name="fake_connection")
    fake_connection.should_receive('request').with_args('POST',
      '/upload', self.payload, AppScaleLogger.HEADERS) \
      .and_return().once()
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
