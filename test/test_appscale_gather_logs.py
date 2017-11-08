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


# Third party libraries
from flexmock import flexmock
import SOAPpy


# AppScale import, the library that we're testing here
from appscale.tools import utils
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.local_state import LocalState
from appscale.tools.parse_args import ParseArgs


class TestAppScaleGatherLogs(unittest.TestCase):

  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-gather-logs"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

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

    self.failed = flexmock(name='success', returncode=1)
    self.failed.should_receive('wait').and_return(1)


  def test_appscale_in_two_node_virt_deployment(self):
    # pretend that the place we're going to put logs into doesn't exist
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args('/tmp/foobaz').and_return(False)

    # and mock out the mkdir operation
    flexmock(os)
    os.should_receive('mkdir').with_args('/tmp/foobaz').and_return()

    # next, mock out finding the login ip address
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    nodes_info = {
      "node_info": [
        {
          "public_ip": "public1",
          "private_ip": "private1",
          "roles": ["load_balancer", "taskqueue_master", "zookeeper",
                   "db_master", "taskqueue", "shadow", "login"]
        }, {
          "public_ip": "public2",
          "private_ip": "private2",
          "roles": ["memcache", "appengine", "zookeeper"]
        }, {
          "public_ip": "public3",
          "private_ip": "private3",
          "roles": ["memcache", "appengine"]
        },
      ]
    }
    fake_nodes_json.should_receive('read').and_return(json.dumps(nodes_info))
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')
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

    # and slip in a fake appcontroller to report on the two IP addrs
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('get_all_public_ips').with_args(
      'the secret').and_return(json.dumps(['public1', 'public2', 'public3']))
    fake_appcontroller.should_receive('get_role_info').with_args(
      'the secret').and_return(json.dumps(nodes_info['node_info']))
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # fake the creation of the log directories locally
    flexmock(utils)
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/private-ips')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public1')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public1/cassandra')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public1/rabbitmq')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public2')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public2/cassandra')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public2/rabbitmq')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public3')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public3/cassandra')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/public3/rabbitmq')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/load_balancer')
    utils.should_receive('mkdir').with_args(
      '/tmp/foobaz/symlinks/taskqueue_master')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/zookeeper')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/db_master')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/taskqueue')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/shadow')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/login')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/memcache')
    utils.should_receive('mkdir').with_args('/tmp/foobaz/symlinks/appengine')

    # fake creation of symlink to for friendly navigation
    links_mapping = {
      '../../public1': [
        '/tmp/foobaz/symlinks/private-ips/private1',
        '/tmp/foobaz/symlinks/load_balancer/public1',
        '/tmp/foobaz/symlinks/taskqueue_master/public1',
        '/tmp/foobaz/symlinks/zookeeper/public1',
        '/tmp/foobaz/symlinks/db_master/public1',
        '/tmp/foobaz/symlinks/taskqueue/public1',
        '/tmp/foobaz/symlinks/shadow/public1',
        '/tmp/foobaz/symlinks/login/public1',
      ],
      '../../public2': [
        '/tmp/foobaz/symlinks/private-ips/private2',
        '/tmp/foobaz/symlinks/zookeeper/public2',
        '/tmp/foobaz/symlinks/appengine/public2',
        '/tmp/foobaz/symlinks/memcache/public2',
      ],
      '../../public3': [
        '/tmp/foobaz/symlinks/private-ips/private3',
        '/tmp/foobaz/symlinks/appengine/public3',
        '/tmp/foobaz/symlinks/memcache/public3',
      ]
    }
    for original_dir, expected_links in links_mapping.iteritems():
      for expected_link in expected_links:
        os.should_receive('symlink').with_args(original_dir, expected_link)

    # finally, fake the copying of the log files
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('/var/log/appscale'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)
    subprocess.should_receive('Popen').with_args(re.compile('/var/log/kern.log*'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)
    subprocess.should_receive('Popen').with_args(re.compile('/var/log/monit*'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)
    subprocess.should_receive('Popen').with_args(
      re.compile('/var/log/haproxy*'), shell=True, stdout=self.fake_temp_file,
      stderr=subprocess.STDOUT).and_return(self.success)
    subprocess.should_receive('Popen').with_args(re.compile('/var/log/nginx'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)
    subprocess.should_receive('Popen').with_args(
      re.compile('/var/log/rabbitmq'), shell=True, stdout=self.fake_temp_file,
      stderr=subprocess.STDOUT).and_return(self.success)
    subprocess.should_receive('Popen').with_args(re.compile('/var/log/syslog*'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)
    subprocess.should_receive('Popen').with_args(re.compile('/var/log/zookeeper'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)
    subprocess.should_receive('Popen').with_args(
      re.compile('/opt/cassandra/cassandra/logs'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT
    ).and_return(self.success)

    argv = [
      "--keyname", self.keyname,
      "--location", "/tmp/foobaz"
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.gather_logs(options)
