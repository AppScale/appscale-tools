#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import base64
import httplib
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import time
import unittest
import uuid
import yaml


# Third party libraries
import apiclient.discovery
import apiclient.errors
import boto
from flexmock import flexmock
import httplib2
import oauth2client.client
import oauth2client.file
import oauth2client.tools
import SOAPpy


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from agents.ec2_agent import EC2Agent
from agents.gce_agent import GCEAgent
from appcontroller_client import AppControllerClient
from appscale_logger import AppScaleLogger
from appscale_tools import AppScaleTools
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException
from local_state import APPSCALE_VERSION
from local_state import LocalState
from node_layout import NodeLayout
from parse_args import ParseArgs
from remote_helper import RemoteHelper
from user_app_client import UserAppClient
import user_app_client


class TestAppScaleRunInstances(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-run-instances"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('success').and_return()

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
    tempfile.should_receive('NamedTemporaryFile')\
      .and_return(self.fake_temp_file)
    tempfile.should_receive('TemporaryFile').and_return(self.fake_input_file)

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


  def test_appscale_in_one_node_virt_deployment(self):
    # let's say that appscale isn't already running

    local_state = flexmock(LocalState)
    local_state.should_receive('ensure_appscale_isnt_running').and_return()
    local_state.should_receive('make_appscale_directory').and_return()

    rh = flexmock(RemoteHelper)
    rh.should_receive('copy_deployment_credentials').and_return()

    # mock out talking to logs.appscale.com
    fake_connection = flexmock(name='fake_connection')
    fake_connection.should_receive('request').with_args('POST', '/upload', str,
      AppScaleLogger.HEADERS).and_return()

    flexmock(httplib)
    httplib.should_receive('HTTPConnection').with_args('logs.appscale.com') \
      .and_return(fake_connection)

    # mock out generating the secret key
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return('the secret')

    # mock out writing the secret key to ~/.appscale, as well as reading it
    # later
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    fake_secret.should_receive('write').and_return()
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)
    builtins.should_receive('open').with_args(secret_key_location, 'w') \
      .and_return(fake_secret)

    # mock out copying over the keys
    local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*.key'),False,5)

    # mock out our attempts to find /etc/appscale and presume it does exist
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,\
        stdin=re.compile('ls /etc/appscale'))\
      .and_return()

    # mock out our attempts to find /etc/appscale/version and presume it does
    # exist
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,\
        stdin=re.compile('ls /etc/appscale/{0}'.format(APPSCALE_VERSION)))\
      .and_return()

    # finally, put in a mock indicating that the database the user wants
    # is supported
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,\
        stdin=re.compile('ls /etc/appscale/{0}/{1}'\
          .format(APPSCALE_VERSION, 'cassandra')))\
      .and_return()

    # mock out generating the private key
    local_state.should_receive('shell')\
      .with_args(re.compile('^openssl'),False,stdin=None)\
      .and_return()

    # mock out removing the old json file
    local_state = flexmock(LocalState)
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,stdin=re.compile('rm -rf'))\
      .and_return()

    # assume that we started god fine
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,stdin=re.compile('god &'))\
      .and_return()


    # and that we copied over the AppController's god file
    local_state.should_receive('shell')\
      .with_args(re.compile('scp .*appcontroller\.god.*'),False,5)\
      .and_return()

    # also, that we started the AppController itself
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,\
        stdin=re.compile('^god load .*appcontroller\.god'))\
      .and_return()

    # assume that the AppController comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('1.2.3.4',
      AppControllerClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # same for the UserAppServer
    fake_socket.should_receive('connect').with_args(('1.2.3.4',
      UserAppClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # as well as for the AppDashboard
    fake_socket.should_receive('connect').with_args(('1.2.3.4',
      RemoteHelper.APP_DASHBOARD_PORT)).and_raise(Exception) \
      .and_raise(Exception).and_return(None)

    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('set_parameters').with_args(list, list,
      ['none'], 'the secret').and_return('OK')
    fake_appcontroller.should_receive('get_all_public_ips')\
      .with_args('the secret') \
      .and_return(json.dumps(['1.2.3.4']))
    role_info = [{
      'public_ip' : '1.2.3.4',
      'private_ip' : '1.2.3.4',
      'jobs' : ['shadow', 'login']
    }]
    fake_appcontroller.should_receive('get_role_info').with_args('the secret') \
      .and_return(json.dumps(role_info))
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('nothing interesting here') \
      .and_return('Database is at not-up-yet') \
      .and_return('Database is at 1.2.3.4')
    fake_appcontroller.should_receive('is_done_initializing') \
      .and_return(False) \
      .and_return(True)
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://1.2.3.4:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "1.2.3.4",
        "private_ip" : "1.2.3.4",
        "jobs" : ["shadow", "login"]
      }])))

    # copying over the locations yaml and json files should be fine
    local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*/etc/appscale/locations-bookey.yaml'),\
        False,5)\
      .and_return()

    local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*/etc/appscale/locations-bookey.json'),\
        False,5)\
      .and_return()

    local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*/root/.appscale/locations-bookey.json'),\
        False,5)\
      .and_return()

    # same for the secret key
    local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*.secret'),False,5)\
      .and_return()


    # mock out calls to the UserAppServer and presume that calls to create new
    # users succeed
    fake_userappserver = flexmock(name='fake_appcontroller')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@a.com', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@1.2.3.4', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('set_cloud_admin_status').with_args(
      'a@a.com', 'true', 'the secret').and_return()
    fake_userappserver.should_receive('set_capabilities').with_args(
      'a@a.com', UserAppClient.ADMIN_CAPABILITIES, 'the secret').and_return()
    SOAPpy.should_receive('SOAPProxy').with_args('https://1.2.3.4:4343') \
      .and_return(fake_userappserver)

    # don't use a 192.168.X.Y IP here, since sometimes we set our virtual
    # machines to boot with those addresses (and that can mess up our tests).
    ips_layout = yaml.safe_load("""
master : 1.2.3.4
database: 1.2.3.4
zookeeper: 1.2.3.4
appengine:  1.2.3.4
    """)

    argv = [
      "--ips_layout", base64.b64encode(yaml.dump(ips_layout)),
      "--keyname", self.keyname,
      "--test"
    ]


    options = ParseArgs(argv, self.function).args
    AppScaleTools.run_instances(options)


  def test_appscale_in_one_node_cloud_deployment_auto_spot_price(self):
    # let's say that appscale isn't already running

    local_state = flexmock(LocalState)
    local_state.should_receive('ensure_appscale_isnt_running').and_return()
    local_state.should_receive('make_appscale_directory').and_return()

    # mock out talking to logs.appscale.com
    fake_connection = flexmock(name='fake_connection')
    fake_connection.should_receive('request').with_args('POST', '/upload', str,
      AppScaleLogger.HEADERS).and_return()

    flexmock(httplib)
    httplib.should_receive('HTTPConnection').with_args('logs.appscale.com') \
      .and_return(fake_connection)

    # mock out generating the secret key
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return('the secret')

    # mock out writing the secret key to ~/.appscale, as well as reading it
    # later
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    fake_secret.should_receive('write').and_return()
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)
    builtins.should_receive('open').with_args(secret_key_location, 'w') \
      .and_return(fake_secret)

    # mock out interactions with AWS
    fake_ec2 = flexmock(name='fake_ec2')
    
    # first, pretend that our image does exist in EC2
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()

    # next, assume that our keypair doesn't exist yet
    fake_ec2.should_receive('get_key_pair').with_args(self.keyname) \
      .and_return(None)

    # same for the security group
    fake_ec2.should_receive('get_all_security_groups').and_return([])

    # mock out creating the keypair
    fake_key = flexmock(name='fake_key', material='baz')
    local_state.should_receive('write_key_file').with_args(
      re.compile(self.keyname), fake_key.material).and_return()
    fake_ec2.should_receive('create_key_pair').with_args(self.keyname) \
      .and_return(fake_key)

    # and the same for the security group
    fake_ec2.should_receive('create_security_group').with_args('bazgroup',
      str).and_return()
    fake_ec2.should_receive('authorize_security_group').with_args('bazgroup',
      from_port=1, to_port=65535, ip_protocol='udp', cidr_ip='0.0.0.0/0')
    fake_ec2.should_receive('authorize_security_group').with_args('bazgroup',
      from_port=1, to_port=65535, ip_protocol='tcp', cidr_ip='0.0.0.0/0')
    fake_ec2.should_receive('authorize_security_group').with_args('bazgroup',
      ip_protocol='icmp', cidr_ip='0.0.0.0/0')

    # slip in some fake spot instance info
    fake_entry = flexmock(name='fake_entry', price=1)
    fake_ec2.should_receive('get_spot_price_history').with_args(
      product_description='Linux/UNIX', instance_type='m1.large') \
      .and_return([fake_entry])

    # also mock out acquiring a spot instance
    fake_ec2.should_receive('request_spot_instances').with_args('1.1',
      'ami-ABCDEFG', key_name=self.keyname, security_groups=['bazgroup'],
      instance_type='m1.large', count=1)

    # assume that there are no instances running initially, and that the
    # instance we spawn starts as pending, then becomes running
    no_instances = flexmock(name='no_instances', instances=[])

    pending_instance = flexmock(name='pending_instance', state='pending',
      key_name=self.keyname, id='i-ABCDEFG')
    pending_reservation = flexmock(name='pending_reservation',
      instances=[pending_instance])

    running_instance = flexmock(name='running_instance', state='running',
      key_name=self.keyname, id='i-ABCDEFG', public_dns_name='public1',
      private_dns_name='private1')
    running_reservation = flexmock(name='running_reservation',
      instances=[running_instance])

    fake_ec2.should_receive('get_all_instances').and_return(no_instances) \
      .and_return(pending_reservation).and_return(running_reservation)

    # finally, inject the mocked EC2 in
    flexmock(boto)
    boto.should_receive('connect_ec2').and_return(fake_ec2)

    # assume that root login is not enabled
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin='ls').and_return(RemoteHelper.LOGIN_AS_UBUNTU_USER)

    # assume that we can enable root login
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('sudo cp')).and_return()

    # and assume that we can copy over our ssh keys fine
    local_state.should_receive('shell').with_args(re.compile('scp .*[r|d]sa'),
      False, 5).and_return()
    local_state.should_receive('shell').with_args(re.compile('scp .*{0}'
      .format(self.keyname)), False, 5).and_return()

    # mock out seeing if the image is appscale-compatible, and assume it is
    # mock out our attempts to find /etc/appscale and presume it does exist
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale')).and_return()

    # mock out our attempts to find /etc/appscale/version and presume it does
    # exist
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale/{0}'
      .format(APPSCALE_VERSION)))

    # put in a mock indicating that the database the user wants is supported
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale/{0}/{1}'
      .format(APPSCALE_VERSION, 'cassandra')))

    # mock out generating the private key
    local_state.should_receive('shell').with_args(re.compile('openssl'),
      False, stdin=None)

    # assume that we started god fine
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('god &'))

    # and that we copied over the AppController's god file
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('appcontroller.god'))

    # also, that we started the AppController itself
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('god load'))

    # assume that ssh comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      RemoteHelper.SSH_PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # assume that the AppController comes up on the third attempt
    fake_socket.should_receive('connect').with_args(('public1',
      AppControllerClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # same for the UserAppServer
    fake_socket.should_receive('connect').with_args(('public1',
      UserAppClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # as well as for the AppDashboard
    fake_socket.should_receive('connect').with_args(('public1',
      RemoteHelper.APP_DASHBOARD_PORT)).and_raise(Exception) \
      .and_raise(Exception).and_return(None)

    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('set_parameters').with_args(list, list,
      ['none'], 'the secret').and_return('OK')
    fake_appcontroller.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return(json.dumps(['public1']))
    role_info = [{
      'public_ip' : 'public1',
      'private_ip' : 'private1',
      'jobs' : ['shadow', 'login']
    }]
    fake_appcontroller.should_receive('get_role_info').with_args('the secret') \
      .and_return(json.dumps(role_info))
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('nothing interesting here') \
      .and_return('Database is at not-up-yet') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('is_done_initializing') \
      .and_return(False) \
      .and_return(True)
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "public1",
        "private_ip" : "private1",
        "jobs" : ["shadow", "login"]
      }])))

    # copying over the locations yaml and json files should be fine
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('locations-{0}'.format(self.keyname)))

    # same for the secret key
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('{0}.secret'.format(self.keyname)))

    # mock out calls to the UserAppServer and presume that calls to create new
    # users succeed
    fake_userappserver = flexmock(name='fake_appcontroller')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@a.com', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@public1', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('set_cloud_admin_status').with_args(
      'a@a.com', 'true', 'the secret').and_return()
    fake_userappserver.should_receive('set_capabilities').with_args(
      'a@a.com', UserAppClient.ADMIN_CAPABILITIES, 'the secret').and_return()
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:4343') \
      .and_return(fake_userappserver)

    argv = [
      "--min", "1",
      "--max", "1",
      "--infrastructure", "ec2",
      "--machine", "ami-ABCDEFG",
      "--use_spot_instances",
      "--keyname", self.keyname,
      "--group", "bazgroup",
      "--test"
    ]

    options = ParseArgs(argv, self.function).args
    AppScaleTools.run_instances(options)


  def test_appscale_in_one_node_cloud_deployment_manual_spot_price(self):
    # let's say that appscale isn't already running

    local_state = flexmock(LocalState)
    local_state.should_receive('ensure_appscale_isnt_running').and_return()
    local_state.should_receive('make_appscale_directory').and_return()

    # mock out talking to logs.appscale.com
    fake_connection = flexmock(name='fake_connection')
    fake_connection.should_receive('request').with_args('POST', '/upload', str,
      AppScaleLogger.HEADERS).and_return()

    flexmock(httplib)
    httplib.should_receive('HTTPConnection').with_args('logs.appscale.com') \
      .and_return(fake_connection)

    # mock out generating the secret key
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return('the secret')

    # mock out writing the secret key to ~/.appscale, as well as reading it
    # later
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    fake_secret.should_receive('write').and_return()
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)
    builtins.should_receive('open').with_args(secret_key_location, 'w') \
      .and_return(fake_secret)

    # mock out interactions with AWS
    fake_ec2 = flexmock(name='fake_ec2')

    # first, pretend that our image does exist in EC2
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()

    # next, assume that our keypair doesn't exist yet
    fake_ec2.should_receive('get_key_pair').with_args(self.keyname) \
      .and_return(None)

    # same for the security group
    fake_ec2.should_receive('get_all_security_groups').and_return([])

    # mock out creating the keypair
    fake_key = flexmock(name='fake_key', material='baz')
    local_state.should_receive('write_key_file').with_args(
      re.compile(self.keyname), fake_key.material).and_return()
    fake_ec2.should_receive('create_key_pair').with_args(self.keyname) \
      .and_return(fake_key)

    # and the same for the security group
    fake_ec2.should_receive('create_security_group').with_args('bazgroup',
      str).and_return()
    fake_ec2.should_receive('authorize_security_group').with_args('bazgroup',
      from_port=1, to_port=65535, ip_protocol='udp', cidr_ip='0.0.0.0/0')
    fake_ec2.should_receive('authorize_security_group').with_args('bazgroup',
      from_port=1, to_port=65535, ip_protocol='tcp', cidr_ip='0.0.0.0/0')
    fake_ec2.should_receive('authorize_security_group').with_args('bazgroup',
      ip_protocol='icmp', cidr_ip='0.0.0.0/0')

    # also mock out acquiring a spot instance
    fake_ec2.should_receive('request_spot_instances').with_args('1.23',
      'ami-ABCDEFG', key_name=self.keyname, security_groups=['bazgroup'],
      instance_type='m1.large', count=1)

    # assume that there are no instances running initially, and that the
    # instance we spawn starts as pending, then becomes running
    no_instances = flexmock(name='no_instances', instances=[])

    pending_instance = flexmock(name='pending_instance', state='pending',
      key_name=self.keyname, id='i-ABCDEFG')
    pending_reservation = flexmock(name='pending_reservation',
      instances=[pending_instance])

    running_instance = flexmock(name='running_instance', state='running',
      key_name=self.keyname, id='i-ABCDEFG', public_dns_name='public1',
      private_dns_name='private1')
    running_reservation = flexmock(name='running_reservation',
      instances=[running_instance])

    fake_ec2.should_receive('get_all_instances').and_return(no_instances) \
      .and_return(pending_reservation).and_return(running_reservation)

    # finally, inject the mocked EC2 in
    flexmock(boto)
    boto.should_receive('connect_ec2').and_return(fake_ec2)

    # assume that root login is not enabled
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin='ls').and_return(RemoteHelper.LOGIN_AS_UBUNTU_USER)

    # assume that we can enable root login
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('sudo cp')).and_return()

    # and assume that we can copy over our ssh keys fine
    local_state.should_receive('shell').with_args(re.compile('scp .*[r|d]sa'),
      False, 5).and_return()
    local_state.should_receive('shell').with_args(re.compile('scp .*{0}'
      .format(self.keyname)), False, 5).and_return()

    # mock out seeing if the image is appscale-compatible, and assume it is
    # mock out our attempts to find /etc/appscale and presume it does exist
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale')).and_return()

    # mock out our attempts to find /etc/appscale/version and presume it does
    # exist
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale/{0}'
      .format(APPSCALE_VERSION)))

    # put in a mock indicating that the database the user wants is supported
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale/{0}/{1}'
      .format(APPSCALE_VERSION, 'cassandra')))

    # mock out generating the private key
    local_state.should_receive('shell').with_args(re.compile('openssl'),
      False, stdin=None)

    # assume that we started god fine
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('god &'))

    # and that we copied over the AppController's god file
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('appcontroller.god'))

    # also, that we started the AppController itself
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('god load'))

    # assume that ssh comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      RemoteHelper.SSH_PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # assume that the AppController comes up on the third attempt
    fake_socket.should_receive('connect').with_args(('public1',
      AppControllerClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # same for the UserAppServer
    fake_socket.should_receive('connect').with_args(('public1',
      UserAppClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # as well as for the AppDashboard
    fake_socket.should_receive('connect').with_args(('public1',
      RemoteHelper.APP_DASHBOARD_PORT)).and_raise(Exception) \
      .and_raise(Exception).and_return(None)

    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('set_parameters').with_args(list, list,
      ['none'], 'the secret').and_return('OK')
    fake_appcontroller.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return(json.dumps(['public1']))
    role_info = [{
      'public_ip' : 'public1',
      'private_ip' : 'private1',
      'jobs' : ['shadow', 'login']
    }]
    fake_appcontroller.should_receive('get_role_info').with_args('the secret') \
      .and_return(json.dumps(role_info))
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('nothing interesting here') \
      .and_return('Database is at not-up-yet') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('is_done_initializing') \
      .and_return(False) \
      .and_return(True)
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "public1",
        "private_ip" : "private1",
        "jobs" : ["shadow", "login"]
      }])))

    # copying over the locations yaml and json files should be fine
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('locations-{0}'.format(self.keyname)))

    # same for the secret key
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('{0}.secret'.format(self.keyname)))

    # mock out calls to the UserAppServer and presume that calls to create new
    # users succeed
    fake_userappserver = flexmock(name='fake_appcontroller')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@a.com', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@public1', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('set_cloud_admin_status').with_args(
      'a@a.com', 'true', 'the secret').and_return()
    fake_userappserver.should_receive('set_capabilities').with_args(
      'a@a.com', UserAppClient.ADMIN_CAPABILITIES, 'the secret').and_return()
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:4343') \
      .and_return(fake_userappserver)

    argv = [
      "--min", "1",
      "--max", "1",
      "--infrastructure", "ec2",
      "--machine", "ami-ABCDEFG",
      "--use_spot_instances",
      "--max_spot_price", "1.23",
      "--keyname", self.keyname,
      "--group", "bazgroup",
      "--test"
    ]

    options = ParseArgs(argv, self.function).args
    AppScaleTools.run_instances(options)


  def test_appscale_in_one_node_virt_deployment_with_login_override(self):
    # let's say that appscale isn't already running
    local_state = flexmock(LocalState)
    local_state.should_receive('ensure_appscale_isnt_running').and_return()
    local_state.should_receive('make_appscale_directory').and_return()
    local_state.should_receive('update_local_metadata').and_return()
    local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "1.2.3.4",
        "private_ip" : "1.2.3.4",
        "jobs" : ["shadow", "login"]
      }])))
    local_state.should_receive('get_secret_key').and_return("fookey")


    flexmock(RemoteHelper)
    RemoteHelper.should_receive('start_head_node')\
        .and_return(('1.2.3.4','i-ABCDEFG'))
    RemoteHelper.should_receive('sleep_until_port_is_open').and_return()
    RemoteHelper.should_receive('copy_local_metadata').and_return()
    RemoteHelper.should_receive('create_user_accounts').and_return()
    RemoteHelper.should_receive('wait_for_machines_to_finish_loading')\
        .and_return()

    acc = flexmock(AppControllerClient)
    acc.should_receive('get_uaserver_host').and_return('host')

    flexmock(UserAppClient).should_receive('set_admin_role').and_return()


    # don't use a 192.168.X.Y IP here, since sometimes we set our virtual
    # machines to boot with those addresses (and that can mess up our tests).
    ips_layout = yaml.safe_load("""
master : 1.2.3.4
database: 1.2.3.4
zookeeper: 1.2.3.4
appengine:  1.2.3.4
    """)

    argv = [
      "--ips_layout", base64.b64encode(yaml.dump(ips_layout)),
      "--keyname", self.keyname,
      "--test",
      "--login_host", "www.booscale.com"
    ]


    options = ParseArgs(argv, self.function).args
    AppScaleTools.run_instances(options)


  def test_appscale_in_one_node_gce_deployment(self):
    # presume that our client_secrets file exists
    project_id = "1234567890"
    client_secrets = "/boo/client_secrets.json"
    instance_type = 'n1-standard-8'
    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(client_secrets).and_return(True)

    # and that the user has an ssh key already set up, which we can copy to
    # ~/.appscale
    os.path.should_receive('exists').with_args(GCEAgent.GCE_PRIVATE_SSH_KEY) \
      .and_return(True)
    os.path.should_receive('exists').with_args(GCEAgent.GCE_PUBLIC_SSH_KEY) \
      .and_return(True)

    private_key = '{0}{1}.key'.format(LocalState.LOCAL_APPSCALE_PATH,
      self.keyname)
    public_key = '{0}{1}.pub'.format(LocalState.LOCAL_APPSCALE_PATH,
      self.keyname)

    flexmock(shutil)
    shutil.should_receive('copy').with_args(client_secrets,
      LocalState.get_client_secrets_location(self.keyname))
    shutil.should_receive('copy').with_args(GCEAgent.GCE_PRIVATE_SSH_KEY,
      private_key)
    shutil.should_receive('copy').with_args(GCEAgent.GCE_PUBLIC_SSH_KEY,
      public_key)

    # let's say that appscale isn't already running
    local_state = flexmock(LocalState)
    local_state.should_receive('ensure_appscale_isnt_running').and_return()
    local_state.should_receive('make_appscale_directory').and_return()

    # mock out talking to logs.appscale.com
    fake_connection = flexmock(name='fake_connection')
    fake_connection.should_receive('request').with_args('POST', '/upload', str,
      AppScaleLogger.HEADERS).and_return()

    flexmock(httplib)
    httplib.should_receive('HTTPConnection').with_args('logs.appscale.com') \
      .and_return(fake_connection)

    # mock out generating the secret key
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return('the secret')

    # mock out writing the secret key to ~/.appscale, as well as reading it
    # later
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    fake_secret.should_receive('write').and_return()
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)
    builtins.should_receive('open').with_args(secret_key_location, 'w') \
      .and_return(fake_secret)

    # mock out interactions with GCE
    # first, mock out the oauth library calls
    fake_flow = flexmock(name='fake_flow')
    flexmock(oauth2client.client)
    oauth2client.client.should_receive('flow_from_clientsecrets').with_args(
      client_secrets, scope=str).and_return(fake_flow)

    fake_storage = flexmock(name='fake_storage')
    fake_storage.should_receive('get').and_return(None)

    flexmock(oauth2client.file)
    oauth2client.file.should_receive('Storage').with_args(str).and_return(
      fake_storage)

    fake_credentials = flexmock(name='fake_credentials')
    flexmock(oauth2client.tools)
    oauth2client.tools.should_receive('run').with_args(fake_flow,
      fake_storage).and_return(fake_credentials)

    # next, mock out http calls to GCE
    fake_http = flexmock(name='fake_http')
    fake_authorized_http = flexmock(name='fake_authorized_http')

    flexmock(httplib2)
    httplib2.should_receive('Http').and_return(fake_http)
    fake_credentials.should_receive('authorize').with_args(fake_http) \
      .and_return(fake_authorized_http)

    # presume that there is an ssh key stored, but it isn't ours
    metadata_info = {
      u'kind': u'compute#project', 
      u'description': u'', 
      u'commonInstanceMetadata': {
        u'items': [{
          u'value': u'cgb:ssh-rsa keyinfo myhost', 
          u'key': u'sshKeys'}], 
        u'kind': u'compute#metadata'},
    }
    fake_metadata_request = flexmock(name='fake_metadata_request')
    fake_metadata_request.should_receive('execute').with_args(
      fake_authorized_http).and_return(metadata_info)

    fake_projects = flexmock(name='fake_projects')
    fake_projects.should_receive('get').with_args(project=project_id) \
      .and_return(fake_metadata_request)

    fake_gce = flexmock(name='fake_gce')
    fake_gce.should_receive('projects').and_return(fake_projects)

    # presume that our image does exist in GCE, with some fake data
    # acquired by running a not mocked version of this code
    image_name = 'appscale-image-name'
    image_info = {
      u'kind': u'compute#image',
      u'description': u'',
      u'rawDisk': {u'containerType': u'TAR', u'source': u''},
      u'preferredKernel': unicode(GCEAgent.GCE_URL) + \
        u'/google/global/kernels/gce-v20130515',
      u'sourceType': u'RAW',
      u'creationTimestamp': u'2013-05-21T08:05:12.198-07:00',
      u'id': u'4235320207849085220',
      u'selfLink': unicode(GCEAgent.GCE_URL) + \
        u'961228229472/global/images/' + unicode(image_name),
      u'name': unicode(image_name)
    }
    fake_image_request = flexmock(name='fake_image_request')
    fake_image_request.should_receive('execute').with_args(
      fake_authorized_http).and_return(image_info)

    fake_images = flexmock(name='fake_images')
    fake_images.should_receive('get').with_args(project=project_id,
      image=image_name).and_return(fake_image_request)

    fake_gce.should_receive('images').and_return(fake_images)

    # next, presume that the network doesn't exist yet
    fake_network_request = flexmock(name='fake_network_request')
    fake_network_request.should_receive('execute').with_args(
      fake_authorized_http).and_raise(apiclient.errors.HttpError, None, None)

    fake_networks = flexmock(name='fake_networks')
    fake_networks.should_receive('get').with_args(project=project_id,
      network='bazgroup').and_return(fake_network_request)
    fake_gce.should_receive('networks').and_return(fake_networks)

    # next, presume that the firewall doesn't exist yet
    fake_firewall_request = flexmock(name='fake_firewall_request')
    fake_firewall_request.should_receive('execute').with_args(
      fake_authorized_http).and_raise(apiclient.errors.HttpError, None, None)

    fake_firewalls = flexmock(name='fake_firewalls')
    fake_firewalls.should_receive('get').with_args(project=project_id,
      firewall='bazgroup').and_return(fake_firewall_request)
    fake_gce.should_receive('firewalls').and_return(fake_firewalls)

    # presume that we can create the network fine
    create_network = u'operation-1369175117235-4dd41ec7d6c11-8013657f'
    network_info = {
      u'status': u'PENDING',
      u'kind': u'compute#operation',
      u'name': create_network,
      u'startTime': u'2013-05-21T15:25:17.308-07:00',
      u'insertTime': u'2013-05-21T15:25:17.235-07:00',
      u'targetLink': unicode(GCEAgent.GCE_URL) + \
        u'appscale.com:appscale/global/networks/bazgroup',
      u'operationType': u'insert',
      u'progress': 0,
      u'id': u'4904874319704759670',
      u'selfLink': unicode(GCEAgent.GCE_URL) + \
        u'appscale.com:appscale/global/operations/' + \
        u'operation-1369175117235-4dd41ec7d6c11-8013657f',
      u'user': u'Chris@appscale.com'
    }

    fake_network_insert_request = flexmock(name='fake_network_insert_request')
    fake_network_insert_request.should_receive('execute').with_args(
      fake_authorized_http).and_return(network_info)
    fake_networks.should_receive('insert').with_args(project=project_id,
      body=dict).and_return(fake_network_insert_request)

    created_network_info = {
      u'status': u'DONE'
    }

    fake_network_checker = flexmock(name='fake_network_checker')
    fake_network_checker.should_receive('execute').and_return(
      created_network_info)
    fake_blocker = flexmock(name='fake_blocker')
    fake_blocker.should_receive('get').with_args(project=project_id,
      operation=create_network).and_return(fake_network_checker)
    fake_gce.should_receive('globalOperations').and_return(fake_blocker)

    # and presume that we can create the firewall fine
    create_firewall = u'operation-1369176378310-4dd4237a84021-68e4dfa6'
    firewall_info = {
      u'status': u'PENDING',
      u'kind': u'compute#operation',
      u'name': create_firewall,
      u'startTime': u'2013-05-21T15:46:18.402-07:00',
      u'insertTime': u'2013-05-21T15:46:18.310-07:00',
      u'targetLink': unicode(GCEAgent.GCE_URL) + \
        u'appscale.com:appscale/global/firewalls/bazgroup',
      u'operationType': u'insert',
      u'progress': 0,
      u'id': u'13248349431060541723',
      u'selfLink': unicode(GCEAgent.GCE_URL) + \
        u'appscale.com:appscale/global/operations/' + \
        u'operation-1369176378310-4dd4237a84021-68e4dfa6',
      u'user': u'Chris@appscale.com'
    }

    fake_firewall_insert_request = flexmock(name='fake_firewall_insert_request')
    fake_firewall_insert_request.should_receive('execute').with_args(
      fake_authorized_http).and_return(firewall_info)
    fake_firewalls.should_receive('insert').with_args(project=project_id,
      body=dict).and_return(fake_firewall_insert_request)

    created_firewall_info = {
      u'status': u'DONE'
    }

    fake_firewall_checker = flexmock(name='fake_network_checker')
    fake_firewall_checker.should_receive('execute').and_return(
      created_firewall_info)
    fake_blocker.should_receive('get').with_args(project=project_id,
      operation=create_firewall).and_return(fake_firewall_checker)

    # we only need to create one node, so set up mocks for that
    add_instance = u'operation-1369248752891-4dd5311848461-afc55a20'
    add_instance_info = {
      u'status': u'PENDING',
      u'kind': u'compute#operation',
      u'name': add_instance,
      u'azone': unicode(GCEAgent.GCE_URL) + u'appscale.com:appscale/zones/us-central1-a',
      u'startTime': u'2013-05-22T11:52:32.939-07:00',
      u'insertTime': u'2013-05-22T11:52:32.891-07:00',
      u'targetLink': unicode(GCEAgent.GCE_URL) + u'appscale.com:appscale/zones/us-central1-a/instances/appscale-bazgroup-feb10b11-62bc-4536-ac25-9734f2267d6d',
      u'operationType': u'insert',
      u'progress': 0,
      u'id': u'6663616273628949255',
      u'selfLink': unicode(GCEAgent.GCE_URL) + u'appscale.com:appscale/zones/us-central1-a/operations/operation-1369248752891-4dd5311848461-afc55a20',
      u'user': u'Chris@appscale.com'
    }

    fake_add_instance_request = flexmock(name='fake_add_instance_request')
    fake_add_instance_request.should_receive('execute').with_args(
      fake_authorized_http).and_return(add_instance_info)

    fake_instances = flexmock(name='fake_instances')
    fake_gce.should_receive('instances').and_return(fake_instances)
    fake_instances.should_receive('insert').with_args(project=project_id,
      body=dict, zone=str).and_return(fake_add_instance_request)

    created_instance_info = {
      u'status': u'DONE'
    }

    fake_instance_checker = flexmock(name='fake_network_checker')
    fake_instance_checker.should_receive('execute').and_return(
      created_instance_info)
    fake_blocker.should_receive('get').with_args(project=project_id,
      operation=add_instance).and_return(fake_instance_checker)

    # add some fake data in where no instances are initially running, then one
    # is (in response to our insert request)
    no_instance_info = {
    }

    list_instance_info = {
      u'items': [{
        u'status': u'RUNNING',
        u'kind': u'compute#instance',
        u'machineType': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/machineTypes/' + instance_type,
        u'name': u'appscale-bazgroup-feb10b11-62bc-4536-ac25-9734f2267d6d',
        u'zone': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/us-central1-a',
        u'tags': {u'fingerprint': u'42WmSpB8rSM='},
        u'image': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/images/lucid64',
        u'disks': [{
          u'index': 0,
          u'kind': u'compute#attachedDisk',
          u'type': u'EPHEMERAL',
          u'mode': u'READ_WRITE'
        }],
        u'canIpForward': False,
        u'serviceAccounts': [{
          u'scopes': [GCEAgent.GCE_SCOPE],
          u'email': u'961228229472@project.gserviceaccount.com'
        }],
        u'metadata': {
          u'kind': u'compute#metadata',
          u'fingerprint': u'42WmSpB8rSM='
        },
        u'creationTimestamp': u'2013-05-22T11:52:33.254-07:00',
        u'id': u'8684033495853907982',
        u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/us-central1-a/instances/appscale-bazgroup-feb10b11-62bc-4536-ac25-9734f2267d6d',
        u'networkInterfaces': [{
          u'accessConfigs': [{
            u'kind': u'compute#accessConfig',
            u'type': u'ONE_TO_ONE_NAT',
            u'name': u'External NAT',
            u'natIP': u'public1'
          }],
          u'networkIP': u'private1',
          u'network': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/networks/bazgroup',
          u'name': u'nic0'
        }]
      }],
      u'kind': u'compute#instanceList',
      u'id': u'projects/appscale.com:appscale/zones/us-central1-a/instances',
      u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/961228229472/zones/us-central1-a/instances'
    }

    fake_list_instance_request = flexmock(name='fake_list_instance_request')
    fake_list_instance_request.should_receive('execute').with_args(
      fake_authorized_http).and_return(no_instance_info).and_return(
        list_instance_info)

    fake_instances.should_receive('list').with_args(project=project_id,
      filter="name eq appscale-bazgroup-.*", zone=GCEAgent.DEFAULT_ZONE) \
      .and_return(fake_list_instance_request)

    # finally, inject our fake GCE connection
    flexmock(apiclient.discovery)
    apiclient.discovery.should_receive('build').with_args('compute', str) \
      .and_return(fake_gce)

    # assume that root login is not enabled
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin='ls').and_raise(ShellException)

    # assume that we can enable root login
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('sudo cp')).and_return()

    # and assume that we can copy over our ssh keys fine
    local_state.should_receive('shell').with_args(re.compile('scp .*[r|d]sa'),
      False, 5).and_return()
    local_state.should_receive('shell').with_args(re.compile('scp .*{0}'
      .format(self.keyname)), False, 5).and_return()

    # mock out seeing if the image is appscale-compatible, and assume it is
    # mock out our attempts to find /etc/appscale and presume it does exist
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale')).and_return()

    # mock out our attempts to find /etc/appscale/version and presume it does
    # exist
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale/{0}'
      .format(APPSCALE_VERSION)))

    # put in a mock indicating that the database the user wants is supported
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('/etc/appscale/{0}/{1}'
      .format(APPSCALE_VERSION, 'cassandra')))

    # mock out generating the private key
    local_state.should_receive('shell').with_args(re.compile('openssl'),
      False, stdin=None)

    # assume that we started god fine
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('god &'))

    # and that we copied over the AppController's god file
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('appcontroller.god'))

    # also, that we started the AppController itself
    local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('god load'))

    # assume that ssh comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      RemoteHelper.SSH_PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # assume that the AppController comes up on the third attempt
    fake_socket.should_receive('connect').with_args(('public1',
      AppControllerClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # same for the UserAppServer
    fake_socket.should_receive('connect').with_args(('public1',
      UserAppClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # as well as for the AppDashboard
    fake_socket.should_receive('connect').with_args(('public1',
      RemoteHelper.APP_DASHBOARD_PORT)).and_raise(Exception) \
      .and_raise(Exception).and_return(None)

    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('set_parameters').with_args(list, list,
      ['none'], 'the secret').and_return('OK')
    fake_appcontroller.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return(json.dumps(['public1']))
    role_info = [{
      'public_ip' : 'public1',
      'private_ip' : 'private1',
      'jobs' : ['shadow', 'login']
    }]
    fake_appcontroller.should_receive('get_role_info').with_args('the secret') \
      .and_return(json.dumps(role_info))
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('nothing interesting here') \
      .and_return('Database is at not-up-yet') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('is_done_initializing') \
      .and_return(False) \
      .and_return(True)
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "public1",
        "private_ip" : "private1",
        "jobs" : ["shadow", "login"]
      }])))

    # copying over the locations yaml and json files should be fine
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('locations-{0}'.format(self.keyname)))

    # same for the secret key
    local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('{0}.secret'.format(self.keyname)))

    # mock out calls to the UserAppServer and presume that calls to create new
    # users succeed
    fake_userappserver = flexmock(name='fake_appcontroller')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@a.com', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@public1', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('set_cloud_admin_status').with_args(
      'a@a.com', 'true', 'the secret').and_return()
    fake_userappserver.should_receive('set_capabilities').with_args(
      'a@a.com', UserAppClient.ADMIN_CAPABILITIES, 'the secret').and_return()
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:4343') \
      .and_return(fake_userappserver)

    argv = [
      "--min", "1",
      "--max", "1",
      "--group", "bazgroup",
      "--infrastructure", "gce",
      "--gce_instance_type", instance_type,
      "--machine", image_name,
      "--keyname", self.keyname,
      "--client_secrets", client_secrets,
      "--project", project_id,
      "--test"
    ]

    options = ParseArgs(argv, self.function).args
    AppScaleTools.run_instances(options)
