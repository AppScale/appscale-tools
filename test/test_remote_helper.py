#!/usr/bin/env python

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


# Third party libraries
import boto.ec2
from flexmock import flexmock
import SOAPpy


# AppScale import, the library that we're testing here
from appscale.tools.agents.euca_agent import EucalyptusAgent
from appscale.tools.agents import factory
from appscale.tools.agents.gce_agent import CredentialTypes
from appscale.tools.agents.gce_agent import GCEAgent
from appscale.tools.appcontroller_client import AppControllerClient
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.custom_exceptions import BadConfigurationException
from appscale.tools.local_state import LocalState
from appscale.tools.node_layout import NodeLayout
from appscale.tools.node_layout import SimpleNode
from appscale.tools.remote_helper import RemoteHelper


class FakeAgent(object):
  PARAM_CREDENTIALS = None
  PARAM_SPOT_PRICE = None
  PARAM_REGION = None

  def get_params_from_args(self, options):
    return {}

  @classmethod
  def describe_instances(self, params):
    return (
     ['0.0.0.1', '0.0.0.2', '0.0.0.3', '0.0.0.4'],
     ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'],
     ['i-APPSCALE1', 'i-APPSCALE2', 'i-APPSCALE3', 'i-APPSCALE4'])

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
    self.options = flexmock(
      infrastructure='ec2',
      group='boogroup',
      machine='ami-ABCDEFG',
      instance_type='m1.large',
      keyname='bookey',
      table='cassandra',
      verbose=False,
      test=False,
      use_spot_instances=False,
      zone='my-zone-1b',
      static_ip=None,
      replication=None,
      appengine=None,
      autoscale=None,
      user_commands=[],
      flower_password='',
      max_memory='400',
      ips={
        'zookeeper': 'node-2', 'master': 'node-1',
        'appengine': 'node-3', 'database': 'node-4'}
    )
    self.my_id = "12345"
    self.node_layout = NodeLayout(self.options)

    # set up phony AWS credentials for each test
    # ones that test not having them present can
    # remove them
    for credential in EucalyptusAgent.REQUIRED_EC2_CREDENTIALS:
      os.environ[credential] = "baz"
    os.environ['EC2_URL'] = "http://boo"

    # mock out calls to EC2
    # begin by assuming that our ssh keypair doesn't exist, and thus that we
    # need to create it
    key_contents = "key contents here"
    fake_key = flexmock(name="fake_key", material=key_contents)
    fake_key.should_receive('save').with_args(os.environ['HOME']+'/.appscale').and_return(None)

    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_key_pair').with_args('bookey') \
      .and_return(None)
    fake_ec2.should_receive('create_key_pair').with_args('bookey') \
      .and_return(fake_key)

    # mock out writing the secret key
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.LOCAL_APPSCALE_PATH + "bookey.secret"
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('write').and_return()
    builtins.should_receive('open').with_args(secret_key_location, 'w') \
      .and_return(fake_secret)

    # also, mock out the keypair writing and chmod'ing
    ssh_key_location = LocalState.LOCAL_APPSCALE_PATH + "bookey.key"
    fake_file = flexmock(name="fake_file")
    fake_file.should_receive('write').with_args(key_contents).and_return()

    builtins.should_receive('open').with_args(ssh_key_location, 'w') \
      .and_return(fake_file)

    flexmock(os)
    os.should_receive('chmod').with_args(ssh_key_location, 0600).and_return()

    # next, assume there are no security groups up at first, but then it gets
    # created.
    udp_rule = flexmock(from_port=1, to_port=65535, ip_protocol='udp')
    tcp_rule = flexmock(from_port=1, to_port=65535, ip_protocol='tcp')
    icmp_rule = flexmock(from_port=-1, to_port=-1, ip_protocol='icmp')
    group = flexmock(name='boogroup', rules=[tcp_rule, udp_rule, icmp_rule])
    fake_ec2.should_receive('get_all_security_groups').with_args().and_return([])
    fake_ec2.should_receive('get_all_security_groups').with_args('boogroup').and_return([group])

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
      id='i-12345678', ip_address='1.2.3.4', private_ip_address='1.2.3.4')
    fake_running_reservation = flexmock(instances=fake_running_instance)

    fake_ec2.should_receive('get_all_instances').and_return([]) \
      .and_return([]) \
      .and_return([fake_pending_reservation]) \
      .and_return([fake_running_reservation])

    # next, assume that our run_instances command succeeds
    fake_ec2.should_receive('run_instances').and_return()

    # finally, inject our mocked EC2
    flexmock(boto.ec2)
    boto.ec2.should_receive('connect_to_region').and_return(fake_ec2)

    # assume that ssh comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      RemoteHelper.SSH_PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)
    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    self.fake_temp_file = flexmock(name='fake_temp_file')
    self.fake_temp_file.should_receive('seek').with_args(0).and_return()
    self.fake_temp_file.should_receive('read').and_return('boo out')
    self.fake_temp_file.should_receive('close').and_return()

    flexmock(tempfile)
    tempfile.should_receive('NamedTemporaryFile')\
      .and_return(self.fake_temp_file)

    self.success = flexmock(name='success', returncode=0)
    self.success.should_receive('wait').and_return(0)

    self.failed = flexmock(name='success', returncode=1)
    self.failed.should_receive('wait').and_return(1)

    # assume that root login isn't already enabled
    local_state = flexmock(LocalState)
    local_state.should_receive('shell') \
      .with_args(re.compile('^ssh .*root'), False, 1, stdin='ls') \
      .and_return(RemoteHelper.LOGIN_AS_UBUNTU_USER)

    # and assume that we can ssh in as ubuntu to enable root login
    local_state = flexmock(LocalState)
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh .*ubuntu'),False,5)\
      .and_return()

    # also assume that we can scp over our ssh keys
    local_state.should_receive('shell')\
      .with_args(re.compile('scp .*/root/.ssh/id_'),False,5)\
      .and_return()

    local_state.should_receive('shell')\
      .with_args(re.compile('scp .*/root/.appscale/bookey.key'),False,5)\
      .and_return()

  def test_start_head_node(self):
    self.options = flexmock(
      infrastructure='public cloud',
      group='group',
      machine='vm image',
      instance_type='instance type',
      keyname='keyname',
      table='cassandra',
      verbose=False,
      test=False,
      use_spot_instances=False,
      zone='zone',
      static_ip=None,
      replication=None,
      appengine=None,
      autoscale=None,
      user_commands=[],
      flower_password='',
      max_memory='X',
    )

    self.node_layout = NodeLayout(self.options)

    flexmock(LocalState).\
      should_receive("generate_secret_key").\
      with_args(self.options.keyname).\
      and_return('some secret key')

    flexmock(LocalState).\
      should_receive("get_key_path_from_name").\
      with_args(self.options.keyname).\
      and_return('some key path')

    flexmock(NodeLayout).should_receive('head_node').\
      and_return(SimpleNode('some IP', 'cloud'))

    fake_agent = FakeAgent()
    flexmock(factory.InfrastructureAgentFactory).\
      should_receive('create_agent').\
      with_args('public cloud').\
      and_return(fake_agent)

    self.additional_params = {}
    deployment_params = {}

    flexmock(LocalState).\
      should_receive('generate_deployment_params').\
      with_args(self.options, self.node_layout, self.additional_params).\
      and_return(deployment_params)

    flexmock(AppScaleLogger).should_receive('log').and_return()
    flexmock(AppScaleLogger).should_receive('remote_log_tools_state').\
      and_return()

    flexmock(time).should_receive('sleep').and_return()

    flexmock(RemoteHelper).\
      should_receive('copy_deployment_credentials').\
      with_args('some IP', self.options).\
      and_return()

    flexmock(RemoteHelper).\
      should_receive('run_user_commands').\
      with_args('some IP', self.options.user_commands,
                self.options.keyname, self.options.verbose).\
      and_return()

    flexmock(RemoteHelper).\
      should_receive('start_remote_appcontroller').\
      with_args('some IP', self.options.keyname, self.options.verbose).\
      and_return()

    layout = {}
    flexmock(NodeLayout).should_receive('to_list').and_return(layout)

    flexmock(AppControllerClient).\
      should_receive('set_parameters').\
      with_args(layout, deployment_params).\
      and_return()

    RemoteHelper.start_head_node(self.options, 'an ID', self.node_layout)


  def test_rsync_files_from_dir_that_doesnt_exist(self):
    # if the user specifies that we should copy from a directory that doesn't
    # exist, we should throw up and die
    flexmock(os.path)
    os.path.should_receive('exists').with_args('/tmp/booscale-local').\
      and_return(False)
    self.assertRaises(BadConfigurationException, RemoteHelper.rsync_files,
      'public1', 'booscale', '/tmp/booscale-local', False)


  def test_rsync_files_from_dir_that_does_exist(self):
    # if the user specifies that we should copy from a directory that does
    # exist, and has all the right directories in it, we should succeed
    flexmock(os.path)
    os.path.should_receive('exists').with_args('/tmp/booscale-local').\
      and_return(True)

    # assume the rsyncs succeed
    local_state = flexmock(LocalState)
    local_state.should_receive('shell')\
      .with_args(re.compile('^rsync'),False)\
      .and_return().ordered()

    RemoteHelper.rsync_files('public1', 'booscale', '/tmp/booscale-local',
      False)

  def test_copy_deployment_credentials_in_cloud(self):
    options = flexmock(
      keyname='key1',
      infrastructure='ec2',
      verbose=True,
    )

    local_state = flexmock(LocalState)
    remote_helper = flexmock(RemoteHelper)
    local_state.should_receive('get_secret_key_location').and_return()
    local_state.should_receive('get_key_path_from_name').and_return()
    local_state.should_receive('get_certificate_location').and_return()
    local_state.should_receive('get_private_key_location').and_return()

    remote_helper.should_receive('scp').and_return()
    local_state.should_receive('generate_ssl_cert').and_return()
    popen_object = flexmock(communicate=lambda: ['hash_id'])
    flexmock(subprocess).should_receive('Popen').and_return(popen_object)
    remote_helper.should_receive('ssh').and_return()
    flexmock(AppScaleLogger).should_receive('log').and_return()

    RemoteHelper.copy_deployment_credentials('public1', options)

    flexmock(GCEAgent).should_receive('get_secrets_type').\
      and_return(CredentialTypes.OAUTH)
    flexmock(os.path).should_receive('exists').and_return(True)

    options = flexmock(
      keyname='key1',
      infrastructure='gce',
      verbose=True,
    )
    local_state.should_receive('get_oauth2_storage_location').and_return()

    RemoteHelper.copy_deployment_credentials('public1', options)

  def test_start_remote_appcontroller(self):
    # mock out removing the old json file
    local_state = flexmock(LocalState)
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,stdin=re.compile('rm -rf'))\
      .and_return()

    # assume we started monit on public1 fine
    local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'), False, 5, stdin=re.compile('monit'))\
      .and_return()

    # and assume we started the AppController on public1 fine
    local_state.should_receive('shell').with_args(
      re.compile('^ssh'), False, 5, stdin='service appscale-controller start')

    # finally, assume the appcontroller comes up after a few tries
    # assume that ssh comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      AppControllerClient.PORT)).and_raise(Exception) \
      .and_raise(Exception).and_return(None)
    socket.should_receive('socket').and_return(fake_socket)

    # Mock out additional remote calls. 
    local_state.should_receive('shell').with_args('ssh -i /root/.appscale/bookey.key -o LogLevel=quiet -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null root@public1 ', False, 5, stdin='cp /root/appscale/AppController/scripts/appcontroller /etc/init.d/').and_return()

    local_state.should_receive('shell').with_args('ssh -i /root/.appscale/bookey.key -o LogLevel=quiet -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null root@public1 ', False, 5, stdin='chmod +x /etc/init.d/appcontroller').and_return()

    local_state.should_receive('shell').with_args('ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null root@elastic-ip ', False, 5, stdin='chmod +x /etc/init.d/appcontroller').and_return()

    RemoteHelper.start_remote_appcontroller('public1', 'bookey', False)


  def test_copy_local_metadata(self):
    # Assume the locations files were copied successfully.
    local_state = flexmock(LocalState)
    locations_yaml = '{}/locations-bookey.yaml'.\
      format(RemoteHelper.CONFIG_DIR)
    local_state.should_receive('shell').with_args(
      re.compile('^scp .*{}'.format(locations_yaml)), False, 5)

    locations_json = '{}/locations-bookey.json'.\
      format(RemoteHelper.CONFIG_DIR)
    local_state.should_receive('shell').with_args(
      re.compile('^scp .*{}'.format(locations_json)), False, 5)

    local_state.should_receive('shell').with_args(
      re.compile('^scp .*/root/.appscale/locations-bookey.json'), False, 5)

    # Assume the secret file was copied successfully.
    local_state.should_receive('shell').with_args(
      re.compile('^scp .*bookey.secret'), False, 5)

    RemoteHelper.copy_local_metadata('public1', 'bookey', False)


  def test_create_user_accounts(self):
    # mock out reading the secret key
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.LOCAL_APPSCALE_PATH + "bookey.secret"
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out reading the locations.json file, and slip in our own json
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location('bookey')).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location('bookey'), 'r') \
      .and_return(fake_nodes_json)

    # Mock out SOAP interactions with the AppController.
    fake_appcontroller = flexmock(name="fake_appcontroller")
    fake_appcontroller.should_receive('does_user_exist').with_args('boo@foo.goo',
      'the secret').and_return('false')
    fake_appcontroller.should_receive('create_user').with_args('boo@foo.goo', str,
      'xmpp_user', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_user_exist').with_args('boo@public1',
      'the secret').and_return('false')
    fake_appcontroller.should_receive('create_user').with_args('boo@public1', str,
      'xmpp_user', 'the secret').and_return('true')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)
    RemoteHelper.create_user_accounts('boo@foo.goo', 'password', 'public1',
      'bookey')


  def test_wait_for_machines_to_finish_loading(self):
    # mock out reading the secret key
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.LOCAL_APPSCALE_PATH + "bookey.secret"
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out getting all the ips in the deployment from the head node
    fake_soap = flexmock(name='fake_soap')
    fake_soap.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return(json.dumps(['public1', 'public2']))
    role_info = [
      {
        'public_ip' : 'public1',
        'private_ip' : 'private1',
        'jobs' : ['shadow', 'db_master']
      },
      {
        'public_ip' : 'public2',
        'private_ip' : 'private2',
        'jobs' : ['appengine']
      }
    ]
    fake_soap.should_receive('get_role_info').with_args('the secret') \
      .and_return(json.dumps(role_info))

    # also, let's say that our machines aren't running the first time we ask,
    # but that they are the second time
    fake_soap.should_receive('is_done_initializing').with_args('the secret') \
      .and_return(False).and_return(True)

    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_soap)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public2:17443') \
      .and_return(fake_soap)

    RemoteHelper.wait_for_machines_to_finish_loading('public1', 'bookey')


  reattach_options = flexmock(
      infrastructure='euca',
      group='group',
      machine='vm image',
      instance_type='instance type',
      keyname='keyname',
      table='cassandra',
      verbose=False,
      test=False,
      use_spot_instances=False,
      zone='zone',
      static_ip=None,
      replication=None,
      appengine=None,
      autoscale=None,
      user_commands=[],
      flower_password='',
      max_memory='X',
      ips={
        'master': 'node-1', 'zookeeper': 'node-2',
        'appengine': 'node-3', 'database': 'node-4'}
    )

  reattach_node_info = [{ "public_ip": "0.0.0.0",
                          "private_ip": "0.0.0.0",
                          "instance_id": "i-APPSCALE1",
                          "jobs": ['load_balancer', 'taskqueue', 'shadow', 'login',
                                   'taskqueue_master'] },
                        { "public_ip": "0.0.0.0",
                          "private_ip": "0.0.0.0",
                          "instance_id": "i-APPSCALE2",
                          "jobs": ['memcache', 'appengine'] },
                        { "public_ip": "0.0.0.0",
                          "private_ip": "0.0.0.0",
                          "instance_id": "i-APPSCALE3",
                          "jobs": ['zookeeper'] },
                        { "public_ip": "0.0.0.0",
                          "private_ip": "0.0.0.0",
                          "instance_id": "i-APPSCALE4",
                          "jobs": ['db_master'] }
                        ]

  def test_start_all_nodes_reattach(self):
    self.node_layout = NodeLayout(self.reattach_options)
    self.node_layout.is_valid()
    fake_agent = FakeAgent()
    flexmock(factory.InfrastructureAgentFactory). \
      should_receive('create_agent'). \
      with_args('euca'). \
      and_return(fake_agent)

    LocalState.should_receive('get_login_host').and_return('0.0.0.1')

    LocalState.should_receive('get_local_nodes_info') \
      .and_return(self.reattach_node_info)

    RemoteHelper.start_all_nodes(self.reattach_options,
                                 self.node_layout)



  def test_start_all_nodes_reattach_changed_asf(self):
    self.options = flexmock(
      infrastructure='public cloud',
      group='group',
      machine='vm image',
      instance_type='instance type',
      keyname='keyname',
      table='cassandra',
      verbose=False,
      test=False,
      use_spot_instances=False,
      zone='zone',
      static_ip=None,
      replication=None,
      appengine=None,
      autoscale=None,
      user_commands=[],
      flower_password='',
      max_memory='X',
      ips={
        'zookeeper': 'node-2', 'master': 'node-1',
        'appengine': 'node-3', 'database': 'node-3'}
    )

    self.node_layout = NodeLayout(self.options)

    fake_agent = FakeAgent()
    flexmock(factory.InfrastructureAgentFactory). \
      should_receive('create_agent'). \
      with_args('public cloud'). \
      and_return(fake_agent)

    LocalState.should_receive('get_login_host').and_return('0.0.0.1')

    LocalState.should_receive('get_local_nodes_info')\
      .and_return(self.reattach_node_info)

    self.assertRaises(BadConfigurationException)

  def test_start_all_nodes_reattach_changed_locations(self):
    self.node_layout = NodeLayout(self.reattach_options)

    fake_agent = FakeAgent()
    flexmock(factory.InfrastructureAgentFactory). \
      should_receive('create_agent'). \
      with_args('public cloud'). \
      and_return(fake_agent)

    LocalState.should_receive('get_login_host').and_return('0.0.0.1')

    node_info = [{ "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE1",
                   "jobs": ['load_balancer', 'taskqueue', 'shadow', 'login',
                            'taskqueue_master'] },
                 { "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE2",
                   "jobs": ['memcache', 'appengine'] },
                 { "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE3",
                   "jobs": ['zookeeper', "appengine"] },
                 { "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE4",
                   "jobs": ['db_master'] }
                 ]

    LocalState.should_receive('get_local_nodes_info').and_return(node_info)

    self.assertRaises(BadConfigurationException)
