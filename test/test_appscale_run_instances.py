#!/usr/bin/env python


# General-purpose Python library imports
import base64
import httplib
import json
import os
import re
import socket
import sys
import tempfile
import time
import unittest
import uuid
import yaml


# Third party libraries
import boto.ec2
from flexmock import flexmock
import SOAPpy


# AppScale import, the library that we're testing here
from appscale.tools.agents.ec2_agent import EC2Agent
from appscale.tools.appcontroller_client import AppControllerClient
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.local_state import APPSCALE_VERSION
from appscale.tools.local_state import LocalState
from appscale.tools.parse_args import ParseArgs
from appscale.tools.remote_helper import RemoteHelper
from appscale.tools.custom_exceptions import BadConfigurationException


class TestAppScaleRunInstances(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.group = "bazgroup"
    self.function = "appscale-run-instances"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('success').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    # pretend we have an appscalefile at the right location, and that it
    # specifies the keyname and group
    appscalefile_path = os.getcwd() + os.sep + "AppScalefile"
    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(appscalefile_path) \
      .and_return(True)

    appscalefile_contents = """
keyname: {0}
group: {1}
""".format(self.keyname, self.group)

    self.builtins = flexmock(sys.modules['__builtin__'])
    self.builtins.should_call('open')  # set the fall-through
    fake_appscalefile = flexmock(name="fake_appscalefile")
    fake_appscalefile.should_receive('read').and_return(appscalefile_contents)
    fake_appscalefile.should_receive('write').and_return()
    self.builtins.should_receive('open').with_args(appscalefile_path, 'r') \
      .and_return(fake_appscalefile)
    self.builtins.should_receive('open').with_args(appscalefile_path, 'w') \
      .and_return(fake_appscalefile)

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

    # mock out interactions with AWS
    self.fake_ec2 = flexmock(name='fake_ec2')

    # And add in mocks for libraries most of the tests mock out
    self.local_state = flexmock(LocalState)


  def tearDown(self):
    # remove the environment variables we set up to not accidentally mess
    # up other unit tests
    for credential in EC2Agent.REQUIRED_EC2_CREDENTIALS:
      os.environ[credential] = ""


  def setup_ec2_mocks(self):
    # first, pretend that our image does exist in EC2
    self.fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()

    # Next, pretend that if the user wants to use an Elastic IP / Static IP,
    # that it has already been allocated for them.
    self.fake_ec2.should_receive('get_all_addresses').with_args('elastic-ip') \
      .and_return()

    # Associating the Elastic IP should work fine (since we validate that the
    # user owns it above).
    self.fake_ec2.should_receive('associate_address').with_args('i-ABCDEFG',
      'elastic-ip').and_return()

    # Also pretend that the availability zone we want to use exists.
    self.fake_ec2.should_receive('get_all_zones').with_args('my-zone-1b') \
      .and_return('anything')

    # next, assume that our keypair doesn't exist yet
    self.fake_ec2.should_receive('get_key_pair').with_args(self.keyname) \
      .and_return(None)

    # next, assume there are no security groups up at first, but then it gets
    # created.
    udp_rule = flexmock(from_port=1, to_port=65535, ip_protocol='udp')
    tcp_rule = flexmock(from_port=1, to_port=65535, ip_protocol='tcp')
    icmp_rule = flexmock(from_port=-1, to_port=-1, ip_protocol='icmp')
    group = flexmock(name=self.group, rules=[tcp_rule, udp_rule, icmp_rule])
    self.fake_ec2.should_receive('get_all_security_groups').with_args().and_return([])
    self.fake_ec2.should_receive('get_all_security_groups').with_args(self.group).and_return([group])


    # mock out creating the keypair
    fake_key = flexmock(name='fake_key', material='baz')
    self.local_state.should_receive('write_key_file').with_args(
      re.compile(self.keyname), fake_key.material).and_return()
    self.fake_ec2.should_receive('create_key_pair').with_args(self.keyname) \
      .and_return(fake_key)

    # and the same for the security group
    self.fake_ec2.should_receive('create_security_group').with_args(self.group,
      str).and_return()
    self.fake_ec2.should_receive('authorize_security_group').with_args(self.group,
      from_port=1, to_port=65535, ip_protocol='udp', cidr_ip='0.0.0.0/0')
    self.fake_ec2.should_receive('authorize_security_group').with_args(self.group,
      from_port=1, to_port=65535, ip_protocol='tcp', cidr_ip='0.0.0.0/0')
    self.fake_ec2.should_receive('authorize_security_group').with_args(self.group,
      from_port=-1, to_port=-1, ip_protocol='icmp', cidr_ip='0.0.0.0/0')

    # assume that there are no instances running initially, and that the
    # instance we spawn starts as pending, then becomes running
    no_instances = flexmock(name='no_instances', instances=[])

    pending_instance = flexmock(name='pending_instance', state='pending',
      key_name=self.keyname, id='i-ABCDEFG')
    pending_reservation = flexmock(name='pending_reservation',
      instances=[pending_instance])

    running_instance = flexmock(name='running_instance', state='running',
      key_name=self.keyname, id='i-ABCDEFG', ip_address='public1',
      private_ip_address='private1')
    running_reservation = flexmock(name='running_reservation',
      instances=[running_instance])

    self.fake_ec2.should_receive('get_all_instances').and_return(no_instances) \
      .and_return(no_instances).and_return(pending_reservation) \
      .and_return(running_reservation)

    # finally, inject the mocked EC2 in
    flexmock(boto.ec2)
    boto.ec2.should_receive('connect_to_region').and_return(self.fake_ec2)


  def setup_appscale_compatibility_mocks(self):
    # Assume the config directory exists.
    self.local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile(RemoteHelper.CONFIG_DIR)).and_return()

    flexmock(RemoteHelper)
    RemoteHelper.should_receive('get_host_appscale_version').\
      and_return(APPSCALE_VERSION)

    # Assume we are using a supported database.
    db_file = '{}/{}/{}'.\
      format(RemoteHelper.CONFIG_DIR, APPSCALE_VERSION, 'cassandra')
    self.local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile(db_file))


  def setup_appcontroller_mocks(self, public_ip, private_ip):
    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('set_parameters').\
      with_args(str, str, 'the secret').and_return('OK')
    fake_appcontroller.should_receive('get_all_public_ips').\
      with_args('the secret').and_return(json.dumps([public_ip]))
    role_info = [{
      'public_ip' : public_ip,
      'private_ip' : private_ip,
      'jobs' : ['shadow', 'login'],
      'instance_id': 'i-APPSCALE'
    }]
    fake_appcontroller.should_receive('get_role_info').with_args('the secret') \
      .and_return(json.dumps(role_info))
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('nothing interesting here') \
      .and_return('Database is at not-up-yet') \
      .and_return('Database is at {0}'.format(public_ip))
    fake_appcontroller.should_receive('is_done_initializing') \
      .and_return(False) \
      .and_return(True)
    fake_appcontroller.should_receive('is_initialized').and_return(True)
    fake_appcontroller.should_receive('does_user_exist').and_return(False)
    fake_appcontroller.should_receive('set_admin_role').and_return()
    fake_appcontroller.should_receive('create_user').with_args(
      'a@a.com', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_appcontroller.should_receive('create_user').with_args(
      'a@' + public_ip, str, 'xmpp_user', 'the secret') \
      .and_return('true')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://{0}:17443'.format(
      public_ip)).and_return(fake_appcontroller)


  def setup_socket_mocks(self, host):
    # assume that ssh comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args((host,
      RemoteHelper.SSH_PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # assume that the AppController comes up on the third attempt
    fake_socket.should_receive('connect').with_args((host,
      AppControllerClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # as well as for the AppDashboard
    fake_socket.should_receive('connect').with_args((host,
      RemoteHelper.APP_DASHBOARD_PORT)).and_raise(Exception) \
      .and_raise(Exception).and_return(None)

    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)


  def test_appscale_in_one_node_virt_deployment(self):
    self.local_state.should_receive('shell').\
      with_args("ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet "
                "-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no "
                "-o UserKnownHostsFile=/dev/null root@public1 ",
                False, 5,
                stdin="cp /root/appscale/AppController/scripts/appcontroller "
                      "/etc/init.d/")

    self.local_state.should_receive('shell').\
      with_args("ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet "
                "-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no "
                "-o UserKnownHostsFile=/dev/null root@1.2.3.4 ",
                False, 5, stdin="chmod +x /etc/init.d/appcontroller")
    
    self.local_state.should_receive('shell').\
      with_args("ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet "
                "-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no "
                "-o UserKnownHostsFile=/dev/null root@public1 ",
                False, 5,
                stdin="cp /root/appscale/AppController/scripts/appcontroller "
                      "/etc/init.d/")

    # let's say that appscale isn't already running
    self.local_state.should_receive('ensure_appscale_isnt_running').and_return()
    self.local_state.should_receive('make_appscale_directory').and_return()

    rh = flexmock(RemoteHelper)
    rh.should_receive('copy_deployment_credentials').and_return()

    # mock out talking to logs.appscale.com
    fake_connection = flexmock(name='fake_connection')
    fake_connection.should_receive('request').\
      with_args('POST', '/upload', str, AppScaleLogger.HEADERS).and_return()

    flexmock(httplib)
    httplib.should_receive('HTTPConnection').\
      with_args('logs.appscale.com').and_return(fake_connection)

    # mock out generating the secret key
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return('the secret')

    # mock out writing the secret key to ~/.appscale, as well as reading it
    # later
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    fake_secret.should_receive('write').and_return()
    self.builtins.should_receive('open').\
      with_args(secret_key_location, 'r').and_return(fake_secret)
    self.builtins.should_receive('open').\
      with_args(secret_key_location, 'w').and_return(fake_secret)

    # Don't write local metadata files.
    flexmock(LocalState).should_receive('update_local_metadata')

    # mock out copying over the keys
    self.local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*.key'),False,5)

    self.setup_appscale_compatibility_mocks()

    # mock out generating the private key
    self.local_state.should_receive('shell')\
      .with_args(re.compile('^openssl'),False,stdin=None)\
      .and_return()

    # mock out removing the old json file
    self.local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,stdin=re.compile('rm -rf'))\
      .and_return()

    # assume that we started monit fine
    self.local_state.should_receive('shell')\
      .with_args(re.compile('^ssh'),False,5,stdin=re.compile('monit'))\
      .and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('^ssh'), False, 5, stdin='service appscale-controller start')

    self.local_state.should_receive('shell').\
      with_args('ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet '
                '-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no '
                '-o UserKnownHostsFile=/dev/null root@1.2.3.4 ',
                False, 5,
                stdin='cp /root/appscale/AppController/scripts/appcontroller /etc/init.d/').and_return()

    self.setup_socket_mocks('1.2.3.4')
    self.setup_appcontroller_mocks('1.2.3.4', '1.2.3.4')

    # mock out reading the locations.json file, and slip in our own json
    self.local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip": "1.2.3.4",
        "private_ip": "1.2.3.4",
        "jobs": ["shadow", "login"]
      }])))

    # Assume the locations files were copied successfully.
    locations_file = '{}/locations-bookey.yaml'.\
      format(RemoteHelper.CONFIG_DIR)
    self.local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*{}'.format(locations_file)), False, 5)\
      .and_return()

    locations_json = '{}/locations-bookey.json'.\
      format(RemoteHelper.CONFIG_DIR)
    self.local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*{}'.format(locations_json)), False, 5)\
      .and_return()

    user_locations = '/root/.appscale/locations-bookey.json'
    self.local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*{}'.format(user_locations)), False, 5)\
      .and_return()

    # Assume the secret key was copied successfully.
    self.local_state.should_receive('shell')\
      .with_args(re.compile('^scp .*.secret'), False, 5)\
      .and_return()

    flexmock(AppControllerClient)
    AppControllerClient.should_receive('does_user_exist').and_return(True)

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
    local_appscale_path = os.path.expanduser("~") + os.sep + ".appscale" + \
      os.sep + self.keyname + ".key"
    self.local_state.should_receive('ensure_appscale_isnt_running').and_return()
    self.local_state.should_receive('make_appscale_directory').and_return()
    self.local_state.should_receive('get_key_path_from_name').and_return(
      local_appscale_path)

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
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    fake_secret.should_receive('write').and_return()
    self.builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)
    self.builtins.should_receive('open').with_args(secret_key_location, 'w') \
      .and_return(fake_secret)

    self.setup_ec2_mocks()

    # slip in some fake spot instance info
    fake_entry = flexmock(name='fake_entry', price=1)
    self.fake_ec2.should_receive('get_spot_price_history').with_args(
      start_time=str, end_time=str,
      product_description='Linux/UNIX', instance_type='m3.medium',
      availability_zone='my-zone-1b').and_return([fake_entry])

    # also mock out acquiring a spot instance
    self.fake_ec2.should_receive('request_spot_instances').with_args('1.1',
      'ami-ABCDEFG', key_name=self.keyname, security_groups=[self.group],
      instance_type='m3.medium', count=1, placement='my-zone-1b')

    # Don't write local metadata files.
    flexmock(LocalState).should_receive('update_local_metadata')

    # assume that root login is not enabled
    self.local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin='ls').and_return(RemoteHelper.LOGIN_AS_UBUNTU_USER)

    # assume that we can enable root login
    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5,
      stdin='sudo touch /root/.ssh/authorized_keys').and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5,
      stdin='sudo chmod 600 /root/.ssh/authorized_keys').and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5, stdin='mktemp').and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5,
      stdin=re.compile(
        'sudo sort -u ~/.ssh/authorized_keys /root/.ssh/authorized_keys -o '
      )
    ).and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5,
      stdin=re.compile(
        'sudo sed -n '
        '\'\/\.\*Please login\/d; w\/root\/\.ssh\/authorized_keys\' '
      )
    ).and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5, stdin=re.compile('rm -f ')
    ).and_return()

    # and assume that we can copy over our ssh keys fine
    self.local_state.should_receive('shell').\
      with_args(re.compile('scp .*[r|d]sa'), False, 5).and_return()
    self.local_state.should_receive('shell').\
      with_args(re.compile('scp .*{0}'.format(self.keyname)), False, 5).\
      and_return()

    self.local_state.should_receive('shell').\
      with_args('ssh -i /root/.appscale/bookey.key -o LogLevel=quiet -o '
                'NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no '
                '-o UserKnownHostsFile=/dev/null root@public1 ',
                False, 5,
                stdin='cp /root/appscale/AppController/scripts/appcontroller '
                      '/etc/init.d/').\
      and_return()

    self.local_state.should_receive('shell').\
      with_args('ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet '
                '-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no '
                '-o UserKnownHostsFile=/dev/null root@elastic-ip ',
                False, 5,
                stdin='cp /root/appscale/AppController/scripts/appcontroller '
                      '/etc/init.d/').\
      and_return()

    self.local_state.should_receive('shell').\
      with_args('ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet '
                '-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no '
                '-o UserKnownHostsFile=/dev/null root@elastic-ip ',
                False, 5, stdin='chmod +x /etc/init.d/appcontroller').\
      and_return()

    self.setup_appscale_compatibility_mocks()

    # mock out generating the private key
    self.local_state.should_receive('shell').with_args(re.compile('openssl'),
      False, stdin=None)

    # assume that we started monit fine
    self.local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('monit'))

    self.local_state.should_receive('shell').with_args(
      re.compile('^ssh'), False, 5, stdin='service appscale-controller start')

    self.setup_socket_mocks('elastic-ip')
    self.setup_appcontroller_mocks('elastic-ip', 'private1')

    # mock out reading the locations.json file, and slip in our own json
    self.local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "elastic-ip",
        "private_ip" : "private1",
        "jobs": ["shadow", "login"]
      }])))

    # copying over the locations yaml and json files should be fine
    self.local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('locations-{0}'.format(self.keyname)))

    # same for the secret key
    self.local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('{0}.secret'.format(self.keyname)))

    flexmock(RemoteHelper).should_receive('copy_deployment_credentials')
    flexmock(AppControllerClient)
    AppControllerClient.should_receive('does_user_exist').and_return(True)

    # Let's mock the call to describe_instances when checking for old
    # instances to re-use, and then to start the headnode.
    pending_instance = flexmock(name='pending_instance', state='pending',
      key_name=self.keyname, id='i-ABCDEFG')
    pending_reservation = flexmock(name='pending_reservation',
      instances=[pending_instance])

    no_instances = flexmock(name='no_instances', instances=[])
    running_instance = flexmock(name='running_instance', state='running',
      key_name=self.keyname, id='i-ABCDEFG', ip_address='public1',
      private_ip_address='private1')
    running_reservation = flexmock(name='running_reservation',
      instances=[running_instance])

    self.fake_ec2.should_receive('get_all_instances').and_return(no_instances) \
      .and_return(no_instances) \
      .and_return(no_instances).and_return(pending_reservation) \
      .and_return(running_reservation)

    argv = [
      "--min", "1",
      "--max", "1",
      "--infrastructure", "ec2",
      "--machine", "ami-ABCDEFG",
      "--instance_type", "m3.medium",
      "--use_spot_instances",
      "--keyname", self.keyname,
      "--group", self.group,
      "--test",
      "--zone", "my-zone-1b",
      "--static_ip", "elastic-ip"
    ]

    options = ParseArgs(argv, self.function).args
    AppScaleTools.run_instances(options)


  def test_appscale_in_one_node_cloud_deployment_manual_spot_price(self):
    # let's say that appscale isn't already running
    local_appscale_path = os.path.expanduser("~") + os.sep + ".appscale" + \
      os.sep + self.keyname + ".key"
    self.local_state.should_receive('ensure_appscale_isnt_running').and_return()
    self.local_state.should_receive('make_appscale_directory').and_return()
    self.local_state.should_receive('get_key_path_from_name').and_return(
      local_appscale_path)

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
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    fake_secret.should_receive('write').and_return()
    self.builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)
    self.builtins.should_receive('open').with_args(secret_key_location, 'w') \
      .and_return(fake_secret)

    self.setup_ec2_mocks()

    # also mock out acquiring a spot instance
    self.fake_ec2.should_receive('request_spot_instances').with_args('1.23',
      'ami-ABCDEFG', key_name=self.keyname, security_groups=['bazgroup'],
      instance_type='m3.medium', count=1, placement='my-zone-1b')

    # Don't write local metadata files.
    flexmock(LocalState).should_receive('update_local_metadata')

    # assume that root login is not enabled
    self.local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin='ls').and_return(RemoteHelper.LOGIN_AS_UBUNTU_USER)

    # assume that we can enable root login
    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5,
      stdin='sudo touch /root/.ssh/authorized_keys').and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5,
      stdin='sudo chmod 600 /root/.ssh/authorized_keys').and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5, stdin='mktemp').and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5,
      stdin=re.compile(
        'sudo sort -u ~/.ssh/authorized_keys /root/.ssh/authorized_keys -o '
      )
    ).and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5,
      stdin=re.compile(
        'sudo sed -n '
        '\'\/\.\*Please login\/d; w\/root\/\.ssh\/authorized_keys\' '
      )
    ).and_return()

    self.local_state.should_receive('shell').with_args(
      re.compile('ssh'), False, 5, stdin=re.compile('rm -f ')
    ).and_return()

    # and assume that we can copy over our ssh keys fine
    self.local_state.should_receive('shell').with_args(re.compile('scp .*[r|d]sa'),
      False, 5).and_return()
    self.local_state.should_receive('shell').with_args(re.compile('scp .*{0}'
      .format(self.keyname)), False, 5).and_return()

    self.setup_appscale_compatibility_mocks()

    # mock out generating the private key
    self.local_state.should_receive('shell').with_args(re.compile('openssl'),
      False, stdin=None)

    # assume that we started monit fine
    self.local_state.should_receive('shell').with_args(re.compile('ssh'),
      False, 5, stdin=re.compile('monit'))

    self.local_state.should_receive('shell').with_args(
      re.compile('^ssh'), False, 5, stdin='service appscale-controller start')

    self.setup_socket_mocks('public1')
    self.setup_appcontroller_mocks('public1', 'private1')

    # mock out reading the locations.json file, and slip in our own json
    self.local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "public1",
        "private_ip" : "private1",
        "jobs" : ["shadow", "login"]
      }])))

    # copying over the locations json file should be fine
    self.local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('locations-{0}'.format(self.keyname)))

    # same for the secret key
    self.local_state.should_receive('shell').with_args(re.compile('scp'),
      False, 5, stdin=re.compile('{0}.secret'.format(self.keyname)))

    self.local_state.should_receive('shell').with_args('ssh -i /root/.appscale/boobazbargfoo.key -o LogLevel=quiet -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null root@public1 ', False, 5, stdin='cp /root/appscale/AppController/scripts/appcontroller /etc/init.d/').and_return()

    self.local_state.should_receive('shell').with_args('ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null root@elastic-ip ', False, 5, stdin='cp /root/appscale/AppController/scripts/appcontroller /etc/init.d/').and_return()

    self.local_state.should_receive('shell').with_args('ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null root@elastic-ip ', False, 5, stdin='chmod +x /etc/init.d/appcontroller').and_return()

    self.local_state.should_receive('shell').with_args('ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null root@public1 ', False, 5, stdin='cp /root/appscale/AppController/scripts/appcontroller /etc/init.d/')

    self.local_state.should_receive('shell').with_args('ssh -i /root/.appscale/boobazblargfoo.key -o LogLevel=quiet -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null root@public1 ', False, 5, stdin='chmod +x /etc/init.d/appcontroller').and_return()

    flexmock(RemoteHelper).should_receive('copy_deployment_credentials')
    flexmock(AppControllerClient)
    AppControllerClient.should_receive('does_user_exist').and_return(True)

    # Let's mock the call to describe_instances when checking for old
    # instances to re-use, and then to start the headnode.
    pending_instance = flexmock(name='pending_instance', state='pending',
                                key_name=self.keyname, id='i-ABCDEFG')
    pending_reservation = flexmock(name='pending_reservation',
                                   instances=[pending_instance])

    no_instances = flexmock(name='no_instances', instances=[])
    running_instance = flexmock(name='running_instance', state='running',
                                key_name=self.keyname, id='i-ABCDEFG',
                                ip_address='public1',
                                private_ip_address='private1')
    running_reservation = flexmock(name='running_reservation',
                                   instances=[running_instance])

    self.fake_ec2.should_receive('get_all_instances').and_return(no_instances) \
      .and_return(no_instances) \
      .and_return(no_instances).and_return(pending_reservation) \
      .and_return(running_reservation)

    argv = [
      "--min", "1",
      "--max", "1",
      "--infrastructure", "ec2",
      "--instance_type", "m3.medium",
      "--machine", "ami-ABCDEFG",
      "--use_spot_instances",
      "--max_spot_price", "1.23",
      "--keyname", self.keyname,
      "--group", self.group,
      "--test",
      "--zone", "my-zone-1b"
    ]

    options = ParseArgs(argv, self.function).args
    AppScaleTools.run_instances(options)


  def test_appscale_in_one_node_virt_deployment_with_login_override(self):
    # let's say that appscale isn't already running
    self.local_state.should_receive('ensure_appscale_isnt_running').and_return()
    self.local_state.should_receive('make_appscale_directory').and_return()
    self.local_state.should_receive('update_local_metadata').and_return()
    self.local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "1.2.3.4",
        "private_ip" : "1.2.3.4",
        "jobs" : ["shadow", "login"]
      }])))
    self.local_state.should_receive('get_secret_key').and_return("fookey")

    flexmock(RemoteHelper)
    RemoteHelper.should_receive('enable_root_ssh').and_return()
    RemoteHelper.should_receive('ensure_machine_is_compatible')\
        .and_return()
    RemoteHelper.should_receive('start_head_node')\
        .and_return(('1.2.3.4','i-ABCDEFG'))
    RemoteHelper.should_receive('sleep_until_port_is_open').and_return()
    RemoteHelper.should_receive('copy_local_metadata').and_return()
    RemoteHelper.should_receive('create_user_accounts').and_return()
    RemoteHelper.should_receive('wait_for_machines_to_finish_loading')\
        .and_return()
    RemoteHelper.should_receive('copy_deployment_credentials')

    flexmock(AppControllerClient)
    AppControllerClient.should_receive('does_user_exist').and_return(True)
    AppControllerClient.should_receive('is_initialized').and_return(True)
    AppControllerClient.should_receive('set_admin_role').and_return()

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
