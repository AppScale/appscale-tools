#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import base64
import httplib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import yaml


# Third party libraries
from flexmock import flexmock
import M2Crypto
import SOAPpy


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
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

#    flexmock(LocalState)
#    LocalState.should_receive('shell').and_raise(Exception)
#    LocalState.should_receive('ensure_appscale_isnt_running').and_return()
#
#    remote_helper = flexmock(RemoteHelper)
#    remote_helper.should_receive('start_head_node').and_return()
#    remote_helper.should_receive('ensure_machine_is_compatible').and_return()
#    remote_helper.should_receive('does_host_have_location').and_return()

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


  def test_appscale_in_one_node_virt_deployment(self):
    # let's say that appscale isn't already running

#    osp = flexmock(os.path)
#    #osp.should_call('exists')
#    osp.should_receive('exists').with_args(
#      LocalState.get_locations_yaml_location(self.keyname)).and_return(False)
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

    # mock out seeing if the image is appscale-compatible, and assume it is
    # mock out our attempts to find /etc/appscale and presume it does exist
    flexmock(subprocess)
    #subprocess.should_receive('Popen').with_args(re.compile('/etc/appscale'),
    subprocess.should_receive('Popen').with_args(re.compile('ssh'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT,\
      stdin=self.fake_input_file) \
      .and_return(self.success)

    # mock out our attempts to find /etc/appscale/version and presume it does
    # exist
    #subprocess.should_receive('Popen').with_args(re.compile(
    #  '/etc/appscale/{0}'.format(APPSCALE_VERSION)),
    subprocess.should_receive('Popen').with_args(re.compile('ssh'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT,\
      stdin=self.fake_input_file) \
      .and_return(self.success)

    # put in a mock indicating that the database the user wants is supported
    #subprocess.should_receive('Popen').with_args(re.compile(
    #  '/etc/appscale/{0}/{1}'.format(APPSCALE_VERSION, 'cassandra')),
    subprocess.should_receive('Popen').with_args(re.compile('ssh'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT,\
      stdin=self.fake_input_file) \
      .and_return(self.success)

    # mock out generating the private key
    flexmock(M2Crypto.RSA)
    fake_rsa_key = flexmock(name='fake_rsa_key')
    fake_rsa_key.should_receive('save_key').with_args(
      LocalState.get_private_key_location(self.keyname), None)
    M2Crypto.RSA.should_receive('gen_key').and_return(fake_rsa_key)

    flexmock(M2Crypto.EVP)
    fake_pkey = flexmock(name='fake_pkey')
    fake_pkey.should_receive('assign_rsa').with_args(fake_rsa_key).and_return()
    M2Crypto.EVP.should_receive('PKey').and_return(fake_pkey)

    # and mock out generating the certificate
    flexmock(M2Crypto.X509)
    fake_cert = flexmock(name='fake_x509')
    fake_cert.should_receive('set_pubkey').with_args(fake_pkey).and_return()
    fake_cert.should_receive('set_subject')
    fake_cert.should_receive('set_issuer_name')
    fake_cert.should_receive('set_not_before')
    fake_cert.should_receive('set_not_after')
    fake_cert.should_receive('set_version')
    fake_cert.should_receive('set_serial_number')
    fake_cert.should_receive('sign').with_args(fake_pkey, md="sha1")
    fake_cert.should_receive('save_pem').with_args(
      LocalState.get_certificate_location(self.keyname))
    M2Crypto.X509.should_receive('X509').and_return(fake_cert)

    # assume that we started god fine
    #subprocess.should_receive('Popen').with_args(re.compile('god &'),
    subprocess.should_receive('Popen').with_args(re.compile('ssh'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT,\
      stdin=self.fake_input_file) \
      .and_return(self.success)

    # and that we copied over the AppController's god file
    #subprocess.should_receive('Popen').with_args(re.compile(
    #  'appcontroller.god'),
    subprocess.should_receive('Popen').with_args(re.compile('ssh'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT,\
      stdin=self.fake_input_file) \
      .and_return(self.success)

    # also, that we started the AppController itself
    #subprocess.should_receive('Popen').with_args(re.compile('god load'),
    subprocess.should_receive('Popen').with_args(re.compile('ssh'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT,\
      stdin=self.fake_input_file) \
      .and_return(self.success)

    # assume that the AppController comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('1.2.3.4',
      AppControllerClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # same for the UserAppServer
    fake_socket.should_receive('connect').with_args(('1.2.3.4',
      UserAppClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # as well as for the AppLoadBalancer
    fake_socket.should_receive('connect').with_args(('1.2.3.4',
      RemoteHelper.APP_LOAD_BALANCER_PORT)).and_raise(Exception) \
      .and_raise(Exception).and_return(None)

    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('set_parameters').with_args(list, list,
      ['none'], 'the secret').and_return('OK')
    fake_appcontroller.should_receive('get_all_public_ips').with_args('the secret') \
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
      .and_raise(Exception) \
      .and_return(False) \
      .and_return(True)
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://1.2.3.4:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
#    os.path.should_receive('exists').with_args(
#      LocalState.get_locations_json_location(self.keyname)).and_return(True)
#
#    fake_nodes_json = flexmock(name="fake_nodes_json")
#    fake_nodes_json.should_receive('read').and_return(json.dumps([{
#      "public_ip" : "1.2.3.4",
#      "private_ip" : "1.2.3.4",
#      "jobs" : ["shadow", "login"]
#    }]))
#    fake_nodes_json.should_receive('write').and_return()
#    builtins.should_receive('open').with_args(
#      LocalState.get_locations_json_location(self.keyname), 'r') \
#      .and_return(fake_nodes_json)
#    builtins.should_receive('open').with_args(
#      LocalState.get_locations_json_location(self.keyname), 'w') \
#      .and_return(fake_nodes_json)
    local_state.should_receive('get_local_nodes_info').and_return(json.loads(
      json.dumps([{
        "public_ip" : "1.2.3.4",
        "private_ip" : "1.2.3.4",
        "jobs" : ["shadow", "login"]
      }])))


    # copying over the locations yaml and json files should be fine
    #subprocess.should_receive('Popen').with_args(re.compile(
    #  'locations-{0}.[yaml|json]'.format(self.keyname)),
    subprocess.should_receive('Popen').with_args(re.compile('ssh'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT,\
      stdin=self.fake_input_file) \
      .and_return(self.success)

    #self.success.should_receive('wait').and_return(0)


    # same for the secret key
    #subprocess.should_receive('Popen').with_args(re.compile(
    #  '{0}.secret'.format(self.keyname)),
    subprocess.should_receive('Popen').with_args(re.compile('scp'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    #self.success.should_receive('wait').and_return(0)

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
