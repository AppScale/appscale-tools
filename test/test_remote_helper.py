#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import json
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
import M2Crypto
import SOAPpy


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appcontroller_client import AppControllerClient
from appscale_logger import AppScaleLogger
from custom_exceptions import AppScaleException
from custom_exceptions import BadConfigurationException
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
    subprocess.should_receive('Popen').with_args(re.compile('ubuntu'), \
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.failed).and_return(self.success)

    # also assume that we can scp over our ssh keys, but that it fails the first
    # time
    subprocess.should_receive('Popen').with_args(re.compile('/root/.ssh/id_'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.failed).and_return(self.success)
    subprocess.should_receive('Popen').with_args(re.compile(
      '/root/.appscale/bookey.key'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.failed).and_return(self.success)


  def test_start_head_node_in_cloud_but_ami_not_appscale(self):
    # mock out our attempts to find /etc/appscale and presume it doesn't exist
    subprocess.should_receive('Popen').with_args(re.compile('/etc/appscale'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.failed)

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


  def test_rsync_files_from_dir_that_doesnt_exist(self):
    # if the user specifies that we should copy from a directory that doesn't
    # exist, we should throw up and die
    flexmock(os.path)
    os.path.should_receive('exists').with_args('/tmp/booscale-local/lib').and_return(False)
    self.assertRaises(BadConfigurationException, RemoteHelper.rsync_files,
      'public1', 'booscale', '/tmp/booscale-local')


  def test_rsync_files_from_dir_that_does_exist(self):
    # if the user specifies that we should copy from a directory that does
    # exist, and has all the right directories in it, we should succeed
    flexmock(os.path)
    os.path.should_receive('exists').with_args(re.compile(
      '/tmp/booscale-local/')).and_return(True)

    # assume the rsyncs succeed
    subprocess.should_receive('Popen').with_args(re.compile('rsync'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    RemoteHelper.rsync_files('public1', 'booscale', '/tmp/booscale-local')


  def test_copy_deployment_credentials_in_cloud(self):
    # mock out the scp'ing to public1 and assume they succeed
    subprocess.should_receive('Popen').with_args(re.compile('secret.key'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    subprocess.should_receive('Popen').with_args(re.compile('ssh.key'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    # mock out generating the private key
    flexmock(M2Crypto.RSA)
    fake_rsa_key = flexmock(name='fake_rsa_key')
    fake_rsa_key.should_receive('save_key').with_args(
      LocalState.get_private_key_location('bookey'), None)
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
    fake_cert.should_receive('sign').with_args(fake_pkey, md="sha256")
    fake_cert.should_receive('save_pem').with_args(
      LocalState.get_certificate_location('bookey'))
    M2Crypto.X509.should_receive('X509').and_return(fake_cert)

    # next, mock out copying the private key and certificate
    subprocess.should_receive('Popen').with_args(re.compile('mycert.pem'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    subprocess.should_receive('Popen').with_args(re.compile('mykey.pem'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    subprocess.should_receive('Popen').with_args(re.compile('mkdir -p'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    options = flexmock(name='options', keyname='bookey', infrastructure='ec2')
    RemoteHelper.copy_deployment_credentials('public1', options)


  def test_start_remote_appcontroller(self):
    # mock out removing the old json file
    subprocess.should_receive('Popen').with_args(re.compile('rm -rf'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    # assume we started god on public1 fine
    subprocess.should_receive('Popen').with_args(re.compile('god &'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    # also assume that we scp'ed over the god config file fine
    subprocess.should_receive('Popen').with_args(re.compile('appcontroller'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    # and assume we started the AppController on public1 fine
    subprocess.should_receive('Popen').with_args(re.compile('god load'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)

    # finally, assume the appcontroller comes up after a few tries
    # assume that ssh comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      AppControllerClient.PORT)).and_raise(Exception) \
      .and_raise(Exception).and_return(None)
    socket.should_receive('socket').and_return(fake_socket)

    RemoteHelper.start_remote_appcontroller('public1', 'bookey')


  def test_copy_local_metadata(self):
    # mock out the copying of the two files
    subprocess.should_receive('Popen').with_args(re.compile(
      'locations-bookey.[yaml|json]'),
      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) \
      .and_return(self.success)
    RemoteHelper.copy_local_metadata('public1', 'bookey')


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
    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(json.dumps([{
      "public_ip" : "public1",
      "private_ip" : "private1",
      "jobs" : ["shadow", "login"]
    }]))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location('bookey'), 'r') \
      .and_return(fake_nodes_json)

    # mock out SOAP interactions with the UserAppServer
    fake_soap = flexmock(name='fake_soap')
    fake_soap.should_receive('commit_new_user').with_args('boo@foo.goo', str,
      'xmpp_user', 'the secret').and_return('true')
    fake_soap.should_receive('commit_new_user').with_args('boo@public1', str,
      'xmpp_user', 'the secret').and_return('true')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:4343') \
      .and_return(fake_soap)

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
