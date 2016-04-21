#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import yaml


# Third party libraries
import apiclient
import boto.ec2
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
from agents.gce_agent import CredentialTypes
from agents.gce_agent import GCEAgent
from appscale_logger import AppScaleLogger
from appscale_tools import AppScaleTools
from custom_exceptions import AppScaleException
from local_state import LocalState
from parse_args import ParseArgs


class TestAppScaleTerminateInstances(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.group = "bazboogroup"
    self.function = "appscale-terminate-instances"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('verbose').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    local_state = flexmock(LocalState)
    local_state.should_receive('shell').and_return("")

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


  def test_terminate_when_not_running(self):
    # let's say that there's no locations.yaml file, which means appscale isn't
    # running, so we should throw up and die
    flexmock(os.path)
    os.path.should_call('exists')  # set up the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return(False)

    argv = [
      "--keyname", self.keyname,
      "--test"
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppScaleException, AppScaleTools.terminate_instances,
      options)


  def test_terminate_in_virtual_cluster_and_succeeds(self):
    # let's say that there is a locations.yaml file, which means appscale is
    # running, so we should terminate the services on each box
    flexmock(os.path)
    os.path.should_call('exists')  # set up the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return(True)

    # mock out reading the locations.yaml file, and pretend that we're on
    # a virtualized cluster
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')

    fake_yaml_file = flexmock(name='fake_file')
    fake_yaml_file.should_receive('read').and_return(yaml.dump({
      'infrastructure' : 'xen'
    }))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_yaml_location(self.keyname), 'r') \
      .and_return(fake_yaml_file)

    # mock out reading the json file, and pretend that we're running in a
    # two node deployment
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_json_file = flexmock(name='fake_file')
    fake_json_file.should_receive('read').and_return(json.dumps([
      {
        'public_ip' : 'public1',
        'jobs' : ['shadow']
      },
      {
        'public_ip' : 'public2',
        'jobs' : ['appengine']
      }
    ]))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_json_file)

    # and slip in a fake secret file
    fake_secret_file = flexmock(name='fake_file')
    fake_secret_file.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(
      LocalState.get_secret_key_location(self.keyname), 'r') \
      .and_return(fake_secret_file)

    # mock out talking to the appcontroller, and assume that it tells us there
    # there are still two machines in this deployment
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return(json.dumps(['public1', 'public2']))

    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # and mock out the ssh call to kill the remote appcontroller, assuming that
    # it fails the first time and passes the second
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('controller stop'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.failed).and_return(self.success)

    # next, mock out our checks to see how the stopping process is going and
    # assume that it has stopped
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('ps x'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # finally, mock out removing the yaml file, json file, and secret key from
    # this machine
    flexmock(os)
    os.should_receive('remove').with_args(
      LocalState.get_locations_yaml_location(self.keyname)).and_return()
    os.should_receive('remove').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return()
    os.should_receive('remove').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return()

    # also mock out asking the user for confirmation on shutting down
    # their cloud
    builtins.should_receive('raw_input').and_return('yes')

    argv = [
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.terminate_instances(options)


  def test_terminate_in_cloud_and_succeeds(self):
    # let's say that there is a locations.yaml file, which means appscale is
    # running, so we should terminate the services on each box
    flexmock(os.path)
    os.path.should_call('exists')  # set up the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return(True)

    # mock out reading the locations.yaml file, and pretend that we're on
    # a virtualized cluster
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')

    fake_yaml_file = flexmock(name='fake_file')
    fake_yaml_file.should_receive('read').and_return(yaml.dump({
      'infrastructure' : 'ec2',
      'group' : self.group,
    }))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_yaml_location(self.keyname), 'r') \
      .and_return(fake_yaml_file)

    # mock out reading the json file, and pretend that we're running in a
    # two node deployment
    fake_json_file = flexmock(name='fake_file')
    fake_json_file.should_receive('read').and_return(json.dumps([
      {
        'public_ip' : 'public1',
        'jobs' : ['shadow']
      },
      {
        'public_ip' : 'public2',
        'jobs' : ['appengine']
      }
    ]))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_json_file)

    # and slip in a fake secret file
    fake_secret_file = flexmock(name='fake_file')
    fake_secret_file.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(
      LocalState.get_secret_key_location(self.keyname), 'r') \
      .and_return(fake_secret_file)

    # mock out talking to EC2
    fake_ec2 = flexmock(name='fake_ec2')

    # let's say that three instances are running, and that two of them are in
    # our deployment
    fake_one_running = flexmock(name='fake_one', key_name=self.keyname, state='running',
      id='i-ONE', public_dns_name='public1', private_dns_name='private1')
    fake_two_running = flexmock(name='fake_two', key_name=self.keyname, state='running',
      id='i-TWO', public_dns_name='public2', private_dns_name='private2')
    fake_three_running = flexmock(name='fake_three', key_name='abcdefg',
      state='running', id='i-THREE', public_dns_name='public3',
      private_dns_name='private3')
    fake_reservation_running = flexmock(name='fake_reservation', instances=[fake_one_running,
      fake_two_running, fake_three_running])

    fake_one_terminated = flexmock(name='fake_one', key_name=self.keyname, state='terminated',
      id='i-ONE', public_dns_name='public1', private_dns_name='private1')
    fake_two_terminated = flexmock(name='fake_two', key_name=self.keyname, state='terminated',
      id='i-TWO', public_dns_name='public2', private_dns_name='private2')
    fake_three_terminated = flexmock(name='fake_three', key_name='abcdefg',
      state='terminated', id='i-THREE', public_dns_name='public3',
      private_dns_name='private3')
    fake_reservation_terminated = flexmock(name='fake_reservation', instances=[fake_one_terminated,
      fake_two_terminated, fake_three_terminated])

    fake_ec2.should_receive('get_all_instances').and_return(fake_reservation_running) \
      .and_return(fake_reservation_terminated)

    flexmock(boto.ec2)
    boto.ec2.should_receive('connect_to_region').and_return(fake_ec2)

    # and mock out the call to kill the instances
    fake_ec2.should_receive('terminate_instances').with_args(['i-ONE',
      'i-TWO']).and_return([fake_one_terminated, fake_two_terminated])

    # mock out the call to delete the keypair
    fake_ec2.should_receive('delete_key_pair').and_return()

    # and the call to delete the security group - let's say that we can't
    # delete the group the first time, and can the second
    fake_ec2.should_receive('delete_security_group').and_return(False) \
      .and_return(True)

    # finally, mock out removing the yaml file, json file, and secret key from
    # this machine
    flexmock(os)
    os.should_receive('remove').with_args(
      LocalState.get_locations_yaml_location(self.keyname)).and_return()
    os.should_receive('remove').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return()
    os.should_receive('remove').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return()

    # also mock out asking the user for confirmation on shutting down
    # their cloud
    builtins.should_receive('raw_input').and_return('yes')

    argv = [
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.terminate_instances(options)


  def test_terminate_in_gce_and_succeeds(self):
    # let's say that there is a locations.yaml file, which means appscale is
    # running, so we should terminate the services on each box
    flexmock(os.path)
    os.path.should_call('exists')  # set up the fall-through
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_yaml_location(self.keyname)).and_return(True)
    os.path.should_receive('exists').with_args(
      LocalState.get_client_secrets_location(self.keyname)).and_return(True)
    os.path.should_receive('exists').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return(True)

    # mock out reading the locations.yaml file, and pretend that we're on
    # GCE
    project_id = "1234567890"
    zone = 'my-zone-1b'
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')

    fake_yaml_file = flexmock(name='fake_file')
    fake_yaml_file.should_receive('read').and_return(yaml.dump({
      'infrastructure' : 'gce',
      'group' : self.group,
      'project' : project_id,
      'zone' : zone
    }))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_yaml_location(self.keyname), 'r') \
      .and_return(fake_yaml_file)

    # mock out reading the json file, and pretend that we're running in a
    # two node deployment
    fake_json_file = flexmock(name='fake_file')
    fake_json_file.should_receive('read').and_return(json.dumps([
      {
        'public_ip' : 'public1',
        'jobs' : ['shadow']
      },
      {
        'public_ip' : 'public2',
        'jobs' : ['appengine']
      }
    ]))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_json_file)

    # and slip in a fake secret file
    fake_secret_file = flexmock(name='fake_file')
    fake_secret_file.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(
      LocalState.get_secret_key_location(self.keyname), 'r') \
      .and_return(fake_secret_file)

    # also add in a fake client-secrets file for GCE
    client_secrets = LocalState.get_client_secrets_location(self.keyname)

    # mock out talking to GCE
    # first, mock out the oauth library calls
    fake_flow = flexmock(name='fake_flow')
    flexmock(oauth2client.client)
    oauth2client.client.should_receive('flow_from_clientsecrets').with_args(
      client_secrets, scope=str).and_return(fake_flow)

    fake_storage = flexmock(name='fake_storage')
    fake_storage.should_receive('get').and_return(None)

    fake_flags = oauth2client.tools.argparser.parse_args(args=[])

    flexmock(oauth2client.file)
    oauth2client.file.should_receive('Storage').with_args(str).and_return(
      fake_storage)

    fake_credentials = flexmock(name='fake_credentials')
    flexmock(oauth2client.tools)
    oauth2client.tools.should_receive('run_flow').with_args(fake_flow,
      fake_storage, fake_flags).and_return(fake_credentials)

    # next, mock out http calls to GCE
    fake_http = flexmock(name='fake_http')
    fake_authorized_http = flexmock(name='fake_authorized_http')

    flexmock(httplib2)
    httplib2.should_receive('Http').and_return(fake_http)
    fake_credentials.should_receive('authorize').with_args(fake_http) \
      .and_return(fake_authorized_http)

    fake_gce = flexmock(name='fake_gce')

    # let's say that two instances are running
    instance_one_info = {
      u'status': u'RUNNING',
      u'kind': u'compute#instance',
      u'machineType': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/machineTypes/n1-standard-1',
      u'name': u'bazboogroup-one',
      u'zone': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b',
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
      u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b/instances/bazboogroup-feb10b11-62bc-4536-ac25-9734f2267d6d',
      u'networkInterfaces': [{
        u'accessConfigs': [{
          u'kind': u'compute#accessConfig',
          u'type': u'ONE_TO_ONE_NAT',
          u'name': u'External NAT',
          u'natIP': u'public1'
        }],
        u'networkIP': u'private1',
        u'network': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/networks/bazboogroup',
        u'name': u'nic0'
      }]
    }

    instance_two_info = {
      u'status': u'RUNNING',
      u'kind': u'compute#instance',
      u'machineType': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/machineTypes/n1-standard-1',
      u'name': u'bazboogroup-two',
      u'zone': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b',
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
      u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b/instances/bazboogroup-feb10b11-62bc-4536-ac25-9734f2267d6d',
      u'networkInterfaces': [{
        u'accessConfigs': [{
          u'kind': u'compute#accessConfig',
          u'type': u'ONE_TO_ONE_NAT',
          u'name': u'External NAT',
          u'natIP': u'public1'
        }],
        u'networkIP': u'private1',
        u'network': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/networks/bazboogroup',
        u'name': u'nic0'
      }]
    }

    list_instance_info = {
      u'items': [instance_one_info, instance_two_info],
      u'kind': u'compute#instanceList',
      u'id': u'projects/appscale.com:appscale/zones/my-zone-1b/instances',
      u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/961228229472/zones/my-zone-1b/instances'
    }

    fake_list_instance_request = flexmock(name='fake_list_instance_request')
    fake_list_instance_request.should_receive('execute').with_args(
      http=fake_authorized_http).and_return(list_instance_info)

    fake_instances = flexmock(name='fake_instances')
    fake_instances.should_receive('list').with_args(project=project_id,
      filter="name eq bazboogroup-.*", zone=zone) \
      .and_return(fake_list_instance_request)
    fake_gce.should_receive('instances').and_return(fake_instances)

    # And assume that we can kill both of our instances fine
    delete_instance = u'operation-1369676691806-4ddb6b4ab6f39-a095d3de'
    delete_instance_info_one = {
      u'status': u'PENDING',
      u'kind': u'compute#operation',
      u'name': delete_instance,
      u'zone': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b',
      u'startTime': u'2013-05-27T10:44:51.849-07:00',
      u'insertTime': u'2013-05-27T10:44:51.806-07:00',
      u'targetId': u'12912855597472179535',
      u'targetLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b/instances/appscalecgb20-0cf89267-5887-4048-b774-ca20de47a07f',
      u'operationType': u'delete',
      u'progress': 0,
      u'id': u'11114355109942058217',
      u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b/operations/operation-1369676691806-4ddb6b4ab6f39-a095d3de',
      u'user': u'Chris@appscale.com'
    }

    delete_instance_info_two = {
      u'status': u'PENDING',
      u'kind': u'compute#operation',
      u'name': delete_instance,
      u'zone': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b',
      u'startTime': u'2013-05-27T10:44:51.849-07:00',
      u'insertTime': u'2013-05-27T10:44:51.806-07:00',
      u'targetId': u'12912855597472179535',
      u'targetLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b/instances/appscalecgb20-0cf89267-5887-4048-b774-ca20de47a07f',
      u'operationType': u'delete',
      u'progress': 0,
      u'id': u'11114355109942058217',
      u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/zones/my-zone-1b/operations/operation-1369676691806-4ddb6b4ab6f39-a095d3de',
      u'user': u'Chris@appscale.com'
    }

    fake_delete_instance_request_one = flexmock(name='fake_delete_instance_request_one')
    fake_delete_instance_request_one.should_receive('execute').with_args(
      http=fake_authorized_http).and_return(delete_instance_info_one)
    fake_instances.should_receive('delete').with_args(project=project_id,
      zone=zone, instance='bazboogroup-one').and_return(
      fake_delete_instance_request_one)

    fake_delete_instance_request_two = flexmock(name='fake_delete_instance_request_two')
    fake_delete_instance_request_two.should_receive('execute').with_args(
      http=fake_authorized_http).and_return(delete_instance_info_two)
    fake_instances.should_receive('delete').with_args(project=project_id,
      zone=zone, instance='bazboogroup-two').and_return(
      fake_delete_instance_request_two)

    # mock out our waiting for the instances to be deleted
    all_done = {
      u'status' : u'DONE'
    }

    fake_instance_checker = flexmock(name='fake_instance_checker')
    fake_instance_checker.should_receive('execute').and_return(all_done)

    fake_blocker = flexmock(name='fake_blocker')
    fake_blocker.should_receive('get').with_args(project=project_id,
      operation=delete_instance, zone=zone).and_return(
      fake_instance_checker)
    fake_gce.should_receive('zoneOperations').and_return(fake_blocker)

    # mock out the call to delete the firewall
    delete_firewall = u'operation-1369677695390-4ddb6f07cc611-5a8f1654'
    fake_delete_firewall_info = {
      u'status': u'PENDING',
      u'kind': u'compute#operation',
      u'name': delete_firewall,
      u'startTime': u'2013-05-27T11:01:35.482-07:00',
      u'insertTime': u'2013-05-27T11:01:35.390-07:00',
      u'targetId': u'11748720697396371259',
      u'targetLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/firewalls/appscalecgb20',
      u'operationType': u'delete',
      u'progress': 0,
      u'id': u'15574488986772298961',
      u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/operations/operation-1369677695390-4ddb6f07cc611-5a8f1654',
      u'user': u'Chris@appscale.com'
    }
    fake_delete_firewall_request = flexmock(name='fake_delete_firewall_request')
    fake_delete_firewall_request.should_receive('execute').and_return(fake_delete_firewall_info)

    fake_firewalls = flexmock(name='fake_firewalls')
    fake_firewalls.should_receive('delete').with_args(project=project_id,
      firewall=self.group).and_return(fake_delete_firewall_request)
    fake_gce.should_receive('firewalls').and_return(fake_firewalls)

    # mock out the call to make sure the firewall was deleted
    fake_firewall_checker = flexmock(name='fake_firewall_checker')
    fake_firewall_checker.should_receive('execute').and_return(all_done)

    fake_blocker.should_receive('get').with_args(project=project_id,
      operation=delete_firewall).and_return(fake_firewall_checker)
    fake_gce.should_receive('globalOperations').and_return(fake_blocker)

    # and the call to delete the network
    delete_network = u'operation-1369677749954-4ddb6f3bd1849-056cf8ca'
    fake_delete_network_info = {
      u'status': u'PENDING',
      u'kind': u'compute#operation',
      u'name': delete_network,
      u'startTime': u'2013-05-27T11:02:30.012-07:00',
      u'insertTime': u'2013-05-27T11:02:29.954-07:00',
      u'targetId': u'17688075350400527692',
      u'targetLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/networks/appscalecgb20',
      u'operationType': u'delete',
      u'progress': 0,
      u'id': u'12623697331874594836',
      u'selfLink': u'https://www.googleapis.com/compute/v1beta14/projects/appscale.com:appscale/global/operations/operation-1369677749954-4ddb6f3bd1849-056cf8ca',
      u'user': u'Chris@appscale.com'
    }
    fake_delete_network_request = flexmock(name='fake_delete_network_request')
    fake_delete_network_request.should_receive('execute').and_return(fake_delete_network_info)

    fake_networks = flexmock(name='fake_networks')
    fake_networks.should_receive('delete').with_args(project=project_id,
      network=self.group).and_return(fake_delete_network_request)
    fake_gce.should_receive('networks').and_return(fake_networks)

    # mock out the call to make sure the network was deleted
    fake_network_checker = flexmock(name='fake_network_checker')
    fake_network_checker.should_receive('execute').and_return(all_done)

    fake_blocker.should_receive('get').with_args(project=project_id,
      operation=delete_network).and_return(fake_network_checker)

    # finally, inject our fake GCE connection
    flexmock(apiclient.discovery)
    apiclient.discovery.should_receive('build').with_args('compute',
      GCEAgent.API_VERSION).and_return(fake_gce)

    flexmock(GCEAgent).should_receive('get_secrets_type')\
      .and_return(CredentialTypes.OAUTH)

    # finally, mock out removing the yaml file, json file, and secret key from
    # this machine
    flexmock(os)
    os.should_receive('remove').with_args(
      LocalState.get_locations_yaml_location(self.keyname)).and_return()
    os.should_receive('remove').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return()
    os.should_receive('remove').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return()

    argv = [
      "--keyname", self.keyname,
      "--test"
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.terminate_instances(options)
