#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import json
import os
import sys
import unittest
import yaml


# Third party testing libraries
import SOAPpy
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from custom_exceptions import BadConfigurationException
from local_state import LocalState
from node_layout import NodeLayout


class TestLocalState(unittest.TestCase):


  def setUp(self):
    # set up a mock here to avoid making every test do it
    flexmock(os)
    flexmock(os.path)
    os.path.should_call('exists')

    self.keyname = "booscale"
    self.locations_yaml = LocalState.LOCAL_APPSCALE_PATH + "locations-" + \
      self.keyname + ".yaml"


  def test_make_appscale_directory_creation(self):
    # let's say that our ~/.appscale directory
    # does not exist
    os.path.should_receive('exists') \
      .with_args(LocalState.LOCAL_APPSCALE_PATH) \
      .and_return(False) \
      .once()

    # thus, mock out making the appscale dir
    os.should_receive('mkdir') \
      .with_args(LocalState.LOCAL_APPSCALE_PATH) \
      .and_return()

    LocalState.make_appscale_directory()


  def test_ensure_appscale_isnt_running_but_it_is(self):
    # if there is a locations.yaml file and force isn't set,
    # we should abort
    os.path.should_receive('exists').with_args(self.locations_yaml) \
      .and_return(True)

    self.assertRaises(BadConfigurationException,
      LocalState.ensure_appscale_isnt_running, self.keyname,
      False)


  def test_ensure_appscale_isnt_running_but_it_is_w_force(self):
    # if there is a locations.yaml file and force is set,
    # we shouldn't abort
    os.path.should_receive('exists').with_args(self.locations_yaml) \
      .and_return(True)

    LocalState.ensure_appscale_isnt_running(self.keyname, True)


  def test_ensure_appscale_isnt_running_and_it_isnt(self):
    # if there isn't a locations.yaml file, we're good to go
    os.path.should_receive('exists').with_args(self.locations_yaml) \
      .and_return(False)

    LocalState.ensure_appscale_isnt_running(self.keyname, False)


  def test_generate_deployment_params(self):
    # this method is fairly light, so just make sure that it constructs the dict
    # to send to the AppController correctly
    options = flexmock(name='options', table='cassandra', keyname='boo',
      appengine='1', autoscale=False, group='bazgroup',
      infrastructure='ec2', machine='ami-ABCDEFG', instance_type='m1.large')
    node_layout = NodeLayout({
      'table' : 'cassandra',
      'infrastructure' : "ec2",
      'min' : 2,
      'max' : 2
    })

    expected = {
      'table' : 'cassandra',
      'hostname' : 'public1',
      'ips' : {'node-1': ['rabbitmq_slave', 'database', 'rabbitmq', 'memcache',
        'db_slave', 'appengine']},
      'keyname' : 'boo',
      'replication' : '2',
      'appengine' : '1',
      'autoscale' : 'False',
      'group' : 'bazgroup',
      'machine' : 'ami-ABCDEFG',
      'infrastructure' : 'ec2',
      'instance_type' : 'm1.large',
      'min_images' : 2,
      'max_images' : 2
    }
    actual = LocalState.generate_deployment_params(options, node_layout,
      'public1')
    self.assertEquals(expected, actual)


  def test_obscure_dict(self):
    # make sure that EC2 credentials get filtered correctly
    creds = {
      'ec2_access_key' : 'ABCDEFG',
      'ec2_secret_key' : 'HIJKLMN',
      'CLOUD_EC2_ACCESS_KEY' : 'OPQRSTU',
      'CLOUD_EC2_SECRET_KEY' : 'VWXYZAB'
    }

    expected = {
      'ec2_access_key' : '***DEFG',
      'ec2_secret_key' : '***KLMN',
      'CLOUD_EC2_ACCESS_KEY' : '***RSTU',
      'CLOUD_EC2_SECRET_KEY' : '***YZAB'
    }

    actual = LocalState.obscure_dict(creds)
    self.assertEquals(expected['ec2_access_key'], actual['ec2_access_key'])
    self.assertEquals(expected['ec2_secret_key'], actual['ec2_secret_key'])
    self.assertEquals(expected['CLOUD_EC2_ACCESS_KEY'],
      actual['CLOUD_EC2_ACCESS_KEY'])
    self.assertEquals(expected['CLOUD_EC2_SECRET_KEY'],
      actual['CLOUD_EC2_SECRET_KEY'])


  def test_update_local_metadata(self):
    # mock out getting all the ips in the deployment from the head node
    fake_soap = flexmock(name='fake_soap')
    fake_soap.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return('public1')
    role_info = [{
        'public_ip' : 'public1',
        'private_ip' : 'private1',
        'jobs' : ['shadow', 'db_master']
    }]
    fake_soap.should_receive('get_role_info').with_args('the secret') \
      .and_return(role_info)
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_soap)

    # mock out reading the secret key
    fake_secret = flexmock(name='fake_secret')
    fake_secret.should_receive('read').and_return('the secret')
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')
    builtins.should_receive('open').with_args(
      LocalState.get_secret_key_location('booscale'), 'r') \
      .and_return(fake_secret)

    # mock out writing the yaml file
    fake_locations_yaml = flexmock(name='fake_locations_yaml')
    fake_locations_yaml.should_receive('write').with_args(yaml.dump({
      'load_balancer': 'public1', 'instance_id': 'i-ABCDEFG',
      'secret': 'the secret', 'infrastructure': 'ec2',
      'group': 'boogroup', 'ips': 'public1', 'table': 'cassandra',
      'db_master': 'node-0'
    })).and_return()
    builtins.should_receive('open').with_args(
      LocalState.get_locations_yaml_location('booscale'), 'w') \
      .and_return(fake_locations_yaml)

    # and mock out writing the json file
    fake_locations_json = flexmock(name='fake_locations_json')
    fake_locations_json.should_receive('write').with_args(json.dumps(
      role_info)).and_return()
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location('booscale'), 'w') \
      .and_return(fake_locations_json)

    options = flexmock(name='options', table='cassandra', infrastructure='ec2',
      keyname='booscale', group='boogroup')
    node_layout = NodeLayout(options={
      'min' : 1,
      'max' : 1,
      'infrastructure' : 'ec2',
      'table' : 'cassandra'
    })
    host = 'public1'
    instance_id = 'i-ABCDEFG'
    LocalState.update_local_metadata(options, node_layout, host, instance_id)
