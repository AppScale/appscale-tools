#!/usr/bin/env python


# General-purpose Python library imports
import os
import unittest


# Third party testing libraries
import boto
from flexmock import flexmock


# AppScale import, the library that we're testing here
from appscale.tools.agents.ec2_agent import EC2Agent
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.node_layout import NodeLayout


class TestNodeLayout(unittest.TestCase):


  def setUp(self):
    # mock out logging, since it clutters out test output
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # next, pretend our ec2 credentials are properly set
    for credential in EC2Agent.REQUIRED_CREDENTIALS:
      os.environ[credential] = "baz"

    # finally, pretend that our ec2 image to use exists
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()
    flexmock(boto)
    boto.should_receive('connect_ec2').with_args('baz', 'baz').and_return(
      fake_ec2)

    # add in some instance variables so that we don't have
    # a lot IP addresses everywhere
    self.blank_input_yaml = None
    self.default_options = {
      'table' : 'cassandra'
    }
    self.ip_1 = '192.168.1.1'
    self.ip_2 = '192.168.1.2'
    self.ip_3 = '192.168.1.3'
    self.ip_4 = '192.168.1.4'
    self.ip_5 = '192.168.1.5'
    self.ip_6 = '192.168.1.6'
    self.ip_7 = '192.168.1.7'
    self.ip_8 = '192.168.1.8'

  def test_simple_layout_yaml_only(self):
    # Specifying one controller and one server should be ok
    input_yaml_1 = {
      'controller' : self.ip_1,
      'servers' : [self.ip_2]
    }
    options_1 = self.default_options.copy()
    options_1['ips'] = input_yaml_1
    layout_1 = NodeLayout(options_1)
    self.assertEquals(True, layout_1.is_valid())

    # Specifying one controller should be ok
    input_yaml_2 = {'controller' : self.ip_1}
    options_2 = self.default_options.copy()
    options_2['ips'] = input_yaml_2
    layout_2 = NodeLayout(options_2)
    self.assertEquals(True, layout_2.is_valid())

    # Specifying the same IP more than once is not ok
    input_yaml_3 = {'controller' : self.ip_1, 'servers' : [self.ip_1]}
    options_3 = self.default_options.copy()
    options_3['ips'] = input_yaml_3
    layout_3 = NodeLayout(options_3)
    self.assertEquals(False, layout_3.is_valid())
    self.assertEquals(NodeLayout.DUPLICATE_IPS, layout_3.errors())

    # Failing to specify a controller is not ok
    input_yaml_4 = {'servers' : [self.ip_1, self.ip_2]}
    options_4 = self.default_options.copy()
    options_4['ips'] = input_yaml_4
    layout_4 = NodeLayout(options_4)
    self.assertEquals(False, layout_4.is_valid())
    self.assertEquals(NodeLayout.NO_CONTROLLER, layout_4.errors())

    # Specifying more than one controller is not ok
    input_yaml_5 = {'controller' : [self.ip_1, self.ip_2], 'servers' :
      [self.ip_3]}
    options_5 = self.default_options.copy()
    options_5['ips'] = input_yaml_5
    layout_5 = NodeLayout(options_5)
    self.assertEquals(False, layout_5.is_valid())
    self.assertEquals(NodeLayout.ONLY_ONE_CONTROLLER, layout_5.errors())

    # Specifying something other than controller and servers in simple
    # deployments is not ok
    input_yaml_6 = {'controller' : self.ip_1, 'servers' : [self.ip_2],
      'boo' : self.ip_3}
    options_6 = self.default_options.copy()
    options_6['ips'] = input_yaml_6
    layout_6 = NodeLayout(options_6)
    self.assertEquals(False, layout_6.is_valid())
    self.assertEquals(["The flag boo is not a supported flag"],
      layout_6.errors())


  def test_simple_layout_options(self):
    # Using Euca with no input yaml, and no max or min images is not ok
    options_1 = self.default_options.copy()
    options_1['infrastructure'] = 'euca'
    layout_1 = NodeLayout(options_1)
    self.assertEquals(False, layout_1.is_valid())
    self.assertEquals(NodeLayout.NO_YAML_REQUIRES_MIN, layout_1.errors())

    options_2 = self.default_options.copy()
    options_2['infrastructure'] = "euca"
    options_2['max'] = 2
    layout_2 = NodeLayout(options_2)
    self.assertEquals(False, layout_2.is_valid())
    self.assertEquals(NodeLayout.NO_YAML_REQUIRES_MIN, layout_2.errors())

    options_3 = self.default_options.copy()
    options_3['infrastructure'] = "euca"
    options_3['min'] = 2
    layout_3 = NodeLayout(options_3)
    self.assertEquals(False, layout_3.is_valid())
    self.assertEquals(NodeLayout.NO_YAML_REQUIRES_MAX, layout_3.errors())

    # Using Euca with no input yaml, with max and min images set is ok
    options_4 = self.default_options.copy()
    options_4['infrastructure'] = "euca"
    options_4['min'] = 2
    options_4['max'] = 2
    layout_4 = NodeLayout(options_4)
    self.assertEquals(True, layout_4.is_valid())

    # Using virtualized deployments with no input yaml is not ok
    options_5 = self.default_options.copy()
    layout_5 = NodeLayout(options_5)
    self.assertEquals(False, layout_5.is_valid())
    self.assertEquals([NodeLayout.INPUT_YAML_REQUIRED], layout_5.errors())


  def test_advanced_format_yaml_only(self):
    input_yaml = {'master' : self.ip_1, 'database' : self.ip_1,
      'appengine' : self.ip_1, 'open' : self.ip_2}
    options = self.default_options.copy()
    options['ips'] = input_yaml
    layout_1 = NodeLayout(options)
    self.assertEquals(True, layout_1.is_valid())

  def test_with_login_override(self):
    # if the user wants to set a login host, make sure that gets set as the
    # login node's public IP address instead of what we'd normally put in

    # use a simple deployment so we can get the login node with .head_node()
    input_yaml_1 = {
      'controller' : self.ip_1,
      'servers' : [self.ip_2]
    }
    options_1 = self.default_options.copy()
    options_1['ips'] = input_yaml_1
    options_1['login_host'] = "www.booscale.com"
    layout_1 = NodeLayout(options_1)
    self.assertEquals(True, layout_1.is_valid())

    head_node = layout_1.head_node()
    self.assertEquals(options_1['login_host'], head_node.public_ip)


  def test_is_database_replication_valid_with_db_slave(self):
    fake_node = flexmock()
    fake_node.should_receive('is_role').with_args('database').and_return(False)
    fake_node.should_receive('is_role').with_args('db_master').and_return(False)
    fake_node.should_receive('is_role').with_args('db_slave').and_return(True)
    output = NodeLayout({}).is_database_replication_valid([fake_node])
    self.assertTrue(output['result'])


  def test_with_wrong_number_of_disks(self):
    # suppose that the user has specified two nodes, but only one EBS / PD disk
    # this should fail.
    input_yaml = {
      'controller' : self.ip_1,
      'servers' : [self.ip_2]
    }
    options = self.default_options.copy()
    options['ips'] = input_yaml
    options['disks'] = {
      self.ip_1 : 'disk_number_one'
    }
    layout = NodeLayout(options)
    self.assertEquals(False, layout.is_valid())


  def test_with_right_number_of_disks_but_not_unique(self):
    # suppose that the user has specified two nodes, but uses the same name for
    # both disks. This isn't acceptable.
    input_yaml = {
      'controller' : self.ip_1,
      'servers' : [self.ip_2]
    }
    options = self.default_options.copy()
    options['ips'] = input_yaml
    options['disks'] = {
      self.ip_1 : 'disk_number_one',
      self.ip_2 : 'disk_number_one'
    }
    layout = NodeLayout(options)
    self.assertEquals(False, layout.is_valid())


  def test_with_right_number_of_unique_disks(self):
    # suppose that the user has specified two nodes, and two EBS / PD disks
    # with different names. This is the desired user behavior.
    input_yaml = {
      'controller' : self.ip_1,
      'servers' : [self.ip_2]
    }
    options = self.default_options.copy()
    options['ips'] = input_yaml
    options['disks'] = {
      self.ip_1 : 'disk_number_one',
      self.ip_2 : 'disk_number_two'
    }
    layout = NodeLayout(options)
    self.assertEquals(True, layout.is_valid())
    self.assertEquals('disk_number_one', layout.head_node().disk)
    self.assertEquals('disk_number_two', layout.other_nodes()[0].disk)


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


  def test_from_locations_json_list_valid(self):
    node_layout = NodeLayout(self.reattach_options)
    self.assertTrue(node_layout.is_valid())
    new_layout = node_layout.from_locations_json_list(self.reattach_node_info)
    self.assertNotEqual(new_layout, None)
    nodes_copy = new_layout[:]
    for old_node in node_layout.nodes:
      for _, node in enumerate(nodes_copy):
        # Match nodes based on jobs/roles.
        if set(old_node.roles) == set(node.roles):
          nodes_copy.remove(node)
    self.assertEqual(nodes_copy, [])


  def test_from_locations_json_list_able_to_match(self):
    options = flexmock(
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
        'appengine': 'node-4', 'database': 'node-3'}
    )

    node_layout = NodeLayout(options)
    self.assertTrue(node_layout.is_valid())

    new_layout = node_layout.from_locations_json_list(self.reattach_node_info)
    self.assertNotEqual(new_layout, None)
    nodes_copy = new_layout[:]
    for old_node in node_layout.nodes:
      for _, node in enumerate(nodes_copy):
        # Match nodes based on jobs/roles.
        if set(old_node.roles) == set(node.roles):
          nodes_copy.remove(node)
    self.assertEqual(nodes_copy, [])

  def test_from_locations_json_list_invalid_locations(self):
    node_layout = NodeLayout(self.reattach_options)
    self.assertTrue(node_layout.is_valid())

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
                   "jobs": ['zookeeper'] },
                 { "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE4",
                   "jobs": ['db_master', 'zookeeper'] }
                 ]

    new_layout = node_layout.from_locations_json_list(node_info)
    self.assertEqual(new_layout, None)


  def test_from_locations_json_list_invalid_asf(self):
    options = flexmock(
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
        'appengine': 'node-3', 'database': 'node-3'}
    )

    node_layout = NodeLayout(options)
    self.assertTrue(node_layout.is_valid())

    new_layout = node_layout.from_locations_json_list(self.reattach_node_info)
    self.assertEqual(new_layout, None)
