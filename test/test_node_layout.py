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
from appscale.tools.custom_exceptions import BadConfigurationException
from appscale.tools.node_layout import NodeLayout

from test_ip_layouts import (DISK_ONE, DISK_TWO, FOUR_NODE_CLOUD,
                             FOUR_NODE_CLUSTER, THREE_NODES_TWO_DISKS_CLOUD,
                             THREE_NODES_TWO_DISKS_FOR_NODESET_CLOUD,
                             THREE_NODE_CLOUD, TWO_NODES_ONE_NOT_UNIQUE_DISK_CLOUD,
                             TWO_NODES_TWO_DISKS_CLOUD, OPEN_NODE_CLOUD,
                             LOGIN_NODE_CLOUD)


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


  def test_advanced_format_yaml_only(self):
    input_yaml = OPEN_NODE_CLOUD
    options = self.default_options.copy()
    options['ips'] = input_yaml
    layout_1 = NodeLayout(options)
    self.assertNotEqual([], layout_1.nodes)

  def test_login_override_master(self):
    # if the user wants to set a login host, make sure that gets set as the
    # master node's public IP address instead of what we'd normally put in

    input_yaml_1 = FOUR_NODE_CLUSTER
    options_1 = self.default_options.copy()
    options_1['ips'] = input_yaml_1
    options_1['login_host'] = "www.booscale.com"
    layout_1 = NodeLayout(options_1)
    self.assertNotEqual([], layout_1.nodes)

    head_node = layout_1.head_node()
    self.assertEquals(options_1['login_host'], head_node.public_ip)

  def test_login_override_login_node(self):
    # if the user wants to set a login host, make sure that gets set as the
    # login node's public IP address instead of what we'd normally put in

    # use a simple deployment so we can get the login node with .head_node()
    input_yaml_1 = LOGIN_NODE_CLOUD
    options_1 = self.default_options.copy()
    options_1['ips'] = input_yaml_1
    options_1['login_host'] = "www.booscale.com"
    layout_1 = NodeLayout(options_1)
    self.assertNotEqual([], layout_1.nodes)

    login_nodes = layout_1.get_nodes(role='login', is_role=True)
    self.assertEqual(1, len(login_nodes))
    self.assertEquals(options_1['login_host'], login_nodes[0].public_ip)


  def test_is_database_replication_valid_with_db_slave(self):
    input_yaml = [{'roles': ['master', 'database', 'appengine'], 'nodes': 1,
                   'instance_type': 'm1.large'}]
    options = self.default_options.copy()
    options['ips'] = input_yaml
    fake_node = flexmock()
    fake_node.should_receive('is_role').with_args('database').and_return(False)
    fake_node.should_receive('is_role').with_args('db_master').and_return(False)
    fake_node.should_receive('is_role').with_args('db_slave').and_return(True)
    # validate_database_replication will raise BadConfigurationException if
    # it is invalid.
    NodeLayout(options).validate_database_replication([fake_node])


  def test_with_wrong_number_of_disks(self):
    # suppose that the user has specified two nodes, but only one EBS / PD disk
    # this should fail.

    input_yaml = THREE_NODES_TWO_DISKS_CLOUD
    options = self.default_options.copy()
    options['ips'] = input_yaml
    self.assertRaises(BadConfigurationException, NodeLayout, options)


  def test_with_right_number_of_disks_but_not_unique(self):
    # suppose that the user has specified two nodes, but uses the same name for
    # both disks. This isn't acceptable.
    input_yaml = TWO_NODES_ONE_NOT_UNIQUE_DISK_CLOUD
    options = self.default_options.copy()
    options['ips'] = input_yaml
    self.assertRaises(BadConfigurationException, NodeLayout, options)


  def test_with_right_number_of_unique_disks_both_nodes(self):
    # suppose that the user has specified two nodes, and two EBS / PD disks
    # with different names. This is the desired user behavior.
    input_yaml = TWO_NODES_TWO_DISKS_CLOUD
    options = self.default_options.copy()
    options['ips'] = input_yaml
    layout = NodeLayout(options)
    self.assertNotEqual([], layout.nodes)
    self.assertEquals(DISK_ONE, layout.head_node().disk)
    self.assertEquals(DISK_TWO, layout.other_nodes()[0].disk)


  def test_with_right_number_of_unique_disks_one_node(self):
    # suppose that the user has specified two nodes, and two EBS / PD disks
    # with different names. This is the desired user behavior.
    input_yaml = THREE_NODES_TWO_DISKS_FOR_NODESET_CLOUD
    options = self.default_options.copy()
    options['ips'] = input_yaml
    layout = NodeLayout(options)
    self.assertNotEqual([], layout.nodes)
    self.assertEquals(DISK_ONE, layout.other_nodes()[0].disk)
    self.assertEquals(DISK_TWO, layout.other_nodes()[1].disk)


  # Disk tests for new ASF.
  DISK_ONE = 'disk_number_1'
  DISK_TWO = 'disk_number_2'

  def test_new_with_wrong_number_of_disks(self):
    # suppose that the user has specified two nodes, but only one EBS / PD disk
    # this should fail.

    input_yaml = [
      {'roles': ['master', 'database'], 'nodes': 1, 'disks': self.DISK_ONE},
      {'roles': ['appengine'], 'nodes': 2, 'disks': self.DISK_TWO}]
    options = self.default_options.copy()
    options['ips'] = input_yaml
    self.assertRaises(BadConfigurationException, NodeLayout, options)


  def test_new_with_right_number_of_disks_but_not_unique(self):
    # suppose that the user has specified two nodes, but uses the same name for
    # both disks. This isn't acceptable.
    input_yaml = [
      {'roles': ['master', 'database'], 'nodes': 1, 'disks': self.DISK_ONE},
      {'roles': ['appengine'], 'nodes': 1, 'disks': self.DISK_ONE}]
    options = self.default_options.copy()
    options['ips'] = input_yaml
    self.assertRaises(BadConfigurationException, NodeLayout, options)


  def test_new_with_right_number_of_unique_disks_both_nodes(self):
    # suppose that the user has specified two nodes, and two EBS / PD disks
    # with different names. This is the desired user behavior.
    input_yaml = [{'roles': ['master', 'database'], 'nodes': 1,
                   'instance_type': 'm1.large', 'disks': self.DISK_ONE},
                  {'roles': ['appengine'], 'nodes': 1,
                   'instance_type': 'm1.large', 'disks': self.DISK_TWO}]
    options = self.default_options.copy()
    options['ips'] = input_yaml
    layout = NodeLayout(options)
    self.assertNotEqual([], layout.nodes)
    self.assertEquals(self.DISK_ONE, layout.head_node().disk)
    self.assertEquals(self.DISK_TWO, layout.other_nodes()[0].disk)


  def test_new_with_right_number_of_unique_disks_one_node(self):
    # suppose that the user has specified two nodes, and two EBS / PD disks
    # with different names. This is the desired user behavior.
    input_yaml = [
      {'roles': ['master', 'database'], 'nodes': 1, 'instance_type': 'm1.large'},
      {'roles': ['appengine'], 'nodes': 2,
       'instance_type': 'm1.large', 'disks': [self.DISK_ONE, self.DISK_TWO]}]
    options = self.default_options.copy()
    options['ips'] = input_yaml
    layout = NodeLayout(options)
    self.assertNotEqual([], layout.nodes)
    self.assertEquals(self.DISK_ONE, layout.other_nodes()[0].disk)
    self.assertEquals(self.DISK_TWO, layout.other_nodes()[1].disk)


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
      static_ip=[],
      replication=None,
      appengine=None,
      autoscale=None,
      user_commands=[],
      flower_password='',
      max_memory='X',
      ips=FOUR_NODE_CLOUD
    )

  reattach_node_info = [{ "public_ip": "0.0.0.0",
                          "private_ip": "0.0.0.0",
                          "instance_id": "i-APPSCALE1",
                          "roles": ['load_balancer', 'taskqueue', 'shadow',
                                    'login', 'taskqueue_master'],
                          "instance_type": "instance_type_1"},
                        { "public_ip": "0.0.0.0",
                          "private_ip": "0.0.0.0",
                          "instance_id": "i-APPSCALE2",
                          "roles": ['memcache', 'appengine'],
                          "instance_type": "instance_type_1"},
                        { "public_ip": "0.0.0.0",
                          "private_ip": "0.0.0.0",
                          "instance_id": "i-APPSCALE3",
                          "roles": ['zookeeper'],
                          "instance_type": "instance_type_1"},
                        { "public_ip": "0.0.0.0",
                          "private_ip": "0.0.0.0",
                          "instance_id": "i-APPSCALE4",
                          "roles": ['database', 'db_master'],
                          "instance_type": "instance_type_1"}
                        ]


  def test_from_locations_json_list_valid(self):
    node_layout = NodeLayout(self.reattach_options)
    self.assertNotEqual([], node_layout.nodes)
    old_nodes = node_layout.nodes[:]
    new_layout = node_layout.from_locations_json_list(self.reattach_node_info)
    for node in new_layout:
      # Match nodes based on jobs/roles.
      for index, old_node in enumerate(old_nodes):
        if set(old_node.roles) == set(node.roles):
          old_nodes.pop(index)
          break

    self.assertEqual(old_nodes, [])

  def test_from_locations_json_list_after_clean(self):
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
      ips=FOUR_NODE_CLOUD
    )
    cleaned_node_info = [{"public_ip": "0.0.0.0",
                           "private_ip": "0.0.0.0",
                           "instance_id": "i-APPSCALE1",
                           "roles": ['load_balancer', 'taskqueue', 'shadow',
                                    'login',
                                    'taskqueue_master'],
                           "instance_type": "instance_type_1"},
                          {"public_ip": "0.0.0.0",
                           "private_ip": "0.0.0.0",
                           "instance_id": "i-APPSCALE2",
                           "roles": ['open'],
                           "instance_type": "instance_type_1"},
                          {"public_ip": "0.0.0.0",
                           "private_ip": "0.0.0.0",
                           "instance_id": "i-APPSCALE3",
                           "roles": ['open'],
                           "instance_type": "instance_type_1"},
                          {"public_ip": "0.0.0.0",
                           "private_ip": "0.0.0.0",
                           "instance_id": "i-APPSCALE4",
                           "roles": ['open'],
                           "instance_type": "instance_type_1"}
                          ]
    node_layout = NodeLayout(options)
    self.assertNotEqual([], node_layout.nodes)
    old_nodes = node_layout.nodes[:]
    new_layout = node_layout.from_locations_json_list(cleaned_node_info)
    for node in new_layout:
      # Match nodes based on jobs/roles.
      for index, old_node in enumerate(old_nodes):
        if set(old_node.roles) == set(node.roles):
          old_nodes.pop(index)
          break

    self.assertEqual(old_nodes, [])

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
      ips=FOUR_NODE_CLOUD
    )

    node_layout = NodeLayout(options)
    self.assertNotEqual([], node_layout.nodes)
    old_nodes = node_layout.nodes[:]
    new_layout = node_layout.from_locations_json_list(self.reattach_node_info)
    for node in new_layout:
      # Match nodes based on jobs/roles.
      for index, old_node in enumerate(old_nodes):
        if set(old_node.roles) == set(node.roles):
          old_nodes.pop(index)
          break

    self.assertEqual(old_nodes, [])

  def test_from_locations_json_list_invalid_locations(self):
    node_layout = NodeLayout(self.reattach_options)
    self.assertNotEqual([], node_layout.nodes)

    node_info = [{ "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE1",
                   "roles": ['load_balancer', 'taskqueue', 'shadow', 'login',
                            'taskqueue_master'] },
                 { "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE2",
                   "roles": ['memcache', 'appengine'] },
                 { "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE3",
                   "roles": ['zookeeper'] },
                 { "public_ip": "0.0.0.0",
                   "private_ip": "0.0.0.0",
                   "instance_id": "i-APPSCALE4",
                   "roles": ['database', 'db_master', 'zookeeper'] }
                 ]

    with self.assertRaises(BadConfigurationException):
      node_layout.from_locations_json_list(node_info)


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
      ips=THREE_NODE_CLOUD
    )

    node_layout = NodeLayout(options)
    self.assertNotEqual([], node_layout.nodes)

    with self.assertRaises(BadConfigurationException):
      node_layout.from_locations_json_list(self.reattach_node_info)
