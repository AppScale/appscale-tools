from unittest.case import TestCase
from utils.commons import AppScaleToolsException
from utils.node_layout import *

__author__ = 'hiranya'

class TestNodeLayout(TestCase):

  def test_single_node_layout(self):
    node_layout = NodeLayout('resources/simple1.yaml')
    self.assertEquals(len(node_layout.nodes), 1)
    node = node_layout.nodes[0]
    self.assertTrue(isinstance(node, SimpleAppScaleNode))
    self.assertEquals(node.id, '10.0.0.1')
    head_node = node_layout.get_head_node()
    self.assertEquals(node.id, head_node.id)

  def test_controller_single_server_layout(self):
    node_layout = NodeLayout('resources/simple2.yaml')
    self.assertEquals(len(node_layout.nodes), 2)
    master_nodes_count = 0
    master_node = None
    worker_node = None
    for node in node_layout.nodes:
      self.assertTrue(isinstance(node, SimpleAppScaleNode))
      if node.has_role(ROLE_SHADOW):
        master_nodes_count += 1
        master_node = node
      else:
        worker_node = node

    self.assertEquals(master_nodes_count, 1)
    self.assertEquals(master_node.id, node_layout.get_head_node().id)
    self.assertEquals(master_node.id, '10.0.0.1')
    self.assertEquals(worker_node.id, '10.0.0.2')

    self.assertTrue(master_node.has_role(ROLE_DATABASE_MASTER))
    self.assertFalse(master_node.has_role(ROLE_DATABASE_SLAVE))
    self.assertTrue(master_node.has_role(ROLE_RABBITMQ_MASTER))
    self.assertFalse(master_node.has_role(ROLE_RABBITMQ_SLAVE))
    self.assertFalse(master_node.has_role(ROLE_APPENGINE))

    self.assertFalse(worker_node.has_role(ROLE_DATABASE_MASTER))
    self.assertTrue(worker_node.has_role(ROLE_DATABASE_SLAVE))
    self.assertFalse(worker_node.has_role(ROLE_RABBITMQ_MASTER))
    self.assertTrue(worker_node.has_role(ROLE_RABBITMQ_SLAVE))
    self.assertTrue(worker_node.has_role(ROLE_APPENGINE))

  def test_controller_three_servers_layout(self):
    node_layout = NodeLayout('resources/simple7.yaml')
    self.assertEquals(len(node_layout.nodes), 4)
    master_nodes_count = 0
    master_node = None
    worker_nodes = []
    for node in node_layout.nodes:
      self.assertTrue(isinstance(node, SimpleAppScaleNode))
      if node.has_role(ROLE_SHADOW):
        master_nodes_count += 1
        master_node = node
      else:
        worker_nodes.append(node)

    self.assertEquals(master_nodes_count, 1)
    self.assertEquals(len(worker_nodes), 3)
    self.assertEquals(master_node.id, node_layout.get_head_node().id)
    self.assertEquals(master_node.id, '10.0.0.1')

    self.assertTrue(master_node.has_role(ROLE_DATABASE_MASTER))
    self.assertFalse(master_node.has_role(ROLE_DATABASE_SLAVE))
    self.assertTrue(master_node.has_role(ROLE_RABBITMQ_MASTER))
    self.assertFalse(master_node.has_role(ROLE_RABBITMQ_SLAVE))
    self.assertFalse(master_node.has_role(ROLE_APPENGINE))

    for worker_node in worker_nodes:
      ip = worker_node.id
      self.assertTrue(ip == '10.0.0.2' or ip == '10.0.0.3' or ip == '10.0.0.4')
      self.assertFalse(worker_node.has_role(ROLE_DATABASE_MASTER))
      self.assertTrue(worker_node.has_role(ROLE_DATABASE_SLAVE))
      self.assertFalse(worker_node.has_role(ROLE_RABBITMQ_MASTER))
      self.assertTrue(worker_node.has_role(ROLE_RABBITMQ_SLAVE))
      self.assertTrue(worker_node.has_role(ROLE_APPENGINE))

  def test_duplicate_ip(self):
    try:
      NodeLayout('resources/simple3.yaml')
      self.fail('No error was thrown for duplicate IPs')
    except AppScaleToolsException as e:
      self.assertEquals(e.code, NodeLayout.ERROR_DUPLICATE_IPS)

  def test_no_controller(self):
    try:
      NodeLayout('resources/simple4.yaml')
      self.fail('No error was thrown for missing controller')
    except AppScaleToolsException as e:
      self.assertEquals(e.code, NodeLayout.ERROR_NO_CONTROLLER)

  def test_multiple_controllers(self):
    try:
      NodeLayout('resources/simple5.yaml')
      self.fail('No error was thrown for multiple controllers')
    except AppScaleToolsException as e:
      self.assertEquals(e.code, NodeLayout.ERROR_MULTIPLE_CONTROLLERS)

  def test_unsupported_option(self):
    try:
      NodeLayout('resources/simple6.yaml')
      self.fail('No error was thrown for unsupported option')
    except AppScaleToolsException as e:
      self.assertEquals(e.code, NodeLayout.ERROR_UNSUPPORTED_LAYOUT)

  def test_simple_format_options(self):
    try:
      NodeLayout(None, { cli.OPTION_INFRASTRUCTURE : 'euca' })
    except AppScaleToolsException as e:
      self.assertEquals(e.code, NodeLayout.ERROR_MISSING_REQUIRED_OPTIONS)

    try:
      NodeLayout(None, {
        cli.OPTION_INFRASTRUCTURE : 'euca',
        cli.OPTION_MIN_IMAGES: 1
      })
    except AppScaleToolsException as e:
      self.assertEquals(e.code, NodeLayout.ERROR_MISSING_REQUIRED_OPTIONS)

    try:
      NodeLayout(None, {
        cli.OPTION_INFRASTRUCTURE : 'euca',
        cli.OPTION_MAX_IMAGES: 3
      })
    except AppScaleToolsException as e:
      self.assertEquals(e.code, NodeLayout.ERROR_MISSING_REQUIRED_OPTIONS)

    layout = NodeLayout(None, {
      cli.OPTION_INFRASTRUCTURE : 'euca',
      cli.OPTION_MAX_IMAGES: 3,
      cli.OPTION_MIN_IMAGES: 1
    })
    self.assertTrue(len(layout.nodes), 3)
    self.assertEquals(layout.get_head_node().id, 'node-0')

    try:
      NodeLayout(None, {
        cli.OPTION_INFRASTRUCTURE : 'xen'
      })
    except AppScaleToolsException as e:
      self.assertEquals(e.code, NodeLayout.ERROR_UNSUPPORTED_LAYOUT)

  def test_advanced_format_yaml_only(self):
    layout = NodeLayout('resources/advanced1.yaml')
    nodes = layout.nodes
    self.assertEquals(len(nodes), 2)
    open_node = None
    for node in nodes:
      if node.has_role(ROLE_OPEN):
        open_node = node
    self.assertTrue(open_node is not None)
    self.assertEquals(len(open_node.roles), 1)

    head_node = layout.get_head_node()
    self.assertTrue(isinstance(head_node, AdvancedAppScaleNode))
    self.assertTrue(head_node is not None)
    self.assertTrue(head_node.has_role(ROLE_DATABASE_MASTER))