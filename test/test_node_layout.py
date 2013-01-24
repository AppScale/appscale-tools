#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import re
import sys
import unittest


# Third party testing libraries
import boto
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appscale_logger import AppScaleLogger
from node_layout import NodeLayout

from agents.ec2_agent import EC2Agent


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
    boto.should_receive('connect_ec2').with_args('baz', 'baz').and_return(fake_ec2)

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
    layout_1 = NodeLayout(input_yaml_1, self.default_options)
    self.assertEquals(True, layout_1.is_valid())

    # Specifying one controller should be ok
    input_yaml_2 = {'controller' : self.ip_1}
    layout_2 = NodeLayout(input_yaml_2, self.default_options)
    self.assertEquals(True, layout_2.is_valid())

    # Specifying the same IP more than once is not ok
    input_yaml_3 = {'controller' : self.ip_1, 'servers' : [self.ip_1]}
    layout_3 = NodeLayout(input_yaml_3, self.default_options)
    self.assertEquals(False, layout_3.is_valid())
    self.assertEquals(NodeLayout.DUPLICATE_IPS, layout_3.errors())

    # Failing to specify a controller is not ok
    input_yaml_4 = {'servers' : [self.ip_1, self.ip_2]}
    layout_4 = NodeLayout(input_yaml_4, self.default_options)
    self.assertEquals(False, layout_4.is_valid())
    self.assertEquals(NodeLayout.NO_CONTROLLER, layout_4.errors())

    # Specifying more than one controller is not ok
    input_yaml_5 = {'controller' : [self.ip_1, self.ip_2], 'servers' : [self.ip_3]}
    layout_5 = NodeLayout(input_yaml_5, self.default_options)
    self.assertEquals(False, layout_5.is_valid())
    self.assertEquals(NodeLayout.ONLY_ONE_CONTROLLER, layout_5.errors())

    # Specifying something other than controller and servers in simple
    # deployments is not ok
    input_yaml_6 = {'controller' : self.ip_1, 'servers' : [self.ip_2],
      'boo' : self.ip_3}
    layout_6 = NodeLayout(input_yaml_6, self.default_options)
    self.assertEquals(False, layout_6.is_valid())
    self.assertEquals(["The flag boo is not a supported flag"],
      layout_6.errors())


  def test_simple_layout_options(self):
    # Using Euca with no input yaml, and no max or min images is not ok
    options_1 = {'infrastructure' : "euca", 'table' : 'cassandra'}
    layout_1 = NodeLayout(self.blank_input_yaml, options_1)
    self.assertEquals(False, layout_1.is_valid())
    self.assertEquals(NodeLayout.NO_YAML_REQUIRES_MIN, layout_1.errors())

    options_2 = {'infrastructure' : "euca", 'table' : 'cassandra', 'max' : 2}
    layout_2 = NodeLayout(self.blank_input_yaml, options_2)
    self.assertEquals(False, layout_2.is_valid())
    self.assertEquals(NodeLayout.NO_YAML_REQUIRES_MIN, layout_2.errors())

    options_3 = {'infrastructure' : "euca", 'table': 'cassandra', 'min' : 2}
    layout_3 = NodeLayout(self.blank_input_yaml, options_3)
    self.assertEquals(False, layout_3.is_valid())
    self.assertEquals(NodeLayout.NO_YAML_REQUIRES_MAX, layout_3.errors())

    # Using Euca with no input yaml, with max and min images set is ok
    options_4 = {'infrastructure' : "euca", 'table' : 'cassandra', 'min' : 2, 'max' : 2}
    layout_4 = NodeLayout(self.blank_input_yaml, options_4)
    self.assertEquals(True, layout_4.is_valid())

    # Using Xen or hybrid cloud deployments with no input yaml is not ok
    options_5 = {'infrastructure' : "xen", 'table' : 'cassandra'}
    layout_5 = NodeLayout(self.blank_input_yaml, options_5)
    self.assertEquals(False, layout_5.is_valid())
    self.assertEquals([NodeLayout.INPUT_YAML_REQUIRED], layout_5.errors())


  """
  def test_advanced_format_yaml_only
    input_yaml_1 = {:master => @ip_1, :database => @ip_1, :appengine => @ip_1, :open => @ip_2}
    layout_1 = NodeLayout.new(input_yaml_1, @blank_options)
    assert_equal(true, layout_1.valid?)
  end

  def test_dont_warn_users_on_supported_deployment_strategies
    # all simple deployment strategies are supported
    input_yaml_1 = {:controller => @ip_1}
    layout_1 = NodeLayout.new(input_yaml_1, @blank_options)
    assert_equal(true, layout_1.supported?)

    input_yaml_2 = {:controller => @ip_1, :servers => [@ip_2]}
    layout_2 = NodeLayout.new(input_yaml_2, @blank_options)
    assert_equal(true, layout_2.supported?)

    input_yaml_3 = {:controller => @ip_1, :servers => [@ip_2, @ip_3]}
    layout_3 = NodeLayout.new(input_yaml_3, @blank_options)
    assert_equal(true, layout_3.supported?)

    # in advanced deployments, four nodes are ok with the following
    # layout: (1) load balancer, (2) appserver, (3) database,
    # (4) zookeeper
    advanced_yaml_1 = {
      :master => @ip_1,
      :appengine => @ip_2,
      :database => @ip_3,
      :zookeeper => @ip_4
    }
    advanced_layout_1 = NodeLayout.new(advanced_yaml_1, @blank_options)
    assert_equal(true, advanced_layout_1.valid?)
    assert_equal(true, advanced_layout_1.supported?)

    # in advanced deployments, eight nodes are ok with the following
    # layout: (1) load balancer, (2) appserver, (3) appserver,
    # (4) database, (5) database, (6) zookeeper, (7) zookeeper,
    # (8) zookeeper
    advanced_yaml_2 = {
      :master => @ip_1,
      :appengine => [@ip_2, @ip_3],
      :database => [@ip_4, @ip_5],
      :zookeeper => [@ip_6, @ip_7, @ip_8]
    }
    advanced_layout_2 = NodeLayout.new(advanced_yaml_2, @blank_options)
    assert_equal(true, advanced_layout_2.valid?)
    assert_equal(true, advanced_layout_2.supported?)
  end

  def test_warn_users_on_unsupported_deployment_strategies
    # don't test simple deployments - those are all supported
    # instead, test out some variations of the supported advanced
    # strategies, as those should not be supported
    advanced_yaml_1 = {
      :master => @ip_1,
      :appengine => @ip_1,
      :database => @ip_2,
      :zookeeper => @ip_2
    }
    advanced_layout_1 = NodeLayout.new(advanced_yaml_1, @blank_options)
    assert_equal(true, advanced_layout_1.valid?)
    assert_equal(false, advanced_layout_1.supported?)

    # four node deployments that don't match the only supported
    # deployment are not supported
    advanced_yaml_2 = {
      :master => @ip_1,
      :appengine => @ip_2,
      :database => @ip_3,
      :zookeeper => @ip_3,
      :open => @ip_4
    }
    advanced_layout_2 = NodeLayout.new(advanced_yaml_2, @blank_options)
    assert_equal(true, advanced_layout_2.valid?)
    assert_equal(false, advanced_layout_2.supported?)

    # eight node deployments that don't match the only supported
    # deployment are not supported
    advanced_yaml_3 = {
      :master => @ip_1,
      :appengine => [@ip_2, @ip_3],
      :database => [@ip_4, @ip_5],
      :zookeeper => [@ip_6, @ip_7],
      :open => @ip_8
    }
    advanced_layout_3 = NodeLayout.new(advanced_yaml_3, @blank_options)
    assert_equal(true, advanced_layout_3.valid?)
    assert_equal(false, advanced_layout_3.supported?)
  end
end
"""
