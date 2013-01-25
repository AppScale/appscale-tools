#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import sys
import unittest


# Third party testing libraries
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from node_layout import NodeLayout
from remote_helper import RemoteHelper


class TestRemoteHelper(unittest.TestCase):


  def setUp(self):
    self.options = flexmock()
    self.options.should_receive('ips').and_return({
      'controller' : "192.168.1.1"
    })
    self.options.should_receive('table').and_return('cassandra')
    self.node_layout = NodeLayout(self.options)


  def test_start_head_node(self):
    RemoteHelper.start_head_node(self.options, self.node_layout)
