#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import sys
import unittest


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from agents.factory import InfrastructureAgentFactory
from custom_exceptions import UnknownInfrastructureException


class TestFactory(unittest.TestCase):


  def test_bad_agent_name(self):
    # Passing in an invalid agent name should raise an exception.
    self.assertRaises(UnknownInfrastructureException,
      InfrastructureAgentFactory.create_agent, 'bad agent name')
