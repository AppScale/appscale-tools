#!/usr/bin/env python

# General-purpose Python library imports
import unittest


# AppScale import, the library that we're testing here
from appscale.tools.agents.factory import InfrastructureAgentFactory
from appscale.tools.custom_exceptions import UnknownInfrastructureException


class TestFactory(unittest.TestCase):


  def test_bad_agent_name(self):
    # Passing in an invalid agent name should raise an exception.
    self.assertRaises(UnknownInfrastructureException,
      InfrastructureAgentFactory.create_agent, 'bad agent name')
