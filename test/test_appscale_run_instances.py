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
from appscale_tools import AppScaleTools
from custom_exceptions import BadConfigurationException
from parse_args import ParseArgs
import local_state


class TestAppScaleRunInstances(unittest.TestCase):


  def setUp(self):
    self.argv = ["--min", "1", "--max", "1", "--infrastructure",
      "ec2", "--machine", "ami-ABCDEFG"]
    self.function = "appscale-run-instances"

    for var in vm_tools.EC2_ENVIRONMENT_VARIABLES:
      os.environ[var] = "BOO"

    # let's say that our ~/.appscale directory
    # already exists
    flexmock(os)
    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists') \
      .with_args(local_state.LOCAL_APPSCALE_PATH) \
      .and_return(True)
