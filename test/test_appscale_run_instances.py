#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import re
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
import vm_tools


class TestAppScaleRunInstances(unittest.TestCase):


  def setUp(self):
    self.argv = ["--min", "1", "--max", "1"]

    for var in vm_tools.EC2_ENVIRONMENT_VARIABLES:
      os.environ[var] = "BOO"

    # let's say that our ~/.appscale directory
    # already exists
    flexmock(os)
    flexmock(os.path)
    os.path.should_receive('exists') \
      .with_args(local_state.LOCAL_APPSCALE_PATH) \
      .and_return(True)

    # also, let's say that any Python libraries
    # already exist
    lib = re.compile('/System/.*')
    os.path.should_receive('exists') \
      .with_args(lib) \
      .and_return(True)


"""
  def test_environment_variables_not_set_in_cloud_deployments(self):
    argv = self.argv[:] + ["--infrastructure", "euca", "--machine", "emi-ABCDEFG"]
    options = ParseArgs(argv, "appscale-run-instances").args

    for var in vm_tools.EC2_ENVIRONMENT_VARIABLES:
      os.environ[var] = ''

    tools = AppScaleTools()
    self.assertRaises(BadConfigurationException, tools.run_instances, options)

  def test_usage_is_up_to_date
    AppScaleTools::RUN_INSTANCES_FLAGS.each { |flag|
      assert_equal(true, 
        AppScaleTools::RUN_INSTANCES_USAGE.include?("-#{flag}"), 
        "No usage text for #{flag}.")
    } 
  end
end
"""
