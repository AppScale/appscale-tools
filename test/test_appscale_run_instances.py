#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import sys
import unittest


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
import common_functions
from appscale_tools import AppScaleTools


class TestAppScaleRunInstances(unittest.TestCase):


  def setUp(self):
    pass


"""
$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'

require 'test/unit'


class TestAppScaleRunInstances < Test::Unit::TestCase
  def setup
    EC2_ENVIRONMENT_VARIABLES.each { |var|
      ENV[var] = "BOO"
    }

    file = flexmock(File)
    file.should_receive(:exists?).and_return(true)
  end

  def test_machine_not_set_in_cloud_deployments
    options = {
      "infrastructure" => "euca"
    }
    assert_raises(BadConfigurationException) {
      AppScaleTools.run_instances(options)
    }
  end

  def test_environment_variables_not_set_in_cloud_deployments
    options = {
      "infrastructure" => "euca",
      "machine" => "emi-ABCDEFG"
    }

    EC2_ENVIRONMENT_VARIABLES.each { |var|
      ENV[var] = nil
    }

    assert_raises(BadConfigurationException) {
      AppScaleTools.run_instances(options)
    }
  end

  def test_usage_is_up_to_date
    AppScaleTools::RUN_INSTANCES_FLAGS.each { |flag|
      assert_equal(true, 
        AppScaleTools::RUN_INSTANCES_USAGE.include?("-#{flag}"), 
        "No usage text for #{flag}.")
    } 
  end
end
"""
