#!/usr/bin/env python


# General-purpose Python library imports
import os
import sys
import unittest


# Third party testing libraries
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
import common_functions
from custom_exceptions import BadConfigurationException
from parse_args import ParseArgs


class TestParseArgs(unittest.TestCase):
  

  def setUp(self):
    self.argv = ['--min', '1', '--max', '1']
    self.function = "appscale-run-instances"


  def test_flags_that_cause_program_abort(self):
    # using a flag that isn't acceptable should raise
    # an exception
    argv_1 = ['--boo!']
    self.assertRaises(SystemExit, ParseArgs, argv_1, 
      self.function)

    # the version flag should quit and print the current
    # version of the tools
    argv_2 = ['--version']
    all_flags_2 = ['version']
    with self.assertRaises(SystemExit) as context_manager:
      ParseArgs(argv_2, self.function)
    self.assertEquals(common_functions.APPSCALE_VERSION,
      context_manager.exception.message)

  def test_get_min_and_max(self):
    # Setting min or max below 1 is not acceptable
    argv_1 = ['--min', '0', '--max', '1']
    self.assertRaises(BadConfigurationException,
      ParseArgs, argv_1, self.function)

    argv_2 = ['--min', '1', '--max', '0']
    self.assertRaises(BadConfigurationException,
      ParseArgs, argv_2, self.function)

    # If max is specified but not min, min should be equal to max
    argv_3 = ['--max', '1']
    actual_3 = ParseArgs(argv_3, self.function)
    self.assertEquals(actual_3.args.min, actual_3.args.max)

    # If max is less than min, it should abort
    argv_4 = ['--min', '10', '--max', '1']
    self.assertRaises(BadConfigurationException, ParseArgs, argv_4,
      self.function)

  def test_table_flags(self):
    # Specifying a table that isn't accepted should abort
    argv_1 = self.argv[:] + ['--table', 'non-existent-database']
    self.assertRaises(BadConfigurationException, ParseArgs, argv_1,
      self.function)

    # Specifying a table that is accepted should return that in the result
    argv_2 = self.argv[:] + ['--table', 'cassandra']
    actual_2 = ParseArgs(argv_2, self.function)
    self.assertEquals('cassandra', actual_2.args.table)

    # Failing to specify a table should default to a predefined table
    args_3 = self.argv[:]
    actual_3 = ParseArgs(args_3, self.function)
    self.assertEquals(common_functions.DEFAULT_DATASTORE, actual_3.args.table)

    # Specifying a non-positive integer for n should abort
    argv_4 = self.argv[:] + ['--table', 'cassandra', '-n', '0']
    self.assertRaises(BadConfigurationException, ParseArgs, argv_4,
      self.function)

    # Specifying a positive integer for n should be ok
    argv_5 = self.argv[:] + ['--table', 'cassandra', '-n', '2']
    actual_5 = ParseArgs(argv_5, self.function)
    self.assertEquals(2, actual_5.args.n)

  def test_gather_logs_flags(self):
    # Specifying auto, force, or test should have that carried over
    # to in the resulting hash
    argv = ["--location", "/boo/baz"]
    actual = ParseArgs(argv, "appscale-gather-logs")
    self.assertEquals("/boo/baz", actual.args.location)

"""
  def test_developer_flags
    # Specifying auto, force, or test should have that carried over
    # to in the resulting hash
    ['auto', 'force', 'test'].each { |param|
      args = ["--#{param}"]
      all_flags = [param]
      actual = ParseArgs.get_vals_from_args(args, all_flags, @usage)
      assert_equal(true, actual[param])
    }
  end

  def test_infrastructure_flags
    # Specifying infastructure as EC2 or Eucalyptus is acceptable.
    args_1 = ['--infrastructure', 'ec2']
    all_flags_1 = ['infrastructure']
    actual_1 = ParseArgs.get_vals_from_args(args_1, all_flags_1, @usage)
    assert_equal('ec2', actual_1['infrastructure'])

    args_2 = ['--infrastructure', 'euca']
    all_flags_2 = ['infrastructure']
    actual_2 = ParseArgs.get_vals_from_args(args_2, all_flags_2, @usage)
    assert_equal('euca', actual_2['infrastructure'])

    # Specifying something else as the infrastructure is not acceptable.
    args_3 = ['--infrastructure', 'boocloud']
    all_flags_3 = ['infrastructure']
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_3, all_flags_3, @usage)
    }

    # Specifying infrastructure via --iaas is not acceptable.
    args_4 = ['--iaas']
    all_flags_4 = AppScaleTools::RUN_INSTANCES_FLAGS
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_4, all_flags_4, @usage)
    }
  end

  def test_instance_types
    # Specifying m1.large as the instance type is acceptable.
    args_1 = ['--instance_type', 'm1.large']
    all_flags_1 = ['instance_type']
    assert_nothing_raised(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_1, all_flags_1, @usage)
    }

    # Specifying blarg1.humongous as the instance type is not
    # acceptable.
    args_2 = ['--instance_type', 'blarg1.humongous']
    all_flags_2 = ['instance_type']
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_2, all_flags_2, @usage)
    }
  end

end
"""
