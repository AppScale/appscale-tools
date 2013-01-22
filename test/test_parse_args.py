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
from common_functions import APPSCALE_VERSION
from custom_exceptions import BadConfigurationException
from parse_args import ParseArgs


class TestParseArgs(unittest.TestCase):
  

  def setUp(self):
    pass


  def test_flags_that_cause_program_abort(self):
    # using a flag that isn't acceptable should raise
    # an exception
    argv_1 = ['--boo!']
    function = "appscale-run-instances"
    description = "baz"
    self.assertRaises(SystemExit, ParseArgs, argv_1, 
      function, description)

    # the version flag should quit and print the current
    # version of the tools
    argv_2 = ['--version']
    all_flags_2 = ['version']
    with self.assertRaises(SystemExit) as context_manager:
      ParseArgs(argv_2, function, description)
    self.assertEquals(APPSCALE_VERSION, context_manager.exception.message)

  def test_get_min_and_max(self):
    # Setting min or max below 1 is not acceptable
    argv_1 = ['--min', '0', '--max', '1']
    function = "appscale-run-instances"
    description = "baz"
    self.assertRaises(BadConfigurationException,
      ParseArgs, argv_1, function, description)

    argv_2 = ['--min', '1', '--max', '0']
    self.assertRaises(BadConfigurationException,
      ParseArgs, argv_2, function, description)

    # If max is specified but not min, min should be equal to max
    argv_3 = ['--max', '1']
    actual_3 = ParseArgs(argv_3, function, description)
    self.assertEquals(actual_3.args.min, actual_3.args.max)

    # If max is less than min, it should abort
    argv_4 = ['--min', '10', '--max', '1']
    self.assertRaises(BadConfigurationException, ParseArgs, argv_4,
      function, description)

"""
  def test_table_flags
    # Specifying a table that isn't accepted should abort
    args_1 = ['--table', 'non-existant-table']
    all_flags_1 = ['table']
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_1, all_flags_1, @usage)
    }

    # Specifying a table that is accepted should return that in the result
    args_2 = ['--table', 'cassandra']
    all_flags_2 = ['table']
    expected_2 = Hash[*args_2]
    actual_2 = ParseArgs.get_vals_from_args(args_2, all_flags_2, @usage)
    assert_equal('cassandra', actual_2['table'])

    # Failing to specify a table should default to a predefined table
    args_3 = []
    all_flags_3 = ['table']
    expected_3 = {}
    actual_3 = ParseArgs.get_vals_from_args(args_3, all_flags_3, @usage)
    assert_equal(DEFAULT_DATASTORE, actual_3['table'])

    # Specifying r or w when Voldemort isn't used should abort
    args_4 = ['--table', 'cassandra', '-r', '1']
    all_flags_4 = ['table', 'r', 'w']
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_4, all_flags_4, @usage)
    }

    args_5 = ['--table', 'cassandra', '-w', '1']
    all_flags_5 = ['table', 'r', 'w']
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_5, all_flags_5, @usage)
    }

    # Specifying a non-positive integer for r or w with Voldemort should abort
    args_6 = ['--table', 'voldemort', '-r', 'boo']
    all_flags_6 = ['table', 'r', 'w']
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_6, all_flags_6, @usage)
    }

    args_7 = ['--table', 'voldemort', '-w', '0']
    all_flags_7 = ['table', 'r', 'w']
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_7, all_flags_7, @usage)
    }

    # Specifying a non-positive integer for n should abort
    args_8 = ['--table', 'cassandra', '-n', '0']
    all_flags_8 = ['table', 'n']
    assert_raises(BadConfigurationException) {
      ParseArgs.get_vals_from_args(args_8, all_flags_8, @usage)
    }

    # Specifying a positive integer for n should be ok
    args_9 = ['--table', 'cassandra', '-n', '2']
    all_flags_9 = ['table', 'n']
    expected_9 = Hash[*args_9]
    actual_9 = ParseArgs.get_vals_from_args(args_9, all_flags_9, @usage)
    assert_equal(2, actual_9['replication'])

    # Specifying a positive integer for r or w with Voldemort should be ok
    # These tests are disabled right now since Voldemort is no longer a
    # supported datastore.
    # TODO(cgb): Remove these if we decide we're not going to support
    # Voldemort in the future, or remove this TODO if we do support
    # Voldemort again.
    #args_10 = ['--table', 'voldemort', '-r', '3']
    #all_flags_10 = ['table', 'r', 'w']
    #actual_10 = ParseArgs.get_vals_from_args(args_10, all_flags_10, @usage)
    #assert_equal(3, actual_10['voldemort_r'])

    #args_11 = ['--table', 'voldemort', '-w', '3']
    #all_flags_11 = ['table', 'r', 'w']
    #actual_11 = ParseArgs.get_vals_from_args(args_11, all_flags_11, @usage)
    #assert_equal(3, actual_11['voldemort_w'])
  end

  def test_gather_logs_flags
    # Specifying auto, force, or test should have that carried over
    # to in the resulting hash
    args = ["--location", "/boo/baz"]
    all_flags = ['location']
    actual = ParseArgs.get_vals_from_args(args, all_flags, @usage)
    assert_equal("/boo/baz", actual['location'])
  end

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
