#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import base64
import os
import sys
import unittest
import yaml


# Third-party imports
import boto
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
import local_state

from agents.base_agent import AgentConfigurationException
from agents.ec2_agent import EC2Agent
from agents.euca_agent import EucalyptusAgent
from appscale_logger import AppScaleLogger
from custom_exceptions import BadConfigurationException
from parse_args import ParseArgs


class TestParseArgs(unittest.TestCase):
  

  def setUp(self):
    self.cloud_argv = ['--min', '1', '--max', '1']
    self.cluster_argv = ['--ips', 'ips.yaml']
    self.function = "appscale-run-instances"

    # mock out all logging, since it clutters our output
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # set up phony AWS credentials for each test
    # ones that test not having them present can
    # remove them
    for credential in EucalyptusAgent.REQUIRED_EC2_CREDENTIALS:
      os.environ[credential] = "baz"
    os.environ['EC2_URL'] = "http://boo"

    # similarly, pretend that our image does exist in EC2
    # and Euca
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()
    fake_ec2.should_receive('get_image').with_args('emi-ABCDEFG') \
      .and_return()

    flexmock(boto)
    boto.should_receive('connect_ec2').with_args('baz', 'baz').and_return(fake_ec2)
    boto.should_receive('connect_euca').and_return(fake_ec2)



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
    try:
      ParseArgs(argv_2, self.function)
      raise
    except SystemExit:
      pass
    #with self.assertRaises(SystemExit) as context_manager:
    #  ParseArgs(argv_2, self.function)
    #self.assertEquals(local_state.APPSCALE_VERSION,
    #  context_manager.exception.message)


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
    argv_1 = self.cluster_argv[:] + ['--table', 'non-existent-database']
    self.assertRaises(SystemExit, ParseArgs, argv_1, self.function)

    # Specifying a table that is accepted should return that in the result
    argv_2 = self.cluster_argv[:] + ['--table', 'cassandra']
    actual_2 = ParseArgs(argv_2, self.function)
    self.assertEquals('cassandra', actual_2.args.table)

    # Failing to specify a table should default to a predefined table
    args_3 = self.cluster_argv[:]
    actual_3 = ParseArgs(args_3, self.function)
    self.assertEquals(ParseArgs.DEFAULT_DATASTORE, actual_3.args.table)

    # Specifying a non-positive integer for n should abort
    argv_4 = self.cloud_argv[:] + ['--table', 'cassandra', '-n', '0']
    self.assertRaises(BadConfigurationException, ParseArgs, argv_4,
      self.function)

    # Specifying a positive integer for n should be ok
    argv_5 = self.cloud_argv[:] + ['--table', 'cassandra', '-n', '2']
    actual_5 = ParseArgs(argv_5, self.function)
    self.assertEquals(2, actual_5.args.n)


  def test_gather_logs_flags(self):
    # Specifying auto, force, or test should have that carried over
    # to in the resulting hash
    argv = ["--location", "/boo/baz"]
    actual = ParseArgs(argv, "appscale-gather-logs")
    self.assertEquals("/boo/baz", actual.args.location)


  def test_developer_flags(self):
    # Specifying force or test should have that carried over
    # to in the resulting hash
    argv_1 = self.cloud_argv[:] + ['--force']
    actual_1 = ParseArgs(argv_1, self.function)
    self.assertEquals(True, actual_1.args.force)

    argv_2 = self.cloud_argv[:] + ['--test']
    actual_2 = ParseArgs(argv_2, self.function)
    self.assertEquals(True, actual_2.args.test)


  def test_infrastructure_flags(self):
    # Specifying infastructure as EC2 or Eucalyptus is acceptable.
    argv_1 = self.cloud_argv[:] + ['--infrastructure', 'ec2', '--machine', 'ami-ABCDEFG']
    actual_1 = ParseArgs(argv_1, self.function)
    self.assertEquals('ec2', actual_1.args.infrastructure)

    argv_2 = self.cloud_argv[:] + ['--infrastructure', 'euca', '--machine', 'emi-ABCDEFG']
    actual_2 = ParseArgs(argv_2, self.function)
    self.assertEquals('euca', actual_2.args.infrastructure)

    # Specifying something else as the infrastructure is not acceptable.
    argv_3 = self.cloud_argv[:] + ['--infrastructure', 'boocloud', '--machine', 'boo']
    self.assertRaises(SystemExit, ParseArgs, argv_3, self.function)


  def test_instance_types(self):
    # Not specifying an instance type should default to a predetermined
    # value.
    argv_1 = self.cloud_argv[:]
    actual = ParseArgs(argv_1, self.function)
    self.assertEquals(ParseArgs.DEFAULT_INSTANCE_TYPE, actual.args.instance_type)

    # Specifying m1.large as the instance type is acceptable.
    argv_2 = self.cloud_argv[:] + ['--infrastructure', 'ec2', '--machine',
      'ami-ABCDEFG', '--instance_type', 'm1.large']
    actual = ParseArgs(argv_2, self.function)
    self.assertEquals("m1.large", actual.args.instance_type)

    # Specifying blarg1.humongous as the instance type is not
    # acceptable.
    argv_3 = self.cloud_argv[:] + ['--infrastructure', 'ec2', '--machine',
      'ami-ABCDEFG', '--instance_type', 'blarg1.humongous']
    self.assertRaises(SystemExit, ParseArgs, argv_3, self.function)


  def test_machine_not_set_in_cloud_deployments(self):
    # when running in a cloud infrastructure, we need to know what
    # machine image to use
    argv = self.cloud_argv[:] + ["--infrastructure", "euca"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv,
      "appscale-run-instances")


  def test_scaling_flags(self):
    # Specifying a value for add_to_existing should fail
    argv_1 = ["--add_to_existing", "boo"]
    self.assertRaises(SystemExit, ParseArgs, argv_1,
      "appscale-add-keypair")

    # not specifying a value should set it to true
    argv_2 = ["--add_to_existing"]
    actual = ParseArgs(argv_2, "appscale-add-keypair")
    self.assertEquals(True, actual.args.add_to_existing)


  def test_environment_variables_not_set_in_ec2_cloud_deployments(self):
    argv = self.cloud_argv[:] + ["--infrastructure", "ec2", "--machine", "ami-ABCDEFG"]
    for var in EC2Agent.REQUIRED_EC2_CREDENTIALS:
      os.environ[var] = ''
    self.assertRaises(AgentConfigurationException, ParseArgs, argv, self.function)


  def test_environment_variables_not_set_in_euca_cloud_deployments(self):
    argv = self.cloud_argv[:] + ["--infrastructure", "euca", "--machine", "emi-ABCDEFG"]
    for var in EucalyptusAgent.REQUIRED_EUCA_CREDENTIALS:
      os.environ[var] = ''
    self.assertRaises(AgentConfigurationException, ParseArgs, argv, self.function)


  def test_failure_when_ami_doesnt_exist(self):
    # mock out boto calls to EC2 and put in that the image doesn't exist
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_raise(boto.exception.EC2ResponseError, '', '')

    flexmock(boto)
    boto.should_receive('connect_ec2').with_args('baz', 'baz').and_return(fake_ec2)

    argv = self.cloud_argv[:] + ["--infrastructure", "ec2", "--machine", "ami-ABCDEFG"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, self.function)


  def test_failure_when_user_doesnt_specify_ips_or_machine(self):
    argv = self.cloud_argv[:] + ['--infrastructure', 'ec2']
    self.assertRaises(BadConfigurationException, ParseArgs, argv, self.function)


  def test_ips_layout_flag(self):
    # first, make sure that the flag works
    ips_layout = yaml.load("""
    'controller' : public1,
    'servers' : public2'
    """)
    base64ed_ips = base64.b64encode(yaml.dump(ips_layout))
    argv = ['--ips_layout', base64ed_ips]
    actual = ParseArgs(argv, self.function).args
    self.assertEquals(base64ed_ips, actual.ips_layout)

    # next, make sure that it got assigned to ips
    self.assertEquals(ips_layout, actual.ips)


  def test_scp_flag(self):
    # first, make sure --scp fails if no arg is provided
    argv_1 = self.cloud_argv[:] + ['--scp']
    self.assertRaises(SystemExit, ParseArgs, argv_1, self.function)

    argv_2 = self.cloud_argv[:] + ['--scp', '/tmp/booscale']
    actual = ParseArgs(argv_2, self.function).args
    self.assertEquals('/tmp/booscale', actual.scp)
