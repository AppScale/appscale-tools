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
from agents.base_agent import AgentConfigurationException
from agents.ec2_agent import EC2Agent
from agents.euca_agent import EucalyptusAgent
from appscale_logger import AppScaleLogger
from custom_exceptions import BadConfigurationException
from parse_args import ParseArgs


class TestParseArgs(unittest.TestCase):
  

  def setUp(self):
    self.cloud_argv = ['--min', '1', '--max', '1', '--group', 'blargscale',
      '--infrastructure', 'ec2', '--machine', 'ami-ABCDEFG', '--zone',
      'my-zone-1b']
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

    # pretend that our credentials are valid.
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_all_instances')

    # similarly, pretend that our image does exist in EC2
    # and Euca
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()
    fake_ec2.should_receive('get_image').with_args('emi-ABCDEFG') \
      .and_return('anything')

    # Slip in mocks that assume our EBS volume exists in EC2.
    fake_ec2.should_receive('get_all_volumes').with_args(['vol-ABCDEFG']) \
      .and_return('anything')

    # Also pretend that the availability zone we want to use exists.
    fake_ec2.should_receive('get_all_zones').with_args('my-zone-1b') \
      .and_return('anything')

    # Pretend that a bad availability zone doesn't exist.
    fake_ec2.should_receive('get_all_zones').with_args('bad-zone-1b') \
      .and_raise(boto.exception.EC2ResponseError, 'baz', 'baz')

    # Pretend that we have one elastic IP allocated for use.
    fake_ec2.should_receive('get_all_addresses').with_args('GOOD.IP.ADDRESS') \
      .and_return('anything')

    # Pretend that asking for a bad elastic IP doesn't work.
    fake_ec2.should_receive('get_all_addresses').with_args('BAD.IP.ADDRESS') \
      .and_raise(boto.exception.EC2ResponseError, 'baz', 'baz')

    fake_price = flexmock(name='fake_price', price=1.00)
    fake_ec2.should_receive('get_spot_price_history').and_return([fake_price])

    flexmock(boto)
    flexmock(boto.ec2)
    boto.ec2.should_receive('connect_to_region').with_args('my-zone-1',
      aws_access_key_id='baz', aws_secret_access_key='baz').and_return(fake_ec2)
    boto.ec2.should_receive('connect_to_region').with_args('bad-zone-1',
      aws_access_key_id='baz', aws_secret_access_key='baz').and_return(fake_ec2)
    boto.should_receive('connect_euca').and_return(fake_ec2)


  def tearDown(self):
    for credential in EucalyptusAgent.REQUIRED_EC2_CREDENTIALS:
      os.environ[credential] = ''
    os.environ['EC2_URL'] = ''


  def test_flags_that_cause_program_abort(self):
    # using a flag that isn't acceptable should raise
    # an exception
    argv_1 = ['--boo!']
    self.assertRaises(SystemExit, ParseArgs, argv_1, 
      self.function)

    # the version flag should quit and print the current
    # version of the tools
    argv_2 = ['--version']
    try:
      ParseArgs(argv_2, self.function)
      raise
    except SystemExit:
      pass


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
    # throw in a mock that says our ips.yaml file exists
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args('ips.yaml').and_return(True)

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
    argv_4 = self.cloud_argv[:] + ['--table', 'cassandra', '--n', '0']
    self.assertRaises(BadConfigurationException, ParseArgs, argv_4,
      self.function)

    # Specifying a positive integer for n should be ok
    argv_5 = self.cloud_argv[:] + ['--table', 'cassandra', '--n', '2']
    actual_5 = ParseArgs(argv_5, self.function)
    self.assertEquals(2, actual_5.args.replication)


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
    argv_1 = self.cloud_argv[:] + ['--infrastructure', 'ec2', '--machine',
      'ami-ABCDEFG']
    actual_1 = ParseArgs(argv_1, self.function)
    self.assertEquals('ec2', actual_1.args.infrastructure)

    argv_2 = self.cloud_argv[:] + ['--infrastructure', 'euca', '--machine',
        'emi-ABCDEFG']
    actual_2 = ParseArgs(argv_2, self.function)
    self.assertEquals('euca', actual_2.args.infrastructure)

    # Specifying something else as the infrastructure is not acceptable.
    argv_3 = self.cloud_argv[:] + ['--infrastructure', 'boocloud', '--machine',
      'boo']
    self.assertRaises(SystemExit, ParseArgs, argv_3, self.function)

    # Specifying --machine when we're not running in a cloud is not acceptable.
    flexmock(os.path)
    os.path.should_call('exists')  # set the fall-through
    os.path.should_receive('exists').with_args("ips.yaml").and_return(True)

    argv_4 = self.cluster_argv[:] + ['--machine', 'boo']
    self.assertRaises(BadConfigurationException, ParseArgs, argv_4,
      self.function)


  def test_instance_types(self):
    # Not specifying an instance type should default to a predetermined
    # value.
    argv_1 = self.cloud_argv[:]
    actual = ParseArgs(argv_1, self.function)
    self.assertEquals(ParseArgs.DEFAULT_EC2_INSTANCE_TYPE, \
      actual.args.instance_type)

    # Specifying m3.medium as the instance type is acceptable.
    argv_2 = self.cloud_argv[:] + ['--infrastructure', 'ec2', '--machine',
      'ami-ABCDEFG', '--instance_type', 'm3.medium']
    actual = ParseArgs(argv_2, self.function)
    self.assertEquals("m3.medium", actual.args.instance_type)

    # Specifying blarg1.humongous as the instance type is not
    # acceptable.
    argv_3 = self.cloud_argv[:] + ['--infrastructure', 'ec2', '--machine',
      'ami-ABCDEFG', '--instance_type', 'blarg1.humongous']
    self.assertRaises(SystemExit, ParseArgs, argv_3, self.function)


  def test_machine_not_set_in_cloud_deployments(self):
    # when running in a cloud infrastructure, we need to know what
    # machine image to use
    argv = ['--min', '1', '--max', '1', "--infrastructure", "euca"]
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
    argv = self.cloud_argv[:] + ["--infrastructure", "ec2", "--machine",
        "ami-ABCDEFG"]
    for var in EC2Agent.REQUIRED_EC2_CREDENTIALS:
      os.environ[var] = ''
    self.assertRaises(AgentConfigurationException, ParseArgs, argv,
      self.function)


  def test_environment_variables_not_set_in_euca_cloud_deployments(self):
    argv = self.cloud_argv[:] + ["--infrastructure", "euca", "--machine",
      "emi-ABCDEFG"]
    for var in EucalyptusAgent.REQUIRED_EUCA_CREDENTIALS:
      os.environ[var] = ''
    self.assertRaises(AgentConfigurationException, ParseArgs, argv,
      self.function)


  def test_failure_when_ami_doesnt_exist(self):
    # mock out boto calls to EC2 and put in that the image doesn't exist
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_all_instances')
    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_raise(boto.exception.EC2ResponseError, '', '')

    flexmock(boto.ec2)
    boto.ec2.should_receive('connect_to_region').with_args(str,
      aws_access_key_id='baz', aws_secret_access_key='baz') \
      .and_return(fake_ec2)

    argv = self.cloud_argv[:] + ["--infrastructure", "ec2", "--machine",
      "ami-ABCDEFG"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, self.function)


  def test_failure_when_user_doesnt_specify_ips_or_machine(self):
    argv = ['--min', '1', '--max', '1', '--infrastructure', 'ec2']
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


  def test_login_flag(self):
    # if the user wants to override the URL where we log in at, make sure it
    # fails if they don't give us a URL to log in to
    argv_1 = self.cloud_argv[:] + ['--login_host']
    self.assertRaises(SystemExit, ParseArgs, argv_1, self.function)

    # and it should succeed if they do give us the URL
    argv_2 = self.cloud_argv[:] + ['--login_host', 'www.booscale.com']
    actual = ParseArgs(argv_2, self.function).args
    self.assertEquals('www.booscale.com', actual.login_host)


  def test_spot_instances_flag(self):
    # if the user wants to use spot instances, that only works on ec2, so
    # abort if they're running on euca
    euca_argv = ['--min', '1', '--max', '1', '--group', 'blargscale',
      '--infrastructure', 'euca', '--machine', 'emi-ABCDEFG',
      '--use_spot_instances']
    self.assertRaises(BadConfigurationException, ParseArgs, euca_argv,
      self.function)

    # also abort if they're running on a virtualized cluster
    cluster_argv = self.cluster_argv[:] + ['--use_spot_instances']
    self.assertRaises(BadConfigurationException, ParseArgs, cluster_argv,
      self.function)

    # succeed if they're running on ec2
    ec2_argv = self.cloud_argv[:] + ['--use_spot_instances']
    actual = ParseArgs(ec2_argv, self.function).args
    self.assertEquals(True, actual.use_spot_instances)


  def test_max_spot_instance_price_flag(self):
    # if the user wants to use spot instances, that only works on ec2, so
    # abort if they're running on euca
    euca_argv = ['--min', '1', '--max', '1', '--group', 'blargscale',
      '--infrastructure', 'euca', '--machine', 'emi-ABCDEFG',
      '--max_spot_price', '20']
    self.assertRaises(BadConfigurationException, ParseArgs, euca_argv,
      self.function)

    # also abort if they're running on a virtualized cluster
    cluster_argv = self.cluster_argv[:] + ['--max_spot_price', '20']
    self.assertRaises(BadConfigurationException, ParseArgs, cluster_argv,
      self.function)

    # fail if running on EC2 and they didn't say that we should use spot
    # instances
    ec2_bad_argv = self.cloud_argv[:] + ['--max_spot_price', '20']
    self.assertRaises(BadConfigurationException, ParseArgs, ec2_bad_argv,
      self.function)

    # succeed if they did say it
    ec2_argv = self.cloud_argv[:] + ['--use_spot_instances', '--max_spot_price',
      '20.0']
    actual = ParseArgs(ec2_argv, self.function).args
    self.assertEquals(True, actual.use_spot_instances)
    self.assertEquals(20.0, actual.max_spot_price)


  def test_ec2_creds_in_run_instances(self):
    # specifying EC2_ACCESS_KEY but not EC2_SECRET_KEY should fail
    argv = self.cloud_argv[:] + ["--infrastructure", "ec2", "--machine",
      "ami-ABCDEFG", "--EC2_ACCESS_KEY", "access_key"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, self.function)

    # specifying EC2_SECRET_KEY but not EC2_ACCESS_KEY should fail
    argv = self.cloud_argv[:] + ["--infrastructure", "ec2", "--machine",
      "ami-ABCDEFG", "--EC2_SECRET_KEY", "secret_key"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, self.function)

    # specifying both should result in them being set in the environment
    argv = self.cloud_argv[:] + ["--infrastructure", "ec2", "--machine",
      "ami-ABCDEFG", "--EC2_ACCESS_KEY", "baz", "--EC2_SECRET_KEY",
      "baz"]
    ParseArgs(argv, self.function)
    self.assertEquals("baz", os.environ['EC2_ACCESS_KEY'])
    self.assertEquals("baz", os.environ['EC2_SECRET_KEY'])

    # specifying a EC2_URL should result in it being set in the environment
    argv = self.cloud_argv[:] + ["--infrastructure", "ec2", "--machine",
      "ami-ABCDEFG", "--EC2_ACCESS_KEY", "baz", "--EC2_SECRET_KEY",
      "baz", "--EC2_URL", "http://boo.baz"]
    ParseArgs(argv, self.function)
    self.assertEquals("baz", os.environ['EC2_ACCESS_KEY'])
    self.assertEquals("baz", os.environ['EC2_SECRET_KEY'])
    self.assertEquals("http://boo.baz", os.environ['EC2_URL'])


  def test_ec2_creds_in_term_instances(self):
    function = "appscale-terminate-instances"

    # specifying EC2_ACCESS_KEY but not EC2_SECRET_KEY should fail
    argv = ["--EC2_ACCESS_KEY", "access_key"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, function)

    # specifying EC2_SECRET_KEY but not EC2_ACCESS_KEY should fail
    argv = ["--EC2_SECRET_KEY", "secret_key"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, function)

    # specifying both should result in them being set in the environment
    argv = ["--EC2_ACCESS_KEY", "baz", "--EC2_SECRET_KEY", "baz"]
    ParseArgs(argv, function)
    self.assertEquals("baz", os.environ['EC2_ACCESS_KEY'])
    self.assertEquals("baz", os.environ['EC2_SECRET_KEY'])

    # specifying a EC2_URL should result in it being set in the environment
    argv = ["--EC2_ACCESS_KEY", "baz", "--EC2_SECRET_KEY", "baz", "--EC2_URL",
      "http://boo.baz"]
    ParseArgs(argv, function)
    self.assertEquals("baz", os.environ['EC2_ACCESS_KEY'])
    self.assertEquals("baz", os.environ['EC2_SECRET_KEY'])
    self.assertEquals("http://boo.baz", os.environ['EC2_URL'])


  def test_disks_flag(self):
    # specifying a EBS mount or PD mount is only valid for EC2/Euca/GCE, so
    # fail on a cluster deployment.
    argv = self.cluster_argv[:] + ["--disks", "ABCDFEG"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, self.function)

    # if we get a --disk flag, fail if it's not a dict (after base64, yaml load)
    bad_disks_layout = yaml.load("""
    public1,
    """)
    base64ed_bad_disks = base64.b64encode(yaml.dump(bad_disks_layout))
    cloud_argv1 = self.cloud_argv[:] + ["--disks", base64ed_bad_disks]
    self.assertRaises(BadConfigurationException, ParseArgs, cloud_argv1,
      self.function)

    # passing in a dict should be fine, and result in us seeing the same value
    # for --disks that we passed in.
    disks = {'public1' : 'vol-ABCDEFG'}
    good_disks_layout = yaml.load("""
public1 : vol-ABCDEFG
    """)
    base64ed_good_disks = base64.b64encode(yaml.dump(good_disks_layout))
    cloud_argv2 = self.cloud_argv[:] + ["--disks", base64ed_good_disks]
    actual = ParseArgs(cloud_argv2, self.function).args
    self.assertEquals(disks, actual.disks)


  def test_zone_flag(self):
    # Specifying an availability zone is only valid for EC2/Euca/GCE, so
    # fail on a cluster deployment.
    argv = self.cluster_argv[:] + ["--zone", "my-zone-1b"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, self.function)

    # If we want to specify the zone on a cloud deployment, but the zone is not
    # an acceptable value, we should fail.
    cloud_argv1 = self.cloud_argv[:] + ["--zone", "bad-zone-1b"]
    self.assertRaises(BadConfigurationException, ParseArgs, cloud_argv1,
      self.function)

    # passing in a zone on a cloud is fine, and should result in us seeing the
    # same zone that we passed in.
    cloud_argv2 = self.cloud_argv[:]
    actual = ParseArgs(cloud_argv2, self.function).args
    self.assertEquals('my-zone-1b', actual.zone)


  def test_static_ip_flag(self):
    # Specifying a static IP is only valid for EC2/Euca/GCE, so fail on a
    # cluster deployment.
    argv = self.cluster_argv[:] + ["--static_ip", "1.2.3.4"]
    self.assertRaises(BadConfigurationException, ParseArgs, argv, self.function)

    # Specifying a static IP that the user has not allocated when on a cloud
    # is not fine - it should raise an exception.
    cloud_argv1 = self.cloud_argv[:] + ["--static_ip", "BAD.IP.ADDRESS"]
    self.assertRaises(BadConfigurationException, ParseArgs, cloud_argv1,
      self.function)

    # Specifying a static IP that the user has allocated when running on a cloud
    # is fine - we should see it in the args we get back.
    cloud_argv2 = self.cloud_argv[:] + ["--static_ip", "GOOD.IP.ADDRESS"]
    actual = ParseArgs(cloud_argv2, self.function).args
    self.assertEquals('GOOD.IP.ADDRESS', actual.static_ip)

  def test_no_password_for_flower_results_in_default(self):
    argv = self.cluster_argv[:]
    actual = ParseArgs(argv, self.function).args
    self.assertEquals(ParseArgs.DEFAULT_FLOWER_PASSWORD, actual.flower_password)

  def test_password_for_flower_gets_passed_through(self):
    password = "abcdefg"
    argv = self.cluster_argv[:] + ["--flower_password", password]
    actual = ParseArgs(argv, self.function).args
    self.assertEquals(password, actual.flower_password)

  def test_no_max_memory_flag_gets_set_to_default(self):
    argv = self.cluster_argv[:]
    actual = ParseArgs(argv, self.function).args
    self.assertEquals(ParseArgs.DEFAULT_MAX_MEMORY, actual.max_memory)

  def test_max_memory_flag_gets_passed_through(self):
    argv = self.cluster_argv[:] + ["--max_memory", "800"]
    actual = ParseArgs(argv, self.function).args
    self.assertEquals(800, actual.max_memory)
