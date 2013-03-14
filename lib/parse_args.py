#!/usr/bin/env python


# General-purpose Python library imports
import os
import base64
import argparse


# Third-party imports
import yaml


# AppScale-specific imports
import local_state
from custom_exceptions import BadConfigurationException
from agents.base_agent import BaseAgent
from agents.factory import InfrastructureAgentFactory


class ParseArgs():
  """ParseArgs provides the AppScale Tools with the ability
  to parse command-line arguments. Callers can customize
  the arguments that are acceptable for their executable
  as well as the description and usage printed for users
  in need of assistance.
  """


  # The datastore that should be used if the user fails to
  # manually specify the datastore to use.
  DEFAULT_DATASTORE = "cassandra"


  # A list of the datastores that AppScale can deploy over.
  ALLOWED_DATASTORES = ["hbase", "hypertable", "cassandra"]


  # The instance type that should be used if the user does not specify one.
  DEFAULT_INSTANCE_TYPE = "m1.large"


  # A list of the instance types we allow users to run AppScale over.
  # TODO(cgb): Change this to a map that maps to the number of each type that
  # users can spawn without having to contact Amazon, and enforce this
  # limitation.
  ALLOWED_INSTANCE_TYPES = [
    # Standard Instances (First Generation)
    "m1.small", "m1.medium", "m1.large", "m1.xlarge",

    # Standard Instances (Second Generation)
    "m3.xlarge", "m3.2xlarge",

    # High-Memory Instances
    "m2.xlarge", "m2.2xlarge", "m2.4xlarge",

    # High-CPU Instances
    "c1.medium", "c1.xlarge",

    # Cluster Compute Instances
    "cc2.8xlarge",

    # High Memory Cluster Instances
    "cr1.8xlarge",

    # Cluster GPU Instances
    "cg1.4xlarge",

    # High I/O Instances
    "hi1.4xlarge",

    # High Storage Instances
    "hs1.8xlarge",
    ]


  # The default security group to create and use for AppScale cloud deployments.
  DEFAULT_SECURITY_GROUP = "appscale"


  # The default keypair name to create and use for AppScale cloud deployments.
  DEFAULT_KEYNAME = "appscale"


  def __init__(self, argv, function):
    """Creates a new ParseArgs for a set of acceptable flags.

    Args:
      argv: A list of strs, representing command-line arguments
        passed in by the user.
      function: A str that represents the executable we are
        parsing arguments for, which is used to make sure

    Raises:
      SystemExit: If the user asks us for just the version
        of the AppScale Tools, or gives us arguments that
        are not acceptable for the executable we are parsing
        arguments for.
    """
    self.parser = argparse.ArgumentParser(function)
    self.add_allowed_flags(function)
    self.args = self.parser.parse_args(argv)

    if self.args.version:
      raise SystemExit(local_state.APPSCALE_VERSION)

    self.validate_allowed_flags(function)


  def add_allowed_flags(self, function):
    """Adds flag parsing capabilities based on the given function.

    Args:
      function: The name of the function that we're adding flags
        on behalf of.
    Raises:
      SystemExit: If function is not a supported function.
    """
    self.parser.add_argument('--version', action='store_true',
      default=False,
      help="shows the tools version and quits")

    # flags relating to how much output we produce
    self.parser.add_argument('--verbose', '-v', action='store_true',
      default=False,
      help="prints additional output (useful for debugging)")

    if function == "appscale-run-instances":
      # flags relating to how many VMs we should spawn
      self.parser.add_argument('--min', type=int,
        help="the minimum number of VMs to use")
      self.parser.add_argument('--max', type=int,
        help="the maximum number of VMs to use")
      self.parser.add_argument('--ips',
        help="a YAML file dictating the placement strategy")
      self.parser.add_argument('--ips_layout',
        help="a base64-encoded YAML dictating the placement strategy")

      # flags relating to cloud infrastructures
      self.parser.add_argument('--infrastructure', '-i',
        choices=InfrastructureAgentFactory.VALID_AGENTS,
        help="the cloud infrastructure to use")
      self.parser.add_argument('--machine', '-m',
        help="the ami/emi that has AppScale installed")
      self.parser.add_argument('--instance_type', '-t',
        default=self.DEFAULT_INSTANCE_TYPE,
        choices=self.ALLOWED_INSTANCE_TYPES,
        help="the instance type to use")
      self.parser.add_argument('--group', '-g',
        help="the security group to use")
      self.parser.add_argument('--keyname', '-k', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
      self.parser.add_argument('--use_spot_instances', action='store_true',
        default=False,
        help="use spot instances instead of on-demand instances (EC2 only)")
      self.parser.add_argument('--max_spot_price', type=float,
        help="the maximum price to pay for spot instances in EC2")

      # flags relating to the datastore used
      self.parser.add_argument('--table',
        default=self.DEFAULT_DATASTORE,
        choices=self.ALLOWED_DATASTORES,
        help="the datastore to use")
      self.parser.add_argument('--replication', '-n', type=int,
        help="the database replication factor")

      # flags relating to application servers
      group = self.parser.add_mutually_exclusive_group()
      group.add_argument('--appengine', type=int,
        help="the number of application servers to use per app")
      group.add_argument('--autoscale', action='store_true',
        help="adds/removes application servers based on incoming traffic")

      # flags relating to the location where users reach appscale
      self.parser.add_argument('--login_host',
        help="override the provided login host with this one")

      # developer flags
      self.parser.add_argument('--force', action='store_true',
        default=False,
        help="forces tools to continue if keyname or group exist")
      self.parser.add_argument('--scp',
        help="the location to copy a local AppScale branch from")
      self.parser.add_argument('--test', action='store_true',
        default=False,
        help="uses a default username and password for cloud admin")
      self.parser.add_argument('--admin_user',
        help="uses the given e-mail instead of prompting for one")
      self.parser.add_argument('--admin_pass',
        help="uses the given password instead of prompting for one")
    elif function == "appscale-gather-logs":
      self.parser.add_argument('--keyname', '-k', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
      self.parser.add_argument('--location',
        help="the location to store the collected logs")
    elif function == "appscale-add-keypair":
      # flags relating to how many VMs we should spawn
      self.parser.add_argument('--ips',
        help="a YAML file dictating the placement strategy")
      self.parser.add_argument('--ips_layout',
        help="a base64-encoded YAML dictating the placement strategy")

      self.parser.add_argument('--keyname', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")

      self.parser.add_argument('--auto', action='store_true',
        default=False,
        help="don't prompt the user for the password for each machine")

      self.parser.add_argument('--add_to_existing',
        default=False,
        action='store_true',
        help='if we should add the given nodes to an existing deployment')
    elif function == "appscale-add-instances":
      self.parser.add_argument('--ips',
        help="a YAML file dictating the placement strategy")
      self.parser.add_argument('--keyname', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
    elif function == "appscale-upload-app":
      self.parser.add_argument('--file',
        help="a directory containing the Google App Engine app to upload")
      self.parser.add_argument('--keyname', '-k',
        default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
      self.parser.add_argument('--test', action='store_true',
        default=False,
        help="uses a default username and password for cloud admin")
      self.parser.add_argument('--email',
        help="the e-mail address to use as the app's admin")
    elif function == "appscale-terminate-instances":
      self.parser.add_argument('--keyname', '-k',
        default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
    elif function == "appscale-remove-app":
      self.parser.add_argument('--keyname', '-k', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
      self.parser.add_argument('--appname',
        help="the name of the application to remove")
      self.parser.add_argument('--confirm', action='store_true',
        default=False,
        help="does not ask user to confirm application removal")
    elif function == "appscale-reset-pwd":
      self.parser.add_argument('--keyname', '-k',
        default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
    elif function == "appscale-describe-instances":
      self.parser.add_argument('--keyname', '-k', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
    else:
      raise SystemExit


  def validate_allowed_flags(self, function):
    """Checks the values passed in by the user to ensure that
    they are valid for an AppScale deployment.

    Args:
      function: The name of the function that we should be
        validating parameters for.
    Raises:
      SystemExit: If function is not a supported function.
    """
    if function == "appscale-run-instances":
      self.validate_ips_flags()
      self.validate_num_of_vms_flags()
      self.validate_infrastructure_flags()
      self.validate_credentials()
      self.validate_machine_image()
      self.validate_database_flags()
      self.validate_appengine_flags()
      self.validate_admin_flags()
    elif function == "appscale-add-keypair":
      self.validate_ips_flags()
      pass
    elif function == "appscale-upload-app":
      if not self.args.file:
        raise SystemExit("Must specify --file.")
    elif function == "appscale-gather-logs":
      if not self.args.location:
        self.args.location = "/tmp/{0}-logs/".format(self.args.keyname)
    elif function == "appscale-terminate-instances":
      pass
    elif function == "appscale-remove-app":
      if not self.args.appname:
        raise SystemExit("Must specify appname")
    elif function == "appscale-reset-pwd":
      pass
    elif function == "appscale-describe-instances":
      pass
    elif function == "appscale-add-instances":
      if 'ips' in self.args:
        with open(self.args.ips, 'r') as file_handle:
          self.args.ips = yaml.safe_load(file_handle.read())
      else:
        raise SystemExit
    else:
      raise SystemExit


  def validate_num_of_vms_flags(self):
    """Validates the values given to us by the user relating to the
    number of virtual machines we spawn in a cloud deployment.

    Raises:
      BadConfigurationException: If the values for the min or max
        flags are invalid.
    """
    if self.args.ips:
      return

    # if min is not set and max is, set min == max
    if self.args.min is None and self.args.max:
      self.args.min = self.args.max

    if self.args.ips:
      if not os.path.exists(self.args.ips):
        raise BadConfigurationException("The given ips.yaml file did not exist.")
    elif self.args.ips_layout:
      self.args.ips = yaml.safe_load(base64.b64decode(self.args.ips_layout))
    else:
      if self.args.min < 1:
        raise BadConfigurationException("Min cannot be less than 1.")

      if self.args.max < 1:
        raise BadConfigurationException("Max cannot be less than 1.")

      if self.args.min > self.args.max:
        raise BadConfigurationException("Min cannot exceed max.")


  def validate_ips_flags(self):
    """Sets up the ips flag if the ips_layout flag is given.
    """
    if self.args.ips_layout:
      self.args.ips = yaml.safe_load(base64.b64decode(self.args.ips_layout))


  def validate_infrastructure_flags(self):
    """Validates flags corresponding to cloud infrastructures.

    Raises:
      BadConfigurationException: If the value given to us for
        infrastructure-related flags were invalid.
    """
    if not self.args.infrastructure:
      # make sure we didn't get a group or machine flag, since those are
      # infrastructure-only
      if self.args.group:
        raise BadConfigurationException("Cannot specify a security group " + \
          "when --infrastructure is not specified.")

      if self.args.machine:
        raise BadConfigurationException("Cannot specify a machine image " + \
          "when --infrastructure is not specified.")

      if self.args.use_spot_instances or self.args.max_spot_price:
        raise BadConfigurationException("Can't run spot instances when " + \
          "--infrastructure is not specified.")

      return

    # make sure the user gave us an ami if running in cloud
    if self.args.infrastructure and not self.args.machine:
      raise BadConfigurationException("Need a machine image (ami) " +
        "when running in a cloud infrastructure.")

    # if the user wants to use spot instances in a cloud, make sure that it's
    # EC2 (since Euca doesn't have spot instances)
    if self.args.infrastructure != 'ec2' and (self.args.use_spot_instances or \
      self.args.max_spot_price):
      raise BadConfigurationException("Can't run spot instances unless " + \
        "Amazon EC2 is the infrastructure used.")

    # if the user does want to set a max spot price, make sure they told us that
    # they want to use spot instances in the first place
    if self.args.max_spot_price and not self.args.use_spot_instances:
      raise BadConfigurationException("Can't have a max spot instance price" + \
        " if --use_spot_instances is not set.")


  def validate_credentials(self):
    if not self.args.infrastructure:
      return

    cloud_agent = InfrastructureAgentFactory.create_agent(
      self.args.infrastructure)
    params = cloud_agent.get_params_from_args(self.args)
    cloud_agent.assert_required_parameters(params, BaseAgent.OPERATION_RUN)


  def validate_machine_image(self):
    """Checks with the given cloud (if running in a cloud) to ensure that the
    user-specified ami/emi exists, aborting if it does not.

    Raises:
      BadConfigurationException: If the given machine image does not exist.
    """
    if not self.args.infrastructure:
      return

    cloud_agent = InfrastructureAgentFactory.create_agent(
      self.args.infrastructure)
    params = cloud_agent.get_params_from_args(self.args)
    if not cloud_agent.does_image_exist(params):
      raise BadConfigurationException("Couldn't find the given machine image.")


  def validate_database_flags(self):
    """Validates the values given to us by the user for any flag
    relating to the database used.

    Raises:
      BadConfigurationException: If the values for any of the
        database flags are not valid.
    """
    if self.args.replication is not None and self.args.replication < 1:
      raise BadConfigurationException("Replication factor must exceed 0.")


  def validate_appengine_flags(self):
    """Validates the values given to us by the user for any flag relating to
    the number of AppServers to launch per App Engine app.

    Raises:
      BadConfigurationException: If the value for the --appengine flag is
        invalid.
    """
    if self.args.appengine:
      if self.args.appengine < 1:
        raise BadConfigurationException("Number of application servers " + \
          "must exceed zero.")

      self.args.autoscale = False
    elif self.args.autoscale:
      self.args.appengine = 1
    else:  # neither are set
      self.args.appengine = 1
      self.args.autoscale = True


  def validate_admin_flags(self):
    """Validates the flags that correspond to setting administrator e-mails
    and passwords.

    Raises:
      BadConfigurationException: If admin_user, admin_pass, and test are all
        set, or if admin_user (or admin_pass) is set but the other isn't.
    """
    if self.args.admin_user and not self.args.admin_pass:
      raise BadConfigurationException("If admin_user is set, admin_pass " + \
        "must also be set.")
    if self.args.admin_pass and not self.args.admin_user:
      raise BadConfigurationException("If admin_pass is set, admin_user " + \
        "must also be set.")
    if self.args.admin_user and self.args.admin_pass and self.args.test:
      raise BadConfigurationException("Cannot set admin_user, " + \
        "admin_pass, and test.")
