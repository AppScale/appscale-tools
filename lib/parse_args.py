#!/usr/bin/env python


# General-purpose Python library imports
import base64
import argparse
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
  ALLOWED_INSTANCE_TYPES = ["m1.large"]


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
      self.parser.add_argument('--infrastructure',
        choices=InfrastructureAgentFactory.VALID_AGENTS,
        help="the cloud infrastructure to use")
      self.parser.add_argument('--machine',
        help="the ami/emi that has AppScale installed")
      self.parser.add_argument('--instance_type',
        default=self.DEFAULT_INSTANCE_TYPE,
        choices=self.ALLOWED_INSTANCE_TYPES,
        help="the instance type to use")
      self.parser.add_argument('--group',
        default=self.DEFAULT_SECURITY_GROUP,
        help="the security group to use")
      self.parser.add_argument('--keyname', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")

      # flags relating to the datastore used
      self.parser.add_argument('--table',
        default=self.DEFAULT_DATASTORE,
        choices=self.ALLOWED_DATASTORES,
        help="the datastore to use")
      self.parser.add_argument('-n', type=int,
        help="the database replication factor")

      # flags relating to application servers
      self.parser.add_argument('--appengine', type=int, default=1,
        help="the number of application servers to use per app")
      self.parser.add_argument('--autoscale', action='store_true',
        default=True,
        help="adds/removes application servers based on incoming traffic")

      # flags relating to how much output we produce
      self.parser.add_argument('--verbose', '-v', action='store_true',
        default=False,
        help="prints additional output (useful for debugging)")

      # developer flags
      self.parser.add_argument('--force', action='store_true',
        default=False,
        help="forces tools to continue if keyname or group exist")
      self.parser.add_argument('--scp',
        help="the location to copy a local AppScale branch from")
      self.parser.add_argument('--test', action='store_true',
        default=False,
        help="uses a default username and password for cloud admin")
    elif function == "appscale-gather-logs":
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

      # flags relating to how much output we produce
      self.parser.add_argument('--verbose', '-v', action='store_true',
        default=False,
        help="prints additional output (useful for debugging)")

      self.parser.add_argument('--add_to_existing',
        default=False,
        action='store_true',
        help='if we should add the given nodes to an existing deployment')
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
    elif function == "appscale-gather-logs":
      pass
    elif function == "appscale-add-keypair":
      self.validate_ips_flags()
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
      return

    # make sure the user gave us an ami if running in cloud
    if self.args.infrastructure and not self.args.machine:
      raise BadConfigurationException("Need a machine image (ami) " +
        "when running in a cloud infrastructure.")


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
    if self.args.n is not None and self.args.n < 1:
      raise BadConfigurationException("Replication factor must exceed 0.")
