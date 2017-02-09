#!/usr/bin/env python


# General-purpose Python library imports
import argparse
import base64
import os
import uuid


# Third-party imports
import yaml


# AppScale-specific imports
try:
  from agents.azure_agent import AzureAgent
except ImportError:
  AzureAgent = None
from agents.base_agent import BaseAgent
from agents.ec2_agent import EC2Agent
from agents.gce_agent import GCEAgent
from agents.factory import InfrastructureAgentFactory
from custom_exceptions import BadConfigurationException
from local_state import APPSCALE_VERSION
from local_state import LocalState


class ParseArgs(object):
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
  ALLOWED_DATASTORES = ["cassandra"]


  # A list of the instance types we allow users to run AppScale over in EC2.
  # TODO(cgb): Change this to a map that maps to the number of each type that
  # users can spawn without having to contact Amazon, and enforce this
  # limitation.
  ALLOWED_EC2_INSTANCE_TYPES = [
    # General Purpose Instances
    "m3.medium", "m3.large", "m3.xlarge", "m3.2xlarge",

    # Compute Optimized Instances
    "c3.large", "c3.xlarge", "c3.2xlarge", "c3.4xlarge", "c3.8xlarge",

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

  ALLOWED_GCE_INSTANCE_TYPES = [
    "n1-standard-1",
    "n1-standard-2",
    "n1-standard-4",
    "n1-standard-8",
    "n1-highcpu-2",
    "n1-highcpu-4",
    "n1-highcpu-8",
    "n1-highmem-2",
    "n1-highmem-4",
    "n1-highmem-8"
  ]

  # A list of instance types we allow users to run AppScale over in Azure.
  ALLOWED_AZURE_INSTANCE_TYPES = [
    "Standard_A3", "Standard_A4", "Standard_A5", "Standard_A6", "Standard_A7",
    "Standard_A8", "Standard_A9", "Standard_A10", "Standard_A11", "Standard_D2",
    "Standard_D3", "Standard_D4", "Standard_D11", "Standard_D12", "Standard_D13",
    "Standard_D14", "Standard_D2_v2", "Standard_D3_v2", "Standard_D4_v2",
    "Standard_D5_v2", "Standard_D11_v2", "Standard_D12_v2", "Standard_D13_v2",
    "Standard_D14_v2", "Standard_D15_v2", "Standard_DS2", "Standard_DS3",
    "Standard_DS4", "Standard_DS11", "Standard_DS12", "Standard_DS13",
    "Standard_DS14", "Standard_DS2_v2", "Standard_DS3_v2", "Standard_DS4_v2",
    "Standard_DS5_v2", "Standard_DS11_v2", "Standard_DS12_v2", "Standard_DS13_v2",
    "Standard_DS14_v2", "Standard_DS15_v2", "Standard_F4", "Standard_F8",
    "Standard_F16", "Standard_F4s", "Standard_F8s", "Standard_F16s"
    "Standard_G1", "Standard_G2", "Standard_G3", "Standard_G4", "Standard_G5",
    "Standard_GS1", "Standard_GS2", "Standard_GS3", "Standard_GS4", "Standard_GS5"]

  # A combined list of instance types for the different cloud infrastructures.
  ALLOWED_INSTANCE_TYPES = ALLOWED_EC2_INSTANCE_TYPES + ALLOWED_GCE_INSTANCE_TYPES + \
                           ALLOWED_AZURE_INSTANCE_TYPES

  # A combined list of instance types for different clouds that have less
  # than 4 GB RAM, the amount recommended for Cassandra.
  DISALLOWED_INSTANCE_TYPES = EC2Agent.DISALLOWED_INSTANCE_TYPES + \
                              GCEAgent.DISALLOWED_INSTANCE_TYPES

  # This check is to avoid import errors whenever Azure agent is not required.
  if AzureAgent is not None:
    DISALLOWED_INSTANCE_TYPES += AzureAgent.DISALLOWED_INSTANCE_TYPES

  # The default security group to create and use for AppScale cloud deployments.
  DEFAULT_SECURITY_GROUP = "appscale"


  # The default keypair name to create and use for AppScale cloud deployments.
  DEFAULT_KEYNAME = "appscale"


  # The default password that should be used to log into the celery web
  # interface (flower).
  DEFAULT_FLOWER_PASSWORD = "appscale"


  # The amount of memory to use for App Engine apps if the user does not
  # explicitly provide a value, in megabytes.
  DEFAULT_MAX_MEMORY = 400


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
      raise SystemExit(APPSCALE_VERSION)

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

      # Infrastructure-agnostic flags
      self.parser.add_argument('--disks',
        help="a base64-encoded YAML dictating the PD or EBS disks to use")
      self.parser.add_argument('--zone', '-z',
        help="the availability zone that instances should be deployed to")
      self.parser.add_argument('--static_ip',
        help="the static IP address that should be used for the login node " +
          "in cloud deployments")

      # flags relating to EC2-like cloud infrastructures
      # Don't use dashes in the random suffix, since network names on Google
      # Compute Engine aren't allowed to have dashes in them.
      random_suffix = str(uuid.uuid4()).replace('-', '')
      keyname = "appscale{0}".format(random_suffix)
      self.parser.add_argument('--infrastructure', '-i',
        choices=InfrastructureAgentFactory.VALID_AGENTS,
        help="the cloud infrastructure to use")
      self.parser.add_argument('--machine', '-m',
        help="the ami/emi that has AppScale installed")
      self.parser.add_argument('--instance_type', '-t',
        choices=self.ALLOWED_INSTANCE_TYPES,
        help="the EC2 instance type to use")
      self.parser.add_argument('--group', '-g', default=keyname,
        help="the security group to use")
      self.parser.add_argument('--keyname', '-k', default=keyname,
        help="the keypair name to use")
      self.parser.add_argument('--use_spot_instances', action='store_true',
        default=False,
        help="use spot instances instead of on-demand instances (EC2 only)")
      self.parser.add_argument('--max_spot_price', type=float,
        help="the maximum price to pay for spot instances in EC2")
      self.parser.add_argument('--EC2_ACCESS_KEY',
        help="the access key that identifies this user in an EC2-compatible" + \
          " service")
      self.parser.add_argument('--EC2_SECRET_KEY',
        help="the secret key that identifies this user in an EC2-compatible" + \
          " service")
      self.parser.add_argument('--EC2_URL',
        help="a URL that identifies where an EC2-compatible service runs")

      # Google Compute Engine-specific flags
      gce_group = self.parser.add_mutually_exclusive_group()
      gce_group.add_argument('--client_secrets',
        help="the JSON file that can be used to authenticate with Google " + \
          "APIs via OAuth")
      gce_group.add_argument('--oauth2_storage',
        help="the location on the local filesystem where signed OAuth2 " + \
          "credentials can be found")
      self.parser.add_argument('--project',
        help="the name of the project that is allowed to use Google " + \
          "Compute Engine")

      # Microsoft Azure specific flags
      self.parser.add_argument('--azure_app_secret_key',
        help="the authentication key for the application")
      self.parser.add_argument('--azure_app_id',
        help="the application or the client ID")
      self.parser.add_argument('--azure_group_tag',
        help="the tag set for an Azure resource group")
      self.parser.add_argument('--azure_resource_group',
        help="the resource group to use")
      self.parser.add_argument('--azure_storage_account',
        help="the storage account name under an Azure resource group")
      self.parser.add_argument('--azure_subscription_id',
        help="the Azure subscription ID for the account")
      self.parser.add_argument('--azure_tenant_id',
        help="the tenant ID of the Azure endpoints")

      # flags relating to the datastore used
      self.parser.add_argument('--table',
        default=self.DEFAULT_DATASTORE,
        choices=self.ALLOWED_DATASTORES,
        help="the datastore to use")
      self.parser.add_argument('--replication', '--n', type=int,
        help="the database replication factor")
      self.parser.add_argument('--clear_datastore', action='store_true',
        default=False,
        help="erases all stored user and application data")

      # flags relating to application servers
      self.parser.add_argument('--max_memory', type=int,
        default=self.DEFAULT_MAX_MEMORY,
        help="the maximum amount of memory to use for App Engine apps " \
        "(in megabytes)")

      group = self.parser.add_mutually_exclusive_group()
      group.add_argument('--appengine', type=int,
        help="the number of application servers to use per app")
      group.add_argument('--autoscale', action='store_true',
        help="adds/removes application servers based on incoming traffic")

      # flags relating to the location where users reach appscale
      self.parser.add_argument('--login_host',
        help="override the provided login host with this one")

      # developer flags
      self.parser.add_argument('--flower_password',
        default=self.DEFAULT_FLOWER_PASSWORD,
        help="the password that should be used to log into the flower web " \
          "interface")
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
      self.parser.add_argument('--user_commands',
        help="a base64-encoded YAML dictating the commands to run before " +
          "starting each AppController")
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
      self.parser.add_argument('--root_password',
        default=False,
        help='the root password of the host AppScale is to run on')
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
      self.parser.add_argument('--EC2_ACCESS_KEY',
        help="the access key that identifies this user in an EC2-compatible" + \
          " service")
      self.parser.add_argument('--EC2_SECRET_KEY',
        help="the secret key that identifies this user in an EC2-compatible" + \
          " service")
      self.parser.add_argument('--EC2_URL',
        help="a URL that identifies where an EC2-compatible service runs")
      self.parser.add_argument('--test', action='store_true',
        default=False,
        help="uses a default username and password for cloud admin")
      self.parser.add_argument('--terminate', action="store_true",
        default=False,
        help="terminate running instances (if in cloud environment)")
      self.parser.add_argument('--clean', action="store_true",
        default=False,
        help="clean running instances")
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
    elif function == "appscale-relocate-app":
      self.parser.add_argument('--keyname', '-k', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
      self.parser.add_argument('--appname',
        help="the name of the application to relocate")
      self.parser.add_argument('--http_port', type=int,
        help="the port that the application should now serve unencrypted " \
        "traffic on")
      self.parser.add_argument('--https_port', type=int,
        help="the port that the application should now serve encrypted " \
        "traffic on")
    elif function == "appscale-get-property":
      self.parser.add_argument('--keyname', '-k', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
      self.parser.add_argument('--property',
        help="a regular expression indicating which properties to retrieve")
    elif function == "appscale-set-property":
      self.parser.add_argument('--keyname', '-k', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
      self.parser.add_argument('--property_name',
        help="the name of the AppController property to set")
      self.parser.add_argument('--property_value',
        help="the value of the AppController property to set")
    elif function == "appscale-upgrade":
      self.parser.add_argument('--keyname', '-k', default=self.DEFAULT_KEYNAME,
        help="the keypair name to use")
      self.parser.add_argument('--ips_layout',
        help="a YAML file dictating the placement strategy")
      self.parser.add_argument(
        '--login_host', help='The public IP address of the head node')
      self.parser.add_argument(
        '--test', action='store_true', default=False,
        help='Skips user input when upgrading deployment')
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
      self.validate_environment_flags()
      self.validate_credentials()
      self.validate_machine_image()
      self.validate_database_flags()
      self.validate_appengine_flags()
      self.validate_developer_flags()
    elif function == "appscale-add-keypair":
      self.validate_ips_flags()
    elif function == "appscale-upload-app":
      if not self.args.file:
        raise SystemExit("Must specify --file.")
      else:
        self.shell_check(self.args.file)
    elif function == "appscale-gather-logs":
      if not self.args.location:
        self.args.location = "/tmp/{0}-logs/".format(self.args.keyname)
    elif function == "appscale-terminate-instances":
      self.validate_environment_flags()
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
    elif function == "appscale-relocate-app":
      if not self.args.appname:
        raise BadConfigurationException("Need to specify the application to " +
          "relocate with --appname.")

      if not self.args.http_port:
        raise BadConfigurationException("Need to specify the port to move " +
          "the app to with --http_port.")

      if not self.args.https_port:
        raise BadConfigurationException("Need to specify the port to move " +
          "the app to with --https_port.")

      if self.args.http_port < 1 or self.args.http_port > 65535:
        raise BadConfigurationException("Need to specify a http port between " +
          "1 and 65535. Please change --http_port accordingly.")

      if self.args.https_port < 1 or self.args.https_port > 65535:
        raise BadConfigurationException("Need to specify a https port " +
          "between 1 and 65535. Please change --https_port accordingly.")
    elif function == "appscale-get-property":
      pass
    elif function == "appscale-set-property":
      pass
    elif function == "appscale-upgrade":
      pass
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
        raise BadConfigurationException("The given ips.yaml file didn't exist.")
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
    """Sets up the ips flag if the ips_layout flag is given."""
    if self.args.ips_layout:
      self.args.ips = yaml.safe_load(base64.b64decode(self.args.ips_layout))


  def validate_environment_flags(self):
    """Validates flags dealing with setting environment variables.

    Raises:
      BadConfigurationException: If the user gives us either EC2_ACCESS_KEY
        or EC2_SECRET_KEY, but forgets to also specify the other.
    """
    if self.args.EC2_ACCESS_KEY and not self.args.EC2_SECRET_KEY:
      raise BadConfigurationException("When specifying EC2_ACCESS_KEY, " + \
        "EC2_SECRET_KEY must also be specified.")

    if self.args.EC2_SECRET_KEY and not self.args.EC2_ACCESS_KEY:
      raise BadConfigurationException("When specifying EC2_SECRET_KEY, " + \
        "EC2_ACCESS_KEY must also be specified.")

    if self.args.EC2_ACCESS_KEY:
      os.environ['EC2_ACCESS_KEY'] = self.args.EC2_ACCESS_KEY

    if self.args.EC2_SECRET_KEY:
      os.environ['EC2_SECRET_KEY'] = self.args.EC2_SECRET_KEY

    if self.args.EC2_URL:
      os.environ['EC2_URL'] = self.args.EC2_URL


  def validate_infrastructure_flags(self):
    """Validates flags corresponding to cloud infrastructures.

    Raises:
      BadConfigurationException: If the value given to us for
        infrastructure-related flags were invalid.
    """
    if not self.args.infrastructure:
      # Make sure we didn't get a machine flag, since that's infrastructure-only
      if self.args.machine:
        raise BadConfigurationException("Cannot specify a machine image " + \
          "when infrastructure is not specified.")

      # Also make sure they gave us a valid availability zone.
      if self.args.zone:
        raise BadConfigurationException("Cannot specify an availability zone " +
          "when infrastructure is not specified.")

      # Fail if the user is trying to use AWS Spot Instances on a virtualized
      # cluster.
      if self.args.use_spot_instances or self.args.max_spot_price:
        raise BadConfigurationException("Can't run spot instances when " + \
          "when infrastructure is not specified.")

      # Fail if the user is trying to use persistent disks on a virtualized
      # cluster.
      if self.args.disks:
        raise BadConfigurationException("Can't specify persistent disks " + \
          "when infrastructure is not specified.")

      # Fail if the user is trying to use an Elastic IP / Static IP on a
      # virtualized cluster.
      if self.args.static_ip:
        raise BadConfigurationException("Can't specify a static IP " + \
          "when infrastructure is not specified.")

      return

    # Make sure the user gave us an ami/emi if running in a cloud.
    if not self.args.machine:
      raise BadConfigurationException("Need a machine image (ami) " +
        "when running in a cloud infrastructure.")

    # Also make sure they gave us an availability zone if they want to use
    # persistent disks.
    if self.args.disks and not self.args.zone:
      raise BadConfigurationException("Need an availability zone specified " +
        "when persistent disks are specified.")

    # In Google Compute Engine, we have to specify the availability zone.
    if self.args.infrastructure == 'gce' and not self.args.zone:
      self.args.zone = GCEAgent.DEFAULT_ZONE

    # If the user wants to use spot instances in a cloud, make sure that it's
    # EC2 (since Euca doesn't have spot instances).
    if self.args.infrastructure != 'ec2' and (self.args.use_spot_instances or \
      self.args.max_spot_price):
      raise BadConfigurationException("Can't run spot instances unless " + \
        "Amazon EC2 is the infrastructure used.")

    # If the user does want to set a max spot price, make sure they told us that
    # they want to use spot instances in the first place.
    if self.args.max_spot_price and not self.args.use_spot_instances:
      raise BadConfigurationException("Can't have a max spot instance price" + \
        " if --use_spot_instances is not set.")

    # If the user does want to use persistent disks, make sure they specified
    # them in the right format, a dictionary mapping node IDs to disk names.
    if self.args.disks:
      self.args.disks = yaml.safe_load(base64.b64decode(self.args.disks))

      if not isinstance(self.args.disks, dict):
        raise BadConfigurationException("--disks must be a dict, but was a " \
          "{0}".format(type(self.args.disks)))

    if not self.args.instance_type:
      raise BadConfigurationException("Cannot start a cloud instance without " \
                                      "the instance type.")

    if self.args.instance_type in self.DISALLOWED_INSTANCE_TYPES and \
        not (self.args.force or self.args.test):
      LocalState.confirm_or_abort("The {0} instance type does not have " \
        "enough RAM to run Cassandra in a production setting. Please " \
        "consider using a larger instance type.".format(
        self.args.instance_type))

    if self.args.infrastructure == 'azure':
      if not self.args.azure_subscription_id:
        raise BadConfigurationException("Cannot start an Azure instance without " \
                                        "the Subscription ID.")
      if not self.args.azure_app_id:
        raise BadConfigurationException("Cannot authenticate an Azure instance " \
                                        "without the App ID.")
      if not self.args.azure_app_secret_key:
        raise BadConfigurationException("Cannot authenticate an Azure instance " \
                                        "without the App Secret Key.")
      if not self.args.azure_tenant_id:
        raise BadConfigurationException("Cannot authenticate an Azure instance " \
                                        "without the Tenant ID.")

  def validate_credentials(self):
    """If running over a cloud infrastructure, makes sure that all of the
    necessary credentials have been specified.
    """
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

    if not cloud_agent.does_zone_exist(params):
      raise BadConfigurationException("Couldn't find the given zone.")

    # Make sure that if the user gives us an Elastic IP / static IP, that they
    # actually own it.
    if self.args.static_ip:
      if not cloud_agent.does_address_exist(params):
        raise BadConfigurationException("Couldn't find the given static IP.")

    if not self.args.disks:
      return

    for disk in set(self.args.disks.values()):
      if not cloud_agent.does_disk_exist(params, disk):
        raise BadConfigurationException("Couldn't find disk {0}".format(disk))


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


  def validate_developer_flags(self):
    """Validates the flags that correspond to flags typically used only by
    AppScale developers, such as automatically setting administrator e-mails
    and passwords.

    Raises:
      BadConfigurationException: If admin_user, admin_pass, and test are all
        set, or if admin_user (or admin_pass) is set but the other isn't. This
        exception can also be thrown if user_commands is not a list.
    """
    if self.args.user_commands:
      self.args.user_commands = yaml.safe_load(base64.b64decode(
        self.args.user_commands))
      if not isinstance(self.args.user_commands, list):
        raise BadConfigurationException("user_commands must be a list. " +
          "Please make it a list and try again.")
    else:
      self.args.user_commands = []

    if self.args.admin_user and not self.args.admin_pass:
      raise BadConfigurationException("If admin_user is set, admin_pass " + \
        "must also be set.")
    if self.args.admin_pass and not self.args.admin_user:
      raise BadConfigurationException("If admin_pass is set, admin_user " + \
        "must also be set.")
    if self.args.admin_user and self.args.admin_pass and self.args.test:
      raise BadConfigurationException("Cannot set admin_user, " + \
        "admin_pass, and test.")


  def shell_check(self, argument):
    """ Checks for special characters in arguments that are part of shell
    commands.

    Args:
      argument: A str, the argument to be checked.
    Raises:
      BadConfigurationException if single quotes are present in argument.
    """
    if '\'' in argument:
      raise BadConfigurationException("Single quotes (') are not allowed " + \
        "in filenames.")
