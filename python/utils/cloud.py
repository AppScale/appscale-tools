from datetime import datetime, timedelta
import os
from urlparse import urlparse
import boto
import time
from boto.exception import EC2ResponseError
from utils import commons
from utils.commons import AppScaleToolsException

__author__ = 'hiranya'

class CloudAgent:
  """
  A CloudAgent instance is responsible for interfacing AppScale Tools with
  a particular cloud (IaaS) environment. AppScale Tools delegate all IaaS
  interactions to a CloudAgent instance. The primary objective of a
  CloudAgent is to be able to spawn virtual machines (VMs) in the target
  IaaS environment, on behalf of AppScale Tools.
  """

  def spawn_vms(self, count, key_name, group_name, machine, instance_type):
    """
    Start the specified number of VMs in the target IaaS using the other
    parameters provided.

    Args:
      count         Number of VMs to be launched
      key_name      Security keyname to which all spawned VMs will be bound
      group_name    Security group with which the spawned VMs will be associated
      machine       Machine image ID to launch
      instance_type Type of the VMs to be launched

    Returns:
      A tuple of the form (public-ips, private-ips, instance-IDs) where each
      element is a list of strings.

    Raises:
      AppScaleToolsException  If any given arguments are invalid or a runtime
                              error is encountered.
    """
    raise NotImplementedError

  def configure_security(self, key_name, group_name, path):
    """
    Configure security for the VMs spawned in the cloud. This method should
    check and validate the existence of specified security artifacts and
    attempt to generate them when appropriate.

    Args:
      key_name      Security keyname to which all spawned VMs will be bound
      group_name    Security group with which the spawned VMs will be associated
      path          Directory where the generated artifacts should be stored

    Raises:
      AppScaleToolsException  If any given arguments are invalid or a runtime
                              error is encountered.
    """
    raise NotImplementedError

  def validate(self, machine, instance_type, key_name):
    """
    Validate the specified machine image ID, instance type and the security key
    name. Actual validation semantics may depend on the type of IaaS the agent
    is interfacing with.

    Args:
      machine       Machine image ID to be validated
      instance_type Instance type to be validated
      key_name      Security key name to be tested and validated

    Raises:
      AppScaleToolsException  If any of the validations fails
    """
    raise NotImplementedError

  def get_environment_variables(self):
    """
    Extract and return a map of environment variables required for the
    operation within the underlying IaaS environment.

    Returns:
      A dictionary of environment variables
    """
    raise NotImplementedError

  def get_security_keys(self):
    """
    Returns a tuple of file paths where each file path to point to a security
    key related to the underlying IaaS.

    Returns:
      A tuple of the form (private-key, certificate) where each entry is a file
      path.
    """
    raise NotImplementedError

class EC2Agent(CloudAgent):
  """
  A CloudAgent implementation for the EC2 environment.
  """

  INSTANCE_TYPES = ( 'm1.large', 'c1.xlarge' )

  def __init__(self):
    """
    Create a new instance of the EC2Agent class.
    """
    self.image_id_prefix = 'ami-'
    self.required_variables = (
      'EC2_PRIVATE_KEY', 'EC2_CERT', 'EC2_SECRET_KEY', 'EC2_ACCESS_KEY'
    )

  def configure_security(self, key_name, group_name, path):
    """
    Configure EC2 security for the spawned EC2 nodes. Generates an EC2 key pair
    with the specified keyname and stores it under the specified file path.
    Checks for the existence of the specified security group and if creates
    it if not present. Newly created groups are further configured to enable
    access on all TCP, UDP and ICMP ports.

    Args:
      key_name      Security keyname to which all spawned VMs will be bound
      group_name    Security group with which the spawned VMs will be associated
      path          Directory where the generated artifacts should be stored

    Raises:
      AppScaleToolsException  If an error occurs while interacting with EC2
                              back-end services.
    """

    logger = commons.get_logger()
    try:
      conn = self.open_connection()

      reservations = conn.get_all_instances()
      instances = [i for r in reservations for i in r.instances]
      for i in instances:
        if i.state == 'running' and i.key_name == key_name:
          commons.error('Specified key name is already in use.')

      named_key_loc = os.path.join(path, key_name + '.key')
      named_backup_key_loc = os.path.join(path, key_name + '.private')
      logger.info('Creating key-pair: %s' % key_name)
      key = conn.create_key_pair(key_name)
      for loc in (named_key_loc, named_backup_key_loc):
        key_file = open(loc, 'w')
        key_file.write(key.material)
        key_file.close()
      os.chmod(named_key_loc, 0600)
      os.chmod(named_backup_key_loc, 0600)

      groups = conn.get_all_security_groups()
      group_exists = False
      for group in groups:
        if group.name == group_name:
          group_exists = True
          break
      if not group_exists:
        logger.info('Creating security group: %s' % group_name)
        security_group = conn.create_security_group(group_name,
          'AppScale security group')
        tcp_enabled = security_group.authorize(ip_protocol='tcp', from_port=1,
          to_port=65535, cidr_ip='0.0.0.0/0')
        udp_enabled = security_group.authorize(ip_protocol='udp', from_port=1,
          to_port=65535, cidr_ip='0.0.0.0/0')
        icmp_enabled = security_group.authorize(ip_protocol='icmp',
          cidr_ip='0.0.0.0/0')
        if not tcp_enabled or not udp_enabled or not icmp_enabled:
          commons.error('Failed to add one or more firewall rules to '
                        'security group: %s' % group_name)
      elif logger.is_verbose:
        logger.verbose('Security group %s already exists' % group_name)
    except Exception as e:
      self.__handle_exception('Error while configuring cloud security', e)

  def spawn_vms(self, count, key_name, group_name, machine, instance_type):
    """
    Spawns the specified number of EC2 instances. This method blocks until
    the specified number of VMs are actually up and running in EC2.

    Args:
      count         Number of VMs to be launched
      key_name      Security keyname to which all spawned VMs will be bound
      group_name    Security group with which the spawned VMs will be associated
      machine       Machine image ID to launch
      instance_type Type of the VMs to be launched

    Returns:
      A tuple of the form (public-ips, private-ips, instance-IDs) where each
      element is a list of strings.

    Raises:
      AppScaleToolsException  If an error occurs while interacting with EC2
                              back-end services.
    """

    logger = commons.get_logger()
    try:
      conn = self.open_connection()

      all_instances = self.__describe_instances()
      instance_info = self.__filter_instances(all_instances,
        key_name, 'running')
      terminated_info = self.__filter_instances(all_instances,
        key_name, 'terminated')
      if not len(terminated_info[0]) is 0:
        commons.error('One or more terminated instances were detected with'
                      ' the key %s' % key_name)
      conn.run_instances(machine, count, count, key_name=key_name,
        security_groups=[group_name], instance_type=instance_type)

      end_time = datetime.now() + timedelta(0, 1800)
      now = datetime.now()

      while now < end_time:
        time_left = (end_time - now).seconds
        notice = '[{0}] Starting the head node ({1} seconds left ' \
                 'until timeout) ...'.format(now, time_left)
        logger.info(notice)
        all_instances = self.__describe_instances()
        latest_instance_info = self.__filter_instances(all_instances,
          key_name, 'running')
        terminated_info = self.__filter_instances(all_instances,
          key_name, 'terminated')
        if not len(terminated_info[0]) is 0:
          commons.error('One or more terminated instances were detected with'
                        ' the key %s' % key_name)
        public_ips = commons.diff(latest_instance_info[0], instance_info[0])
        if count == len(public_ips):
          private_ips = []
          instance_ids = []
          for public_ip in public_ips:
            index = latest_instance_info[0].index(public_ip)
            private_ips.append(latest_instance_info[1][index])
            instance_ids.append(latest_instance_info[2][index])
          return public_ips, private_ips, instance_ids
        time.sleep(20)
        now = datetime.now()
    except Exception as e:
      self.__handle_exception('Error while starting VMs in the cloud', e)

    commons.error('Failed to spawn the required VMs')

  def __handle_exception(self, msg, exception):
    """
    Log, wrap and rethrow the error.

    Args:
      msg       A prefix to be added to the generated error message
      exception An Exception object to be wrapped and raised

    Raises:
      AppScaleToolsException  The wrapped up exception
    """
    if isinstance(exception, EC2ResponseError):
      commons.error(msg + ': ' + exception.error_message, exception=exception)
    elif isinstance(exception, AppScaleToolsException):
      raise exception
    else:
      commons.error(msg + ': ' + str(exception.message), exception=exception)

  def __describe_instances(self):
    """
    Query the back-end EC2 services and obtain a description of all available
    instances. This is similar to running ec2-describe-instances in the command
    line. Returned results may also contain some recently terminated instances.

    Returns:
      A list of instances as returned by EC2 (see Boto EC2 package for the
      exact type details)
    """
    conn = self.open_connection()
    reservations = conn.get_all_instances()
    instances = [i for r in reservations for i in r.instances]
    return instances

  def __filter_instances(self, instances, keyname, state):
    """
    Filter a list of instance records by keyname and their state. This is
    used to filter out the lists returned by __describe_instances method.

    Args:
      keyname Key name of the nodes that should be included in the result
      state   State of the nodes that should be included in the result

    Returns:
      A tuple of the form (public-ips, private-ips, instance-IDs) where each
      element is a list of strings.
    """
    instance_ids = []
    public_ips = []
    private_ips = []
    for i in instances:
      if i.state == state and i.key_name == keyname:
        instance_ids.append(str(i.id))
        public_ips.append(str(i.public_dns_name))
        private_ips.append(str(i.private_ip_address))
    return public_ips, private_ips, instance_ids

  def validate(self, machine, instance_type, keyname):
    """
    Checks if the specified machine ID and keyname exists. The machine ID must
    exist and the keyname must NOT exist for the validation to be successful.
    Also checks for the existence of required environment variables and other
    credentials. Verifies that the specified machine instance type is supported
    by this implementation.

    Args:
      machine       Machine image ID to be validated
      instance_type Instance type to be validated
      key_name      Security key name to be tested and validated

    Raises:
      AppScaleToolsException  If any of the validations fails
    """
    if machine is None:
      commons.error('Machine image ID not specified')
    elif not machine.startswith(self.image_id_prefix):
      commons.error('Invalid machine image ID: ' + machine)

    if instance_type is None:
      commons.error('Instance type not specified')
    elif not instance_type in self.INSTANCE_TYPES:
      commons.error('Instance type %s is not supported' % instance_type)

    for var in self.required_variables:
      if os.environ.get(var) is None:
        commons.error('Required environment variable: %s not set' % var)

    conn = self.open_connection()
    image = conn.get_image(machine)
    if image is None:
      commons.error('Machine image %s does not exist' % machine)

    key_pair = conn.get_key_pair(keyname)
    if key_pair:
      commons.error('Security key %s already exists' % keyname)

  def get_environment_variables(self):
    """
    Extract and return a map of environment variables required for the
    operation within the an EC2 environment.

    Returns:
      A dictionary of environment variables
    """
    values = {}
    for var in self.required_variables:
      values['CLOUD_' + var] = os.environ.get(var)
      if var.endswith('_KEY'):
        values[var.lower()] = os.environ.get(var)

    values['ec2_url'] = os.environ.get('EC2_URL',
      'https://us-east-1.ec2.amazonaws.com')
    return values

  def get_security_keys(self):
    """
    Returns a tuple of file paths where each file path to point to a security
    key related to EC2.

    Returns:
      A tuple of the form (private-key, certificate) where each entry is a file
      path.
    """
    private_key = os.environ['EC2_PRIVATE_KEY']
    cert = os.environ['EC2_CERT']
    return private_key, cert

  def open_connection(self):
    """
    Establish a connection to the EC2 back-end service.

    Returns:
      An instance of Boto EC2Connection class
    """
    access_key = os.environ['EC2_ACCESS_KEY']
    secret_key = os.environ['EC2_SECRET_KEY']
    return boto.connect_ec2(access_key, secret_key)

class EucaAgent(EC2Agent):
  """
  A CloudAgent implementation for the Eucalyptus environment.
  """

  # The version of Eucalyptus API used to interact with Euca clouds
  EUCA_API_VERSION = '2010-08-31'

  def __init__(self):
    """
    Create a new instance of the EucaAgent class.
    """
    EC2Agent.__init__(self)
    self.image_id_prefix = 'emi-'
    self.required_variables = (
      'EC2_PRIVATE_KEY', 'EC2_CERT', 'EC2_SECRET_KEY', 'EC2_ACCESS_KEY',
      'S3_URL', 'EC2_URL'
    )

  def open_connection(self):
    access_key = os.environ['EC2_ACCESS_KEY']
    secret_key = os.environ['EC2_SECRET_KEY']
    ec2_url = os.environ['EC2_URL']
    result = urlparse(ec2_url)
    if result.port is not None:
      port = result.port
    elif result.scheme == 'http':
      port = 80
    elif result.scheme == 'https':
      port = 443
    else:
      commons.error('Unknown scheme in EC2_URL: ' + result.scheme)
      return None

    return boto.connect_euca(host=result.hostname,
      aws_access_key_id=access_key,
      aws_secret_access_key=secret_key,
      port=port,
      path=result.path,
      is_secure=(result.scheme == 'https'),
      api_version=self.EUCA_API_VERSION)


CLOUD_AGENTS = {
  'ec2' : EC2Agent(),
  'euca' : EucaAgent()
}

def validate(infrastructure, machine, instance_type, keyname):
  """
  Validate the given machine ID and keyname for the specified environment.

  Args:
    infrastructure  An infrastructure name (eg: ec2)
    machine         Image ID to be validated
    instance_type   Instance type to be validated
    keyname         Key name to be validated

  Raises:
    AppScaleToolsException  if the validation fails
  """
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  cloud_agent.validate(machine, instance_type, keyname)

def get_cloud_env_variables(infrastructure):
  """
  Obtains a map of environment variables related to the specified environment.

  Args:
    infrastructure  An infrastructure name (eg: ec2)

  Returns:
    A dictionary of environment variables
  """
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  return cloud_agent.get_environment_variables()

def get_security_keys(infrastructure):
  """
  Obtains a tuple of security keys related to the specified environment.

  Args:
    infrastructure  An infrastructure name (eg: ec2)

  Returns:
    A tuple containing the private key and certificate to access the given
    environment.
  """
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  return cloud_agent.get_security_keys()

def spawn_head_node(infrastructure, key_name, group_name,
                    machine, instance_type):
  """
  Spawn the AppScale head node in the specified infrastructure.

  Args:
    infrastructure  An infrastructure name (eg: ec2)
    key_name        Security key to associate the head node with
    group_name      Security group name to associate the head node with
    machine         Machine image to boot
    instance_type   Type of the VM to be launched

  Returns:
    A tuple of the form (public-ip, private-ip, instance-ID) where each
    member is a string.

  Raises:
    AppScaleToolsException  If an error occurs while trying to start the VM.
  """
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  instance_info = cloud_agent.spawn_vms(1, key_name, group_name,
    machine, instance_type)
  return instance_info[0][0], instance_info[1][0], instance_info[2][0]

def configure_security(infrastructure, key_name, group_name, path):
  """
  Configure cloud security for the specified environment.

  Args:
    infrastructure  An infrastructure name (eg: ec2)
    key_name        Security key name to be generated
    group_name      Security group name to be created
    path            Directory where the generated artifacts will be stored

  Raises:
    AppScaleToolsException  If an error occurs while configuring security
  """
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  cloud_agent.configure_security(key_name, group_name, path)

def is_valid_cloud_type(type):
  """
  Checks if the specified infrastructure type is supported.

  Args:
    type  An infrastructure name (eg: EC2)

  Returns:
    True if the infrastructure is supported and False otherwise
  """
  return type is not None and CLOUD_AGENTS.has_key(type)