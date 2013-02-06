from agents.base_agent import BaseAgent, AgentConfigurationException, AgentRuntimeException
import boto
from boto.exception import EC2ResponseError
import datetime
import os
import time
from appscale_logger import AppScaleLogger
from local_state import LocalState

__author__ = 'hiranya'
__email__ = 'hiranya@appscale.com'

class EC2Agent(BaseAgent):
  """
  EC2 infrastructure agent class which can be used to spawn and terminate
  VMs in an EC2 based environment.
  """

  # The maximum amount of time, in seconds, that we are willing to wait for
  # a virtual machine to start up, from the initial run-instances request.
  # Setting this value is a bit of an art, but we choose the value below
  # because our image is roughly 10GB in size, and if Eucalyptus doesn't
  # have the image cached, it could take half an hour to get our image
  # started.
  MAX_VM_CREATION_TIME = 1800

  # The amount of time that run_instances waits between each describe-instances
  # request. Setting this value too low can cause Eucalyptus to interpret
  # requests as replay attacks.
  SLEEP_TIME = 20

  PARAM_CREDENTIALS = 'credentials'
  PARAM_GROUP = 'group'
  PARAM_IMAGE_ID = 'image_id'
  PARAM_INSTANCE_TYPE = 'instance_type'
  PARAM_KEYNAME = 'keyname'
  PARAM_INSTANCE_IDS = 'instance_ids'

  REQUIRED_EC2_RUN_INSTANCES_PARAMS = (
    PARAM_CREDENTIALS,
    PARAM_GROUP,
    PARAM_IMAGE_ID,
    PARAM_INSTANCE_TYPE,
    PARAM_KEYNAME
  )

  REQUIRED_EC2_TERMINATE_INSTANCES_PARAMS = (
    PARAM_CREDENTIALS,
    PARAM_INSTANCE_IDS
  )

  # A list of the environment variables that must be provided
  # to control machines in Amazon EC2.
  # TODO(cgb): Strictly speaking, the tools don't need
  # EC2_CERT and EC2_PRIVATE_KEY, but the AppController does.
  # Once we refactor the AppController to use a library that
  # doesn't need them, remove them from this list.
  REQUIRED_EC2_CREDENTIALS = (
    'EC2_SECRET_KEY',
    'EC2_ACCESS_KEY',
    'EC2_CERT',
    'EC2_PRIVATE_KEY'
  )

  # A tuple of the credentials that we build our internal
  # credential list from.
  REQUIRED_CREDENTIALS = REQUIRED_EC2_CREDENTIALS


  DESCRIBE_INSTANCES_RETRY_COUNT = 3

  def configure_instance_security(self, parameters):
    """
    Setup EC2 security keys and groups. Required input values are read from
    the parameters dictionary. More specifically, this method expects to
    find a 'keyname' parameter and a 'group' parameter in the parameters
    dictionary. Using these provided values, this method will create a new
    EC2 key-pair and a security group. Security group will be granted permissions
    to access any port on the instantiated VMs. (Also see documentation for the
    BaseAgent class)

    Args:
      parameters  A dictionary of parameters
    """
    keyname = parameters[self.PARAM_KEYNAME]
    group = parameters[self.PARAM_GROUP]

    ssh_key = '{0}{1}.key'.format(LocalState.LOCAL_APPSCALE_PATH, keyname)
    AppScaleLogger.log('About to spawn EC2 instances - ' \
              'Expecting to find a key at {0}'.format(ssh_key))
    if os.path.exists(ssh_key):
      self.handle_failure('SSH key found locally - please use a different keyname')

    conn = self.open_connection(parameters)
    key_pair = conn.get_key_pair(keyname)
    if key_pair is None:
      AppScaleLogger.log('Creating key pair: ' + keyname)
      key_pair = conn.create_key_pair(keyname)
    LocalState.write_key_file(ssh_key, key_pair.material)

    security_groups = conn.get_all_security_groups()
    group_exists = False
    for security_group in security_groups:
      if security_group.name == group:
        group_exists = True
        break

    if not group_exists:
      AppScaleLogger.log('Creating security group: ' + group)
      conn.create_security_group(group, 'AppScale security group')
      conn.authorize_security_group(group, from_port=1,
        to_port=65535, ip_protocol='udp', cidr_ip='0.0.0.0/0')
      conn.authorize_security_group(group, from_port=1,
        to_port=65535, ip_protocol='tcp', cidr_ip='0.0.0.0/0')
      conn.authorize_security_group(group, ip_protocol='icmp',
        cidr_ip='0.0.0.0/0')

    return True


  def get_params_from_args(self, args):
    """
    Searches through args to build a dict containing the parameters
    necessary to interact with Amazon EC2.

    Args:
      args: A Namespace containing the arguments that the user has
        invoked an AppScale Tool with.
    """
    params = {
      self.PARAM_CREDENTIALS : {},
      self.PARAM_GROUP : args.group,
      self.PARAM_IMAGE_ID : args.machine,
      self.PARAM_INSTANCE_TYPE : args.instance_type,
      self.PARAM_KEYNAME : args.keyname,
    }

    for credential in self.REQUIRED_CREDENTIALS:
      if os.environ[credential] and os.environ[credential] != '':
        params[self.PARAM_CREDENTIALS][credential] = os.environ[credential]
      else:
        raise AgentConfigurationException("no " + credential)

    return params


  def get_params_from_yaml(self, keyname):
    """Searches through the locations.yaml file to build a dict containing the
    parameters necessary to interact with Amazon EC2.

    Args:
      keyname: The name of the SSH keypair that uniquely identifies this
        AppScale deployment.
    """
    params = {
      self.PARAM_CREDENTIALS : {},
      self.PARAM_GROUP : LocalState.get_group(keyname),
      self.PARAM_KEYNAME : keyname
    }

    for credential in self.REQUIRED_CREDENTIALS:
      if os.environ[credential] and os.environ[credential] != '':
        params[self.PARAM_CREDENTIALS][credential] = os.environ[credential]
      else:
        raise AgentConfigurationException("no " + credential)

    return params

  def assert_required_parameters(self, parameters, operation):
    """
    Assert that all the parameters required for the EC2 agent are in place.
    (Also see documentation for the BaseAgent class)

    Args:
      parameters  A dictionary of parameters
      operation   Operations to be invoked using the above parameters
    """
    required_params = ()
    if operation == BaseAgent.OPERATION_RUN:
      required_params = self.REQUIRED_EC2_RUN_INSTANCES_PARAMS
    elif operation == BaseAgent.OPERATION_TERMINATE:
      required_params = self.REQUIRED_EC2_TERMINATE_INSTANCES_PARAMS

    # make sure the user set something for each parameter
    for param in required_params:
      if not self.has_parameter(param, parameters):
        raise AgentConfigurationException('no ' + param)

    # next, make sure the user actually put in their credentials
    for credential in self.REQUIRED_EC2_CREDENTIALS:
      if not self.has_parameter(credential, parameters['credentials']):
        raise AgentConfigurationException('no ' + credential)

  def describe_instances(self, parameters):
    """
    Retrieves the list of running instances that have been instantiated using a
    particular EC2 keyname. The target keyname is read from the input parameter
    map. (Also see documentation for the BaseAgent class)

    Args:
      parameters  A dictionary containing the 'keyname' parameter

    Returns:
      A tuple of the form (public_ips, private_ips, instances) where each
      member is a list.
    """
    instance_ids = []
    public_ips = []
    private_ips = []

    conn = self.open_connection(parameters)
    reservations = conn.get_all_instances()
    instances = [i for r in reservations for i in r.instances]
    for i in instances:
      if i.state == 'running' and i.key_name == parameters[self.PARAM_KEYNAME]:
        instance_ids.append(i.id)
        public_ips.append(i.public_dns_name)
        private_ips.append(i.private_dns_name)
    return public_ips, private_ips, instance_ids

  def run_instances(self, count, parameters, security_configured):
    """
    Spawns the specified number of EC2 instances using the parameters
    provided. This method is blocking in that it waits until the
    requested VMs are properly booted up. However if the requested
    VMs cannot be procured within 1800 seconds, this method will treat
    it as an error and return. (Also see documentation for the BaseAgent
    class)

    Args:
      count               No. of VMs to spawned
      parameters          A dictionary of parameters. This must contain 'keyname',
                          'group', 'image_id' and 'instance_type' parameters.
      security_configured Uses this boolean value as an heuristic to
                          detect brand new AppScale deployments.

    Returns:
      A tuple of the form (instances, public_ips, private_ips)
    """
    image_id = parameters[self.PARAM_IMAGE_ID]
    instance_type = parameters[self.PARAM_INSTANCE_TYPE]
    keyname = parameters[self.PARAM_KEYNAME]
    group = parameters[self.PARAM_GROUP]
    spot = False

    AppScaleLogger.log('[{0}] [{1}] [{2}] [{3}] [ec2] [{4}] [{5}]'.format(count,
      image_id, instance_type, keyname, group, spot))

    start_time = datetime.datetime.now()
    active_public_ips = []
    active_private_ips = []
    active_instances = []

    try:
      attempts = 1
      while True:
        instance_info = self.describe_instances(parameters)
        active_public_ips = instance_info[0]
        active_private_ips = instance_info[1]
        active_instances = instance_info[2]

        # If security has been configured on this agent just now,
        # that's an indication that this is a fresh cloud deployment.
        # As such it's not expected to have any running VMs.
        if len(active_instances) > 0 or security_configured:
          break
        elif attempts == self.DESCRIBE_INSTANCES_RETRY_COUNT:
          self.handle_failure('Failed to invoke describe_instances')
        attempts += 1

      conn = self.open_connection(parameters)
      if spot:
        price = self.get_optimal_spot_price(conn, instance_type)
        conn.request_spot_instances(str(price), image_id, key_name=keyname,
          security_groups=[group], instance_type=instance_type, count=count)
      else:
        conn.run_instances(image_id, count, count, key_name=keyname,
          security_groups=[group], instance_type=instance_type)

      instance_ids = []
      public_ips = []
      private_ips = []
      end_time = datetime.datetime.now() + datetime.timedelta(0,
        self.MAX_VM_CREATION_TIME)
      now = datetime.datetime.now()

      while now < end_time:
        time_left = (end_time - now).seconds
        AppScaleLogger.log('[{0}] {1} seconds left...'.format(now, time_left))
        instance_info = self.describe_instances(parameters)
        public_ips = instance_info[0]
        private_ips = instance_info[1]
        instance_ids = instance_info[2]
        public_ips = self.diff(public_ips, active_public_ips)
        private_ips = self.diff(private_ips, active_private_ips)
        instance_ids = self.diff(instance_ids, active_instances)
        if count == len(public_ips):
          break
        time.sleep(self.SLEEP_TIME)
        now = datetime.datetime.now()

      if not public_ips:
        self.handle_failure('No public IPs were able to be procured '
                            'within the time limit')

      if len(public_ips) != count:
        for index in range(0, len(public_ips)):
          if public_ips[index] == '0.0.0.0':
            instance_to_term = instance_ids[index]
            AppScaleLogger.log('Instance {0} failed to get a public IP address and' \
                      ' is being terminated'.format(instance_to_term))
            conn.terminate_instances([instance_to_term])

      end_time = datetime.datetime.now()
      total_time = end_time - start_time
      if spot:
        AppScaleLogger.log('TIMING: It took {0} seconds to spawn {1} spot ' \
                  'instances'.format(total_time.seconds, count))
      else:
        AppScaleLogger.log('TIMING: It took {0} seconds to spawn {1} ' \
                  'regular instances'.format(total_time.seconds, count))
      return instance_ids, public_ips, private_ips
    except EC2ResponseError as exception:
      self.handle_failure('EC2 response error while starting VMs: ' +
                          exception.error_message)

  def terminate_instances(self, parameters):
    """
    Stop one of more EC2 instances using. The input instance IDs are
    fetched from the 'instance_ids' parameters in the input map. (Also
    see documentation for the BaseAgent class)

    Args:
      parameters  A dictionary of parameters
    """
    instance_ids = parameters[self.PARAM_INSTANCE_IDS]
    conn = self.open_connection(parameters)
    terminated_instances = conn.terminate_instances(instance_ids)
    for instance in terminated_instances:
      AppScaleLogger.log('Instance {0} was terminated'.format(instance.id))

  def does_image_exist(self, parameters):
    """
    Queries Amazon EC2 to see if the specified image exists.

    Args:
      parameters A dict that contains the machine ID to check for existence.
    Returns:
      True if the machine ID exists, False otherwise.
    """
    try:
      conn = self.open_connection(parameters)
      image_id = parameters[self.PARAM_IMAGE_ID]
      conn.get_image(image_id)
      AppScaleLogger.log('Machine image {0} does exist'.format(image_id))
      return True
    except boto.exception.EC2ResponseError:
      AppScaleLogger.log('Machine image {0} does not exist'.format(image_id))
      return False

  def cleanup_state(self, parameters):
    """
    Removes the keyname and security group created during this AppScale
    deployment.

    Args:
      parameters: A dict that contains the keyname and security group to delete.
    """
    AppScaleLogger.log("Deleting keyname {0}".format(
      parameters[self.PARAM_KEYNAME]))
    conn = self.open_connection(parameters)
    conn.delete_key_pair(parameters[self.PARAM_KEYNAME])

    AppScaleLogger.log("Deleting security group {0}".format(
      parameters[self.PARAM_GROUP]))
    while True:
      try:
        conn.delete_security_group(parameters[self.PARAM_GROUP])
        break
      except EC2ResponseError:
        time.sleep(5)


  def get_optimal_spot_price(self, conn, instance_type):
    """
    Returns the spot price for an EC2 instance of the specified instance type.
    The returned value is computed by averaging all the spot price history values
    returned by the back-end EC2 APIs and incrementing the average by extra 20%.

    Args:
      instance_type An EC2 instance type

    Returns:
      The estimated spot price for the specified instance type
    """
    history = conn.get_spot_price_history(product_description='Linux/UNIX',
      instance_type=instance_type)
    sum = 0.0
    for entry in history:
      sum += entry.price
    average = sum / len(history)
    plus_twenty = average * 1.20
    AppScaleLogger.log('The average spot instance price for a {0} machine is {1}, '\
              'and 20% more is {2}'.format(instance_type, average, plus_twenty))
    return plus_twenty

  def open_connection(self, parameters):
    """
    Initialize a connection to the back-end EC2 APIs.

    Args:
      parameters  A dictionary containing the 'credentials' parameter.

    Returns:
      An instance of Boto EC2Connection
    """
    credentials = parameters[self.PARAM_CREDENTIALS]
    return boto.connect_ec2(str(credentials['EC2_ACCESS_KEY']),
      str(credentials['EC2_SECRET_KEY']))

  def handle_failure(self, msg):
    """
    Log the specified error message and raise an AgentRuntimeException

    Args:
      msg An error message to be logged and included in the raised exception

    Raises:
      AgentRuntimeException Contains the input error message
    """
    AppScaleLogger.log(msg)
    raise AgentRuntimeException(msg)

