"""
Helper library for EC2 interaction
"""
import boto
import boto.ec2
import boto.vpc
import datetime
import glob
import os
import time

from boto.ec2.networkinterface import NetworkInterfaceCollection
from boto.ec2.networkinterface import NetworkInterfaceSpecification
from boto.exception import EC2ResponseError

from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.local_state import LocalState
from base_agent import AgentConfigurationException
from base_agent import AgentRuntimeException
from base_agent import BaseAgent


# pylint: disable-msg=W0511
#    don't bother about todo's


class SecurityGroupNotFoundException(Exception):
  """ Exception to raise when a security group could not be found on EC2."""
  pass


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
  # started.  We set this to 60 minutes so we have some leeway.
  MAX_VM_CREATION_TIME = 3600

  # The amount of time that run_instances waits between each describe-instances
  # request. Setting this value too low can cause Eucalyptus to interpret
  # requests as replay attacks.
  SLEEP_TIME = 20

  PARAM_SPOT = 'use_spot_instances'
  PARAM_SPOT_PRICE = 'max_spot_price'
  PARAM_SUBNET_ID = 'aws_subnet_id'
  PARAM_VPC_ID = 'aws_vpc_id'

  REQUIRED_EC2_RUN_INSTANCES_PARAMS = (
    BaseAgent.PARAM_CREDENTIALS,
    BaseAgent.PARAM_GROUP,
    BaseAgent.PARAM_IMAGE_ID,
    BaseAgent.PARAM_KEYNAME,
    PARAM_SPOT
  )

  REQUIRED_EC2_TERMINATE_INSTANCES_PARAMS = (
    BaseAgent.PARAM_CREDENTIALS,
    BaseAgent.PARAM_INSTANCE_IDS
  )

  # A list of the environment variables that must be provided
  # to control machines in Amazon EC2.
  REQUIRED_EC2_CREDENTIALS = (
    'EC2_SECRET_KEY',
    'EC2_ACCESS_KEY'
  )

  # A tuple of the credentials that we build our internal
  # credential list from.
  REQUIRED_CREDENTIALS = REQUIRED_EC2_CREDENTIALS


  # An int that indicates how many times we should try to create a security
  # group and authorize it for TCP, UDP, or ICMP traffic.
  SECURITY_GROUP_RETRY_COUNT = 3


  DESCRIBE_INSTANCES_RETRY_COUNT = 3


  # The region that instances should be started in and terminated from, if the
  # user does not specify a zone.
  DEFAULT_REGION = "us-east-1"


  # A list of EC2 instance types that have less than 4 GB of RAM, the amount
  # recommended by Cassandra. AppScale will still run on these instance types,
  # but is likely to crash after a day or two of use (as Cassandra will attempt
  # to malloc ~800MB of memory, which will fail on these instance types).
  DISALLOWED_INSTANCE_TYPES = ["m1.small", "c1.medium", "t1.micro"]


  def assert_credentials_are_valid(self, parameters):
    """Contacts AWS to see if the given access key and secret key represent a
    valid set of credentials.

    Args:
      parameters: A dict containing the user's AWS access key and secret key.
    Raises:
      AgentConfigurationException: If the given AWS access key and secret key
      cannot be used to make requests to AWS.
    """
    conn = self.open_connection(parameters)
    try:
      conn.get_all_instances()
    except EC2ResponseError:
      raise AgentConfigurationException("We couldn't validate your EC2 " + \
        "access key and EC2 secret key. Are your credentials valid?")


  def configure_instance_security(self, parameters):
    """
    Setup EC2 security keys and groups. Required input values are read from
    the parameters dictionary. More specifically, this method expects to
    find a 'keyname' parameter and a 'group' parameter in the parameters
    dictionary. Using these provided values, this method will create a new
    EC2 key-pair and a security group. Security group will be granted permission
    to access any port on the instantiated VMs. (Also see documentation for the
    BaseAgent class)

    Args:
      parameters: A dictionary of parameters.
    """
    keyname = parameters[self.PARAM_KEYNAME]
    group = parameters[self.PARAM_GROUP]
    is_autoscale = parameters[self.PARAM_AUTOSCALE_AGENT]

    AppScaleLogger.log("Verifying that keyname {0}".format(keyname) + \
      " is not already registered.")
    conn = self.open_connection(parameters)

    # While creating instances during autoscaling, we do not need to create a
    # new keypair or a security group. We just make use of the existing one.
    if is_autoscale in ['True', True]:
      return

    if conn.get_key_pair(keyname):
      self.handle_failure("SSH keyname {0} is already registered. Please " \
        "change the 'keyname' specified in your AppScalefile to a different " \
        "value, or erase it to have one automatically generated for you." \
        .format(keyname))

    try:
      self.get_security_group_by_name(conn, group,
                                      parameters.get(self.PARAM_VPC_ID))
    except SecurityGroupNotFoundException:
      # If this is raised, the group does not exist.
      pass
    else:
      self.handle_failure("Security group {0} is already registered. Please "
                          "change the 'group' specified in your AppScalefile "
                          "to a different value, or erase it to have one "
                          "automatically generated for you.".format(group))


    AppScaleLogger.log("Creating key pair: {0}".format(keyname))
    key_pair = conn.create_key_pair(keyname)
    ssh_key = '{0}{1}.key'.format(LocalState.LOCAL_APPSCALE_PATH, keyname)
    LocalState.write_key_file(ssh_key, key_pair.material)

    sg = self.create_security_group(parameters, group)

    self.authorize_security_group(parameters, sg.id, from_port=1,
                                  to_port=65535, ip_protocol='udp',
                                  cidr_ip='0.0.0.0/0')
    self.authorize_security_group(parameters, sg.id, from_port=1,
                                  to_port=65535, ip_protocol='tcp',
                                  cidr_ip='0.0.0.0/0')
    self.authorize_security_group(parameters, sg.id, from_port=-1,
                                  to_port=-1, ip_protocol='icmp',
                                  cidr_ip='0.0.0.0/0')
    return True


  def create_security_group(self, parameters, group):
    """Creates a new security group in AWS with the given name.

    Args:
      parameters: A dict that contains the credentials necessary to authenticate
        with AWS.
      group: A str that names the group that should be created.
    Returns:
      The 'boto.ec2.securitygroup.SecurityGroup' that was just created.
    Raises:
      AgentRuntimeException: If the security group could not be created.
    """
    AppScaleLogger.log('Creating security group: {0}'.format(group))
    conn = self.open_connection(parameters)
    specified_vpc = parameters.get(self.PARAM_VPC_ID)

    retries_left = self.SECURITY_GROUP_RETRY_COUNT
    while retries_left:
      try:
        conn.create_security_group(group, 'AppScale security group',
                                   specified_vpc)
      except EC2ResponseError:
        pass
      try:
        return self.get_security_group_by_name(conn, group, specified_vpc)
      except SecurityGroupNotFoundException:
        pass
      time.sleep(self.SLEEP_TIME)
      retries_left -= 1

    raise AgentRuntimeException("Couldn't create security group with " \
      "name {0}".format(group))


  @classmethod
  def get_security_group_by_name(cls, conn, group, vpc_id):
    """Gets a security group in AWS with the given name.

    Args:
      conn: A boto connection.
      group: A str that names the group that should be found.
      vpc_id: A str containing the id of the VPC, used for checking if the
        security group located is in the proper VPC or None.
    Returns:
      The 'boto.ec2.securitygroup.SecurityGroup' that has the correct group
      name.
    Raises:
      SecurityGroupNotFoundException: If the security group could not be found.
    """
    for sg in conn.get_all_security_groups():
      if sg.name == group and sg.vpc_id == vpc_id:
        return sg

    if vpc_id:
      msg = 'Could not find security group with name {} in VPC {}!'.format(
          group, vpc_id)
    else:
      msg = 'Could not find security group with name {} in classic ' \
            'network!'.format(group)
    raise SecurityGroupNotFoundException(msg)


  def authorize_security_group(self, parameters, group_id, from_port,
                               to_port, ip_protocol, cidr_ip):
    """Opens up traffic on the given port range for traffic of the named type.

    Args:
      parameters: A dict that contains the credentials necessary to authenticate
        with AWS.
      group_id: A str that contains the id of the group whose ports should be
        opened.
      from_port: An int that names the first port that access should be allowed
        on.
      to_port: An int that names the last port that access should be allowed on.
      ip_protocol: A str that indicates if TCP, UDP, or ICMP traffic should be
        allowed.
      cidr_ip: A str that names the IP range that traffic should be allowed
        from.
    Raises:
      AgentRuntimeException: If the ports could not be opened on the security
      group.
    """
    AppScaleLogger.log('Authorizing security group {0} for {1} traffic from ' \
      'port {2} to port {3}'.format(group_id, ip_protocol, from_port, to_port))
    conn = self.open_connection(parameters)
    retries_left = self.SECURITY_GROUP_RETRY_COUNT
    while retries_left:
      try:
        conn.authorize_security_group(group_id=group_id, from_port=from_port,
                                      to_port=to_port, cidr_ip=cidr_ip,
                                      ip_protocol=ip_protocol)
      except EC2ResponseError:
        pass
      try:
        group_info = self.get_security_group_by_name(
            conn, parameters[self.PARAM_GROUP], parameters.get(self.PARAM_VPC_ID))
        for rule in group_info.rules:
          if int(rule.from_port) == from_port and int(rule.to_port) == to_port \
            and rule.ip_protocol == ip_protocol:
            return
      except SecurityGroupNotFoundException as e:
        raise AgentRuntimeException(e.message)
      time.sleep(self.SLEEP_TIME)
      retries_left -= 1

    raise AgentRuntimeException("Couldn't authorize {0} traffic from port " \
      "{1} to port {2} on CIDR IP {3}".format(ip_protocol, from_port, to_port,
      cidr_ip))


  def get_params_from_args(self, args):
    """
    Searches through args to build a dict containing the parameters
    necessary to interact with Amazon EC2.

    Args:
      args: A Namespace containing the arguments that the user has
        invoked an AppScale Tool with.
    """
    # need to convert this to a dict if it is not already
    if not isinstance(args, dict):
      args = vars(args)

    params = {
      self.PARAM_CREDENTIALS : {},
      self.PARAM_GROUP : args['group'],
      self.PARAM_IMAGE_ID : args['machine'],
      self.PARAM_INSTANCE_TYPE : args['instance_type'],
      self.PARAM_KEYNAME : args['keyname'],
      self.PARAM_STATIC_IP : args.get(self.PARAM_STATIC_IP),
      self.PARAM_ZONE : args.get('zone'),
      self.PARAM_VERBOSE : args.get('verbose', False),
      self.PARAM_AUTOSCALE_AGENT : False
    }

    if params[self.PARAM_ZONE]:
      params[self.PARAM_REGION] = params[self.PARAM_ZONE][:-1]
    else:
      params[self.PARAM_REGION] = self.DEFAULT_REGION

    for credential in self.REQUIRED_CREDENTIALS:
      if args.get(credential):
        params[self.PARAM_CREDENTIALS][credential] = args[credential]
      else:
        raise AgentConfigurationException("Couldn't find {0} in your " \
          "environment. Please set it and run AppScale again."
          .format(credential))
    self.assert_credentials_are_valid(params)

    if args.get('use_spot_instances') == True:
      params[self.PARAM_SPOT] = True
    else:
      params[self.PARAM_SPOT] = False

    if params[self.PARAM_SPOT]:
      if args.get('max_spot_price'):
        params[self.PARAM_SPOT_PRICE] = args['max_spot_price']
      else:
        params[self.PARAM_SPOT_PRICE] = self.get_optimal_spot_price(
          self.open_connection(params), params[self.PARAM_INSTANCE_TYPE],
          params[self.PARAM_ZONE])

    # If VPC id and Subnet id are not set assume classic networking should be
    # used.
    vpc_id = args.get(self.PARAM_VPC_ID)
    subnet_id = args.get(self.PARAM_SUBNET_ID)
    if not vpc_id and not subnet_id:
      AppScaleLogger.log('Using Classic Networking since subnet and vpc were '
                         'not specified.')
    # All further checks are for VPC Networking.
    elif (vpc_id or subnet_id) and not (vpc_id and subnet_id):
      raise AgentConfigurationException('Both VPC id and Subnet id must be '
                                        'specified to use VPC Networking.')
    else:
      # VPC must exist.
      vpc_conn = self.open_vpc_connection(params)

      params[self.PARAM_VPC_ID] = args[self.PARAM_VPC_ID]
      try:
        vpc_conn.get_all_vpcs(params[self.PARAM_VPC_ID])
      except EC2ResponseError as e:
        raise AgentConfigurationException('Error looking for vpc: {}'.format(
            e.message))

      # Subnet must exist.
      all_subnets = vpc_conn.get_all_subnets(filters={'vpcId': params[self.PARAM_VPC_ID]})
      params[self.PARAM_SUBNET_ID] = args[self.PARAM_SUBNET_ID]

      if not any(subnet.id == params[self.PARAM_SUBNET_ID] for subnet in all_subnets):
        raise AgentConfigurationException('Specified subnet {} does not exist '
                                          'in vpc {}!'.format(params[self.PARAM_SUBNET_ID],
                                                              params[self.PARAM_VPC_ID]))
    return params


  def get_cloud_params(self, keyname):
    """Searches through the locations.json file with key
    'infrastructure_info' to build a dict containing the
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

    zone = LocalState.get_zone(keyname)
    if zone:
      params[self.PARAM_REGION] = zone[:-1]
    else:
      params[self.PARAM_REGION] = self.DEFAULT_REGION


    for credential in self.REQUIRED_CREDENTIALS:
      cred = LocalState.get_infrastructure_option(tag=credential,
                                                  keyname=keyname)
      if not cred:
        raise AgentConfigurationException("no " + credential)

      params[self.PARAM_CREDENTIALS][credential] = cred

    return params

  def assert_required_parameters(self, parameters, operation):
    """
    Assert that all the parameters required for the EC2 agent are in place.
    (Also see documentation for the BaseAgent class)

    Args:
      parameters: A dictionary of parameters.
      operation: Operations to be invoked using the above parameters.
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

  def describe_instances(self, parameters, pending=False):
    """
    Retrieves the list of running instances that have been instantiated using a
    particular EC2 keyname. The target keyname is read from the input parameter
    map. (Also see documentation for the BaseAgent class).

    Args:
      parameters: A dictionary containing the 'keyname' parameter.
      pending: Indicates we also want the pending instances.
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
      if (i.state == 'running' or (pending and i.state == 'pending'))\
           and i.key_name == parameters[self.PARAM_KEYNAME]:
        instance_ids.append(i.id)
        public_ips.append(i.ip_address or i.private_ip_address)
        private_ips.append(i.private_ip_address)
    return public_ips, private_ips, instance_ids

  def run_instances(self, count, parameters, security_configured, public_ip_needed):
    """
    Spawns the specified number of EC2 instances using the parameters
    provided. This method is blocking in that it waits until the
    requested VMs are properly booted up. However if the requested
    VMs cannot be procured within 1800 seconds, this method will treat
    it as an error and return. (Also see documentation for the BaseAgent
    class)

    Args:
      count: Number of VMs to spawned.
      parameters: A dictionary of parameters. This must contain
        'keyname', 'group', 'image_id' and 'instance_type' parameters.
      security_configured: Uses this boolean value as an heuristic to
        detect brand new AppScale deployments.
      public_ip_needed: A boolean, specifies whether to launch with a public
        ip or not.
    Returns:
      A tuple of the form (instances, public_ips, private_ips)
    """
    image_id = parameters[self.PARAM_IMAGE_ID]
    instance_type = parameters[self.PARAM_INSTANCE_TYPE]
    keyname = parameters[self.PARAM_KEYNAME]
    group = parameters[self.PARAM_GROUP]
    zone = parameters[self.PARAM_ZONE]

    # In case of autoscaling, the server side passes these parameters as a
    # string, so this check makes sure that spot instances are only created
    # when the flag is True.
    spot = parameters[self.PARAM_SPOT] in ['True', 'true', True]

    AppScaleLogger.log("Starting {0} machines with machine id {1}, with " \
      "instance type {2}, keyname {3}, in security group {4}, in availability" \
      " zone {5}".format(count, image_id, instance_type, keyname, group, zone))

    if spot:
      AppScaleLogger.log("Using spot instances")
    else:
      AppScaleLogger.log("Using on-demand instances")

    start_time = datetime.datetime.now()
    active_public_ips = []
    active_private_ips = []
    active_instances = []

    # Make sure we do not have terminated instances using the same keyname.
    instances = self.__describe_instances(parameters)
    term_instance_info = self.__get_instance_info(instances,
       'terminated', keyname)
    if len(term_instance_info[2]):
      self.handle_failure('SSH keyname {0} is already registered to a '\
                          'terminated instance. Please change the "keyname" '\
                          'you specified in your AppScalefile to a different '\
                          'value. If the keyname was autogenerated, erase it '\
                          'to have a new one generated for you.'.format(keyname))

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

      # Get subnet from parameters.
      subnet = parameters.get(self.PARAM_SUBNET_ID)

      network_interfaces = None
      groups = None

      conn = self.open_connection(parameters)

      # A subnet indicates we're using VPC Networking.
      if subnet:
        # Get security group by name.
        try:
          sg = self.get_security_group_by_name(conn, group,
                                               parameters[self.PARAM_VPC_ID])
        except SecurityGroupNotFoundException as e:
          raise AgentRuntimeException(e.message)
        # Create network interface specification.
        network_interface = NetworkInterfaceSpecification(
          associate_public_ip_address=public_ip_needed,
          groups=[sg.id], subnet_id=subnet)
        network_interfaces = NetworkInterfaceCollection(network_interface)
      else:
        groups = [group]

      if spot:
        price = parameters[self.PARAM_SPOT_PRICE] or \
          self.get_optimal_spot_price(conn, instance_type, zone)

        conn.request_spot_instances(str(price), image_id, key_name=keyname,
                                    instance_type=instance_type, count=count,
                                    placement=zone, security_groups=groups,
                                    network_interfaces=network_interfaces)
      else:
        conn.run_instances(image_id, count, count, key_name=keyname,
                           instance_type=instance_type, placement=zone,
                           security_groups=groups,
                           network_interfaces=network_interfaces)

      instance_ids = []
      public_ips = []
      private_ips = []
      end_time = datetime.datetime.now() + datetime.timedelta(0,
        self.MAX_VM_CREATION_TIME)

      while datetime.datetime.now() < end_time:
        AppScaleLogger.log("Waiting for your instances to start...")
        public_ips, private_ips, instance_ids = self.describe_instances(
          parameters)

        # If we need a public ip, make sure we actually get one.
        if public_ip_needed and not self.diff(public_ips, private_ips):
          time.sleep(self.SLEEP_TIME)
          continue

        public_ips = self.diff(public_ips, active_public_ips)
        private_ips = self.diff(private_ips, active_private_ips)
        instance_ids = self.diff(instance_ids, active_instances)
        if count == len(public_ips):
          break
        time.sleep(self.SLEEP_TIME)

      if not public_ips:
        self.handle_failure('No public IPs were able to be procured '
                            'within the time limit')

      if len(public_ips) != count:
        for index in range(0, len(public_ips)):
          if public_ips[index] == '0.0.0.0':
            instance_to_term = instance_ids[index]
            AppScaleLogger.log('Instance {0} failed to get a public IP address'\
                    'and is being terminated'.format(instance_to_term))
            conn.terminate_instances([instance_to_term])

      end_time = datetime.datetime.now()
      total_time = end_time - start_time
      if spot:
        AppScaleLogger.log("Started {0} spot instances in {1} seconds" \
          .format(count, total_time.seconds))
      else:
        AppScaleLogger.log("Started {0} on-demand instances in {1} seconds" \
          .format(count, total_time.seconds))
      return instance_ids, public_ips, private_ips
    except EC2ResponseError as exception:
      self.handle_failure('EC2 response error while starting VMs: ' +
                          exception.error_message)


  def associate_static_ip(self, parameters, instance_id, elastic_ip):
    """Associates the given Elastic IP address with the given instance ID.

    Args:
      parameters: A dict that includes the credentials necessary to communicate
        with Amazon Web Services.
      instance_id: A str naming the running instance to associate an Elastic IP
        with.
      elastic_ip: A str naming the already allocated Elastic IP address that
        will be associated.
    """
    try:
      conn = self.open_connection(parameters)
      conn.associate_address(instance_id, elastic_ip)
    except EC2ResponseError as exception:
      self.handle_failure('Unable to associate Elastic IP {0} with instance ' \
        'ID {1} because: {2}'.format(elastic_ip, instance_id,
        exception.error_message))


  def stop_instances(self, parameters):
    """
    Stop one of more EC2 instances. The input instance IDs are
    fetched from the 'instance_ids' parameters in the input map. (Also
    see documentation for the BaseAgent class)

    Args:
      parameters: A dictionary of parameters.
    """
    instance_ids = parameters[self.PARAM_INSTANCE_IDS]
    conn = self.open_connection(parameters)
    conn.stop_instances(instance_ids)
    AppScaleLogger.log('Stopping instances: '+' '.join(instance_ids))
    if not self.wait_for_status_change(parameters, conn, 'stopped',
           max_wait_time=120):
      AppScaleLogger.log("re-stopping instances: "+' '.join(instance_ids))
      conn.stop_instances(instance_ids)
      if not self.wait_for_status_change(parameters, conn, 'stopped',
            max_wait_time=120):
        self.handle_failure("ERROR: could not stop instances: " + \
            ' '.join(instance_ids))


  def terminate_instances(self, parameters):
    """
    Terminate one of more EC2 instances. The input instance IDs are
    fetched from the 'instance_ids' parameters in the input map. (Also
    see documentation for the BaseAgent class)

    Args:
      parameters: A dictionary of parameters.
    """
    instance_ids = parameters[self.PARAM_INSTANCE_IDS]
    conn = self.open_connection(parameters)
    conn.terminate_instances(instance_ids)
    AppScaleLogger.log('Terminating instances: ' + ' '.join(instance_ids))
    if not self.wait_for_status_change(parameters, conn, 'terminated',
            max_wait_time=120):
      AppScaleLogger.log("re-terminating instances: " + ' '.join(instance_ids))
      conn.terminate_instances(instance_ids)
      if not self.wait_for_status_change(parameters, conn, 'terminated',
                max_wait_time=120):
        self.handle_failure("ERROR: could not terminate instances: " + \
            ' '.join(instance_ids))
    # Sending a second terminate to a terminated instance to remove it
    # from the system (ie no more in describe-instances).  This helps when
    # bringing deployments up and down frequently and instances are still
    # associated with keyname (although they are terminated).
    AppScaleLogger.log("Removing terminated instances: " + ' '.join(instance_ids))
    conn.terminate_instances(instance_ids)


  def wait_for_status_change(self, parameters, conn, state_requested,
                             max_wait_time=60,poll_interval=10):
    """ After we have sent a signal to the cloud infrastructure to change the state
      of the instances (unsually from runnning to either stoppped or
      terminated), wait for the status to change.  If all the instances change
      successfully, return True, if not return False.

    Args:
      parameters: A dictionary of parameters.
      conn: A connection object returned from self.open_connection().
      state_requested: String of the requested final state of the instances.
      max_wait_time: int of maximum amount of time (in seconds)  to wait for the
        state change.
      poll_interval: int of the number of seconds to wait between checking of
        the state.
    """
    time_start = time.time()
    instance_ids = parameters[self.PARAM_INSTANCE_IDS]
    instances_in_state = {}
    while True:
      time.sleep(poll_interval)
      reservations = conn.get_all_instances(instance_ids)
      instances = [i for r in reservations for i in r.instances]
      for i in instances:
        # instance i.id reports status = i.state
        if i.state == state_requested and \
           i.key_name == parameters[self.PARAM_KEYNAME]:
          if i.id not in instances_in_state.keys():
            instances_in_state[i.id] = 1 # mark instance done
      if len(instances_in_state.keys()) >= len(instance_ids):
        return True
      if time.time() - time_start > max_wait_time:
        return False


  def does_address_exist(self, parameters):
    """ Queries Amazon EC2 to see if the specified Elastic IP address has been
    allocated with the given credentials.

    Args:
      parameters: A dict that contains the Elastic IP to check for existence.
    Returns:
      True if the given Elastic IP has been allocated, and False otherwise.
    """
    elastic_ip = parameters[self.PARAM_STATIC_IP]
    try:
      conn = self.open_connection(parameters)
      conn.get_all_addresses(elastic_ip)
      AppScaleLogger.log('Elastic IP {0} can be used for this AppScale ' \
        'deployment.'.format(elastic_ip))
      return True
    except boto.exception.EC2ResponseError:
      AppScaleLogger.log('Elastic IP {0} does not exist.'.format(elastic_ip))
      return False


  def does_image_exist(self, parameters):
    """ Queries Amazon EC2 to see if the specified image exists.

    Args:
      parameters: A dict that contains the machine ID to check for existence.
    Returns:
      True if the machine ID exists, False otherwise.
    """
    image_id = parameters[self.PARAM_IMAGE_ID]
    try:
      conn = self.open_connection(parameters)
      conn.get_image(image_id)
      AppScaleLogger.log('Machine image {0} does exist'.format(image_id))
      return True
    except boto.exception.EC2ResponseError:
      AppScaleLogger.log('Machine image {0} does not exist'.format(image_id))
      return False


  def does_disk_exist(self, parameters, disk_name):
    """ Queries Amazon EC2 to see if the specified EBS volume exists.

    Args:
      parameters: A dict that contains the credentials needed to authenticate
        with AWS.
      disk_name: A str naming the EBS volume to check for existence.
    Returns:
      True if the named EBS volume exists, and False otherwise.
    """
    conn = self.open_connection(parameters)
    try:
      conn.get_all_volumes([disk_name])
      AppScaleLogger.log('EBS volume {0} does exist'.format(disk_name))
      return True
    except boto.exception.EC2ResponseError:
      AppScaleLogger.log('EBS volume {0} does not exist'.format(disk_name))
      return False


  def attach_disk(self, parameters, disk_name, instance_id):
    """ Attaches the Elastic Block Store volume specified in 'disk_name' to this
    virtual machine.

    Args:
      parameters: A dict with keys for each parameter needed to connect to AWS.
      disk_name: A str naming the EBS mount to attach to this machine.
      instance_id: A str naming the id of the instance that the disk should be
        attached to. In practice, callers add disks to their own instances.
    Returns:
      The location on the local filesystem where the disk has been attached.
    """
    # In Amazon Web Services, if we're running on a Xen Paravirtualized machine,
    # then devices get added starting at /dev/xvda. If not, they get added at
    # /dev/sda. Find out which one we're on so that we know where the disk will
    # get attached to.
    if glob.glob("/dev/xvd*"):
      mount_point = '/dev/xvdc'
    elif glob.glob("/dev/vd*"):
      mount_point = '/dev/vdc'
    else:
      mount_point = '/dev/sdc'

    conn = self.open_connection(parameters)

    try:
      AppScaleLogger.log('Attaching volume {0} to instance {1}, at {2}'.format(
        disk_name, instance_id, mount_point))
      conn.attach_volume(disk_name, instance_id, mount_point)
      return mount_point
    except EC2ResponseError as exception:
      if self.disk_attached(conn, disk_name, instance_id):
        return mount_point
      AppScaleLogger.log('An error occurred when trying to attach volume {0} '
        'to instance {1} at {2}'.format(disk_name, instance_id, mount_point))
      self.handle_failure('EC2 response error while attaching volume:' +
        exception.error_message)


  def disk_attached(self, conn, disk_name, instance_id):
    """ Check if disk is attached to instance id.

    Args:
      conn: A boto connection.
      disk_name: A str naming the EBS mount to check.
      instance_id: A str naming the id of the instance that the disk should be
        attached to.
    Returns:
      True if the volume is attached to the instance, False if it is not.
    """
    try:
      volumes = conn.get_all_volumes(filters={'attachment.instance-id':
                                              instance_id})
      for volume in volumes:
        if volume.id == disk_name:
          return True

      return False
    except EC2ResponseError as exception:
      AppScaleLogger.log('An error occurred when trying to find '
                         'attached volumes.')
      self.handle_failure('EC2 response error while checking attached '
                          'volumes: {}'.format(exception.error_message))


  def detach_disk(self, parameters, disk_name, instance_id):
    """ Detaches the EBS mount specified in disk_name from the named instance.

    Args:
      parameters: A dict with keys for each parameter needed to connect to AWS.
      disk_name: A str naming the EBS volume to detach.
      instance_id: A str naming the id of the instance that the disk should be
        detached from.
    Returns:
      True if the disk was detached, and False otherwise.
    """
    conn = self.open_connection(parameters)
    try:
      conn.detach_volume(disk_name, instance_id)
      return True
    except boto.exception.EC2ResponseError:
      AppScaleLogger.log("Could not detach volume with name {0}".format(
        disk_name))
      return False


  def does_zone_exist(self, parameters):
    """ Queries Amazon EC2 to see if the specified availability zone exists.

    Args:
      parameters: A dict that contains the availability zone to check for
        existence.
    Returns:
      True if the availability zone exists, and False otherwise.
    """
    zone = parameters[self.PARAM_ZONE]
    try:
      conn = self.open_connection(parameters)
      conn.get_all_zones(zone)
      AppScaleLogger.log('Availability zone {0} does exist'.format(zone))
      return True
    except boto.exception.EC2ResponseError:
      AppScaleLogger.log('Availability zone {0} does not exist'.format(zone))
      return False


  def cleanup_state(self, parameters):
    """ Removes the keyname and security group created during this AppScale
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
    retries_left = self.SECURITY_GROUP_RETRY_COUNT
    while True:
      try:
        sg = self.get_security_group_by_name(conn, parameters[self.PARAM_GROUP],
                                             parameters.get(self.PARAM_VPC_ID))
        conn.delete_security_group(group_id=sg.id)
        return
      except EC2ResponseError as e:
        time.sleep(self.SLEEP_TIME)
        retries_left -= 1
        if retries_left == 0:
          raise AgentRuntimeException('Error deleting security group! Reason: '
                                      '{}'.format(e.message))
      except SecurityGroupNotFoundException:
        AppScaleLogger.log('Could not find security group {}, skipping '
                           'delete.'.format(parameters[self.PARAM_GROUP]))
        return


  def get_optimal_spot_price(self, conn, instance_type, zone):
    """
    Returns the spot price for an EC2 instance of the specified instance type.
    The returned value is computed by averaging all the spot price history
    values returned by the back-end EC2 APIs and incrementing the average by
    extra 10%.

    Args:
      conn: A boto.EC2Connection that can be used to communicate with AWS.
      instance_type: A str representing the instance type whose prices we
        should speculate for.
      zone: A str representing the availability zone that the instance will
        be placed in.
    Returns:
      The estimated spot price for the specified instance type, in the
        specified availability zone.
    """
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(days=7)
    history = conn.get_spot_price_history(start_time=start_time.isoformat(),
      end_time=end_time.isoformat(), product_description='Linux/UNIX',
      instance_type=instance_type, availability_zone=zone)
    var_sum = 0.0
    for entry in history:
      var_sum += entry.price
    average = var_sum / len(history)
    bid_price = average * 1.10
    AppScaleLogger.log('The average spot instance price for a {0} machine is'\
        ' {1}, and 10% more is {2}'.format(instance_type, average, bid_price))
    return bid_price

  def open_connection(self, parameters):
    """
    Initialize a connection to the back-end EC2 APIs.

    Args:
      parameters: A dictionary containing the 'credentials' parameter.
    Returns:
      An instance of Boto EC2Connection
    """
    credentials = parameters[self.PARAM_CREDENTIALS]
    return boto.ec2.connect_to_region(parameters[self.PARAM_REGION],
      aws_access_key_id=credentials['EC2_ACCESS_KEY'],
      aws_secret_access_key=credentials['EC2_SECRET_KEY'])

  def open_vpc_connection(self, parameters):
    """
    Initialize a connection to the back-end VPC APIs.

    Args:
      parameters: A dictionary containing the 'credentials' parameter.
    Returns:
      An instance of Boto VPCConnection
    """
    credentials = parameters[self.PARAM_CREDENTIALS]
    return boto.vpc.connect_to_region(parameters[self.PARAM_REGION],
        aws_access_key_id=credentials['EC2_ACCESS_KEY'],
        aws_secret_access_key=credentials['EC2_SECRET_KEY'])

  def handle_failure(self, msg):
    """ Log the specified error message and raise an AgentRuntimeException

    Args:
      msg: An error message to be logged and included in the raised exception.
    Raises:
      AgentRuntimeException Contains the input error message.
    """
    AppScaleLogger.log(msg)
    raise AgentRuntimeException(msg)

  def __describe_instances(self, parameters):
    """ Query the back-end EC2 services for instance details and return
    a list of instances. This is equivalent to running the standard
    ec2-describe-instances command. The returned list of instances
    will contain all the running and pending instances and it might
    also contain some recently terminated instances.

    Args:
      parameters: A dictionary of parameters.
    Returns:
      A list of instances (element type definition in boto.ec2 package).
    """
    conn = self.open_connection(parameters)
    reservations = conn.get_all_instances()
    instances = [i for r in reservations for i in r.instances]
    return instances

  def __get_instance_info(self, instances, status, keyname):
    """ Filter out a list of instances by instance status and keyname.

    Args:
      instances: A list of instances as returned by describe_instances.
      status: Status of the VMs (eg: running, terminated).
      keyname: Keyname used to spawn instances.
    Returns:
      A tuple of the form (public ips, private ips, instance ids).
    """
    instance_ids = []
    public_ips = []
    private_ips = []
    for i in instances:
      if i.state == status and i.key_name == keyname:
        instance_ids.append(i.id)
        public_ips.append(i.ip_address)
        private_ips.append(i.private_ip_address)
    return public_ips, private_ips, instance_ids
