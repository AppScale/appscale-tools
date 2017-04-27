#!/usr/bin/env python


class BaseAgent:
  """BaseAgent class defines the interface that must be implemented by
  each cloud agent."""


  # A str constant the callers can use when they want to start virtual machines.
  OPERATION_RUN = 'run'


  # A str constant the callers can use when they want to kill virtual machines.
  OPERATION_TERMINATE = 'terminate'


  def assert_credentials_are_valid(self, parameters):
    """Checks with the given cloud to ensure that the given credentials can be
    used to interact with it.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.

    Raises:
      AgentConfigurationException: If the given credentials cannot be used to
        make requests to the underlying cloud.
    """
    raise NotImplementedError


  def configure_instance_security(self, parameters):
    """Configure and setup security features for the VMs spawned via this
    agent.

    This method is called before starting virtual machines. Implementations may
    configure security features such as VM login and firewalls in this method.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.

    Returns:
      True if some action was taken to configure security for the VMs
      and False otherwise.

    Raises:
      AgentRuntimeException: If security features could not be successfully
        configured in the underlying cloud.
    """
    raise NotImplementedError


  def describe_instances(self, parameters, pending=False):
    """Query the underlying cloud platform regarding VMs that are running.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
      pending: If we should show pending instances.
    Returns:
      A tuple of the form (public, private, id) where public is a list
      of private IP addresses, private is a list of private IP addresses,
      and id is a list of platform specific VM identifiers.
    """
    raise NotImplementedError


  def run_instances(self, count, parameters, security_configured, public_ip_needed):
    """Start a set of virtual machines using the parameters provided.

    Args:
      count: An int that indicates the number of VMs to be spawned.
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
      security_configured: True if security has been configured for the VMs
        by this agent, or False otherwise. This is usually the value that was
        returned by a call to the configure_instance_security method.
    Returns:
      A tuple consisting of information related to the spawned VMs. The
      tuple should contain a list of instance IDs, a list of public IP
      addresses and a list of private IP addresses.

    Raises:
      AgentRuntimeException: If an error occurs while trying to spawn VMs.
    """
    raise NotImplementedError


  def associate_static_ip(self, instance_id, static_ip):
    """Associates the given static IP address with the given instance ID.

    Args:
      instance_id: A str that names the instance that the static IP should be
        bound to.
      static_ip: A str naming the static IP to bind to the given instance.
    """
    raise NotImplementedError


  def terminate_instances(self, parameters):
    """Terminate a set of virtual machines using the parameters given.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
    """
    raise NotImplementedError


  def does_address_exist(self, parameters):
    """Verifies that the specified static IP address has been allocated, and
    belongs to the user with the given credentials.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud, as well as a key indicating which static IP address
        should be validated.
    Returns:
      A bool that indicates if the given static IP address exists, and belongs
      to this user.
    """
    raise NotImplementedError


  def does_image_exist(self, parameters):
    """Verifies that the specified machine image exists in this cloud.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud, as well as a key indicating which machine image should
        be checked for existence.
    Returns:
      A bool that indicates if the machine image exists in this cloud.
    """
    raise NotImplementedError


  def does_disk_exist(self, parameters, disk):
    """Verifies that the specified persistent disk exists in this cloud.

    Args:
      parameters: A dict that includes the parameters needed to authenticate
        with this cloud.
      disk: A str containing the name of the disk that we should check for
        existence.
    Returns:
      True if the named persistent disk exists, and False otherwise,
    """
    raise NotImplementedError


  def does_zone_exist(self, parameters):
    """Verifies that the specified zone exists in this cloud.

    Args:
      parameters: A dict that includes a key indicating the zone to check for
        existence.
    Returns:
      True if the zone exists, and False otherwise.
    """
    raise NotImplementedError


  def cleanup_state(self, parameters):
    """Removes any remote state that was created to run AppScale instances
    during this deployment.

    Args:
      parameters: A dict that includes keys indicating the remote state
        that should be deleted.
    """
    raise NotImplementedError


  def get_params_from_args(self, args):
    """Converts a Namespace of arguments to a dict, the internal format used by
    Agents.

    Cloud-specific parameters are also added to this dict.

    Args:
      args: A Namespace of arguments.

    Returns:
      A dict that maps each argument given to the value that was associated with
      it.
    """
    raise NotImplementedError


  def assert_required_parameters(self, parameters, operation):
    """Check whether all the platform specific parameters are present in the
    provided dict. If all the parameters required to perform the given operation
    is available this method simply returns. Otherwise it throws an
    AgentConfigurationException.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
      operation: A str representing the operation for which the parameters
        should be checked.

    Raises:
      AgentConfigurationException: If a required parameter is absent.
    """
    raise NotImplementedError


  def has_parameter(self, param, params):
    """Checks whether the parameter is present in the params dict.

    Args:
      param: A str representing a parameter name.
      params: A dictionary of parameters.

    Returns:
      True if params contains param and the value of param is not None.
      Returns False otherwise.
    """
    return params.get(param) != None


  def diff(self, list1, list2):
    """
    Returns the list of entries that are present in list1 but not
    in list2.

    Args:
      list1: A list of elements
      list2: Another list of elements

    Returns:
      A list of elements unique to list1
    """
    diffed_list = []
    list2 = set(list2)
    for item in list1:
      if item not in list2:
        diffed_list.append(item)
    return diffed_list


class AgentConfigurationException(Exception):
  """An agent implementation may throw this exception when it detects that a
  given cloud configuration is missing some required parameters or contains
  invalid values.
  """


  def __init__(self, msg):
    Exception.__init__(self, msg)


class AgentRuntimeException(Exception):


  def __init__(self, msg):
    Exception.__init__(self, msg)
