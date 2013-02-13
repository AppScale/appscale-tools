from agents.base_agent import AgentConfigurationException
from agents.ec2_agent import EC2Agent
from appscale_logger import AppScaleLogger
from local_state import LocalState

import boto
import os
from urlparse import urlparse

__author__ = 'hiranya'
__email__ = 'hiranya@appscale.com'

class EucalyptusAgent(EC2Agent):
  """
  Eucalyptus infrastructure agent which can be used to spawn and terminate
  VMs in an Eucalyptus based environment.
  """

  # The version of Eucalyptus API used to interact with Euca clouds
  EUCA_API_VERSION = '2010-08-31'


  # A list of the credentials that we require users to provide the AppScale
  # Tools with so that they can interact with Eucalyptus clouds. Right now
  # it's the same as what's needed for EC2, with an extra argument indicating
  # where the Eucalyptus deployment is located.
  REQUIRED_EUCA_CREDENTIALS = list(EC2Agent.REQUIRED_EC2_CREDENTIALS) + \
    ['EC2_URL']


  # A list of credentials that we build our internal credential list from.
  REQUIRED_CREDENTIALS = REQUIRED_EUCA_CREDENTIALS


  def open_connection(self, parameters):
    """
    Initialize a connection to the back-end Eucalyptus APIs.

    Args:
      parameters  A dictionary containing the 'credentials' parameter

    Returns:
      An instance of Boto EC2Connection
    """
    credentials = parameters[self.PARAM_CREDENTIALS]
    access_key = str(credentials['EC2_ACCESS_KEY'])
    secret_key = str(credentials['EC2_SECRET_KEY'])
    ec2_url = str(credentials['EC2_URL'])
    result = urlparse(ec2_url)
    if result.port is not None:
      port = result.port
    elif result.scheme == 'http':
      port = 80
    elif result.scheme == 'https':
      port = 443
    else:
      self.handle_failure('Unknown scheme in EC2_URL: ' + result.scheme)
      return None

    if parameters['IS_VERBOSE']:
      debug_level = 2  # extremely verbose
    else:
      debug_level = 0  # the silent treatment

    return boto.connect_euca(host=result.hostname,
      aws_access_key_id=access_key,
      aws_secret_access_key=secret_key,
      port=port,
      path=result.path,
      is_secure=(result.scheme == 'https'),
      api_version=self.EUCA_API_VERSION, debug=debug_level)


  def configure_instance_security(self, parameters):
    """
    Setup Euca security keys and groups. Required input values are read from
    the parameters dictionary. More specifically, this method expects to
    find a 'keyname' parameter and a 'group' parameter in the parameters
    dictionary. Using these provided values, this method will create a new
    Euca key-pair and a security group. Security group will be granted permissions
    to access any port on the instantiated VMs. (Also see documentation for the
    BaseAgent class)

    Args:
      parameters  A dictionary of parameters
    """
    keyname = parameters[self.PARAM_KEYNAME]
    group = parameters[self.PARAM_GROUP]

    AppScaleLogger.log("Verifying that keyname {0}".format(keyname) + \
      " is not already registered.")
    conn = self.open_connection(parameters)
    try:
      conn.get_key_pair(keyname)
      self.handle_failure('SSH key found locally - please use a different keyname')
    except IndexError:  # in euca, this means the key doesn't exist
      pass

    security_groups = conn.get_all_security_groups()
    group_exists = False
    for security_group in security_groups:
      if security_group.name == group:
        self.handle_failure("Security group already exists - please use a " + \
          "different group name")

    AppScaleLogger.log('Creating key pair: ' + keyname)
    key_pair = conn.create_key_pair(keyname)
    ssh_key = '{0}{1}.key'.format(LocalState.LOCAL_APPSCALE_PATH, keyname)
    LocalState.write_key_file(ssh_key, key_pair.material)

    AppScaleLogger.log('Creating security group: {0}'.format(group))
    conn.create_security_group(group, 'AppScale security group')
    conn.authorize_security_group_deprecated(group, from_port=1,
      to_port=65535, ip_protocol='udp', cidr_ip='0.0.0.0/0')
    conn.authorize_security_group_deprecated(group, from_port=1,
      to_port=65535, ip_protocol='tcp', cidr_ip='0.0.0.0/0')
    conn.authorize_security_group_deprecated(group, ip_protocol='icmp',
      cidr_ip='0.0.0.0/0')

    return True


  def does_image_exist(self, parameters):
    """
    Queries Eucalyptus to see if the specified image exists.

    Args:
      parameters A dict that contains the machine ID to check for existence.
    Returns:
      True if the machine ID exists, False otherwise.
    """
    # note that we can't use does_image_exist in EC2Agent. There, if the image
    # doesn't exist, it throws an EC2ResponseError, but in Eucalyptus, it
    # doesn't (and returns None instead).
    conn = self.open_connection(parameters)
    image_id = parameters[self.PARAM_IMAGE_ID]
    if conn.get_image(image_id):
      AppScaleLogger.log('Machine image {0} does exist'.format(image_id))
      return True
    else:
      AppScaleLogger.log('Machine image {0} does not exist'.format(image_id))
      return False
