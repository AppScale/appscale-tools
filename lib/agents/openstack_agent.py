""" The Openstack Agent. """
from ec2_agent import EC2Agent

import boto
import time
from urlparse import urlparse

__author__ = 'dario nascimento'
__email__ = 'dario.nascimento@tecnico.ulisboa.pt'

class OpenStackAgent(EC2Agent):
  """
  OpenStack infrastructure agent which can be used to spawn and terminate
  VMs in an OpenStack based environment.
  """

  # The version of OpenStack API used to interact with Boto
  # OpenStack_API_VERSION = 'ICE-HOUSE-2014.1'

  # A list of the credentials that we require users to provide the AppScale
  # Tools with so that they can interact with Openstack clouds. Right now
  # it's the same as what's needed for EC2, with an extra argument indicating
  # where the Openstack deployment is located.
  REQUIRED_OPENSTACK_CREDENTIALS = list(EC2Agent.REQUIRED_EC2_CREDENTIALS) + \
    ['EC2_URL']

  # A list of credentials that we build our internal credential list from.
  REQUIRED_CREDENTIALS = REQUIRED_OPENSTACK_CREDENTIALS

  # The default openstack region.
  DEFAULT_REGION = "nova"

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
      if (i.state == 'running' or (pending and i.state == 'pending')) \
        and i.key_name.startswith(parameters[self.PARAM_KEYNAME]):
        instance_ids.append(i.id)
        public_ips.append(i.public_dns_name)
        private_ips.append(i.private_dns_name)
    return public_ips, private_ips, instance_ids

  
  def open_connection(self, parameters):
    """
    Initialize a connection to the back-end OpenStack APIs.

    Args:
      parameters: A dictionary containing the 'credentials' parameter
        EC2_URL usually has the format: 
        http://<nova_controller>:8773/services/Cloud

    Returns:
      An instance of Boto EC2Connection
    """
    credentials = parameters[self.PARAM_CREDENTIALS]
    region_str = self.DEFAULT_REGION
    access_key = str(credentials['EC2_ACCESS_KEY'])
    secret_key = str(credentials['EC2_SECRET_KEY'])
    ec2_url = str(credentials['EC2_URL'])

    result = urlparse(ec2_url)

    if result.port is None or result.hostname is None\
      or result.path is None:
      self.handle_failure('Unknown scheme in Openstack_URL: {0}'+\
        ' : expected like http://<controller>:8773/services/Cloud'\
        .format(result.geturl()))
      return None

    region = boto.ec2.regioninfo.RegionInfo(name=region_str,
      endpoint=result.hostname)
    return boto.connect_ec2(aws_access_key_id=access_key,
      aws_secret_access_key=secret_key,
      is_secure=(result.scheme == 'https'),
      region=region,
      port=result.port,
      path=result.path, debug=2)

  def wait_for_status_change(self, parameters, conn, state_requested, 
    max_wait_time=60, poll_interval=10):
    """ 
    After we have sent a signal to the cloud infrastructure to change the state
    of the instances (unsually from runnning to either stoppped or 
    terminated), wait for the status to change. 

    Args:
    parameters: A dictionary of parameters.
    conn: A connection object returned from self.open_connection().
    state_requrested: String of the requested final state of the instances.
    max_wait_time: int of maximum amount of time (in seconds)  to wait for the
      state change.
    poll_interval: int of the number of seconds to wait between checking of
      the state.

    Returns:
      If all the instances change successfully, return True, if not return False.
    """
    time_start = time.time()
    instance_ids = parameters[self.PARAM_INSTANCE_IDS]
    instances_in_state = {}
    while True:
      time.sleep(poll_interval)
      reservations = conn.get_all_instances(instance_ids)
      instances = [i for r in reservations for i in r.instances]
      for i in instances:
        if i.state == state_requested and \
         i.key_name.startswith(parameters[self.PARAM_KEYNAME]):
          if i.id not in instances_in_state.keys():
            instances_in_state[i.id] = 1 # mark instance done
    if len(instances_in_state.keys()) >= len(instance_ids):
      return True
    if time.time() - time_start > max_wait_time:
      return False

