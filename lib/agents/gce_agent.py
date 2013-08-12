#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)
"""
This file provides a single class, GCEAgent, that the AppScale Tools can use to
interact with Google Compute Engine.
"""

# General-purpose Python library imports
import datetime
import os.path
import shutil
import time
import uuid


# Third-party imports
import apiclient.discovery
# Don't bother us about the discovery.Resource not having certain
# methods, since it gets built dynamically.
# pylint: disable-msg=E1101
import httplib2
import oauth2client.client
import oauth2client.file
import oauth2client.tools


# AppScale-specific imports
from agents.base_agent import AgentConfigurationException
from agents.base_agent import AgentRuntimeException
from agents.base_agent import BaseAgent 
from appscale_logger import AppScaleLogger
from local_state import LocalState


class GCEAgent(BaseAgent):
  """ GCEAgent defines a specialized BaseAgent that allows for interaction with
  Google Compute Engine.

  It authenticates via OAuth2 and interacts with GCE via the Google Client
  Library.
  """


  # The maximum amount of time, in seconds, that we are willing to wait for a
  # virtual machine to start up, after calling instances().add(). GCE is pretty
  # fast at starting up images, and in practice, we haven't seen it take longer
  # than 200 seconds, but this upper bound is set just to be safe.
  MAX_VM_CREATION_TIME = 600


  # The amount of time that run_instances waits between each instances().list()
  # request. Setting this value lower results in more requests made to Google,
  # but is more responsive to when machines become ready to use.
  SLEEP_TIME = 20

  # The following constants are string literals that can be used by callers to
  # index into the parameters the user passes in, as opposed to having to type
  # out the strings each time we need them.
  PARAM_CREDENTIALS = 'credentials'


  PARAM_GROUP = 'group'


  PARAM_IMAGE_ID = 'image_id'


  PARAM_INSTANCE_IDS = 'instance_ids'


  PARAM_INSTANCE_TYPE = 'instance_type'


  PARAM_KEYNAME = 'keyname'


  PARAM_PROJECT = 'project'

  
  PARAM_SECRETS = 'client_secrets'


  PARAM_VERBOSE = 'is_verbose'


  PARAM_ZONE = 'zone'


  # A set that contains all of the items necessary to run AppScale in Google
  # Compute Engine.
  REQUIRED_CREDENTIALS = (
    PARAM_GROUP,
    PARAM_IMAGE_ID,
    PARAM_KEYNAME,
    PARAM_PROJECT,
    PARAM_SECRETS,
    PARAM_ZONE
  )


  # The OAuth 2.0 scope used to interact with Google Compute Engine.
  GCE_SCOPE = 'https://www.googleapis.com/auth/compute'


  # The version of the Google Compute Engine API that we support.
  API_VERSION = 'v1beta15'


  # The URL endpoint that receives Google Compute Engine API requests.
  GCE_URL = 'https://www.googleapis.com/compute/{0}/projects/'.format(
    API_VERSION)


  # The person to contact if there is a problem with the instance. We set this
  # to 'default' to not have to actually put anyone's personal information in.
  DEFAULT_SERVICE_EMAIL = 'default'


  def configure_instance_security(self, parameters):
    """ Creates a GCE network and firewall with the specified name, and opens
    the ports on that firewall as needed for AppScale.

    We expect both the network and the firewall to not exist before this point,
    to avoid accidentally placing AppScale instances from different deployments
    in the same network and firewall (thus enabling them to see each other's web
    traffic).

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        network and firewall that we should create in GCE.
    Returns:
      True, if the named network and firewall was created successfully.
    Raises:
      AgentRuntimeException: If the named network or firewall already exist in
      GCE.
    """
    AppScaleLogger.log("Verifying that SSH key exists locally")
    keyname = parameters[self.PARAM_KEYNAME]
    private_key = LocalState.LOCAL_APPSCALE_PATH + keyname
    public_key = private_key + ".pub"

    if os.path.exists(private_key) or os.path.exists(public_key):
      raise AgentRuntimeException("SSH key already found locally - please " +
        "use a different keyname")

    LocalState.generate_rsa_key(keyname, parameters[self.PARAM_VERBOSE])

    ssh_key_exists, all_ssh_keys = self.does_ssh_key_exist(parameters)
    if not ssh_key_exists:
      self.create_ssh_key(parameters, all_ssh_keys)

    if self.does_network_exist(parameters):
      raise AgentRuntimeException("Network already exists - please use a " + \
        "different group name.")

    if self.does_firewall_exist(parameters):
      raise AgentRuntimeException("Firewall already exists - please use a " + \
        "different group name.")

    network_url = self.create_network(parameters)
    self.create_firewall(parameters, network_url)


  def does_ssh_key_exist(self, parameters):
    """ Queries Google Compute Engine to see if the specified SSH key exists.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine. We don't have an additional key for the name of
        the SSH key, since we use the one in ~/.ssh.
    Returns:
      A tuple of two items. The first item is a bool that is True if
        our public key's contents are in GCE, and False otherwise, while
        the second item is the contents of all SSH keys stored in GCE.
    """
    our_public_ssh_key = None
    public_ssh_key_location = LocalState.LOCAL_APPSCALE_PATH + \
      parameters[self.PARAM_KEYNAME] + ".pub"
    with open(public_ssh_key_location) as file_handle:
      our_public_ssh_key = os.getlogin() + ":" + file_handle.read().rstrip()

    gce_service, credentials = self.open_connection(parameters)
    try:
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.projects().get(
        project=parameters[self.PARAM_PROJECT])
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])

      if not 'items' in response['commonInstanceMetadata']:
        return False, ""

      metadata = response['commonInstanceMetadata']['items']
      if not metadata:
        return False, ""

      for item in metadata:
        if item['key'] != 'sshKeys':
          continue

        # Now that we know there's one or more SSH keys, just make sure that
        # ours is in this list.
        all_ssh_keys = item['value']
        if our_public_ssh_key in all_ssh_keys:
          return True, all_ssh_keys

      return False, all_ssh_keys
    except apiclient.errors.HttpError:
      return False, ""


  def does_network_exist(self, parameters):
    """ Queries Google Compute Engine to see if the specified network exists.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        network that we should query for existence in GCE.
    Returns:
      True if the named network exists, and False otherwise.
    """
    gce_service, credentials = self.open_connection(parameters)
    try:
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.networks().get(
        project=parameters[self.PARAM_PROJECT],
        network=parameters[self.PARAM_GROUP])
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      return True
    except apiclient.errors.HttpError:
      return False


  def does_firewall_exist(self, parameters):
    """ Queries Google Compute Engine to see if the specified firewall exists.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        firewall that we should query for existence in GCE.
    Returns:
      True if the named firewall exists, and False otherwise.
    """
    gce_service, credentials = self.open_connection(parameters)
    try:
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.firewalls().get(
        project=parameters[self.PARAM_PROJECT],
        firewall=parameters[self.PARAM_GROUP])
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      return True
    except apiclient.errors.HttpError:
      return False

  
  def create_ssh_key(self, parameters, all_ssh_keys):
    """ Creates a new SSH key in Google Compute Engine with the contents of
    our newly generated public key.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine.
      all_ssh_keys: A str that contains all of the SSH keys that are
        currently passed in to GCE instances.
    """
    our_public_ssh_key = None
    public_ssh_key_location = LocalState.LOCAL_APPSCALE_PATH + \
      parameters[self.PARAM_KEYNAME] + ".pub"
    with open(public_ssh_key_location) as file_handle:
      our_public_ssh_key = os.getlogin() + ":" + file_handle.read().rstrip()

    if all_ssh_keys:
      new_all_ssh_keys = our_public_ssh_key + "\n" + all_ssh_keys
    else:
      new_all_ssh_keys = our_public_ssh_key

    gce_service, credentials = self.open_connection(parameters)
    http = httplib2.Http()
    auth_http = credentials.authorize(http)
    request = gce_service.projects().setCommonInstanceMetadata(
      project=parameters[self.PARAM_PROJECT],
      body={
        "kind": "compute#metadata",
        "items": [{
          "key": "sshKeys",
          "value": new_all_ssh_keys
        }]
      }
    )
    response = request.execute(auth_http)
    AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
    self.ensure_operation_succeeds(gce_service, auth_http, response,
      parameters[self.PARAM_PROJECT])


  def create_network(self, parameters):
    """ Creates a new network in Google Compute Engine with the specified name.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        network that we should create in GCE.
    Returns:
      The URL corresponding to the name of the network that was created, for use
      with binding this network to one or more firewalls.
    """
    gce_service, credentials = self.open_connection(parameters)
    http = httplib2.Http()
    auth_http = credentials.authorize(http)
    request = gce_service.networks().insert(
      project=parameters[self.PARAM_PROJECT],
      body={
        "name" : parameters[self.PARAM_GROUP],
        "description" : "Network used for AppScale instances",
        "IPv4Range" : "10.240.0.0/16"
      }
    )
    response = request.execute(auth_http)
    AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
    self.ensure_operation_succeeds(gce_service, auth_http, response,
      parameters[self.PARAM_PROJECT])
    return response['targetLink']


  def delete_network(self, parameters):
    """ Deletes the network in Google Compute Engine with the specified name.

    Note that callers should not invoke this method unless they are confident
    that no firewalls or instances are using this network, or this method will
    fail.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        network that we should delete.
    """
    gce_service, credentials = self.open_connection(parameters)
    http = httplib2.Http()
    auth_http = credentials.authorize(http)
    request = gce_service.networks().delete(
      project=parameters[self.PARAM_PROJECT],
      network=parameters[self.PARAM_GROUP]
    )
    response = request.execute(auth_http)
    AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
    self.ensure_operation_succeeds(gce_service, auth_http, response,
      parameters[self.PARAM_PROJECT])


  def create_firewall(self, parameters, network_url):
    """ Creates a new firewall in Google Compute Engine with the specified name,
    bound to the specified network.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        firewall that we should create.
      network_url: A str containing the URL of the network that this new
        firewall should be applied to.
    """
    gce_service, credentials = self.open_connection(parameters)
    http = httplib2.Http()
    auth_http = credentials.authorize(http)
    request = gce_service.firewalls().insert(
      project=parameters[self.PARAM_PROJECT],
      body={
        "name" : parameters[self.PARAM_GROUP],
        "description" : "Firewall used for AppScale instances",
        "network" : network_url,
        "sourceRanges" : ["0.0.0.0/0"],
        "allowed" : [
          {"IPProtocol" : "tcp", "ports": ["1-65535"]},
          {"IPProtocol" : "udp", "ports": ["1-65535"]},
          {"IPProtocol" : "icmp"}
        ]
      }
    )
    response = request.execute(auth_http)
    AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
    self.ensure_operation_succeeds(gce_service, auth_http, response,
      parameters[self.PARAM_PROJECT])


  def delete_firewall(self, parameters):
    """ Deletes a firewall in Google Compute Engine with the specified name.

    Callers should not invoke this method until they are certain that no
    instances are using the specified firewall, or this method will fail.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        firewall that we should create.
    """
    gce_service, credentials = self.open_connection(parameters)
    http = httplib2.Http()
    auth_http = credentials.authorize(http)
    request = gce_service.firewalls().delete(
      project=parameters[self.PARAM_PROJECT],
      firewall=parameters[self.PARAM_GROUP]
    )
    response = request.execute(auth_http)
    AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
    self.ensure_operation_succeeds(gce_service, auth_http, response,
      parameters[self.PARAM_PROJECT])


  def get_params_from_args(self, args):
    """ Constructs a dict with only the parameters necessary to interact with
    Google Compute Engine (here, the client_secrets file and the image name).

    Args:
      args: A Namespace or dict that maps all of the arguments the user has
        invoked an AppScale command with their associated value.
    Returns:
      A dict containing the location of the client_secrets file and that name
      of the image to use in GCE.
    Raises:
      AgentConfigurationException: If the caller fails to specify a
        client_secrets file, or if it doesn't exist on the local filesystem.
    """
    if not isinstance(args, dict):
      args = vars(args)

    if not args['client_secrets']:
      raise AgentConfigurationException("Please specify a client_secrets " + \
        "file in your AppScalefile when running over Google Compute Engine.")

    client_secrets = os.path.expanduser(args['client_secrets'])
    if not os.path.exists(client_secrets):
      raise AgentConfigurationException("Couldn't find your client secrets " + \
        "file at {0}".format(client_secrets))
    shutil.copy(client_secrets, LocalState.get_client_secrets_location(
      args['keyname']))

    params = {
      self.PARAM_GROUP : args['group'],
      self.PARAM_IMAGE_ID : args['machine'],
      self.PARAM_INSTANCE_TYPE : args['gce_instance_type'],
      self.PARAM_KEYNAME : args['keyname'],
      self.PARAM_PROJECT : args['project'],
      self.PARAM_SECRETS : os.path.expanduser(args['client_secrets']),
      self.PARAM_ZONE : args['zone']
    }

    if 'verbose' in args:
      params[self.PARAM_VERBOSE] = args['verbose']
    else:
      params[self.PARAM_VERBOSE] = False

    return params


  def get_params_from_yaml(self, keyname):
    """ Searches through the locations.yaml file to build a dict containing the
    parameters necessary to interact with Google Compute Engine.

    Args:
      keyname: A str that uniquely identifies this AppScale deployment.
    Returns:
      A dict containing all of the credentials necessary to interact with
        Google Compute Engine.
    """
    return {
      self.PARAM_GROUP : LocalState.get_group(keyname),
      self.PARAM_KEYNAME : keyname,
      self.PARAM_PROJECT : LocalState.get_project(keyname),
      self.PARAM_SECRETS : LocalState.get_client_secrets_location(keyname),
      self.PARAM_VERBOSE : False,  # TODO(cgb): Don't put False in here.
      self.PARAM_ZONE : LocalState.get_zone(keyname)
    }


  def assert_required_parameters(self, parameters, _):
    """ Checks the given parameters to make sure that they can be used to
    interact with Google Compute Engine.

    Args:
      parameters: A dict that maps the name of each credential to be used in GCE
        with the value we should use.
      operation: A BaseAgent.OPERATION that indicates if we wish to add or
        delete instances. Unused here, as all operations require the same
        credentials.
    Raises:
      AgentConfigurationException: If any of the required credentials are not
        present, or if the client_secrets parameter refers to a file that is not
        present on the local filesystem.
    """
    # Make sure the user has set each parameter.
    for param in self.REQUIRED_CREDENTIALS:
      if not self.has_parameter(param, parameters):
        raise AgentConfigurationException('The required parameter, {0}, was' \
          ' not specified.'.format(param))

    # Next, make sure that the client_secrets file exists
    if not os.path.exists(parameters[self.PARAM_SECRETS]):
      raise AgentConfigurationException('Could not find your client_secrets ' \
        'file at {0}'.format(parameters[self.PARAM_SECRETS]))


  def describe_instances(self, parameters):
    """ Queries Google Compute Engine to see which instances are currently
    running, and retrieve information about their public and private IPs.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine.
    Returns:
      A tuple of the form (public_ips, private_ips, instance_ids), where each
        member is a list. Items correspond to each other across these lists,
        so a caller is guaranteed that item X in each list belongs to the same
        virtual machine.
    """
    gce_service, credentials = self.open_connection(parameters)
    http = httplib2.Http()
    auth_http = credentials.authorize(http)
    request = gce_service.instances().list(
      project=parameters[self.PARAM_PROJECT],
      filter="name eq appscale-{0}-.*".format(parameters[self.PARAM_GROUP]),
      zone=parameters[self.PARAM_ZONE]
    )
    response = request.execute(auth_http)
    AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])

    instance_ids = []
    public_ips = []
    private_ips = []

    if response and 'items' in response:
      instances = response['items']
      for instance in instances:
        if instance['status'] == "RUNNING":
          instance_ids.append(instance['name'])
          network_interface = instance['networkInterfaces'][0]
          public_ips.append(network_interface['accessConfigs'][0]['natIP'])
          private_ips.append(network_interface['networkIP'])

    return public_ips, private_ips, instance_ids


  def run_instances(self, count, parameters, security_configured):
    """ Starts 'count' instances in Google Compute Engine, and returns once they
    have been started.

    Callers should create a network and attach a firewall to it before using
    this method, or the newly created instances will not have a network and
    firewall to attach to (and thus this method will fail).

    Args:
      count: An int that specifies how many virtual machines should be started.
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine.
      security_configured: Unused, as we assume that the network and firewall
        has already been set up.
    """
    project_id = parameters[self.PARAM_PROJECT]
    image_id = parameters[self.PARAM_IMAGE_ID]
    instance_type = parameters[self.PARAM_INSTANCE_TYPE]
    keyname = parameters[self.PARAM_KEYNAME]
    group = parameters[self.PARAM_GROUP]
    zone = parameters[self.PARAM_ZONE]

    AppScaleLogger.log("Starting {0} machines with machine id {1}, with " \
      "instance type {2}, keyname {3}, in security group {4}, in zone {5}" \
      .format(count, image_id, instance_type, keyname, group, zone))

    # First, see how many instances are running and what their info is.
    start_time = datetime.datetime.now()
    active_public_ips, active_private_ips, active_instances = \
      self.describe_instances(parameters)

    # Construct URLs
    image_url = '{0}{1}/global/images/{2}'.format(self.GCE_URL, project_id,
      image_id)
    project_url = '{0}{1}'.format(self.GCE_URL, project_id)
    machine_type_url = '{0}/zones/{1}/machineTypes/{2}'.format(project_url,
      zone, instance_type)
    network_url = '{0}/global/networks/{1}'.format(project_url, group)

    # Construct the request body
    for index in range(count):
      instances = {
        'name': "appscale-{0}-{1}".format(group, uuid.uuid4()),
        'machineType': machine_type_url,
        'image': image_url,
        'networkInterfaces': [{
          'accessConfigs': [{
            'type': 'ONE_TO_ONE_NAT',
            'name': 'External NAT'
           }],
          'network': network_url
        }],
        'serviceAccounts': [{
             'email': self.DEFAULT_SERVICE_EMAIL,
             'scopes': [self.GCE_SCOPE]
        }]
      }

      # Create the instance
      gce_service, credentials = self.open_connection(parameters)
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.instances().insert(
           project=project_id, body=instances, zone=zone)
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      self.ensure_operation_succeeds(gce_service, auth_http, response,
        parameters[self.PARAM_PROJECT])
    
    instance_ids = []
    public_ips = []
    private_ips = []
    end_time = datetime.datetime.now() + datetime.timedelta(0,
      self.MAX_VM_CREATION_TIME)
    now = datetime.datetime.now()

    while now < end_time:
      AppScaleLogger.log("Waiting for your instances to start...")
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
          AppScaleLogger.log('Instance {0} failed to get a public IP address'\
                  'and is being terminated'.format(instance_to_term))
          self.terminate_instances([instance_to_term])

    end_time = datetime.datetime.now()
    total_time = end_time - start_time
    AppScaleLogger.log("Started {0} on-demand instances in {1} seconds" \
      .format(count, total_time.seconds))
    return instance_ids, public_ips, private_ips


  def terminate_instances(self, parameters):
    """ Deletes the instances specified in 'parameters' running in Google
    Compute Engine.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key mapping to a list of
        instance names that should be deleted.
    """
    instance_ids = parameters[self.PARAM_INSTANCE_IDS]
    responses = []
    for instance_id in instance_ids:
      gce_service, credentials = self.open_connection(parameters)
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.instances().delete(
        project=parameters[self.PARAM_PROJECT],
        zone=parameters[self.PARAM_ZONE],
        instance=instance_id
      )
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      responses.append(response)

    for response in responses:
      gce_service, credentials = self.open_connection(parameters)
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      self.ensure_operation_succeeds(gce_service, auth_http, response,
        parameters[self.PARAM_PROJECT])


  def does_image_exist(self, parameters):
    """ Queries Google Compute Engine to see if the specified image exists for
    this user.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        image that we should check for existence.
    Returns:
      True if the named image exists, and False otherwise.
    """
    gce_service, credentials = self.open_connection(parameters)
    try:
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.images().get(project=parameters[self.PARAM_PROJECT],
        image=parameters[self.PARAM_IMAGE_ID])
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      return True
    except apiclient.errors.HttpError:
      return False


  def does_zone_exist(self, parameters):
    """ Queries Google Compute Engine to see if the specified zone exists for
    this user.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine, and an additional key indicating the name of the
        zone that we should check for existence.
    Returns:
      True if the named zone exists, and False otherwise.
    """
    gce_service, credentials = self.open_connection(parameters)
    try:
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.zones().get(project=parameters[self.PARAM_PROJECT],
        zone=parameters[self.PARAM_ZONE])
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      return True
    except apiclient.errors.HttpError:
      return False


  def does_disk_exist(self, parameters, disk):
    """ Queries Google Compute Engine to see if the specified persistent disk
    exists for this user.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine.
      disk: A str containing the name of the disk that we should check for
        existence.
    Returns:
      True if the named persistent disk exists, and False otherwise.
    """
    gce_service, credentials = self.open_connection(parameters)
    try:
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.disks().get(project=parameters[self.PARAM_PROJECT],
        disk=disk, zone=parameters[self.PARAM_ZONE])
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      return True
    except apiclient.errors.HttpError:
      return False


  def detach_disk(self, parameters, disk_name, instance_id):
    """ Detaches the persistent disk specified in 'disk_name' from the named
    instance.

    Args:
      parameters: A dict with keys for each parameter needed to connect to
        Google Compute Engine.
      disk_name: A str naming the persistent disk to detach.
      instance_id: A str naming the id of the instance that the disk should be
        detached from.
    """
    gce_service, credentials = self.open_connection(parameters)
    http = httplib2.Http()
    auth_http = credentials.authorize(http)
    project_id = parameters[self.PARAM_PROJECT]
    request = gce_service.instances().detachDisk(
      project=project_id,
      zone=parameters[self.PARAM_ZONE],
      instance=instance_id,
      deviceName='sdb')
    response = request.execute(auth_http)
    AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
    self.ensure_operation_succeeds(gce_service, auth_http, response,
      parameters[self.PARAM_PROJECT])


  def cleanup_state(self, parameters):
    """ Deletes the firewall and network that were created during this AppScale
    deployment.

    Args:
      parameters: A dict that contains the name of the firewall and network to
        delete (the group name) as well as the credentials necessary to do so.
    """
    self.delete_firewall(parameters)
    self.delete_network(parameters)


  def open_connection(self, parameters):
    """ Connects to Google Compute Engine with the given credentials.

    Args:
      parameters: A dict that contains all the parameters necessary to
        authenticate this user with Google Compute Engine. We assume that the
        user has already authorized this account for use with GCE.
    Returns:
      An apiclient.discovery.Resource that is a connection valid for requests
      to Google Compute Engine for the given user, and a Credentials object that
      can be used to sign requests performed with that connection.
    """
    # Perform OAuth 2.0 authorization.
    flow = oauth2client.client.flow_from_clientsecrets(
      parameters[self.PARAM_SECRETS], scope=self.GCE_SCOPE)
    storage = oauth2client.file.Storage(LocalState.get_oauth2_storage_location(
      parameters[self.PARAM_KEYNAME]))
    credentials = storage.get()

    if credentials is None or credentials.invalid:
      credentials = oauth2client.tools.run(flow, storage)

    # Build the service
    return apiclient.discovery.build('compute', self.API_VERSION), credentials


  def ensure_operation_succeeds(self, gce_service, auth_http, response,
    project_id):
    """ Waits for the given GCE operation to finish successfully.

    Callers should use this function whenever they perform a destructive
    operation in Google Compute Engine. For example, it is not necessary to use
    this function when seeing if a resource exists (e.g., a network, firewall,
    or instance), but it is useful to use this method when creating or deleting
    a resource. One example is when we create a network. As we are only allowed
    to have five networks, it is useful to make sure that the network was
    successfully created before trying to create a firewall attached to that
    network.

    Args:
      gce_service: An apiclient.discovery.Resource that is a connection valid
        for requests to Google Compute Engine for the given user.
      auth_http: A HTTP connection that has been signed with the given user's
        Credentials, and is authorized with the GCE scope.
      response: A dict that contains the operation that we want to ensure has
        succeeded, referenced by a unique ID (the 'name' field).
      project_id: A str that identifies the GCE project that requests should
        be billed to.
    """
    status = response['status']
    while status != 'DONE' and response:
      operation_id = response['name']

      # Identify if this is a per-zone resource
      if 'zone' in response:
        zone_name = response['zone'].split('/')[-1]
        request = gce_service.zoneOperations().get(
            project=project_id,
            operation=operation_id,
            zone=zone_name)
      else:
        request = gce_service.globalOperations().get(
             project=project_id, operation=operation_id)

      response = request.execute(auth_http)
      if response:
        status = response['status']

        if 'error' in response:
          message = "\n".join([errors['message'] for errors in
            response['error']['errors']])
          raise AgentRuntimeException(str(message))
