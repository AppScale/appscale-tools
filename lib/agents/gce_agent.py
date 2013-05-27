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


  PARAM_GROUP = 'group'


  PARAM_IMAGE_ID = 'image_id'


  PARAM_INSTANCE_IDS = 'instance_ids'


  PARAM_KEYNAME = 'keyname'


  PARAM_PROJECT = 'project'

  
  PARAM_SECRETS = 'client_secrets'


  PARAM_VERBOSE = 'is_verbose'


  # A set that contains all of the items necessary to run AppScale in Google
  # Compute Engine.
  REQUIRED_CREDENTIALS = (
    PARAM_GROUP,
    PARAM_IMAGE_ID,
    PARAM_KEYNAME,
    PARAM_PROJECT,
    PARAM_SECRETS
  )


  # The OAuth 2.0 scope used to interact with Google Compute Engine.
  GCE_SCOPE = 'https://www.googleapis.com/auth/compute'


  # The version of the Google Compute Engine API that we support.
  API_VERSION = 'v1beta14'


  # The URL endpoint that receives Google Compute Engine API requests.
  GCE_URL = 'https://www.googleapis.com/compute/%s/projects/'.format(API_VERSION)


  # The zone that instances should be created in and removed from.
  DEFAULT_ZONE = 'us-central1-a'


  # The instance type that we should run AppScale on in Google Compute Engine.
  # TODO(cgb): Make this a parameter that the user can specify, and validate it
  # in ParseArgs.
  DEFAULT_MACHINE_TYPE = 'n1-standard-1'


  # The person to contact if there is a problem with the instance. We set this
  # to 'default' to not have to actually put anyone's personal information in.
  DEFAULT_SERVICE_EMAIL = 'default'


  # The location on the local filesystem where SSH private keys used with
  # Google Compute Engine are stored, by default.
  GCE_PRIVATE_SSH_KEY = os.path.expanduser("~/.ssh/google_compute_engine")


  # The location on the local filesystem where SSH public keys uploaded to
  # Google Compute Engine are stored, by default.
  GCE_PUBLIC_SSH_KEY = GCE_PRIVATE_SSH_KEY + ".pub"


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
    if not os.path.exists(self.GCE_PRIVATE_SSH_KEY):
      raise AgentRuntimeException("Couldn't find your GCE private key at {0}" \
        .format(self.GCE_PRIVATE_SSH_KEY))

    if not os.path.exists(self.GCE_PUBLIC_SSH_KEY):
      raise AgentRuntimeException("Couldn't find your GCE public key at {0}" \
        .format(self.GCE_PUBLIC_SSH_KEY))

    # Now that we know that the SSH keys exist, copy them to ~/.appscale.
    keyname = parameters[self.PARAM_KEYNAME]
    private_key = '{0}{1}.key'.format(LocalState.LOCAL_APPSCALE_PATH, keyname)
    public_key = '{0}{1}.pub'.format(LocalState.LOCAL_APPSCALE_PATH, keyname)
    shutil.copy(self.GCE_PRIVATE_SSH_KEY, private_key)
    shutil.copy(self.GCE_PUBLIC_SSH_KEY, public_key)

    if self.does_network_exist(parameters):
      raise AgentRuntimeException("Network already exists - please use a " + \
        "different group name.")

    if self.does_firewall_exist(parameters):
      raise AgentRuntimeException("Firewall already exists - please use a " + \
        "different group name.")

    network_url = self.create_network(parameters)
    self.create_firewall(parameters, network_url)


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
    self.ensure_operation_succeeds(gce_service, auth_http, response, parameters[self.PARAM_PROJECT])
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
    self.ensure_operation_succeeds(gce_service, auth_http, response, parameters[self.PARAM_PROJECT])


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
    self.ensure_operation_succeeds(gce_service, auth_http, response, parameters[self.PARAM_PROJECT])


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
    self.ensure_operation_succeeds(gce_service, auth_http, response, parameters[self.PARAM_PROJECT])


  def get_params_from_args(self, args):
    """ Constructs a dict with only the parameters necessary to interact with
    Google Compute Engine (here, the client_secrets file and the image name).

    Args:
      args: A Namespace or dict that maps all of the arguments the user has
        invoked an AppScale command with their associated value.
    Returns:
      A dict containing the location of the client_secrets file and that name
      of the image to use in GCE.
    """
    if not isinstance(args, dict):
      args = vars(args)

    client_secrets = os.path.expanduser(args['client_secrets'])
    if not os.path.exists(client_secrets):
      raise AgentConfigurationException("Couldn't find your client secrets " + \
        "file at {0}".format(client_secrets))
    shutil.copy(client_secrets, LocalState.get_client_secrets_location(
      args['keyname']))

    params = {
      self.PARAM_GROUP : args['group'],
      self.PARAM_IMAGE_ID : args['machine'],
      self.PARAM_KEYNAME : args['keyname'],
      self.PARAM_PROJECT : args['project'],
      self.PARAM_SECRETS : os.path.expanduser(args['client_secrets'])
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
      self.PARAM_VERBOSE : False  # TODO(cgb): Don't put False in here.
    }


  def assert_required_parameters(self, parameters, operation):
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
      zone=self.DEFAULT_ZONE
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
          public_ips.append(instance['networkInterfaces'][0]['accessConfigs'][0]['natIP'])
          private_ips.append(instance['networkInterfaces'][0]['networkIP'])

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
    instance_type = self.DEFAULT_MACHINE_TYPE  #parameters[self.PARAM_INSTANCE_TYPE]
    keyname = parameters[self.PARAM_KEYNAME]
    group = parameters[self.PARAM_GROUP]

    AppScaleLogger.log("Starting {0} machines with machine id {1}, with " \
      "instance type {2}, keyname {3}, in security group {4}".format(count,
      image_id, instance_type, keyname, group))

    # First, see how many instances are running and what their info is.
    start_time = datetime.datetime.now()
    active_public_ips, active_private_ips, active_instances = \
      self.describe_instances(parameters)

    # Construct URLs
    image_url = '{0}{1}/global/images/{2}'.format(self.GCE_URL, project_id, image_id)
    project_url = '{0}{1}'.format(self.GCE_URL, project_id)
    machine_type_url = '{0}/global/machineTypes/{1}'.format(project_url,
      instance_type)
    zone_url = '{0}/zones/{1}'.format(project_url, self.DEFAULT_ZONE)
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
           project=project_id, body=instances, zone=self.DEFAULT_ZONE)
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      self.ensure_operation_succeeds(gce_service, auth_http, response, parameters[self.PARAM_PROJECT])
    
    instance_ids = []
    public_ips = []
    private_ips = []
    end_time = datetime.datetime.now() + datetime.timedelta(0,
      self.MAX_VM_CREATION_TIME)
    now = datetime.datetime.now()

    while now < end_time:
      time_left = (end_time - now).seconds
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
    for instance_id in instance_ids:
      gce_service, credentials = self.open_connection(parameters)
      http = httplib2.Http()
      auth_http = credentials.authorize(http)
      request = gce_service.instances().delete(
        project=parameters[self.PARAM_PROJECT],
        zone=self.DEFAULT_ZONE,
        instance=instance_id
      )
      response = request.execute(auth_http)
      AppScaleLogger.verbose(str(response), parameters[self.PARAM_VERBOSE])
      self.ensure_operation_succeeds(gce_service, auth_http, response, parameters[self.PARAM_PROJECT])


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
    except apiclient.errors.HttpError as http_error:
      return False


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


  def ensure_operation_succeeds(self, gce_service, auth_http, response, project_id):
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
