#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os.path


# Third-party imports
import apiclient.discovery
import httplib2
import oauth2client.client
import oauth2client.file
import oauth2client.tools


# AppScale-specific imports
from agents.base_agent import AgentConfigurationException
from agents.base_agent import BaseAgent 


class GCEAgent(BaseAgent):


  PARAM_GROUP = 'group'


  PARAM_IMAGE_ID = 'image_id'


  PARAM_KEYNAME = 'keyname'


  PARAM_PROJECT = 'project'

  
  PARAM_SECRETS = 'client_secrets'


  REQUIRED_CREDENTIALS = (
    PARAM_GROUP,
    PARAM_IMAGE_ID,
    PARAM_KEYNAME,
    PARAM_PROJECT,
    PARAM_SECRETS
  )


  OAUTH2_STORAGE = 'oauth2.dat'


  GCE_SCOPE = 'https://www.googleapis.com/auth/compute'


  API_VERSION = 'v1beta15'


  GCE_URL = 'https://www.googleapis.com/compute/%s/projects/' % (API_VERSION)


  DEFAULT_ZONE = 'us-central1-a'


  def configure_instance_security(self, parameters):
    raise NotImplementedError


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

    return {
      self.PARAM_GROUP : args['group'],
      self.PARAM_IMAGE_ID : args['machine'],
      self.PARAM_KEYNAME : args['keyname'],
      self.PARAM_PROJECT : args['project'],
      self.PARAM_SECRETS : args['client_secrets']
    }


  def get_params_from_yaml(self, keyname):
    raise NotImplementedError


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

    return


  def describe_instances(self, parameters):
    raise NotImplementedError


  def run_instances(self, count, parameters, security_configured):
    raise NotImplementedError


  def stop_instances(self, parameters):
    raise NotImplementedError


  def terminate_instances(self, parameters):
    raise NotImplementedError


  def wait_for_status_change(self, parameters, conn, state_requested, \
                              max_wait_time=60,poll_interval=10):
    raise NotImplementedError


  def create_image(self, instance_id, name, parameters):
    raise NotImplementedError


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
      return True
    except apiclient.errors.HttpError as http_error:
      if http_error.resp.status == '404':
        return False
      else:
        raise http_error


  def cleanup_state(self, parameters):
    raise NotImplementedError


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
    storage = oauth2client.file.Storage(self.OAUTH2_STORAGE)
    credentials = storage.get()

    if credentials is None or credentials.invalid:
      credentials = oauth2client.tools.run(flow, storage)

    # Build the service
    return apiclient.discovery.build('compute', self.API_VERSION), credentials


  def handle_failure(self, msg):
    raise NotImplementedError
