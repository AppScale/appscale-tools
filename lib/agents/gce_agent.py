#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os.path


# AppScale-specific imports
from agents.base_agent import AgentConfigurationException
from agents.base_agent import BaseAgent 


class GCEAgent(BaseAgent):


  PARAM_GROUP = 'group'


  PARAM_IMAGE_ID = 'image_id'


  PARAM_KEYNAME = 'keyname'

  
  PARAM_SECRETS = 'client_secrets'


  REQUIRED_CREDENTIALS = (
    PARAM_GROUP,
    PARAM_IMAGE_ID,
    PARAM_KEYNAME,
    PARAM_SECRETS
  )


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
    raise NotImplementedError


  def cleanup_state(self, parameters):
    raise NotImplementedError


  def open_connection(self, parameters):
    raise NotImplementedError


  def handle_failure(self, msg):
    raise NotImplementedError
