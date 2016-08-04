#!/usr/bin/env python
"""
This file provides a single class, AzureAgent, that the AppScale Tools can use to
interact with Microsoft Azure.
"""

# General-purpose Python library imports
import json
import os.path
import shutil

# Azure specific imports
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.resource.resources.models import ResourceGroup

import adal

# AppScale-specific imports
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.local_state import LocalState
from base_agent import AgentConfigurationException
from base_agent import BaseAgent

class AzureAgent(BaseAgent):
  """ AzureAgent defines a specialized BasAgent that allows for interaction
  with Microsoft Azure.

  It authenticates using the ADAL (Active Directory Authentication Library) .
  """

  # The Azure URL endpoint that receives all the authentication requests.
  AZURE_AUTH_ENDPOINT = 'https://login.microsoftonline.com/'

  AZURE_RESOURCE_URL = 'https://management.core.windows.net/'

  # The following constants are string literals that can be used by callers to
  # index into the parameters that the user passes in, as opposed to having to
  # type out the strings each time we need them.
  PARAM_CREDS = 'azure_creds'

  PARAM_RESOURCE_GROUP = 'resource_group'

  PARAM_TEST = 'test'

  PARAM_TAG = 'group_tag'

  PARAM_VERBOSE = 'is_verbose'

  PARAM_ZONE = 'zone'

  def assert_credentials_are_valid(self, parameters):
    """ Contacts Azure with the given credentials to ensure that they are
    valid. Gets an access token and a Credentials instance in order to be
    able to access any resources.
    Args:
      parameters: A dict containing credentials necessary to interact with Azure.
    Raises:
      AgentConfigurationException: If the given credentials cannot be used to
        make requests to the underlying cloud.
    """
    creds_location = os.path.expanduser(parameters[self.PARAM_CREDS])
    with open(creds_location) as creds_file:
      creds_json = creds_file.read()
    creds = json.loads(creds_json)

    # Get an Azure access token using ADAL.
    context = adal.AuthenticationContext(
      self.AZURE_AUTH_ENDPOINT + creds['tenant_id'])
    token_response = context.acquire_token_with_client_credentials(
      self.AZURE_RESOURCE_URL, creds['app_id'], creds['app_secret'])
    auth_token = token_response.get('accessToken')

    # To access Azure resources for an application, we need a Service Principal
    # which contains a role assignment. It can be created using the Azure CLI.
    credentials = ServicePrincipalCredentials(client_id = creds['app_id'],
                                              secret = creds['app_secret'],
                                              tenant = creds['tenant_id'])

    # Create a default 'appscalegroup' resource group if none is specified.
    resource_client = ResourceManagementClient(credentials, str(creds['subscription_id']))
    resource_groups = resource_client.resource_groups.list()

    resource_group_name = 'appscale-group'
    if parameters[self.PARAM_RESOURCE_GROUP]:
      resource_group_name = parameters[self.PARAM_RESOURCE_GROUP]

    tag_name = 'default-tag'
    if parameters[self.PARAM_TAG]:
      tag_name = parameters[self.PARAM_RESOURCE_GROUP]

    if (not resource_group_name in resource_groups):
      resource_client.resource_groups.create_or_update(
        resource_group_name, ResourceGroup(location=parameters[self.PARAM_ZONE],
                                           tags={'tag': tag_name}))

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

  def run_instances(self, count, parameters, security_configured):
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

  def associate_static_ip(self, instance_id, static_ip):
    """Associates the given static IP address with the given instance ID.

    Args:
      instance_id: A str that names the instance that the static IP should be
        bound to.
      static_ip: A str naming the static IP to bind to the given instance.
    """

  def terminate_instances(self, parameters):
    """Terminate a set of virtual machines using the parameters given.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
    """

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

  def does_image_exist(self, parameters):
    """Verifies that the specified machine image exists in this cloud.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud, as well as a key indicating which machine image should
        be checked for existence.
    Returns:
      A bool that indicates if the machine image exists in this cloud.
    """
    return True

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

  def does_zone_exist(self, parameters):
    """Verifies that the specified zone exists in this cloud.

    Args:
      parameters: A dict that includes a key indicating the zone to check for
        existence.
    Returns:
      True if the zone exists, and False otherwise.
    """


  def cleanup_state(self, parameters):
    """Removes any remote state that was created to run AppScale instances
    during this deployment.

    Args:
      parameters: A dict that includes keys indicating the remote state
        that should be deleted.
    """

  def get_params_from_args(self, args):
    """ Constructs a dict with only the parameters necessary to interact with
    Microsoft Azure (mainly the an azure_creds JSON file).

    Args:
      args: A Namespace or dict that maps all of the arguments the user has
        invoked an AppScale command with their associated value.
    Returns:
      A dict that maps each argument given to the value that was associated with
      it.
    Raises:
      Agen

    """
    if not isinstance(args, dict):
      args = vars(args)

    if not args.get('azure_creds'):
      raise AgentConfigurationException("Please specify a JSON file location "
        "in the azure_creds section of your AppScalefile when running "
        "over Microsoft Azure.")

    credentials_file = args.get('azure_creds')
    full_credentials = os.path.expanduser(credentials_file)
    if not os.path.exists(full_credentials):
      raise AgentConfigurationException("Couldn't find your credentials at {0}".
        format(full_credentials))

    destination = LocalState.get_client_secrets_location(args['keyname'])
    # Make sure the destination's parent directory exists.
    destination_parent = os.path.abspath(os.path.join(destination, os.pardir))
    if not os.path.exists(destination_parent):
      os.makedirs(destination_parent)

    shutil.copy(full_credentials, destination)

    params = {
      self.PARAM_RESOURCE_GROUP : args['resource_group'],
      self.PARAM_TEST : args['test'],
      self.PARAM_CREDS : args['azure_creds'],
      self.PARAM_VERBOSE : args.get('verbose', False),
      self.PARAM_TAG : args['group_tag'],
      self.PARAM_ZONE : args['zone']
    }
    self.assert_credentials_are_valid(params)
    return params

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


