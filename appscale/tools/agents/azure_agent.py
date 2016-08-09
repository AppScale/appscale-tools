#!/usr/bin/env python
"""
This file provides a single class, AzureAgent, that the AppScale Tools can use to
interact with Microsoft Azure.
"""

# General-purpose Python library imports
import adal
import json
import os.path
import shutil

# Azure specific imports
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.resource.resources.models import ResourceGroup
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountCreateParameters, Sku, SkuName, Kind
from msrestazure.azure_exceptions import CloudError

# AppScale-specific imports
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.local_state import LocalState
from base_agent import AgentConfigurationException
from base_agent import BaseAgent

class AzureAgent(BaseAgent):
  """ AzureAgent defines a specialized BaseAgent that allows for interaction
  with Microsoft Azure. It authenticates using the ADAL (Active Directory
  Authentication Library).
  """

  # The Azure URL endpoint that receives all the authentication requests.
  AZURE_AUTH_ENDPOINT = 'https://login.microsoftonline.com/'

  # The Azure resource URL to get the auth token using client credentials.
  AZURE_RESOURCE_URL = 'https://management.core.windows.net/'

  # Default storage account name to use for Azure in case none specified.
  DEFAULT_STORAGE_ACCT = 'appscalestorage'

  # Default resource group name to use for Azure in case none specified.
  DEFAULT_RESOURCE_GROUP = 'appscale-group'

  # The following constants are string literals that can be used by callers to
  # index into the parameters that the user passes in, as opposed to having to
  # type out the strings each time we need them.
  PARAM_CREDS = 'azure_creds'

  PARAM_EXISTING_RG = 'does_exist'

  PARAM_RESOURCE_GROUP = 'resource_group'

  PARAM_STORAGE_ACCOUNT = 'storage_account'

  PARAM_TEST = 'test'

  PARAM_TAG = 'group_tag'

  PARAM_VERBOSE = 'is_verbose'

  PARAM_ZONE = 'zone'

  # A set that contains all of the items necessary to run AppScale in Azure.
  REQUIRED_CREDENTIALS = (PARAM_CREDS, PARAM_ZONE)

  def assert_credentials_are_valid(self, parameters):
    """ Contacts Azure with the given credentials to ensure that they are
    valid. Gets an access token and a Credentials instance in order to be
    able to access any resources.
    Args:
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
    Returns:
      True, if the credentials were valid.
      A list, of resource group names under the subscription.
    Raises:
      AgentConfigurationException: If an error is encountered during
        authentication.
    """
    creds_dict, credentials = self.open_connection(parameters)
    try:
      resource_client = ResourceManagementClient(credentials, str(creds_dict['subscription_id']))
      resource_groups = resource_client.resource_groups.list()
      rg_names = []
      for rg in resource_groups:
        rg_names.append(rg.name)
      return True, rg_names
    except CloudError as error:
      raise AgentConfigurationException("Unable to authenticate using the "
        "credentials provided. Reason: {}".format(error.message))

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
    """ Starts 'count' instances in Microsoft Azure, and returns once they
    have been started.

    Callers should create a network and attach a firewall to it before using
    this method, or the newly created instances will not have a network and
    firewall to attach to (and thus this method will fail).

    Args:
      count: An int, that specifies how many virtual machines should be started.
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      security_configured: Unused, as we assume that the network and firewall
        has already been set up.
    """
    creds_dict, credentials = self.open_connection(parameters)
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    storage_account = parameters[self.PARAM_STORAGE_ACCOUNT]
    zone = parameters[self.PARAM_ZONE]
    AppScaleLogger.log("Starting {0} machines under resource group '{1}' with "
                       "storage account '{2}' in zone '{3}'".
                       format(count,resource_group, storage_account, zone))
    # Create a resource group and an associated storage account to access resources.
    self.create_resource_group(parameters, creds_dict, credentials)

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
    return True

  def cleanup_state(self, parameters):
    """Removes any remote state that was created to run AppScale instances
    during this deployment.

    Args:
      parameters: A dict that includes keys indicating the remote state
        that should be deleted.
    """

  def get_params_from_args(self, args):
    """ Constructs a dict with only the parameters necessary to interact with
    Microsoft Azure (mainly the Azure credentials JSON file).

    Args:
      args: A Namespace or dict, that maps all of the arguments the user has
        invoked an AppScale command with their associated value.
    Returns:
      A dict, that maps each argument given to the value that was associated with
      it.
    Raises:
      AgentConfigurationException: If the caller fails to specify an Azure
      credentials JSON file, or if it doesn't exist on the local filesystem.
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
      self.PARAM_CREDS: args[self.PARAM_CREDS],
      self.PARAM_RESOURCE_GROUP: args[self.PARAM_RESOURCE_GROUP],
      self.PARAM_STORAGE_ACCOUNT: args[self.PARAM_STORAGE_ACCOUNT],
      self.PARAM_TAG: args[self.PARAM_TAG],
      self.PARAM_TEST: args[self.PARAM_TEST],
      self.PARAM_VERBOSE : args.get(self.PARAM_VERBOSE, False),
      self.PARAM_ZONE : args[self.PARAM_ZONE]
    }
    is_valid, rg_names = self.assert_credentials_are_valid(params)
    if not is_valid:
      raise AgentConfigurationException("Unable to authenticate using the "
                                        "credentials provided.")

    # Check if the resource group passed in exists already, if it does then
    # pass an existing group flag and if not, then create a new group.
    # In case no resource group is passed, create a default appscale-group.
    params[self.PARAM_EXISTING_RG] = False
    if not args[self.PARAM_RESOURCE_GROUP]:
      params[self.PARAM_RESOURCE_GROUP] = self.DEFAULT_RESOURCE_GROUP

    if args[self.PARAM_RESOURCE_GROUP] in rg_names:
      params[self.PARAM_EXISTING_RG] = True
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
    # Make sure that the user has set each parameter.
    for param in self.REQUIRED_CREDENTIALS:
      if not self.has_parameter(param, parameters):
        raise AgentConfigurationException('The required parameter, {0}, was not '
                                          'specified.'.format(param))

    # Next, make sure that the azure_creds JSON file exists.
    credentials_file = parameters.get(self.PARAM_CREDS)
    if not os.path.exists(os.path.expanduser(credentials_file)):
      raise AgentConfigurationException('Could not find your credentials ' \
                                        'file at {0}'.format(credentials_file))

  def open_connection(self, parameters):
    """ Connects to Microsoft Azure with the given credentials, creates a
    an authentication token and uses that to get the ServicePrincipalCredentials
    which is needed to access any resources.

    Args:
      parameters: A dict, containing all the parameters necessary to authenticate
      this user with Azure. We assume that the user has already authorized this
      account by creating a Service Principal with the appropriate (Contributor)
      role.
    Returns:
      A dict, created from the path specified for credentials JSON file.
      A ServicePrincipalCredentials instance, that can be used to access or
      create any resources.
    """
    # Creates a credentials dictionary from the JSON file specified in the
    # AppScalefile.
    creds_location = os.path.expanduser(parameters[self.PARAM_CREDS])
    with open(creds_location) as creds_file:
      creds_json = creds_file.read()
    creds = json.loads(creds_json)

    # Get an Authentication token using ADAL.
    context = adal.AuthenticationContext(
      self.AZURE_AUTH_ENDPOINT + creds['tenant_id'])
    token_response = context.acquire_token_with_client_credentials(
      self.AZURE_RESOURCE_URL, creds['app_id'], creds['app_secret'])
    token_response.get('accessToken')

    # To access Azure resources for an application, we need a Service Principal
    # which contains a role assignment. It can be created using the Azure CLI.
    sp_credentials = ServicePrincipalCredentials(client_id=creds['app_id'],
                                                 secret=creds['app_secret'],
                                                 tenant=creds['tenant_id'])
    return creds, sp_credentials

  def create_resource_group(self, parameters, creds_dict, credentials):
    """ Creates a Resource Group for the application using the Service Principal
    Credentials, if it does not already exist. In the case where no resource
    group is specified, a default 'appscale-group' is created.

    Args:
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      creds_dict: A dict, containing all the credentials needed to talk to Azure.
      credentials: A ServicePrincipalCredentials instance, that can be used to
      access or create any resources.
    Raises:
      AgentConfigurationException: If there was a problem creating or accessing
        a resource group with the given subscription.
    """
    subscription_id = str(creds_dict['subscription_id'])
    resource_client = ResourceManagementClient(credentials, subscription_id)
    rg_name = parameters[self.PARAM_RESOURCE_GROUP]

    tag_name = 'default-tag'
    if parameters[self.PARAM_TAG]:
      tag_name = parameters[self.PARAM_TAG]

    storage_client = StorageManagementClient(credentials, subscription_id)
    try:
      # If the resource group does not already exist, create a new one with the
      # specified storage account.
      if not parameters[self.PARAM_EXISTING_RG]:
        AppScaleLogger.log("Creating a new resource group '{0}' with the tag '{1}'.".
                           format(rg_name, tag_name))
        resource_client.resource_groups.create_or_update(
          rg_name, ResourceGroup(location=parameters[self.PARAM_ZONE],
                                 tags={'tag': tag_name}))
        self.create_storage_account(parameters, storage_client)
      else:
        # If it already exists, check if the specified storage account exists
        # under it and if not, create a new account.
        storage_accounts = storage_client.storage_accounts.list_by_resource_group(rg_name)
        stg_account_names = []
        for account in storage_accounts:
          stg_account_names.append(account.name)

        if parameters[self.PARAM_STORAGE_ACCOUNT] or self.DEFAULT_STORAGE_ACCT in stg_account_names:
            AppScaleLogger.log("Storage account '{0}' under '{1}' resource group "
                               "already exists. So not creating it again.".
                               format(account.name, rg_name))
        else:
          self.create_storage_account(parameters, storage_client)
    except CloudError as error:
      raise AgentConfigurationException("Unable to create a resource group using "
                                        "the credentials provided: {}".format(error.message))

  def create_storage_account(self, parameters, storage_client):
    """ Creates a Storage Account under the Resource Group, if it does not
    already exist. In the case where no resource group is specified, a default
    'appscalestorage' account is created.

    Args:
      parameters: A dict, containing all the parameters necessary to authenticate
        this user with Azure.
      creds_dict: A dict, containing all the credentials needed to talk to Azure.
      credentials: A ServicePrincipalCredentials instance, that can be used to access or
      create any resources.
    Raises:
      AgentConfigurationException: If there was a problem creating or accessing
        a storage account with the given subscription.
    """
    storage_account = self.DEFAULT_STORAGE_ACCT
    rg_name = parameters[self.PARAM_RESOURCE_GROUP]
    if parameters[self.PARAM_STORAGE_ACCOUNT]:
      storage_account = parameters[self.PARAM_STORAGE_ACCOUNT]

    try:
      AppScaleLogger.log("Creating a new storage account '{0}' under the resource "
                         "group '{1}'.".format(storage_account, rg_name))
      result = storage_client.storage_accounts.create(rg_name, storage_account,
                                                      StorageAccountCreateParameters(
                                                        sku=Sku(SkuName.standard_lrs),
                                                        kind=Kind.storage,
                                                        location=parameters[self.PARAM_ZONE]))
      # result is a msrestazure.azure_operation.AzureOperationPoller instance
      # wait insure polling the underlying async operation until it's done.
      result.wait()
    except CloudError as error:
      raise AgentConfigurationException("Unable to create a storage account using "
                                        "the credentials provided: {}".format(error.message))
    