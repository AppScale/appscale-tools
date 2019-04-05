#!/usr/bin/env python
"""
This file provides a single class, AzureAgent, that the AppScale Tools can use to
interact with Microsoft Azure.
"""

# General-purpose Python library imports
import adal
import concurrent.futures
import logging
import math
import os.path
import re
import time
from itertools import count, ifilter

# Azure specific imports
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import ApiEntityReference
from azure.mgmt.compute.models import AvailabilitySet
from azure.mgmt.compute.models import CachingTypes
from azure.mgmt.compute.models import DataDisk
from azure.mgmt.compute.models import DiskCreateOptionTypes
from azure.mgmt.compute.models import HardwareProfile
from azure.mgmt.compute.models import ImageReference
from azure.mgmt.compute.models import LinuxConfiguration
from azure.mgmt.compute.models import ManagedDiskParameters
from azure.mgmt.compute.models import NetworkProfile
from azure.mgmt.compute.models import NetworkInterfaceReference
from azure.mgmt.compute.models import OperatingSystemTypes
from azure.mgmt.compute.models import OSDisk
from azure.mgmt.compute.models import OSProfile
from azure.mgmt.compute.models import Sku as ComputeSku
from azure.mgmt.compute.models import SshConfiguration
from azure.mgmt.compute.models import SshPublicKey
from azure.mgmt.compute.models import StorageProfile
from azure.mgmt.compute.models import SubResource
from azure.mgmt.compute.models import UpgradePolicy
from azure.mgmt.compute.models import UpgradeMode
from azure.mgmt.compute.models import VirtualHardDisk
from azure.mgmt.compute.models import VirtualMachine
from azure.mgmt.compute.models import VirtualMachineScaleSet
from azure.mgmt.compute.models import VirtualMachineScaleSetIPConfiguration
from azure.mgmt.compute.models import VirtualMachineScaleSetNetworkConfiguration
from azure.mgmt.compute.models import VirtualMachineScaleSetNetworkProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetOSDisk
from azure.mgmt.compute.models import VirtualMachineScaleSetOSProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetStorageProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetVMProfile

from azure.mgmt.marketplaceordering.marketplace_ordering_agreements import MarketplaceOrderingAgreements

from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import AddressSpace
from azure.mgmt.network.models import IPAllocationMethod
from azure.mgmt.network.models import NetworkInterfaceIPConfiguration
from azure.mgmt.network.models import NetworkInterface
from azure.mgmt.network.models import PublicIPAddress
from azure.mgmt.network.models import Subnet
from azure.mgmt.network.models import VirtualNetwork

from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.resource.resources.models import ResourceGroup

from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountCreateParameters, SkuName, Kind
from azure.mgmt.storage.models import Sku as StorageSku

from msrestazure.azure_active_directory import ServicePrincipalCredentials
from msrest.exceptions import ClientException
from msrestazure.azure_exceptions import CloudError
from haikunator import Haikunator

# AppScale-specific imports
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.local_state import LocalState
from base_agent import AgentConfigurationException
from base_agent import AgentRuntimeException
from base_agent import BaseAgent

class AzureAgent(BaseAgent):
  """ AzureAgent defines a specialized BaseAgent that allows for interaction
  with Microsoft Azure. It authenticates using the ADAL (Active Directory
  Authentication Library).
  """
  # The Azure URL endpoint that receives all the authentication requests.
  AZURE_AUTH_ENDPOINT = 'https://login.microsoftonline.com/'

  # The Azure Resource URL to get the authentication token using client credentials.
  AZURE_RESOURCE_URL = 'https://management.core.windows.net/'

  # Default Storage Account name to use for Azure.
  DEFAULT_STORAGE_ACCT = 'appscalestorage'

  # Default resource group name to use for Azure.
  DEFAULT_RESOURCE_GROUP = 'appscalegroup'

  # Default resource tag name to use for Azure.
  DEFAULT_TAG = 'default-tag'

  # A list of Azure instance types that have less than 4 GB of RAM, the amount
  # recommended by Cassandra. AppScale will still run on these instance types,
  # but is likely to crash after a day or two of use (as Cassandra will attempt
  # to malloc ~800MB of memory, which will fail on these instance types).
  DISALLOWED_INSTANCE_TYPES = ["Basic_A0", "Basic_A1", "Basic_A2", "Basic_A3",
                               "Basic_A4", "Standard_A0", "Standard_A1",
                               "Standard_A2", "Standard_D1", "Standard_D1_v2",
                               "Standard_DS1", "Standard_DS1_v2"]

  # The following constants are string literals that can be used by callers to
  # index into the parameters that the user passes in, as opposed to having to
  # type out the strings each time we need them.
  PARAM_APP_ID = 'azure_app_id'
  PARAM_APP_SECRET = 'azure_app_secret_key'
  PARAM_DISKS = 'disks'
  PARAM_EXISTING_RG = 'does_exist'
  PARAM_RESOURCE_GROUP = 'azure_resource_group'
  PARAM_STORAGE_ACCOUNT = 'azure_storage_account'
  PARAM_SUBSCRIBER_ID = 'azure_subscription_id'
  PARAM_TENANT_ID = 'azure_tenant_id'
  PARAM_TAG = 'azure_group_tag'

  # A set that contains all of the items necessary to run AppScale in Azure.
  REQUIRED_CREDENTIALS = (
    PARAM_APP_SECRET,
    PARAM_APP_ID,
    BaseAgent.PARAM_IMAGE_ID,
    BaseAgent.PARAM_INSTANCE_TYPE,
    BaseAgent.PARAM_KEYNAME,
    PARAM_SUBSCRIBER_ID,
    PARAM_TENANT_ID,
    BaseAgent.PARAM_ZONE
  )

  # The regex for Azure Marketplace images.
  MARKETPLACE_IMAGE = re.compile(".*:.*:.*:.*")

  # The admin username needed to create an Azure VM instance.
  ADMIN_USERNAME = 'azureuser'

  # The number of seconds to sleep while polling for
  # Azure resources to get created/updated.
  SLEEP_TIME = 10

  # The maximum number of seconds to wait for Azure resources
  # to get created/updated.
  MAX_SLEEP_TIME = 60

  # The maximum number of seconds to wait for an Azure VM to be created.
  # (Takes longer than the creation time for other resources.)
  MAX_VM_UPDATE_TIME = 240

  # The maximum number of seconds to wait for an Azure scale set to be created.
  MAX_VMSS_WAIT_TIME = 300

  # The maximum limit of allowable VMs within a scale set.
  MAX_VMSS_CAPACITY = 20

  # The Virtual Network and Subnet name to use while creating an Azure
  # Virtual machine.
  VIRTUAL_NETWORK = 'appscaleazure'

  # The Compute Azure Resource provider namespace.
  MICROSOFT_COMPUTE_RESOURCE = 'Microsoft.Compute'

  # The Network Azure Resource provider namespace.
  MICROSOFT_NETWORK_RESOURCE = 'Microsoft.Network'

  # The Storage Azure Resource provider namespace.
  MICROSOFT_STORAGE_RESOURCE = 'Microsoft.Storage'

  # The compatible Network Management API version to use with scale sets.
  NETWORK_MGMT_API_VERSION = '2016-09-01'

  def assert_credentials_are_valid(self, parameters):
    """ Contacts Azure with the given credentials to ensure that they are
    valid. Gets an access token and a Credentials instance in order to be
    able to access any resources.
    Args:
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
    Raises:
      AgentConfigurationException: if we are unable to authenticate with Azure.
    """
    credentials = self.open_connection(parameters)
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    try:
      resource_client = ResourceManagementClient(credentials, subscription_id)
      # Try listing resource groups to make sure we can, a CloudError will be
      # raised if the credentials are invalid.
      resource_client.resource_groups.list()
    except ClientException as error:
      logging.exception("Error authenticating with provided credentials.")
      raise AgentConfigurationException("Unable to authenticate using the "
        "credentials provided. Reason: {}".format(error.message))

  def configure_instance_security(self, parameters):
    """ Configure the resource group and storage account needed to create the
    network interface for the VMs to be spawned. This method is called before
    starting virtual machines.
    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
    Returns:
      True, if the group and account were created successfully.
      False, otherwise.
    Raises:
      AgentRuntimeException: If security features could not be successfully
        configured in the underlying cloud.
      AgentConfigurationException: If we are unable to authenticate with Azure.
    """
    is_autoscale = parameters[self.PARAM_AUTOSCALE_AGENT]

    # While creating instances during autoscaling, we do not need to create a
    # new keypair or a resource group. We just make use of the existing one.
    if is_autoscale in ['True', True]:
      return

    credentials = self.open_connection(parameters)
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    storage_account = parameters.get(self.PARAM_STORAGE_ACCOUNT)
    zone = parameters[self.PARAM_ZONE]
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])

    AppScaleLogger.log("Verifying that SSH key exists locally.")
    keyname = parameters[self.PARAM_KEYNAME]
    private_key = LocalState.LOCAL_APPSCALE_PATH + keyname
    public_key = private_key + ".pub"

    if os.path.exists(private_key) or os.path.exists(public_key):
      raise AgentRuntimeException("SSH key already found locally - please "
                                  "use a different keyname.")

    LocalState.generate_rsa_key(keyname, parameters[self.PARAM_VERBOSE])

    AppScaleLogger.log("Configuring network for machine/s under "
                       "resource group '{0}' with storage account '{1}' "
                       "in zone '{2}'".format(resource_group, storage_account, zone))
    # Create a resource group and an associated storage account to access resources.
    self.create_resource_group(parameters, credentials)

    resource_client = ResourceManagementClient(credentials, subscription_id)
    try:
      resource_client.providers.register(self.MICROSOFT_COMPUTE_RESOURCE)
      resource_client.providers.register(self.MICROSOFT_NETWORK_RESOURCE)
    except CloudError as error:
      logging.exception("Encountered an error while registering provider.")
      raise AgentRuntimeException("Unable to register provider. Reason: {}"
                                  .format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to register provider. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

  def attach_disk(self, parameters, disk_name, instance_id):
    """ Attaches the persistent disk specified in 'disk_name' to this virtual
    machine.
    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
      disk_name: A str naming the managed disk to attach to this machine.
      instance_id: A str naming the id of the instance that the disk should be
        attached to.
    Returns:
      A str indicating a symlink to where the persistent disk has been
      attached to.
    Raises:
      AgentRuntimeException if the disk cannot be attached due to a
      CloudError or does not have a successful provisioning state.
    """
    credentials = self.open_connection(parameters)
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    compute_client = ComputeManagementClient(credentials, subscription_id)
    virtual_machine = compute_client.virtual_machines.get(resource_group,
                                                          instance_id)
    storage_profile = virtual_machine.storage_profile

    # pick the LUN (this must be unique)
    existing_luns = set()
    for disk in storage_profile.data_disks:
      # While we're looping check if disk is already attached and return the
      # symlink if it is.
      if disk.name == disk_name:
        return os.path.realpath('/dev/disk/azure/scsi1/lun{}'.format(disk.lun))
      existing_luns.add(disk.lun)

    # Get the first number not being used as a LUN.
    the_chosen_lun = next(ifilter(lambda lun: lun not in existing_luns, count(1)))

    disk = compute_client.disks.get(resource_group, disk_name)
    managed_disk_params = ManagedDiskParameters(id=disk.id)
    data_disk = DataDisk(lun=the_chosen_lun, name=disk.name,
                         create_option=DiskCreateOptionTypes.attach,
                         managed_disk=managed_disk_params)
    storage_profile.data_disks.append(data_disk)
    disk_response = compute_client.virtual_machines.create_or_update(
        resource_group, instance_id, virtual_machine)
    try:
      disk_response.wait(timeout=self.MAX_VM_UPDATE_TIME)
      result = disk_response.result()
      if result.provisioning_state == 'Succeeded':
        return os.path.realpath('/dev/disk/azure/scsi1/lun{}'.format(
            the_chosen_lun))
      else:
        raise AgentRuntimeException("Unable to attach disk {0} to "
                                    "VM {1}".format(disk_name, instance_id))
    except CloudError as error:
      raise AgentRuntimeException("Unable to attach disk {0} to "
          "VM {1}: {2}".format(disk_name, instance_id, error.message))

  def detach_disk(self, parameters, disk_name, instance_id):
    """ Detaches the persistent disk specified in 'disk_name' to this virtual
    machine.
    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
      disk_name: A str naming the managed disk to detach from this machine.
      instance_id: A str naming the id of the instance that the disk should be
        detached from.
    Returns:
      True if the disk was detached, and False otherwise.
    """
    credentials = self.open_connection(parameters)
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    compute_client = ComputeManagementClient(credentials, subscription_id)
    virtual_machine = compute_client.virtual_machines.get(resource_group,
                                                          instance_id)
    storage_profile = virtual_machine.storage_profile
    disks_to_keep = []

    for disk in storage_profile.data_disks:
      if disk.name != disk_name:
        disks_to_keep.append(disk)
      else:
        return True

    storage_profile.data_disks = disks_to_keep
    disk_response = compute_client.virtual_machines.create_or_update(
        resource_group, instance_id, virtual_machine)
    try:
      disk_response.wait(timeout=self.MAX_VM_UPDATE_TIME)
      result = disk_response.result()
      if result.provisioning_state == 'Succeeded':
        return True
      else:
        AppScaleLogger.log("Unable to detach Disk {} from VM {}".format(
            disk_name, instance_id))
        return False
    except CloudError as error:
      AppScaleLogger.log("Unable to detach Disk {} from VM {}: {}".format(
          disk_name, instance_id, error.message))
      return False

  def describe_instances(self, parameters, pending=False):
    """ Queries Microsoft Azure to see which instances are currently
    running, and retrieves information about their public and private IPs.
    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud.
      pending: If we should show pending instances.
    Returns:
      public_ips: A list of public IP addresses.
      private_ips: A list of private IP addresses.
      instance_ids: A list of unique Azure VM names.
    Raises:
      AgentRuntimeException: If we are unable to list instances in the
        cloud.
      AgentConfigurationException: If we are unable to authenticate with Azure.
    """
    credentials = self.open_connection(parameters)
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]

    network_client = NetworkManagementClient(credentials, subscription_id,
                                             api_version=self.NETWORK_MGMT_API_VERSION)
    compute_client = ComputeManagementClient(credentials, subscription_id)

    try:
      # Static IPs are not listed because AppScale does not create them.
      # They are used for creating Azure load balancers from the Portal,
      # which we would retain even on terminating the deployment and reuse
      # across multiple deployments.
      public_ips = [public_ip.ip_address for public_ip in
                    network_client.public_ip_addresses.list(resource_group)
                    if not public_ip.public_ip_allocation_method == 'Static']

      private_ips = [ip_config.private_ip_address
                     for network_interface in
                     network_client.network_interfaces.list(resource_group)
                     for ip_config in network_interface.ip_configurations]

      instance_ids = [vm.name for vm in
                      compute_client.virtual_machines.list(resource_group)]
      vm_vmss_list = [(vm, vmss.name)
         for vmss in compute_client.virtual_machine_scale_sets.list(
            resource_group)
         for vm in compute_client.virtual_machine_scale_set_vms.list(
            resource_group, vmss.name)]

      for vm, vmss_name in vm_vmss_list:
        network_interface_list = network_client.network_interfaces. \
          list_virtual_machine_scale_set_vm_network_interfaces(
            resource_group, vmss_name, vm.instance_id)
        private_ip = next(ip_config.private_ip_address
                          for network_interface in network_interface_list
                          for ip_config in network_interface.ip_configurations
                          if ip_config.private_ip_address)
        public_ips.append(private_ip)
        private_ips.append(private_ip)
        instance_ids.append(vm.name)
    except CloudError as e:
      logging.exception("CloudError received while trying to describe "
                        "instances.")
      raise AgentRuntimeException(e.message)
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to describe instances. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

    return public_ips, private_ips, instance_ids

  def run_instances(self, count, parameters, security_configured, public_ip_needed):
    """ Starts 'count' instances in Microsoft Azure, and returns once they
    have been started. Callers should create a network and attach a firewall
    to it before using this method, or the newly created instances will not
    have a network and firewall to attach to (and thus this method will fail).
    Args:
      count: An int, that specifies how many virtual machines should be started.
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      security_configured: Unused, as we assume that the network and firewall
        has already been set up.
    Returns:
      instance_ids: A list of unique Azure VM names.
      public_ips: A list of public IP addresses.
      private_ips: A list of private IP addresses.
    Raises:
      AgentRuntimeException: If an error has occurred talking to Azure.
    """
    credentials = self.open_connection(parameters)
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    virtual_network = parameters[self.PARAM_GROUP]
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]

    network_client = NetworkManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)

    subnet = self.create_virtual_network(network_client, parameters,
                                         virtual_network, virtual_network)

    active_public_ips, active_private_ips, active_instances = \
      self.describe_instances(parameters)

    # Create an Availability Set for Load Balancer VMs
    lb_avail_set_name = "lb-availability-set"
    availability_set_names = [availability_set.name for availability_set in
                              compute_client.availability_sets.list(resource_group)]
    azure_image_id = parameters[self.PARAM_IMAGE_ID]
    avail_set_sku = None
    if self.MARKETPLACE_IMAGE.match(azure_image_id):
      avail_set_sku = ComputeSku(name='Aligned')

    if lb_avail_set_name not in availability_set_names:
        lb_avail_set = self.create_lb_availability_set(
            compute_client, lb_avail_set_name, parameters, avail_set_sku)
    else:
        lb_avail_set = compute_client.availability_sets.get(resource_group, lb_avail_set_name)

    availability_set = SubResource(lb_avail_set.id)
    using_disks = parameters.get(self.PARAM_DISKS, False)

    if using_disks and not self.MARKETPLACE_IMAGE.match(azure_image_id):
      raise AgentConfigurationException("Managed Disks require use of a "
                                        "publisher image.")
    if public_ip_needed or using_disks:
      lb_vms_exceptions = []
      # Only load balancer VMs with public IPs are added to the availability set and
      # all other nodes with disks created as regular VMs outside of scaleset
      # should not be added.
      if using_disks and not public_ip_needed:
        availability_set = None
      # We can use a with statement to ensure threads are cleaned up promptly
      with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        lb_vms_futures = [executor.submit(self.setup_virtual_machine_creation,
                                          credentials, network_client, parameters,
                                          subnet, availability_set)
                                          for _ in range(count)]
        for future in concurrent.futures.as_completed(lb_vms_futures):
          exception = future.exception()
          if exception:
            lb_vms_exceptions.append(exception)

      for exception in lb_vms_exceptions:
        if not isinstance(exception, (CloudError, AgentRuntimeException)):
          logging.exception(exception)
      if lb_vms_exceptions:
        raise AgentRuntimeException(str(lb_vms_exceptions))
    else:
      self.create_or_update_vm_scale_sets(count, parameters, subnet)

    public_ips, private_ips, instance_ids = self.describe_instances(parameters)
    public_ips = self.diff(public_ips, active_public_ips)
    private_ips = self.diff(private_ips, active_private_ips)
    instance_ids = self.diff(instance_ids, active_instances)

    return instance_ids, public_ips, private_ips

  def create_lb_availability_set(self, compute_client, lb_avail_set_name, parameters, avail_set_sku=None):
    """ Creates an Availability Set for the load balancer VMs.
    Args:
        compute_client: A ComputeManagementClient instance
        lb_avail_set_name: The name to use for the availability set.
        parameters: A dict, containing all the parameters necessary to
          authenticate this user with Azure.
    Raises:
        AgentConfigurationException: If the operation to create an availability
          set did not succeed.
    """
    try:
      # The max number of available platform update and fault domains is 3.
      return compute_client.availability_sets.create_or_update(
        parameters[self.PARAM_RESOURCE_GROUP], lb_avail_set_name,
        AvailabilitySet(location=parameters[self.PARAM_ZONE],
                        sku=avail_set_sku, platform_update_domain_count=3,
                        platform_fault_domain_count=3))

    except CloudError as error:
      logging.exception("Azure agent received a CloudError while creating an "
                        "availability set.")
      raise AgentRuntimeException("Unable to create an Availability Set "
                                  "{0}: {1}".format(lb_avail_set_name,
                                                    error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
                                        "while trying to create an availability set. "
                                        "Please check your cloud configuration. "
                                        "Reason: {}".format(e.message))

  def setup_virtual_machine_creation(self, credentials, network_client,
                                     parameters, subnet, availability_set):
    """ Sets up the network interface and creates the virtual machines needed
    with the load balancer roles.
    Args:
      credentials: A ServicePrincipalCredentials instance, that can be used to
        access or create any resources.
      network_client: A NetworkManagementClient instance.
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      subnet: A Subnet instance from the Virtual Network created.
      availability_set: An Availability Set instance for the load balancer VMs.
    """
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    vm_network_name = Haikunator().haikunate()
    self.create_network_interface(network_client, vm_network_name,
                                  vm_network_name, subnet, parameters)
    network_interface = network_client.network_interfaces.get(
      resource_group, vm_network_name)
    self.create_virtual_machine(credentials, network_client,
                                network_interface.id,
                                parameters, vm_network_name,
                                availability_set)

  def create_virtual_machine(self, credentials, network_client, network_id,
                             parameters, vm_network_name, availability_set):
    """ Creates an Azure virtual machine using the network interface created.
    Args:
      credentials: A ServicePrincipalCredentials instance, that can be used to
        access or create any resources.
      network_client: A NetworkManagementClient instance.
      network_id: The network id of the network interface created.
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      vm_network_name: The name of the virtual machine to use.
      availability_set: An Availability Set instance for the load balancer VMs.
    Raises:
      AgentRuntimeException: If a virtual machine could not be successfully
        created.
      AgentConfigurationException: If we are unable to authenticate with Azure.
    """
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    zone = parameters[self.PARAM_ZONE]
    verbose = parameters[self.PARAM_VERBOSE]
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    azure_instance_type = parameters[self.PARAM_INSTANCE_TYPE]
    AppScaleLogger.verbose("Creating a Virtual Machine '{}'".
                           format(vm_network_name), verbose)

    compute_client = ComputeManagementClient(credentials, subscription_id)
    linux_config = self.create_linux_configuration(parameters)

    os_profile = OSProfile(admin_username=self.ADMIN_USERNAME,
                           computer_name=vm_network_name,
                           linux_configuration=linux_config)

    hardware_profile = HardwareProfile(vm_size=azure_instance_type)

    network_profile = NetworkProfile(
      network_interfaces=[NetworkInterfaceReference(id=network_id)])

    os_type = OperatingSystemTypes.linux
    azure_image_id = parameters[self.PARAM_IMAGE_ID]

    image_ref = None
    image_hd = None
    plan = None
    virtual_hd = None

    # Publisher images are formatted Publisher:Offer:Sku:Tag
    if self.MARKETPLACE_IMAGE.match(azure_image_id):
      publisher, offer, sku, version = azure_image_id.split(":")
      compatible_zone = zone.lower().replace(" ", "")

      image = compute_client.virtual_machine_images.get(
          compatible_zone, publisher, offer, sku, version)
      image_ref = ImageReference(publisher=publisher,
                                 offer=offer,
                                 sku=sku,
                                 version=version)
      plan = image.plan
    else:
      storage_account = parameters[self.PARAM_STORAGE_ACCOUNT]
      virtual_hd = VirtualHardDisk(
        uri='https://{0}.blob.core.windows.net/vhds/{1}.vhd'.
          format(storage_account, vm_network_name))
      image_hd = VirtualHardDisk(uri=parameters[self.PARAM_IMAGE_ID])

    os_disk = OSDisk(os_type=os_type, caching=CachingTypes.read_write,
                     create_option=DiskCreateOptionTypes.from_image,
                     name=vm_network_name, vhd=virtual_hd, image=image_hd)
    storage_profile = StorageProfile(image_reference=image_ref,
                                     os_disk=os_disk)
    try:
      compute_client.virtual_machines.create_or_update(
          resource_group, vm_network_name, VirtualMachine(location=zone,
            plan=plan, os_profile=os_profile, hardware_profile=hardware_profile,
            network_profile=network_profile, storage_profile=storage_profile,
            availability_set=availability_set))
      # Sleep until an IP address gets associated with the VM.
      while True:
        public_ip_address = network_client.public_ip_addresses.get(
          resource_group, vm_network_name)
        if public_ip_address.ip_address:
          AppScaleLogger.log('Azure load balancer VM is available at {}'.
                             format(public_ip_address.ip_address))
          break
        AppScaleLogger.verbose("Waiting {} second(s) for IP address to be "
                               "available".format(self.SLEEP_TIME), verbose)
        time.sleep(self.SLEEP_TIME)
    except CloudError as error:
      logging.exception("Azure agent received a CloudError.")
      raise AgentRuntimeException("Unable to create virtual machine. "
                                  "Reason: {}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to create virtual machine. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

  def create_linux_configuration(self, parameters):
    """ Creates a Linux Configuration to pass in to the virtual machine
    instance to be created.
    Args:
        parameters: A dict, containing all the parameters necessary to
          authenticate this user with Azure.
    Returns:
        An instance of LinuxConfiguration
    """
    is_autoscale = parameters[self.PARAM_AUTOSCALE_AGENT]
    keyname = parameters[self.PARAM_KEYNAME]
    private_key_path = LocalState.LOCAL_APPSCALE_PATH + keyname
    public_key_path = private_key_path + ".pub"
    auth_keys_path = "/home/{}/.ssh/authorized_keys".format(self.ADMIN_USERNAME)

    if is_autoscale in ['True', True]:
      public_key_path = auth_keys_path

    with open(public_key_path, 'r') as pub_ssh_key_fd:
      pub_ssh_key = pub_ssh_key_fd.read()

    public_keys = [SshPublicKey(path=auth_keys_path, key_data=pub_ssh_key)]
    ssh_config = SshConfiguration(public_keys=public_keys)
    linux_config = LinuxConfiguration(disable_password_authentication=True,
                                      ssh=ssh_config)
    return linux_config

  def add_instances_to_existing_ss(self, count, parameters):
    """ Looks through existing scale sets in a particular resource group and
    adds instances (created as a part of autoscaling) to the ones which have
    additional capacity.
    Args:
        count: The number of instances to be created for autoscaling.
        parameters: A dict, containing all the parameters necessary to
          authenticate this user with Azure.
    Returns:
        The number of instances created and added to the existing scale sets.
    Raises:
    Raises:
      AgentRuntimeException: If instances could not successfully be added to
        a Scale Set.
      AgentConfigurationException: If we are unable to authenticate with Azure.
    """
    credentials = self.open_connection(parameters)
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    instance_type = parameters[self.PARAM_INSTANCE_TYPE]
    compute_client = ComputeManagementClient(credentials, subscription_id)

    num_instances_added = 0
    try:
      scalesets_and_counts = []
      for vmss in compute_client.virtual_machine_scale_sets.list(
          resource_group):
        ss_instance_count = len(list(
          compute_client.virtual_machine_scale_set_vms.list(resource_group, vmss.name)))

        if ss_instance_count >= self.MAX_VMSS_CAPACITY:
          continue

        if not vmss.sku.name == instance_type:
          continue
        vmss = compute_client.virtual_machine_scale_sets.get(resource_group,
                                                             vmss.name)
        scalesets_and_counts.append((vmss, ss_instance_count))
    except CloudError as error:
      logging.exception("Azure agent received a CloudError trying to add "
                        "to Scale Sets.")
      raise AgentRuntimeException("Unable to add to Scale Sets due to: {}"
                                  .format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to add to Scale Sets. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

    for vmss, ss_instance_count in scalesets_and_counts:
      ss_upgrade_policy = vmss.upgrade_policy
      ss_location = vmss.location
      ss_profile = vmss.virtual_machine_profile
      ss_overprovision = vmss.overprovision

      new_capacity = min(ss_instance_count + count, self.MAX_VMSS_CAPACITY)
      sku = ComputeSku(name=parameters[self.PARAM_INSTANCE_TYPE],
                       capacity=new_capacity)
      scaleset = VirtualMachineScaleSet(sku=sku,
                                        upgrade_policy=ss_upgrade_policy,
                                        location=ss_location,
                                        virtual_machine_profile=ss_profile,
                                        overprovision=ss_overprovision)
      try:
        create_update_response = compute_client.virtual_machine_scale_sets. \
          create_or_update(resource_group, vmss.name, scaleset)

        self.wait_for_ss_update(new_capacity, create_update_response, vmss.name)
      except CloudError as error:
        logging.exception("Azure agent received a CloudError.")
        raise AgentRuntimeException("Unable to create/update ScaleSet. "
                                    "Reason: {}".format(error.message))
      except ClientException as e:
        logging.exception("ClientException received while attempting to contact"
          " Azure.")
        raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to create/update ScaleSet. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

      newly_added = new_capacity - ss_instance_count
      num_instances_added += newly_added
      count -= newly_added

      # If all the additional instances to be created fit within the
      # capacity of existing scale sets.
      if count == 0:
        break

    return num_instances_added

  def create_or_update_vm_scale_sets(self, count, parameters, subnet):
    """ Creates/Updates a virtual machine scale set containing the given number
    of virtual machines with the virtual network provided.
    Args:
        count: The number of virtual machines to be created in the scale set.
        parameters: A dict, containing all the parameters necessary to
          authenticate this user with Azure.
        subnet:A reference to the subnet ID of the virtual network created.
    Raises:
        AgentConfigurationException: If the operation to create a virtual
        machine scale set did not succeed.
    """
    verbose = parameters[self.PARAM_VERBOSE]
    random_resource_name = Haikunator().haikunate()

    num_instances_to_add = count

    # While autoscaling, look through existing scale sets to check if they have
    # capacity to hold more vms. If they do, update the scale sets with additional
    # vms. If not, then create a new scale set for them.
    is_autoscale = parameters[self.PARAM_AUTOSCALE_AGENT]
    if is_autoscale in ['True', True]:
      instances_added = self.add_instances_to_existing_ss(
        num_instances_to_add, parameters)
      # Exceeded capacity of existing scale sets, so create a new scale set.
      if num_instances_to_add > instances_added:
        num_instances_to_add = num_instances_to_add - instances_added
      else:
        # The required number of instances fit within existing scale sets.
        return

    # Create multiple scale sets with the allowable maximum capacity of VMs.
    if num_instances_to_add > self.MAX_VMSS_CAPACITY:
      # Count of the number of scale sets needed depending on the max capacity.
      scale_set_count = int(math.ceil(num_instances_to_add / float(
        self.MAX_VMSS_CAPACITY)))
      remaining_vms_count = num_instances_to_add

      scalesets_futures = []
      scalesets_exceptions = []
      # We can use a with statement to ensure threads are cleaned up promptly
      with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        for ss_count in range(scale_set_count):
          resource_name = random_resource_name + "-resource-{}".format(ss_count)
          scale_set_name = random_resource_name + "-scaleset-{}".format(
            ss_count)
          capacity = self.MAX_VMSS_CAPACITY
          if remaining_vms_count < self.MAX_VMSS_CAPACITY:
            capacity = remaining_vms_count
          AppScaleLogger.verbose('Creating a Scale Set {0} with {1} VM(s)'.
                                 format(scale_set_name, capacity), verbose)

          # Start creating scalesets.
          scalesets_futures.append(executor.submit(self.create_scale_set,
              capacity, parameters, resource_name, scale_set_name, subnet))
          remaining_vms_count = remaining_vms_count - self.MAX_VMSS_CAPACITY
        for future in concurrent.futures.as_completed(scalesets_futures):
          exception = future.exception()
          if exception:
            scalesets_exceptions.append(exception)

      for exception in scalesets_exceptions:
        if not isinstance(exception, (CloudError, AgentRuntimeException)):
          logging.exception(exception)
      if scalesets_exceptions:
        raise AgentRuntimeException(str(scalesets_exceptions))

    # Create a scale set using the count of VMs provided.
    else:
      scale_set_name = random_resource_name + "-scaleset-{}vms".format(num_instances_to_add)
      AppScaleLogger.verbose('Creating a Scale Set {0} with {1} VM(s)'.
                             format(scale_set_name, num_instances_to_add), verbose)
      self.create_scale_set(num_instances_to_add, parameters, random_resource_name,
                            scale_set_name, subnet)

  def create_scale_set(self, count, parameters, resource_name,
                       scale_set_name, subnet):
    """ Creates a scale set of 'count' number of virtual machines in the given
    subnet and virtual Network.
    Args:
        count: The VM capacity of the scale set to be created.
        parameters: A dict, containing all the parameters necessary to
          authenticate this user with Azure.
        resource_name: The names of the sub resources needed to create
          a virtual machine in a scale set.
        scale_set_name: The name of the scale set to be created.
        subnet: A reference to the subnet ID of the virtual network created.

    Raises:
      AgentRuntimeException: If a scale set could not be successfully created.
      AgentConfigurationException: If we are unable to authenticate with Azure.
    """
    credentials = self.open_connection(parameters)
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    zone = parameters[self.PARAM_ZONE]
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    compute_client = ComputeManagementClient(credentials, subscription_id)

    linux_configuration = self.create_linux_configuration(parameters)

    os_profile = VirtualMachineScaleSetOSProfile(
      computer_name_prefix=resource_name, admin_username=self.ADMIN_USERNAME,
      linux_configuration=linux_configuration)


    subnet_reference = ApiEntityReference(id=subnet.id)
    ip_config = VirtualMachineScaleSetIPConfiguration(name=resource_name,
                                                      subnet=subnet_reference)

    network_interface_config = VirtualMachineScaleSetNetworkConfiguration(
      name=resource_name, primary=True, ip_configurations=[ip_config])

    network_profile = VirtualMachineScaleSetNetworkProfile(
      network_interface_configurations=[network_interface_config])

    os_disk = None
    plan = None
    image_ref = None
    azure_image_id = parameters[self.PARAM_IMAGE_ID]
    # Publisher images are formatted Publisher:Offer:Sku:Tag
    if self.MARKETPLACE_IMAGE.match(azure_image_id):
      publisher, offer, sku, version = azure_image_id.split(":")
      compatible_zone = zone.lower().replace(" ", "")

      image = compute_client.virtual_machine_images.get(
          compatible_zone, publisher, offer, sku, version)
      image_ref = ImageReference(publisher=publisher,
                                 offer=offer,
                                 sku=sku,
                                 version=version)
      plan = image.plan
    else:
      image_hd = VirtualHardDisk(uri=azure_image_id)

      os_disk = VirtualMachineScaleSetOSDisk(
          name=resource_name, caching=CachingTypes.read_write,
          create_option=DiskCreateOptionTypes.from_image,
          os_type=OperatingSystemTypes.linux, image=image_hd)

    storage_profile = VirtualMachineScaleSetStorageProfile(
        os_disk=os_disk, image_reference=image_ref)
    virtual_machine_profile = VirtualMachineScaleSetVMProfile(
      os_profile=os_profile, storage_profile=storage_profile,
      network_profile=network_profile)

    sku = ComputeSku(name=parameters[self.PARAM_INSTANCE_TYPE], capacity=long(count))
    upgrade_policy = UpgradePolicy(mode=UpgradeMode.manual)
    vm_scale_set = VirtualMachineScaleSet(
      sku=sku, upgrade_policy=upgrade_policy, location=zone, plan=plan,
      virtual_machine_profile=virtual_machine_profile, overprovision=False)

    try:
      create_update_response = \
        compute_client.virtual_machine_scale_sets.create_or_update(
          resource_group, scale_set_name, vm_scale_set)

      self.wait_for_ss_update(count, create_update_response, scale_set_name)
    except CloudError as error:
      logging.exception("Azure agent received a CloudError.")
      raise AgentRuntimeException("Unable to create or update Scale Set. "
                                  "Reason: {}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to create a scale set. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

  def wait_for_ss_update(self, count, create_update_response, scale_set_name):
    """ Waits until the scale set has been successfully updated and all the
    instances have been created and are running.

    Args:
        count: The VM capacity of the scale set to be created.
        create_update_response: An instance, of the AzureOperationPoller to
          poll for the status of the operation being performed.
        scale_set_name: The name of the scale set being updated.

    Raises:
      AgentRuntimeException: If there is a problem updating the virtual
        machine scale set.
      AgentConfigurationException: If we are unable to authenticate with Azure.
    """
    try:
      create_update_response.wait(timeout=self.MAX_VMSS_WAIT_TIME)
      result = create_update_response.result()
      if result.provisioning_state == 'Succeeded':
        AppScaleLogger.log("Scale Set '{0}' with {1} VM(s) has been successfully "
                           "configured!".format(scale_set_name, count))
      else:
        AppScaleLogger.log("Unable to create a Scale Set of {0} "
                           "VM(s).Provisioning Status: {1}"
                           .format(count, result.provisioning_state))

    except CloudError as error:
      logging.exception("CloudError during creation of Scale Set.")
      raise AgentRuntimeException("Unable to create a Scale Set of {0} "
                                  "VM(s): {1}".format(count, error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to "
                        "contact Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to create Scale Set. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

  def associate_static_ip(self, instance_id, static_ip):
    """ Associates the given static IP address with the given instance ID.

    Args:
      instance_id: A str that names the instance that the static IP should be
        bound to.
      static_ip: A str naming the static IP to bind to the given instance.
    """

  def terminate_instances(self, parameters):
    """ Deletes the instances specified in 'parameters' running in Azure.
    Args:
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
    Raises:
      AgentRuntimeException: If instances could not successfully be terminated.
      AgentConfigurationException: If we are unable to authenticate with Azure.
    """
    credentials = self.open_connection(parameters)
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    verbose = parameters[self.PARAM_VERBOSE]
    instances_to_delete = parameters[self.PARAM_INSTANCE_IDS]
    AppScaleLogger.verbose("Terminating the vm instance(s) '{}'".
                           format(instances_to_delete), verbose)

    compute_client = ComputeManagementClient(credentials, subscription_id)
    try:
      vmss_list = list(compute_client.virtual_machine_scale_sets.list(
          resource_group))
    except CloudError as e:
      logging.exception("CloudError received trying to list Scale Sets.")
      raise AgentRuntimeException(e.message)
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to list Scale Sets. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

    downscale = parameters[self.PARAM_AUTOSCALE_AGENT]

    # On downscaling of instances, we need to delete the specific instance
    # from the Scale Set.
    if downscale in ['True', True]:
      # Delete the scale set virtual machines matching the given instance ids.
      vmss_vm_delete_futures = []
      vmss_vm_delete_exceptions = []

      try:
        # Get the instance_ids for the Scale Set VMs.
        vmss_vms_to_delete = [(vm.instance_id, vmss.name) for vmss in vmss_list
            for vm in compute_client.virtual_machine_scale_set_vms.list(
            resource_group, vmss.name)
            if vm.name in instances_to_delete]
      except CloudError as e:
        logging.exception("CloudError received while trying to terminate "
                          "instances.")
        raise AgentRuntimeException(e.message)
      except ClientException as e:
        logging.exception("ClientException received while attempting to "
                          "contact Azure.")
        raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to terminate instances. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

      with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        for vm_instance_id, vmss_name in vmss_vms_to_delete:
          vmss_vm_delete_futures.append(executor.submit(
              self.delete_vmss_instance, compute_client, parameters,
              vmss_name, vm_instance_id))

        for future in concurrent.futures.as_completed(vmss_vm_delete_futures):
          exception = future.exception()
          if exception:
            vmss_vm_delete_exceptions.append(exception)

      for exception in vmss_vm_delete_exceptions:
        if not isinstance(exception, (CloudError, AgentRuntimeException)):
          logging.exception(exception)
      if vmss_vm_delete_exceptions:
        raise AgentRuntimeException(str(vmss_vm_delete_exceptions))

      AppScaleLogger.log("Virtual machine(s) have been successfully downscaled.")
      AppScaleLogger.log("Cleaning up any Scale Sets, if needed ...")
      vmss_delete_futures = []
      vmss_delete_exceptions = []

      try:
        ss_to_delete = [vmss.name for vmss in vmss_list if not
          any(compute_client.virtual_machine_scale_set_vms.list(resource_group, vmss.name))]
      except CloudError as e:
        logging.exception("CloudError received while trying to terminate "
                          "instances.")
        raise AgentRuntimeException(e.message)
      except ClientException as e:
        logging.exception("ClientException received while attempting to "
                          "contact Azure.")
        raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to terminate instances. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

      with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        for vmss_name in ss_to_delete:
          vmss_delete_futures.append(executor.submit(
                self.delete_virtual_machine_scale_set, compute_client,
                parameters, vmss_name))

        for future in concurrent.futures.as_completed(vmss_delete_futures):
          exception = future.exception()
          if exception:
            vmss_delete_exceptions.append(exception)

      for exception in vmss_delete_exceptions:
        if not isinstance(exception, (CloudError, AgentRuntimeException)):
          logging.exception(exception)
      if vmss_delete_exceptions:
        raise AgentRuntimeException(str(vmss_delete_exceptions))
      return

    # On appscale down --terminate, we delete all the Scale Sets within the
    # resource group specified, as it is faster than deleting the individual
    # instances within each Scale Set.

    # Get the list of all ScaleSet Instance "Names" before deleting
    # ScaleSets. We refer to the Scale Set VM instances by name rather than
    # instance id.
    try:
      delete_ss_instances = [vm.name for vmss in vmss_list
       for vm in compute_client.virtual_machine_scale_set_vms.list(
       resource_group, vmss.name)]
    except CloudError as e:
      logging.exception("CloudError received while trying to terminate "
                        "instances.")
      raise AgentRuntimeException(e.message)
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to terminate instances. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

    # Delete ScaleSets.
    vmss_delete_futures = []
    vmss_delete_exceptions = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
      for vmss in vmss_list:
        vmss_delete_futures.append(executor.submit(
            self.delete_virtual_machine_scale_set, compute_client,
            parameters, vmss.name))
      for future in concurrent.futures.as_completed(vmss_delete_futures):
        exception = future.exception()
        if exception:
          vmss_delete_exceptions.append(exception)

    for exception in vmss_delete_exceptions:
      if not isinstance(exception, (CloudError, AgentRuntimeException)):
        logging.exception(exception)
    if vmss_delete_exceptions:
      raise AgentRuntimeException(str(vmss_delete_exceptions))

    AppScaleLogger.log("Virtual machine scale set(s) have been successfully "
                       "deleted.")
    # Delete the load balancer virtual machines matching the given instance ids.
    delete_lb_instances = self.diff(instances_to_delete, delete_ss_instances)
    lb_delete_futures = []
    lb_delete_exceptions = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
      for vm_name in delete_lb_instances:
        lb_delete_futures.append(executor.submit(self.delete_virtual_machine,
           compute_client, parameters, vm_name))

      for future in concurrent.futures.as_completed(lb_delete_futures):
        exception = future.exception()
        if exception:
          lb_delete_exceptions.append(exception)

    for exception in lb_delete_exceptions:
      if not isinstance(exception, (CloudError, AgentRuntimeException)):
        logging.exception(exception)
    if lb_delete_exceptions:
      raise AgentRuntimeException(str(lb_delete_exceptions))

    AppScaleLogger.log("Load balancer virtual machine(s) have been "
       "successfully deleted")

  def delete_virtual_machine_scale_set(self, compute_client, parameters, vmss_name):
    """ Deletes the virtual machine scale set created from the specified
    resource group.
    Args:
        compute_client: An instance of the Compute Management client.
        parameters: A dict, containing all the parameters necessary to
          authenticate this user with Azure.
        vmss_name: The name of the virtual machine scale set to be deleted.
    Raises:
      AgentConfigurationException: If we are unable to authenticate with Azure.
      AgentRuntimeException: If a scale set could not be successfully deleted.
    """
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    verbose = parameters[self.PARAM_VERBOSE]
    AppScaleLogger.verbose("Deleting Scale Set {} ...".format(vmss_name), verbose)
    try:
      delete_response = compute_client.virtual_machine_scale_sets.delete(
          resource_group, vmss_name)
    except CloudError as error:
      logging.exception("CloudError received trying to clean up Scale Set.")
      raise AgentRuntimeException("Unable to clean up Scale Set {}. "
                                  "Reason: {}".format(vmss_name, error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to clean up Scale Set {}. Please check your "
          "cloud configuration. Reason: {}".format(vmss_name, e.message))
    resource_name = 'Virtual Machine Scale Set' + ":" + vmss_name
    self.sleep_until_delete_operation_done(delete_response, resource_name,
                                           self.MAX_VM_UPDATE_TIME, verbose)
    AppScaleLogger.verbose("Virtual Machine Scale Set {} has been successfully "
                           "deleted.".format(vmss_name), verbose)

  def delete_vmss_instance(self, compute_client, parameters, vmss_name, instance_id):
    """ Deletes the specified virtual machine instance from the given Scale Set.
    Args:
      compute_client: An instance of the Compute Management client.
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      vmss_name: The Scale Set from which the instance needs to be deleted.
      instance_id: The ID of the instance in the Scale Set to be deleted.
    """
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    verbose = parameters[self.PARAM_VERBOSE]

    vm_info = "Virtual Machine {0} from Scale Set {1}".format(instance_id,
                                                              vmss_name)

    AppScaleLogger.verbose("Deleting {0} ...".format(vm_info), verbose)
    try:
      result = compute_client.virtual_machine_scale_set_vms.delete(
          resource_group, vmss_name, instance_id)
    except CloudError as error:
      logging.exception("CloudError received trying to clean up scale set.")
      raise AgentRuntimeException("Unable to clean up VM {} from Scale Set {}. "
                                  "Reason: {}".format(instance_id, vmss_name,
                                                      error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to clean up VM {} from Scale Set {}. Please check your "
          "cloud configuration. Reason: {}".format(instance_id, vmss_name,
                                                   e.message))
    resource_name = 'Virtual Machine Instance ' + instance_id
    self.sleep_until_delete_operation_done(result, resource_name,
                                           self.MAX_VM_UPDATE_TIME, verbose)

    AppScaleLogger.verbose("{0} from scaleset {1} has been successfully "
                           "deleted".format(instance_id, vmss_name), verbose)

  def delete_virtual_machine(self, compute_client, parameters, vm_name):
    """ Deletes the virtual machine from the resource_group specified.
    Args:
      compute_client: An instance of the Compute Management client.
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      vm_name: The name of the virtual machine to be deleted.
    """
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    verbose = parameters[self.PARAM_VERBOSE]
    AppScaleLogger.verbose("Deleting Virtual Machine {} ...".format(vm_name), verbose)
    try:
      result = compute_client.virtual_machines.delete(resource_group, vm_name)
    except CloudError as error:
      logging.exception("CloudError received trying to clean up scale set.")
      raise AgentRuntimeException("Unable to clean up Virtual Machine {}. "
                                  "Reason: {}".format(vm_name, error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to clean up Virtual Machine {}. Please check your "
          "cloud configuration. Reason: {}".format(vm_name, e.message))
    resource_name = 'Virtual Machine' + ':' + vm_name
    self.sleep_until_delete_operation_done(result, resource_name,
                                           self.MAX_VM_UPDATE_TIME, verbose)
    AppScaleLogger.verbose("Virtual Machine {} has been successfully deleted.".
                           format(vm_name), verbose)

  def sleep_until_delete_operation_done(self, result, resource_name,
                                        max_sleep, verbose):
    """ Sleeps until the delete operation for the resource is completed
    successfully.
    Args:
      result: An instance, of the AzureOperationPoller to poll for the status
        of the operation being performed.
      resource_name: The name of the resource being deleted.
      max_sleep: The maximum number of seconds to sleep for the resources to
        be deleted.
      verbose: A boolean indicating whether or not in verbose mode.
    Raises:
      AgentRuntimeException if we time out waiting for the operation to finish.
    """
    time_start = time.time()
    while not result.done():
      AppScaleLogger.verbose("Waiting {0} second(s) for {1} to be deleted.".
                             format(self.SLEEP_TIME, resource_name), verbose)
      time.sleep(self.SLEEP_TIME)
      total_sleep_time = time.time() - time_start
      if total_sleep_time > max_sleep:
        err_msg = "Waited {0} second(s) for {1} to be deleted. Operation has " \
                  "timed out.".format(total_sleep_time, resource_name)
        AppScaleLogger.log(err_msg)
        raise AgentRuntimeException(err_msg)

  def does_address_exist(self, parameters):
    """ Verifies that the specified static IP address has been allocated, and
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
    """ Verifies that the specified machine image exists in this cloud.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        underlying cloud, as well as a key indicating which machine image should
        be checked for existence.
    Returns:
      A bool that indicates if the machine image exists in this cloud.
    """
    return True

  def does_disk_exist(self, parameters, disk):
    """ Verifies that the specified persistent disk exists in this cloud.

    Args:
      parameters: A dict that includes the parameters needed to authenticate
        with this cloud.
      disk: A str containing the name of the disk that we should check for
        existence.
    Returns:
      True if the named persistent disk exists, and False otherwise,
    """

  def does_zone_exist(self, parameters):
    """ Verifies that the specified zone exists in this cloud.

    Args:
      parameters: A dict that includes a key indicating the zone to check for
        existence.
    Returns:
      True if the zone exists, and False otherwise.
    Raises:
      AgentConfigurationException: If an error is encountered during
        checking for the zone due to configuration errors (zone does not
        exist or authentication issues).
    """
    credentials = self.open_connection(parameters)
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    zone = parameters[self.PARAM_ZONE]
    resource_client = ResourceManagementClient(credentials, subscription_id)
    try:
      resource_providers = resource_client.providers.list()
      for provider in resource_providers:
        for resource_type in provider.resource_types:
          if zone in resource_type.locations:
            return True
    except ClientException as error:
      logging.exception("Unable to check if zone exists.")
      raise AgentConfigurationException("Unable to check if zone exists. "
                                        "Please check your cloud "
                                        "configuration. Reason: {}".format(
                                        error.message))
    return False

  def cleanup_state(self, parameters):
    """ Removes any remote state that was created to run AppScale instances
    during this deployment.
    Args:
      parameters: A dict that includes keys indicating the remote state
        that should be deleted.
    Raises:
      AgentConfigurationException: If we are unable to authenticate with Azure.
      AgentRuntimeException: If an error is encountered trying to clean up
        the state in Azure.
    """
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    resource_group = parameters[self.PARAM_RESOURCE_GROUP]
    credentials = self.open_connection(parameters)
    network_client = NetworkManagementClient(credentials, subscription_id)
    verbose = parameters[self.PARAM_VERBOSE]

    AppScaleLogger.log("Cleaning up the network configuration created for this "
                       "deployment ...")
    try:
      network_interfaces = network_client.network_interfaces.list(resource_group)
      for interface in network_interfaces:
        result = network_client.network_interfaces.delete(resource_group, interface.name)
        resource_name = 'Network Interface' + ':' + interface.name
        self.sleep_until_delete_operation_done(result, resource_name,
                                               self.MAX_SLEEP_TIME, verbose)
        AppScaleLogger.verbose("Network Interface {} has been successfully deleted.".
                               format(interface.name), verbose)
    except CloudError as error:
      logging.exception("CloudError received trying to clean up network interfaces.")
      raise AgentRuntimeException("Unable to clean up network interfaces. "
                                  "Reason: {}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to clean up network interfaces. Please check your "
          "cloud configuration. Reason: {}".format(e.message))

    AppScaleLogger.log("Network Interface(s) have been successfully deleted.")

    try:
      public_ip_addresses = network_client.public_ip_addresses.list(resource_group)
      for public_ip in public_ip_addresses:
        result = network_client.public_ip_addresses.delete(resource_group, public_ip.name)
        resource_name = 'Public IP Address' + ':' + public_ip.name
        self.sleep_until_delete_operation_done(result, resource_name,
                                               self.MAX_SLEEP_TIME, verbose)
        AppScaleLogger.verbose("Public IP Address {} has been successfully deleted.".
                               format(public_ip.name), verbose)
    except CloudError as error:
      logging.exception("Unable to clean up public ips.")
      raise AgentRuntimeException("Unable to clean up public ips. "
                                  "Reason: {}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to clean up public ips. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

    AppScaleLogger.log("Public IP Address(s) have been successfully deleted.")

    try:
      virtual_networks = network_client.virtual_networks.list(resource_group)
      for network in virtual_networks:
        result = network_client.virtual_networks.delete(resource_group, network.name)
        resource_name = 'Virtual Network' + ':' + network.name
        self.sleep_until_delete_operation_done(result, resource_name,
                                               self.MAX_SLEEP_TIME, verbose)
        AppScaleLogger.verbose("Virtual Network {} has been successfully deleted.".
                               format(network.name), verbose)
    except CloudError as error:
      logging.exception("Unable to clean up virtual networks.")
      raise AgentRuntimeException("Unable to clean up virtual networks. "
                                  "Reason: {}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to "
                        "contact Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to clean up virtual networks. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

    AppScaleLogger.log("Virtual Network(s) have been successfully deleted.")

  def get_params_from_args(self, args):
    """ Constructs a dict with only the parameters necessary to interact with
    Microsoft Azure.
    Args:
      args: A Namespace or dict, that maps all of the arguments the user has
        invoked an AppScale command with their associated value.
    Returns:
      A dict, that maps each argument given to the value that was associated with
        it.
    Raises:
      AgentConfigurationException: If unable to authenticate using the credentials
        provided in the AppScalefile.
    """
    if not isinstance(args, dict):
      args = vars(args)

    params = {
      self.PARAM_APP_ID: args[self.PARAM_APP_ID],
      self.PARAM_APP_SECRET: args[self.PARAM_APP_SECRET],
      self.PARAM_IMAGE_ID: args['machine'],
      self.PARAM_INSTANCE_TYPE: args[self.PARAM_INSTANCE_TYPE],
      self.PARAM_GROUP: args[self.PARAM_GROUP],
      self.PARAM_KEYNAME: args[self.PARAM_KEYNAME],
      self.PARAM_RESOURCE_GROUP: args.get(self.PARAM_RESOURCE_GROUP,
                                          self.DEFAULT_RESOURCE_GROUP),
      self.PARAM_STORAGE_ACCOUNT: args.get(self.PARAM_STORAGE_ACCOUNT),
      self.PARAM_SUBSCRIBER_ID: args[self.PARAM_SUBSCRIBER_ID],
      self.PARAM_TAG: args.get(self.PARAM_TAG, self.DEFAULT_TAG),
      self.PARAM_TENANT_ID: args[self.PARAM_TENANT_ID],
      self.PARAM_VERBOSE : args.get('verbose', False),
      self.PARAM_ZONE : args[self.PARAM_ZONE],
      self.PARAM_AUTOSCALE_AGENT: False
    }
    self.assert_credentials_are_valid(params)

    # Perform Marketplace Image checks.
    if self.MARKETPLACE_IMAGE.match(params[self.PARAM_IMAGE_ID]):
      params[self.PARAM_IMAGE_ID] = self.get_marketplace_image_version(params)
      self.check_marketplace_image(params)
    # Only assign default storage account if we are not using a Marketplace
    # Image.
    elif not params[self.PARAM_STORAGE_ACCOUNT]:
     params[self.PARAM_STORAGE_ACCOUNT] = self.DEFAULT_STORAGE_ACCT

    return params

  def get_marketplace_image_version(self, parameters):
    """ Check if the marketplace image specified exists and it's correct
    version if 'latest' was specified.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        Azure.
    Returns:
      A string indicating the given or corrected marketplace image formatted
        "publisher:offer:sku:version". For example if
        "appscale-marketplace:appscale:3:latest" was received at this time would
        return "appscale-marketplace:appscale:3:3.5.2"
    Raises:
      AgentConfigurationException: If the image is invalid or there was an
        authentication issue trying to contact Azure.
    """
    credentials = self.open_connection(parameters)
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    azure_image_id = parameters[self.PARAM_IMAGE_ID]
    zone = parameters[self.PARAM_ZONE]

    AppScaleLogger.log("Checking publisher image version for {}".format(
        azure_image_id))
    publisher, offer, sku, version = azure_image_id.split(":")
    compute_client = ComputeManagementClient(credentials, subscription_id)
    compatible_zone = zone.lower().replace(" ", "")

    if version.lower() != 'latest':
      try:
        compute_client.virtual_machine_images.get(compatible_zone, publisher,
                                                  offer, sku, version)
        return azure_image_id
      except ClientException as e:
        raise AgentConfigurationException("Received CloudError trying to "
                                          "request specified image. Please "
                                          "ensure your image is valid in "
                                          "the AppScalefile and that your "
                                          "cloud configuration is correct. "
                                          "Reason: {}".format(e.message))

    try:
      top_one = compute_client.virtual_machine_images.list(
          compatible_zone, publisher, offer, sku, top=1, orderby='name desc')
    except ClientException as e:
      raise AgentConfigurationException("Received CloudError trying to "
                                        "request specified image. Please "
                                        "ensure your image is valid in "
                                        "the AppScalefile and that your cloud "
                                        "configuration is correct. "
                                        "Reason: {}".format(e.message))
    if len(top_one) == 0:
      raise AgentConfigurationException("Can't resolve the vesion of '{}'"
                                  .format(azure_image_id))

    version = top_one[0].name

    return ":".join([publisher, offer, sku, version])

  def check_marketplace_image(self, parameters):
    """ Check if the marketplace image specified has its terms accepted.
    Otherwise we will not be able to use this image.

    Args:
      parameters: A dict containing values necessary to authenticate with the
        Azure.
    Raises:
      AgentRuntimeException: If we cannot complete the calls to Azure.
    """
    credentials = self.open_connection(parameters)
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    azure_image_id = parameters[self.PARAM_IMAGE_ID]
    zone = parameters[self.PARAM_ZONE]

    publisher, offer, sku, version = azure_image_id.split(":")
    compute_client = ComputeManagementClient(credentials, subscription_id)
    compatible_zone = zone.lower().replace(" ", "")

    AppScaleLogger.log("Using publisher image {}".format(azure_image_id))

    try:
      image = compute_client.virtual_machine_images.get(
          compatible_zone, publisher, offer, sku, version)
      if not image.plan:
        AppScaleLogger.warn("It is not recommended to use a non-AppScale image")
        return
      market_place_client = MarketplaceOrderingAgreements(credentials,
                                                          subscription_id)
      term = market_place_client.marketplace_agreements.get(
          image.plan.publisher, image.plan.product, image.plan.name)
      if not term.accepted:
        AppScaleLogger.log("Marketplace image {}'s license agreement was not "
                           "accepted, accepting it now.".format(azure_image_id))
        term.accepted = True
        market_place_client.marketplace_agreements.create(
            image.plan.publisher, image.plan.product, image.plan.name, term)
    except CloudError as e:
      raise AgentRuntimeException("Received CloudError trying to check and "
        "accept terms for specified image. Reason: {}".format(e))

  def get_cloud_params(self, keyname):
    """ Searches through the locations.json file with key
    'infrastructure_info' to build a dict containing the
    parameters necessary to interact with Microsoft Azure.
    Args:
      keyname: A str that uniquely identifies this AppScale deployment.
    Returns:
      A dict containing all of the credentials necessary to interact with
        Microsoft Azure.
    """
    params = {
      self.PARAM_GROUP: LocalState.get_group(keyname),
      self.PARAM_KEYNAME: keyname,
      self.PARAM_VERBOSE: True,
      self.PARAM_ZONE: LocalState.get_zone(keyname),
      self.PARAM_SUBSCRIBER_ID: LocalState.get_subscription_id(keyname),
      self.PARAM_APP_ID: LocalState.get_app_id(keyname),
      self.PARAM_APP_SECRET: LocalState.get_app_secret_key(keyname),
      self.PARAM_TENANT_ID: LocalState.get_tenant_id(keyname),
      self.PARAM_RESOURCE_GROUP: LocalState.get_resource_group(keyname),
      self.PARAM_STORAGE_ACCOUNT: LocalState.get_storage_account(keyname),
    }
    return params

  def assert_required_parameters(self, parameters, operation):
    """ Check whether all the parameters required to interact with Azure are
    present in the provided dict.
    Args:
      parameters: A dict containing values necessary to authenticate with the
        Azure.
      operation: A str representing the operation for which the parameters
        should be checked.
    Raises:
      AgentConfigurationException: If a required parameter is absent.
    """
    # Make sure that the user has set each parameter.
    for param in self.REQUIRED_CREDENTIALS:
      if not self.has_parameter(param, parameters):
        raise AgentConfigurationException('The required parameter, {0}, was not'
          ' specified.'.format(param))

  def open_connection(self, parameters):
    """ Connects to Microsoft Azure with the given credentials, creates an
    authentication token and uses that to get the ServicePrincipalCredentials
    which is needed to access any resources.
    Args:
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure. We assume that the user has
        already authorized this account by creating a Service Principal
        with the appropriate (Contributor) role.
    Returns:
      A ServicePrincipalCredentials instance, that can be used to access or
        create any resources.
    """
    app_id = parameters[self.PARAM_APP_ID]
    app_secret_key = parameters[self.PARAM_APP_SECRET]
    tenant_id = parameters[self.PARAM_TENANT_ID]

    # Get an Authentication token using ADAL.
    context = adal.AuthenticationContext(self.AZURE_AUTH_ENDPOINT + tenant_id)
    try:
      token_response = context.acquire_token_with_client_credentials(
        self.AZURE_RESOURCE_URL, app_id, app_secret_key)
    except adal.adal_error.AdalError as e:
      raise AgentConfigurationException(
          "Unable to communicate with Azure! Please check your cloud "
          "configuration. Reason: {}".format(e.message))
    token_response.get('accessToken')

    # To access Azure resources for an application, we need a Service Principal
    # with the accurate role assignment. It can be created using the Azure CLI.
    credentials = ServicePrincipalCredentials(client_id=app_id,
                                              secret=app_secret_key,
                                              tenant=tenant_id)
    return credentials


  def create_virtual_network(self, network_client, parameters, network_name,
                             subnet_name):
    """ Creates the network resources, such as Virtual network and Subnet.
    Args:
      network_client: A NetworkManagementClient instance.
      parameters:  A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      network_name: The name to use for the Virtual Network resource.
      subnet_name: The name to use for the Subnet resource.
    Returns:
      A Subnet instance from the Virtual Network created.
    Raises:
      AgentConfigurationException: If we are unable to authenticate with Azure.
      AgentRuntimeException: If an error is encountered trying to create a
        virtual network in Azure.
    """
    group_name = parameters[self.PARAM_RESOURCE_GROUP]
    region = parameters[self.PARAM_ZONE]
    verbose = parameters[self.PARAM_VERBOSE]
    AppScaleLogger.verbose("Creating/Updating the Virtual Network '{}'".
                           format(network_name), verbose)
    address_space = AddressSpace(address_prefixes=['10.1.0.0/16'])
    subnet1 = Subnet(name=subnet_name, address_prefix='10.1.0.0/24')
    try:
      result = network_client.virtual_networks.create_or_update(
          group_name, network_name,
          VirtualNetwork(location=region, address_space=address_space, subnets=[subnet1]))
      self.sleep_until_update_operation_done(result, network_name, verbose)
    except CloudError as error:
      logging.exception("Azure agent received a CloudError.")
      raise AgentRuntimeException("Unable to create virtual network. Reason: "
                                  "{}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
        "while trying to create virtual network. Please check your cloud "
        "configuration. Reason: {}".format(e.message))

    subnet = network_client.subnets.get(group_name, network_name, subnet_name)
    return subnet

  def create_network_interface(self, network_client, interface_name, ip_name,
                               subnet, parameters):
    """ Creates the Public IP Address resource and uses that to create the
    Network Interface.
    Args:
      network_client: A NetworkManagementClient instance.
      interface_name: The name to use for the Network Interface.
      ip_name: The name to use for the Public IP Address.
      subnet: The Subnet resource from the Virtual Network created.
      parameters:  A dict, containing all the parameters necessary to
        authenticate this user with Azure.
    Raises:
      AgentConfigurationException: If we are unable to authenticate with Azure.
      AgentRuntimeException: If an error is encountered trying to create a
        network interface in Azure.
    """
    group_name = parameters[self.PARAM_RESOURCE_GROUP]
    region = parameters[self.PARAM_ZONE]
    verbose = parameters[self.PARAM_VERBOSE]
    AppScaleLogger.verbose("Creating/Updating the Public IP Address '{}'".
                           format(ip_name), verbose)
    ip_address = PublicIPAddress(
      location=region, public_ip_allocation_method=IPAllocationMethod.dynamic,
      idle_timeout_in_minutes=4)
    try:
      result = network_client.public_ip_addresses.create_or_update(
          group_name, ip_name, ip_address)
      self.sleep_until_update_operation_done(result, ip_name, verbose)
    except CloudError as error:
      logging.exception("Azure agent received a CloudError.")
      raise AgentRuntimeException("Unable to create public ip address. "
                                  "Reason: {}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to create a public ip address. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

    public_ip_address = network_client.public_ip_addresses.get(group_name, ip_name)

    AppScaleLogger.verbose("Creating/Updating the Network Interface '{}'".
                           format(interface_name), verbose)
    network_interface_ip_conf = NetworkInterfaceIPConfiguration(
      name=interface_name, private_ip_allocation_method=IPAllocationMethod.dynamic,
      subnet=subnet, public_ip_address=PublicIPAddress(id=(public_ip_address.id)))

    try:
      result = network_client.network_interfaces.create_or_update(group_name,
        interface_name, NetworkInterface(location=region,
                                         ip_configurations=[network_interface_ip_conf]))
      self.sleep_until_update_operation_done(result, interface_name, verbose)
    except CloudError as error:
      logging.exception("Azure agent received a CloudError.")
      raise AgentRuntimeException("Unable to create network interface. "
                                  "Reason: {}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to create network interface. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

  def sleep_until_update_operation_done(self, result, resource_name, verbose):
    """ Sleeps until the create/update operation for the resource is completed
      successfully.
      Args:
        result: An instance, of the AzureOperationPoller to poll for the status
          of the operation being performed.
        resource_name: The name of the resource being updated.
    """
    time_start = time.time()
    while not result.done():
      AppScaleLogger.verbose("Waiting {0} second(s) for {1} to be created/updated.".
                             format(self.SLEEP_TIME, resource_name), verbose)
      time.sleep(self.SLEEP_TIME)
      total_sleep_time = time.time() - time_start
      if total_sleep_time > self.MAX_SLEEP_TIME:
        AppScaleLogger.log("Waited {0} second(s) for {1} to be created/updated. "
          "Operation has timed out.".format(total_sleep_time, resource_name))
        break

  def create_resource_group(self, parameters, credentials):
    """ Creates a Resource Group for the application using the Service Principal
    Credentials, if it does not already exist. In the case where no resource
    group is specified, a default group is created.
    Args:
      parameters: A dict, containing all the parameters necessary to
        authenticate this user with Azure.
      credentials: A ServicePrincipalCredentials instance, that can be used to
        access or create any resources.
    Raises:
      AgentConfigurationException: If we are unable to authenticate with Azure.
      AgentRuntimeException: If there was a problem creating or accessing
        a resource group with the given subscription.
    """
    subscription_id = str(parameters[self.PARAM_SUBSCRIBER_ID])
    resource_client = ResourceManagementClient(credentials, subscription_id)
    resource_group_name = parameters[self.PARAM_RESOURCE_GROUP]

    tag_name = parameters[self.PARAM_TAG]

    storage_client = StorageManagementClient(credentials, subscription_id)
    try:
      resource_client.providers.register(self.MICROSOFT_STORAGE_RESOURCE)
      # If the resource group does not already exist, create a new one with the
      # specified storage account.
      if not self.does_resource_group_exist(resource_group_name, resource_client):
        AppScaleLogger.log("Creating a new resource group '{0}' with the tag "
                           "'{1}'.".format(resource_group_name, tag_name))
        resource_client.resource_groups.create_or_update(
          resource_group_name, ResourceGroup(location=parameters[self.PARAM_ZONE],
                                 tags={'tag': tag_name}))

      if not self.MARKETPLACE_IMAGE.match(parameters[self.PARAM_IMAGE_ID]) \
          and parameters.get(self.PARAM_STORAGE_ACCOUNT):
        # If it already exists, check if the specified storage account exists
        # under it and if not, create a new account.
        storage_accounts = storage_client.storage_accounts.\
          list_by_resource_group(resource_group_name)
        acct_names = []
        for account in storage_accounts:
          acct_names.append(account.name)

        if parameters[self.PARAM_STORAGE_ACCOUNT] in acct_names:
            AppScaleLogger.log("Storage account '{0}' under '{1}' resource group "
              "already exists. So not creating it again.".format(
              parameters[self.PARAM_STORAGE_ACCOUNT], resource_group_name))
        else:
          self.create_storage_account(parameters, storage_client)
    except CloudError as error:
      logging.exception("Unable to create resource group.")
      raise AgentConfigurationException("Unable to create a resource group "
        "using the credentials provided: {}".format(error.message))
    except ClientException as e:
      logging.exception("ClientException received while attempting to contact "
                        "Azure.")
      raise AgentConfigurationException("Unable to communicate with Azure "
          "while trying to create resource group. Please check your cloud "
          "configuration. Reason: {}".format(e.message))

  def create_storage_account(self, parameters, storage_client):
    """ Creates a Storage Account under the Resource Group, if it does not
    already exist. In the case where no resource group is specified, a default
    storage account is created.
    Args:
      parameters: A dict, containing all the parameters necessary to authenticate
        this user with Azure.
      credentials: A ServicePrincipalCredentials instance, that can be used to access or
      create any resources.
    Raises:
      AgentConfigurationException: If there was a problem creating or accessing
        a storage account with the given subscription.
    """
    storage_account = parameters[self.PARAM_STORAGE_ACCOUNT]
    rg_name = parameters[self.PARAM_RESOURCE_GROUP]

    try:
      AppScaleLogger.log("Creating a new storage account '{0}' under the "
        "resource group '{1}'.".format(storage_account, rg_name))
      result = storage_client.storage_accounts.create(
        rg_name, storage_account,StorageAccountCreateParameters(
          sku=StorageSku(SkuName.standard_lrs), kind=Kind.storage,
          location=parameters[self.PARAM_ZONE]))
      # Result is a msrestazure.azure_operation.AzureOperationPoller instance.
      # wait() insures polling the underlying async operation until it's done.
      result.wait()
    except CloudError as error:
      logging.exception("Unable to create storage account.")
      raise AgentConfigurationException("Unable to create a storage account "
        "using the credentials provided: {}".format(error.message))

  def does_resource_group_exist(self, resource_group_name, resource_client):
    """ Checks if the given resource group already exists.
    Args:
      resource_group_name: The name of the resource group to check.
      resource_client: An instance of the ResourceManagementClient.
    Returns:
      True, if resource group already exists.
      False, otherwise.
    """
    resource_groups = resource_client.resource_groups.list()
    for resource_group in resource_groups:
      if resource_group_name == resource_group.name:
        return True
    return False
