#!/usr/bin/env python


# General-purpose Python library imports
import re
import yaml


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory
from appscale_logger import AppScaleLogger
from custom_exceptions import BadConfigurationException
from local_state import LocalState
from parse_args import ParseArgs


class NodeLayout():
  """NodeLayout represents the relationship between IP addresses and the API
  services (roles) that will be used to host them in an AppScale deployment.

  NodeLayouts can be either 'simple' or 'advanced'. In simple deployments,
  we handle the placement for the user, naively placing services via a
  predetermined formula. In advanced deployments, we rely on the user
  telling us where the services should be placed, and verify that the user's
  placement strategy actually makes sense (e.g., not specifying any database
  nodes is not acceptable).
  """

  APPSCALEFILE_INSTRUCTIONS = "https://www.appscale.com/" \
                              "get-started/deploy-appscale#appscalefile"


  # TODO: Update this dictionary as roles get renamed/deprecated.
  DEPRECATED_ROLES = {'appengine': 'compute'}


  # A tuple containing the keys that can be used in simple deployments.
  SIMPLE_FORMAT_KEYS = ('controller', 'servers')


  # A tuple containing the keys that can be used in advanced deployments.
  # TODO: remove 'appengine' role.
  ADVANCED_FORMAT_KEYS = ['master', 'database', 'appengine', 'compute', 'open',
    'login', 'zookeeper', 'memcache', 'taskqueue', 'search', 'load_balancer']


  # A tuple containing all of the roles (simple and advanced) that the
  # AppController recognizes. These include _master and _slave roles, which
  # the user may not be able to specify directly.
  # TODO: remove 'appengine' role.
  VALID_ROLES = ('master', 'appengine', 'compute', 'database', 'shadow', 'open',
    'load_balancer', 'login', 'db_master', 'db_slave', 'zookeeper', 'memcache',
    'taskqueue', 'taskqueue_master', 'taskqueue_slave', 'search')


  # A regular expression that matches IP addresses, used in ips.yaml files for
  # virtualized cluster deployments.
  IP_REGEX = re.compile('\d+\.\d+\.\d+\.\d+')


  # A regular expression that matches cloud IDs, used in ips.yaml files for
  # cloud deployments.
  NODE_ID_REGEX = re.compile('(node)-(\d+)')


  # The message to display to users if they give us an ips.yaml file in a
  # simple deployment, with the same IP address more than once.
  DUPLICATE_IPS = "Cannot specify the same IP address more than once."


  # The message to display if the user wants to run in a simple deployment,
  # but does not specify a controller node.
  NO_CONTROLLER = "No controller was specified"


  # The message to display if the user wants to run in a simple deployment,
  # and specifies too many controller nodes.
  ONLY_ONE_CONTROLLER = "Only one controller is allowed"


  # The message to display if the user wants to run in a cloud without
  # specifying their deployment, but they forget to tell us the minimum number
  # of VMs to use.
  NO_YAML_REQUIRES_MIN = "Must specify min if not using a YAML file"


  # The message to display if the user wants to run in a cloud without
  # specifying their deployment, but they forget to tell us the maximum number
  # of VMs to use.
  NO_YAML_REQUIRES_MAX = "Must specify max if not using a YAML file"


  INPUT_YAML_REQUIRED = "A YAML file is required for virtualized clusters"


  # The message to display if the user mixes advanced and simple tags in their
  # deployment.
  USED_SIMPLE_AND_ADVANCED_KEYS = "Check your node layout and make sure not " \
    "to mix simple and advanced deployment methods."


  def __init__(self, options):
    """Creates a new NodeLayout from the given YAML file.

    Args:
      options: A Namespace or dict that (optionally) contains a field
        containing the YAML representing the placement strategy to use for
        this AppScale deployment. This YAML can be either raw YAML, or
        a str containing a path on the local filesystem that, when read,
        contains the YAML in question. It can also be set to None, for
        deployments when the user specifies how many VMs they wish to use.
    Raises:
      BadConfigurationException if configuration is not valid.
    """
    if not isinstance(options, dict):
      options = vars(options)
    self.master = None
    input_yaml = options.get('ips')
    if isinstance(input_yaml, str):
      with open(input_yaml, 'r') as file_handle:
        self.input_yaml = yaml.safe_load(file_handle.read())
    elif isinstance(input_yaml, dict):
      self.input_yaml = input_yaml
      AppScaleLogger.warn("The AppScalefile is changing, the layout you are "
        "using will be invalid soon. Please see {} for more details.".format(
        self.APPSCALEFILE_INSTRUCTIONS))
    elif isinstance(input_yaml, list):
      self.input_yaml = input_yaml
    else:
      self.input_yaml = None

    self.disks = options.get('disks')
    self.infrastructure = options.get('infrastructure')
    self.min_machines = options.get('min_machines')
    self.max_machines = options.get('max_machines')
    self.replication = options.get('replication')
    self.database_type = options.get('table', 'cassandra')
    self.add_to_existing = options.get('add_to_existing')
    self.default_instance_type = options.get('instance_type')
    self.test = options.get('test')
    self.force = options.get('force')

    if 'login_host' in options and options['login_host'] is not None:
      self.login_host = options['login_host']
    else:
      self.login_host = None

    self.nodes = []
    self.validate_node_layout()

  def is_cloud_ip(self, ip_address):
    """Parses the given IP address or node ID and returns it and a str
    indicating whether or not we are in a cloud deployment.

    Args:
      ip_address: A str that represents the IP address or node ID (of the format
        node-int) to parse.
    Returns:
      True if it is in node-id format or False if it is an ip.
    """
    if self.NODE_ID_REGEX.match(ip_address):
      return True
    elif self.IP_REGEX.match(ip_address):
      return False
    else:
      self.invalid("IP: {} does not match ip or node-id formats.".format(
        ip_address))

  def validate_node_layout(self):
    """Checks to see if this NodeLayout represents an acceptable (new) advanced
    deployment strategy, and if so, constructs self.nodes from it.

    Returns:
      True if the deployment strategy is valid.
    Raises:
      BadConfigurationException with reason if the deployment strategy is not
        valid.
    """
    if self.input_yaml and not isinstance(self.input_yaml, list):
      return self.invalid("Node layout format was not recognized.")
    if not self.input_yaml and self.infrastructure not in \
        InfrastructureAgentFactory.VALID_AGENTS:
      # When running in a cloud, simple formats don't require an input_yaml
      return self.invalid("Node layout format was not recognized.")

    if not self.input_yaml:
      if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
        if not self.min_machines:
          self.invalid(self.NO_YAML_REQUIRES_MIN)

        if not self.max_machines:
          self.invalid(self.NO_YAML_REQUIRES_MAX)

        # No layout was created, so create a generic one and then allow it
        # to be validated.
        self.input_yaml = self.generate_cloud_layout()
      else:
        self.invalid(self.INPUT_YAML_REQUIRED)

    # Keep track of whether the deployment is valid while going through.
    node_hash = {}
    role_count = {
      'compute': 0,
      'shadow': 0,
      'memcache': 0,
      'taskqueue': 0,
      'zookeeper': 0,
      'login': 0,
      'db_master': 0,
      'taskqueue_master': 0
    }
    node_count = 0
    all_disks = []
    login_found = False
    # Loop through the list of "node sets", which are grouped by role.
    for node_set in self.input_yaml:
      # If the key nodes is mapped to an integer it should be a cloud
      # deployment so we will use node-ids.
      using_cloud_ids = isinstance(node_set.get('nodes'), int)

      # In cloud_ids deployments, set the fake public ips to node-#.
      if using_cloud_ids:
        ips_list = ["node-{}".format(node_count + i) \
                    for i in xrange(node_set.get('nodes'))]
        # Update node_count.
        node_count += len(ips_list)
      # Otherwise get the ips and validate them.
      else:
        ip_or_ips = node_set.get('nodes')
        ips_list = ip_or_ips if isinstance(ip_or_ips, list) else [ip_or_ips]
        # Validate that the ips_list are either node-id or ip addresses.
        if any([self.is_cloud_ip(ip) for ip in ips_list]):
          self.invalid("Role(s) {}: using node-id format is not supported"
                       " with the ips_layout format being used. Please "
                       "specify an integer or an ip address."\
                       .format(node_set.get('roles')))

        if len(ips_list) - len(set(ips_list)) > 0:
          self.invalid(self.DUPLICATE_IPS)

      # Get the roles.
      role_or_roles = node_set.get('roles')
      if len(ips_list) == 0:
        self.invalid("Node amount cannot be zero for role(s) {}."\
                     .format(role_or_roles))
      roles = role_or_roles if isinstance(role_or_roles, list) else \
        [role_or_roles]

      # Immediately fail if we have more than one node for master.
      if 'master' in roles and (self.master or len(ips_list) > 1):
        self.invalid("Only one master is allowed.")

      # Create or retrieve the nodes from the node_hash.
      nodes = [node_hash[ip] if ip in node_hash else \
               Node(ip, using_cloud_ids) for ip in ips_list]

      # Validate volume usage, there should be an equal number of volumes to
      # number of nodes.
      if node_set.get('disks', None):
        disk_or_disks = node_set.get('disks')
        disks = disk_or_disks if isinstance(disk_or_disks, list) else \
          [disk_or_disks]
        all_disks.extend(disks)
        self.validate_disks(len(nodes), disks)

        for node, disk in zip(nodes, disks):
          node.disk = disk

      instance_type = node_set.get('instance_type', self.default_instance_type)

      if self.infrastructure:
        if not instance_type:
          self.invalid("Must set a default instance type or specify instance "
                       "type per role.")

      # Check if this is an allowed instance type.
      if instance_type in ParseArgs.DISALLOWED_INSTANCE_TYPES and \
          not (self.force or self.test):
        reason = "the suggested 4GB of RAM"
        if 'database' in roles:
          reason += " to run Cassandra"
        LocalState.confirm_or_abort("The {0} instance type does not have {1}."
                                    "Please consider using a larger instance "
                                    "type.".format(instance_type, reason))
      # Assign master.
      if 'master' in roles:
        self.master = nodes[0]

      # Add the defined roles to the nodes.
      for node in nodes:
        for role in roles:
          node.add_role(role)
          if role == 'login':
            node.public_ip = self.login_host or node.public_ip
        node.instance_type = instance_type
        if not node.is_valid():
          self.invalid(",".join(node.errors()))

      # All nodes that have the same roles will be expanded the same way,
      # so get the updated list of roles from the first node.
      roles = nodes[0].roles

      # Check for login after roles have been expanded.
      if 'login' in roles and login_found:
        self.invalid("Only one login is allowed.")
      elif 'login' in roles:
        login_found = True

      # Update dictionary containing role counts.
      role_count.update({role: role_count.get(role, 0) + len(nodes)
                         for role in roles})
      # Update the node_hash with the modified nodes.
      node_hash.update({node.public_ip: node for node in nodes})

    # Make sure disks are unique.
    if all_disks:
      self.validate_disks(len(all_disks), all_disks)

    self.validate_database_replication(node_hash.values())
    # Distribute unassigned roles and validate that certain roles are filled
    # and return a list of nodes or raise BadConfigurationException.
    nodes = self.distribute_unassigned_roles(node_hash.values(), role_count)

    if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
      if not self.min_machines:
        self.min_machines = len(nodes)
      if not self.max_machines:
        self.max_machines = len(nodes)

    self.nodes = nodes

    return True

  def validate_disks(self, disks_expected, disks):
    """ Checks to make sure that the user has specified exactly one persistent
    disk per node.

    Args:
      disks_expected: The amount of nodes that should have a disk.
      disks: The list of disks provided or None if using the old format.
    Raises: BadConfigurationException indicating why the disks given were
      invalid.
    """
    # Make sure that every node has a disk specified.
    if disks_expected != len(disks):
      self.invalid("When specifying disks you must have the same "
        "amount as nodes.")

    # Next, make sure that there are an equal number of unique disks and nodes.
    if disks_expected != len(set(disks)):
      self.invalid("Please specify a unique disk for every node.")

  def validate_database_replication(self, nodes):
    """Checks if the database replication factor specified is valid, setting
    it if it is not present.

    Raises: BadConfigurationException when database replication factor is
    invalid.
    """
    database_node_count = 0
    for node in nodes:
      if node.is_role('database') or node.is_role('db_master') or \
        node.is_role('db_slave'):
        database_node_count += 1

    if not database_node_count:
      self.invalid("At least one database node must be provided.")

    if not self.replication:
      if database_node_count > 3:
        # If there are a lot of database nodes, we default to 3x replication
        self.replication = 3
      else:
        # If there are only a few nodes, replicate to each one of the nodes
        self.replication = database_node_count

    if self.replication > database_node_count:
      self.invalid("Replication factor cannot exceed # of databases.")

  def distribute_unassigned_roles(self, nodes, role_count):
    """ Distributes roles that were not defined by user.

    Args:
      nodes: The list of nodes.
      role_count: A dict containing roles mapped to their count.
    """
    for role, count in role_count.iteritems():
      # If count is not zero, we do not care.
      if count != 0:
        continue
      # Check if a master node was specified.
      if role == 'shadow':
        self.invalid("Need to specify one master node.")
      # Check if an compute node was specified.
      elif role == 'compute':
        self.invalid("Need to specify at least one compute node.")
      # If no memcache nodes were specified, make all compute nodes
      # into memcache nodes.
      elif role == 'memcache':
        for node in self.get_nodes('compute', True, nodes):
          node.add_role('memcache')
      # If no zookeeper nodes are specified, make the shadow a zookeeper node.
      elif role == 'zookeeper':
        self.master.add_role('zookeeper')
      # If no taskqueue nodes are specified, make the shadow the
      # taskqueue_master.
      elif role == 'taskqueue':
        self.master.add_role('taskqueue')
        self.master.add_role('taskqueue_master')
      elif role == 'login':
        self.master.add_role('login')
        self.master.public_ip = self.login_host or self.master.public_ip
      elif role == 'db_master':
        # Get first database node.
        db_node = self.get_nodes('database', True, nodes)[0]
        # Make first database node db_master.
        db_node.add_db_role(is_master=True)
      elif role == 'taskqueue_master':
        # If master is already taskqueue_master, there is nothing for us to do.
        if self.master.is_role('taskqueue_master'):
          continue
        # Get the taskqueue nodes.
        tq_node = self.get_nodes('taskqueue', True, nodes)
        # If there are no taskqueue nodes, do nothing since that is done in
        # the taskqueue if statement.
        if not tq_node:
          continue
        # Add taskqueue_master to first taskqueue node.
        tq_node[0].add_taskqueue_role(is_master=True)
    return nodes

  def generate_cloud_layout(self):
    """Generates a simple placement strategy for cloud deployments when the user
      has not specified one themselves.

      Returns:
        A dict that has one controller node and the other nodes set as servers.
    """
    master_node_roles = ['master', 'database', 'memcache', 'login',
                         'zookeeper', 'taskqueue']
    layout = [{'roles' : master_node_roles, 'nodes' : 1}]
    if self.min_machines == 1:
      layout[0]['roles'].append('appengine')
      return layout

    other_node_roles = ['database', 'memcache', 'appengine', 'taskqueue']

    num_slaves = self.min_machines - 1
    layout.append({'roles': other_node_roles, 'nodes': num_slaves})

    return layout

  def replication_factor(self):
    """Returns the replication factor for this NodeLayout, if the layout is one
    that AppScale can deploy with.

    Returns:
      The replication factor if the NodeLayout is valid, None otherwise.
    """
    return self.replication

  def head_node(self):
    """ Searches through the nodes in this NodeLayout for the node with the
    'shadow' role.

    Returns:
      The node running the 'shadow' role, or None if (1) the NodeLayout isn't
      acceptable for use with AppScale, or (2) no shadow node was specified.
    """
    return self.master

  def other_nodes(self):
    """ Searches through the nodes in this NodeLayout for all nodes without the
    'shadow' role.

    Returns:
      A list of nodes not running the 'shadow' role, or the empty list if the
      NodeLayout isn't acceptable for use with AppScale.
    """
    return [node for node in self.nodes if not node.is_role('shadow')]

  def get_nodes(self, role, is_role, nodes=None):
    """ Searches through the nodes in this NodeLayout for all nodes with or
    without the role based on boolean value of is_role.

    Args:
      role: A string describing a role that the nodes list is being searched
        for.
      is_role: A boolean to determine whether the return value is the nodes
        that are the role or the nodes that are not the role.
      nodes: The list of nodes, or self.nodes if list is not supplied.

    Returns:
      A list of nodes either running or not running (based on is_role) the
      argument role role, or the empty list if the NodeLayout isn't
      acceptable for use with AppScale.
    """
    if role not in self.VALID_ROLES:
      return []
    nodes = nodes or self.nodes
    return [node for node in nodes if node.is_role(role) == is_role]

  def db_master(self):
    """ Searches through the nodes in this NodeLayout for the node with the
    'db_master' role.

    Returns:
      The node running the 'db_master' role, or None if (1) the NodeLayout isn't
      acceptable for use with AppScale, or (2) no db_master node was specified.
    """
    for node in self.nodes:
      if node.is_role('db_master'):
        return node
    return None

  def are_disks_used(self):
    """ Searches through the nodes in this NodeLayout to see if any persistent
    disks are being used.

    Returns:
      True if any persistent disks are used, and False otherwise.
    """
    disks = [node.disk for node in self.nodes]
    for disk in disks:
      if disk:
        return True
    return False

  def to_list(self):
    """ Converts all of the nodes (except the head node) to a format that can
    be easily JSON-dumped (a list of dicts).

    Returns:
      A list, where each member is a dict corresponding to a Node in this
      AppScale deployment. As callers explicitly specify the head node, we
      don't include it in this list.
    """
    return [node.to_json() for node in self.nodes]

  def from_locations_json_list(self, locations_nodes_list):
    """Returns a list of nodes if the previous locations JSON matches with the
    current NodeLayout from the AppScalefile.

    Args:
      locations_nodes_list: A list of nodes in dictionary form loaded from
        the locations json.
    Raises:
      BadConfigurationException if the locations json nodes cannot be matched
        with the AppScalefile nodes.
    """

    # If the length does not match up the user has added or removed a node in
    # the AppScalefile.
    if len(locations_nodes_list) != len(self.nodes):
      raise BadConfigurationException("AppScale does not currently support "
                                      "changes to AppScalefile or locations "
                                      "JSON between a down and an up. If "
                                      "you would like to "
                                      "change the node layout use "
                                      "down --terminate before an up.")

    # Place defined nodes first so they will be matched before open nodes.
    old_nodes = [node for node in locations_nodes_list if
                 LocalState.get_node_roles(node) != ['open']]
    old_nodes.extend(
        [node for node in locations_nodes_list
         if LocalState.get_node_roles(node) == ['open']])

    def nodes_match(old_node, new_node):
      """ Determines if old node is a sufficient match for the new node. """
      if old_node.get('instance_type') != new_node.instance_type:
        return False

      # Because this function deals with the locations json file we use this
      # method from LocalState.
      local_state_roles = LocalState.get_node_roles(old_node)

      if local_state_roles == ['open']:
        return True

      old_roles = {self.DEPRECATED_ROLES.get(role, role)
                   for role in local_state_roles}
      return old_roles == set(new_node.roles)

    # Ensure each node has a matching locations.json entry.
    for new_node in self.nodes:
      index = next((index for index, old_node in enumerate(old_nodes)
                    if nodes_match(old_node, new_node)), -1)

      if index == -1:
        raise BadConfigurationException('Unable to find a match for {}'
                                        'in locations.json'.format(new_node))
      roles = new_node.roles
      old_node = old_nodes.pop(index)
      new_node.from_json(old_node)
      new_node.roles = roles

      if not new_node.is_valid():
        raise BadConfigurationException('Node is invalid: {}'.format(new_node))

    return self.nodes

  def invalid(self, message):
    """ Wrapper that NodeLayout validation aspects call when the given layout
      is invalid.

    Raises: BadConfigurationException with the given message.
    """
    raise BadConfigurationException(message)


class Node():
  """Nodes are a representation of a virtual machine in an AppScale deployment.
  """

  DUMMY_INSTANCE_ID = "i-APPSCALE"

  def __init__(self, public_ip, cloud, roles=[], disk=None, instance_type=None):
    """Creates a new Node, representing the given id in the specified cloud.


    Args:
      public_ip: The public IP address, and in cloud deployments, we use
      node-int (since we don't know the IP address)
      cloud: The cloud that this Node belongs to.
      roles: A list of roles that this Node will run in an AppScale deployment.
      disk: The name of the persistent disk that this node backs up data to.
    """
    self.public_ip = public_ip
    self.private_ip = public_ip
    self.instance_id = self.DUMMY_INSTANCE_ID
    self.cloud = cloud
    self.roles = roles
    self.disk = disk
    self.instance_type = instance_type
    self.expand_roles()


  def __str__(self):
    return str(self.to_json())


  def add_db_role(self, is_master):
    """Adds a database master or slave role to this Node, depending on
    the argument given.

    Args:
      is_master: A bool that indicates we should add a database master role.
    """
    if is_master:
      self.add_role('db_master')
    else:
      self.add_role('db_slave')


  def add_taskqueue_role(self, is_master):
    """Adds a TaskQueue master or slave role to this Node, depending on
    the argument given.

    Args:
      is_master: A bool that indicates we should add a TaskQueue master role.
    """
    if is_master:
      self.add_role('taskqueue_master')
    else:
      self.add_role('taskqueue_slave')


  def add_role(self, role):
    """Adds the specified role to this Node.

    Args:
      role: A str that represents the role to add to this Node. If the
        role represents more than one other roles (e.g., controller
        represents several internal roles), then we automatically perform
        this conversion for the caller.
    """
    self.roles.append(role)
    self.expand_roles()


  def is_role(self, role):
    """Checks to see if this Node runs the specified role.

    Args:
      role: The role that we should see if this Node runs.
    Returns:
      True if this Node runs the given role, False otherwise.
    """
    if role in self.roles:
      return True
    else:
      return False


  def is_valid(self):
    """Checks to see if this Node's roles can be used together in an AppScale
    deployment.

    Returns:
      True if the roles on this Node can run together, False otherwise.
    """
    if self.errors():
      return False
    else:
      return True


  def errors(self):
    """Reports the reasons why the roles associated with this Node cannot
    function on an AppScale deployment.

    Returns:
      A list of strs, each of which representing a reason why this Node cannot
      operate in an AppScale deployment.
    """
    errors = []
    for role in self.roles:
      if not role in NodeLayout.VALID_ROLES:
        errors.append("Invalid role: {0}".format(role))
    return errors


  def expand_roles(self):
    """Converts the 'master' composite role into the roles it represents, and
    adds dependencies necessary for the 'login' and 'database' roles.
    """
    for i in range(len(self.roles)):
      role = self.roles[i]
      if role in NodeLayout.DEPRECATED_ROLES:
        AppScaleLogger.warn("'{}' role has been deprecated, please use '{}'"
                            .format(role, NodeLayout.DEPRECATED_ROLES[role]))
        self.roles.remove(role)
        self.roles.append(NodeLayout.DEPRECATED_ROLES[role])

    if 'master' in self.roles:
      self.roles.remove('master')
      self.roles.append('shadow')
      self.roles.append('load_balancer')

    if 'login' in self.roles:
      self.roles.append('load_balancer')

    # TODO: remove these, db_slave and taskqueue_slave are currently deprecated.
    if 'db_slave' in self.roles or 'db_master' in self.roles \
        and 'database' not in self.roles:
      self.roles.append('database')

    if 'taskqueue_slave' in self.roles or 'taskqueue_master' in self.roles \
        and 'taskqueue' not in self.roles:
      self.roles.append('taskqueue')

    # Remove any duplicate roles
    self.roles = list(set(self.roles))


  def to_json(self):
    return {
      'public_ip': self.public_ip,
      'private_ip': self.private_ip,
      'instance_id': self.instance_id,
      'roles': self.roles,
      'disk': self.disk,
      'instance_type' : self.instance_type
    }


  def from_json(self, node_dict):
    """Modifies the node it is called on to have the attributes of the passed
    dictionary.

    Args:
      node_dict: A dictionary from JSON of the format:
        {
          'public_ip': self.public_ip,
          'private_ip': self.private_ip,
          'instance_id': self.instance_id,
          'roles': self.roles,
          'disk': self.disk
        }
    """
    self.public_ip = node_dict.get('public_ip')
    self.private_ip = node_dict.get('private_ip')
    self.instance_id = node_dict.get('instance_id')
    self.roles = node_dict.get('roles')
    self.disk = node_dict.get('disk')
    self.instance_type = node_dict.get('instance_type')
