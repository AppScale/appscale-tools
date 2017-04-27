#!/usr/bin/env python


# General-purpose Python library imports
import re
import yaml


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory


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


  # A tuple containing the keys that can be used in simple deployments.
  SIMPLE_FORMAT_KEYS = ('controller', 'servers')


  # A tuple containing the keys that can be used in advanced deployments.
  ADVANCED_FORMAT_KEYS = ['master', 'database', 'appengine', 'open', 'login',
    'zookeeper', 'memcache', 'taskqueue', 'search', 'load_balancer']


  # A tuple containing all of the roles (simple and advanced) that the
  # AppController recognizes. These include _master and _slave roles, which
  # the user may not be able to specify directly.
  VALID_ROLES = ('master', 'appengine', 'database', 'shadow', 'open',
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
    """
    if not isinstance(options, dict):
      options = vars(options)

    input_yaml = options.get('ips')
    if isinstance(input_yaml, str):
      with open(input_yaml, 'r') as file_handle:
        self.input_yaml = yaml.safe_load(file_handle.read())
    elif isinstance(input_yaml, dict):
      self.input_yaml = input_yaml
    else:
      self.input_yaml = None

    self.disks = options.get('disks')
    self.infrastructure = options.get('infrastructure')
    self.min_vms = options.get('min')
    self.max_vms = options.get('max')
    self.replication = options.get('replication')
    self.database_type = options.get('table', 'cassandra')
    self.add_to_existing = options.get('add_to_existing')

    if 'login_host' in options and options['login_host'] is not None:
      self.login_host = options['login_host']
    else:
      self.login_host = None

    self.nodes = []


  def is_valid(self):
    """Determines if the current NodeLayout can be successfully used to
    run an AppScale deployment.

    Returns:
      A bool that indicates if this placement strategy is valid.
    """
    if self.is_simple_format():
      return self.is_valid_simple_format()['result']
    elif self.is_advanced_format():
      return self.is_valid_advanced_format()['result']
    else:
      return False


  def errors(self):
    """Generates a list that indicates why this NodeLayout is invalid
    (e.g., if no database nodes were specified).

    Returns:
      A list containing all of the reasons why this NodeLayout is invalid.
    """
    if self.is_valid():
      return []

    if self.is_simple_format():
      return self.is_valid_simple_format()['message']
    elif self.is_advanced_format():
      return self.is_valid_advanced_format()['message']
    elif not self.input_yaml:
      return [self.INPUT_YAML_REQUIRED]
    else:
      for key in self.input_yaml.keys():
        if key not in self.SIMPLE_FORMAT_KEYS \
          and key not in self.ADVANCED_FORMAT_KEYS:
          return ["The flag {0} is not a supported flag".format(key)]

      return [self.USED_SIMPLE_AND_ADVANCED_KEYS]

  
  def count_roles(self):
    """Counts the number of roles that are hosted within the current
    deployment strategy. In particular, we're interested in counting
    one of the roles that make up a standard 'three-tier' web
    deployment strategy per node, so that we can tell if the deployment
    is officially supported or not.
    
    Returns:
      A dict that maps each of the main three-tier deployment roles to
      how many nodes host that role.
    """
    num_roles = {
      'login' : 0,
      'appengine' : 0,
      'database' : 0,
      'zookeeper' : 0
    }

    for node in self.nodes:
      roles = node.roles
      found_three_tier_role = False
      for role in roles:
        if found_three_tier_role:
          break
        if role == 'login':
          num_roles['login'] += 1
          found_three_tier_role = True
        elif role == 'appengine':
          num_roles['appengine'] += 1
          found_three_tier_role = True
        elif role == 'db_master':
          num_roles['database'] += 1
          found_three_tier_role = True
        elif role == 'db_slave':
          num_roles['database'] += 1
          found_three_tier_role = True
        elif role == 'zookeeper':
          num_roles['zookeeper'] += 1
          found_three_tier_role = True

    return num_roles


  def is_simple_format(self):
    """Determines if this NodeLayout represents a simple AppScale deployment.

    Returns:
      True if the deployment is simple, False otherwise.
    """
    if self.input_yaml:
      for key, _ in self.input_yaml.iteritems():
        if key not in self.SIMPLE_FORMAT_KEYS:
          return False

      return True
    else:
      if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
        # When running in a cloud, simple formats don't require an input_yaml
        return True
      else:
        return False


  def is_advanced_format(self):
    """Checks the YAML given to see if the user wants us to run services
    via the advanced deployment strategy.

    Returns:
      True if all the roles specified are advanced roles, and False otherwise.
    """
    if not self.input_yaml:
      return False

    for key in self.input_yaml.keys():
      if key not in self.ADVANCED_FORMAT_KEYS:
        return False

    return True


  def parse_ip(self, ip_address):
    """Parses the given IP address or node ID and returns it and a str
    indicating whether or not we are in a cloud deployment.

    Args:
      ip_address: A str that represents the IP address or node ID (of the format
        node-int) to parse.
    Returns:
      id: A str that represents the IP address of this machine (if running in a
        virtualized cluster) or the index of this node (if running in a cloud).
      cloud: A str that indicates if we believe that machine is in a virtualized
        cluster or in a cloud.
    """
    match = self.NODE_ID_REGEX.match(ip_address)
    if not match:
      return ip_address, "not-cloud"
    else:
      return match.group(0), match.group(1)


  def is_valid_simple_format(self):
    """Checks to see if this NodeLayout represents an acceptable simple
    deployment strategy, and if so, constructs self.nodes from it.

    Returns:
      A dict that indicates if the deployment strategy is valid, and if
      not, the reason why it is invalid.
    """
    if self.nodes:
      return self.valid()

    if not self.input_yaml:
      if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
        if not self.min_vms:
          return self.invalid(self.NO_YAML_REQUIRES_MIN)

        if not self.max_vms:
          return self.invalid(self.NO_YAML_REQUIRES_MAX)

        # No layout was created, so create a generic one and then allow it
        # to be validated.
        self.input_yaml = self.generate_cloud_layout()
      else:
        return self.invalid(self.INPUT_YAML_REQUIRED)

    nodes = []
    for role, ips in self.input_yaml.iteritems():
      if not ips:
        continue

      if isinstance(ips, str):
        ips = [ips]
      for ip in ips:
        ip, cloud = self.parse_ip(ip)
        node = SimpleNode(ip, cloud, [role])

        # In simple deployments the db master and taskqueue  master is always on
        # the shadow node, and db slave / taskqueue slave is always on the other
        # nodes
        is_master = node.is_role('shadow')
        node.add_db_role(is_master)
        node.add_taskqueue_role(is_master)

        if not node.is_valid():
          return self.invalid(",".join(node.errors()))

        if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
          if not self.NODE_ID_REGEX.match(node.public_ip):
            return self.invalid("{0} is not a valid node ID (must be node-int)".
              format(node.public_ip))
        else:
          # Virtualized cluster deployments use IP addresses as node IDs
          if not self.IP_REGEX.match(node.public_ip):
            return self.invalid("{0} must be an IP address".format(
              node.public_ip))

        nodes.append(node)

    # make sure that the user hasn't erroneously specified the same ip
    # address more than once

    all_ips = []
    ips_provided = self.input_yaml.values()
    for ip_or_ips in ips_provided:
      if isinstance(ip_or_ips, list):
        all_ips += ip_or_ips
      else:
        all_ips.append(ip_or_ips)

    num_of_duplicate_ips = len(all_ips) - len(set(all_ips))
    if num_of_duplicate_ips > 0:
      return self.invalid(self.DUPLICATE_IPS)

    if len(nodes) == 1:
      # Singleton node should be master and app engine
      nodes[0].add_role('appengine')
      nodes[0].add_role('memcache')

    # controller -> shadow
    controller_count = 0
    for node in nodes:
      if node.is_role('shadow'):
        controller_count += 1

    if controller_count == 0:
      return self.invalid(self.NO_CONTROLLER)
    elif controller_count > 1:
      return self.invalid(self.ONLY_ONE_CONTROLLER)

    database_count = 0
    for node in nodes:
      if node.is_role('database'):
        database_count += 1

    # by this point, somebody has a login role, so now's the time to see if we
    # need to override their ip address with --login_host
    if self.login_host is not None:
      for node in nodes:
        if node.is_role('login'):
          node.public_ip = self.login_host

    if self.disks:
      valid, reason = self.is_disks_valid(nodes)
      if not valid:
        return self.invalid(reason)

      for node in nodes:
        node.disk = self.disks.get(node.public_ip)

    rep = self.is_database_replication_valid(nodes)

    if not rep['result']:
      return rep

    self.nodes = nodes
    return self.valid()


  def is_valid_advanced_format(self):
    """Checks to see if this NodeLayout represents an acceptable advanced
    deployment strategy, and if so, constructs self.nodes from it.

    Returns:
      A dict that indicates if the deployment strategy is valid, and if
      not, the reason why it is invalid.
    """
    if self.nodes:
      return self.valid()

    node_hash = {}
    for role, ips in self.input_yaml.iteritems():
      
      if isinstance(ips, str):
        ips = [ips]

      for index, ip_addr in enumerate(ips):
        node = None
        if ip_addr in node_hash:
          node = node_hash[ip_addr]
        else:
          ip_addr, cloud = self.parse_ip(ip_addr)
          node = AdvancedNode(ip_addr, cloud)

        if role == 'database':
          # The first database node is the master
          if index == 0:
            is_master = True
          else:
            is_master = False
          node.add_db_role(is_master)
        elif role == 'db_master':
          node.add_role('zookeeper')
          node.add_role('role')
        elif role == 'taskqueue':
          # Like the database, the first taskqueue node is the master
          if index == 0:
            is_master = True
          else:
            is_master = False
          node.add_role('taskqueue')
          node.add_taskqueue_role(is_master)
        else:
          node.add_role(role)
        
        node_hash[ip_addr] = node

    # Dont need the hash any more, make a nodes list
    nodes = node_hash.values()

    for node in nodes:
      if not node.is_valid():
        return self.invalid(",".join(node.errors()))

      if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
        if not self.NODE_ID_REGEX.match(node.public_ip):
          return self.invalid("{0} is not a valid node ID (must be node-int)".
            format(node.public_ip))
      else:
        # Virtualized cluster deployments use IP addresses as node IDs
        if not self.IP_REGEX.match(node.public_ip):
          return self.invalid("{0} must be an IP address".format(
            node.public_ip))

    if self.add_to_existing:
      self.nodes = nodes
      return self.valid()

    master_nodes = []
    for node in nodes:
      if node.is_role('shadow'):
        master_nodes.append(node)

    # need exactly one master
    if len(master_nodes) == 0:
      return self.invalid("No master was specified")
    elif len(master_nodes) > 1:
      return self.invalid("Only one master is allowed")

    master_node = master_nodes[0]

    login_nodes = []
    for node in nodes:
      if node.is_role('login'):
        login_nodes.append(node)

    # If a login node was not specified, make the master into the login node
    if not login_nodes:
      master_node.add_role('login')

    # by this point, somebody has a login role, so now's the time to see if we
    # need to override their ip address with --login_host
    if self.login_host is not None:
      for node in nodes:
        if node.is_role('login'):
          node.public_ip = self.login_host

    appengine_count = 0
    for node in nodes:
      if node.is_role('appengine'):
        appengine_count += 1

    if appengine_count < 1:
      return self.invalid("Need to specify at least one appengine node")

    memcache_count = 0
    for node in nodes:
      if node.is_role('memcache'):
        memcache_count += 1

    # if no memcache nodes were specified, make all appengine nodes
    # into memcache nodes
    if memcache_count < 1:
      for node in nodes:
        if node.is_role('appengine'):
          node.add_role('memcache')

    if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
      if not self.min_vms:
        self.min_vms = len(nodes)
      if not self.max_vms:
        self.max_vms = len(nodes)

    zookeeper_count = 0
    for node in nodes:
      if node.is_role('zookeeper'):
        zookeeper_count += 1
    if not zookeeper_count:
      master_node.add_role('zookeeper')

    # If no taskqueue nodes are specified, make the shadow the taskqueue_master
    taskqueue_count = 0
    for node in nodes:
      if node.is_role('taskqueue'):
        taskqueue_count += 1

    if not taskqueue_count:
      master_node.add_role('taskqueue')
      master_node.add_role('taskqueue_master')

    if self.disks:
      valid, reason = self.is_disks_valid(nodes)
      if not valid:
        return self.invalid(reason)

      for node in nodes:
        node.disk = self.disks.get(node.public_ip)

    rep = self.is_database_replication_valid(nodes)
    if not rep['result']:
      return rep

    self.nodes = nodes

    return self.valid()


  def is_disks_valid(self, nodes):
    """ Checks to make sure that the user has specified exactly one persistent
    disk per node.

    Returns:
      A tuple of two items. The first item is a bool that indicates if the
      user specified a valid set of disks to use, and the second item is a str
      that indicates why the disks given were invalid (which is empty when the
      disks are valid).
    """
    # Make sure that every node has a disk specified.
    # TODO(cgb): Amend this to only DB nodes.
    if len(nodes) != len(self.disks.keys()):
      return False, "Please specify a disk for every node."

    # Next, make sure that there are an equal number of
    # unique disks and nodes.
    if len(nodes) != len(set(self.disks.values())):
      return False, "Please specify a unique disk for every node."

    return True, ""


  def is_database_replication_valid(self, nodes):
    """Checks if the database replication factor specified is valid, setting
    it if it is not present.

    Returns:
      A dict indicating that the replication factor is valid, or in cases
      when it is not valid, the reason why it is not valid.
    """
    database_node_count = 0
    for node in nodes:
      if node.is_role('database') or node.is_role('db_master') or \
        node.is_role('db_slave'):
        database_node_count += 1

    if not database_node_count:
      return self.invalid("At least one database node must be provided.")

    if not self.replication:
      if database_node_count > 3:
        # If there are a lot of database nodes, we default to 3x replication
        self.replication = 3
      else:
        # If there are only a few nodes, replicate to each one of the nodes
        self.replication = database_node_count

    if self.replication > database_node_count:
      return self.invalid("Replication factor cannot exceed # of databases")

    return self.valid()


  def generate_cloud_layout(self):
    """Generates a simple placement strategy for cloud deployments when the user
      has not specified one themselves.

      Returns:
        A dict that has one controller node and the other nodes set as servers.
    """
    layout = {'controller' : "node-1"}
    servers = []
    num_slaves = self.min_vms - 1
    for i in xrange(num_slaves):
      servers.append("node-{0}".format(i+2))

    layout['servers'] = servers
    return layout


  def replication_factor(self):
    """Returns the replication factor for this NodeLayout, if the layout is one
    that AppScale can deploy with.

    Returns:
      The replication factor if the NodeLayout is valid, None otherwise.
    """
    if self.is_valid():
      return self.replication
    else:
      return None


  def head_node(self):
    """ Searches through the nodes in this NodeLayout for the node with the
    'shadow' role.

    Returns:
      The node running the 'shadow' role, or None if (1) the NodeLayout isn't
      acceptable for use with AppScale, or (2) no shadow node was specified.
    """
    if not self.is_valid():
      return None

    for node in self.nodes:
      if node.is_role('shadow'):
        return node

    return None


  def other_nodes(self):
    """ Searches through the nodes in this NodeLayout for all nodes without the
    'shadow' role.

    Returns:
      A list of nodes not running the 'shadow' role, or the empty list if the
      NodeLayout isn't acceptable for use with AppScale.
    """
    if not self.is_valid():
      return []

    other_nodes = []
    for node in self.nodes:
      if not node.is_role('shadow'):
        other_nodes.append(node)
    return other_nodes

  def get_nodes(self, role, is_role):
    """ Searches through the nodes in this NodeLayout for all nodes with or
    without the role based on boolean value of is_role.

    Args:
      role: A string describing a role that the nodes list is being searched
        for.
      is_role: A boolean to determine whether the return value is the nodes
        that are the role or the nodes that are not the role.

    Returns:
      A list of nodes either running or not running (based on is_role) the
      argument role role, or the empty list if the NodeLayout isn't
      acceptable for use with AppScale.
    """
    if not self.is_valid() or role not in self.VALID_ROLES:
      return []

    nodes_requested = []
    for node in self.nodes:
      if node.is_role(role) == is_role:
        nodes_requested.append(node)
    return nodes_requested


  def db_master(self):
    """ Searches through the nodes in this NodeLayout for the node with the
    'db_master' role.

    Returns:
      The node running the 'db_master' role, or None if (1) the NodeLayout isn't
      acceptable for use with AppScale, or (2) no db_master node was specified.
    """
    if not self.is_valid():
      return None

    for node in self.nodes:
      if node.is_role('db_master'):
        return node
    return None


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
    current NodeLayout from the AppScalefile. Otherwise returns None."""

    # If the length does not match up the user has added or removed a node in
    # the AppScalefile.
    if len(locations_nodes_list) != len(self.nodes):
      return None

    nodes = []

    # Use a copy so we do not overwrite self.nodes when we call
    # Node.from_json since that method modifies the node it is called on.
    nodes_copy = self.nodes[:]
    open_nodes = []
    for old_node in locations_nodes_list:
      old_node_roles = old_node.get('jobs')
      if old_node_roles == ["open"]:
        open_nodes.append(old_node)
        continue
      for _, node in enumerate(nodes_copy):
        # Match nodes based on jobs/roles.
        if set(old_node_roles) == set(node.roles):
          nodes_copy.remove(node)
          node.from_json(old_node)
          if node.is_valid():
            nodes.append(node)
          else:
            # Locations JSON is incorrect if we get here.
            return None
          break
    for open_node in open_nodes:
      try:
        node = nodes_copy.pop()
      except IndexError:
        return None
      # Match nodes based on jobs/roles.
      roles = node.roles
      node.from_json(open_node)
      node.roles = roles
      if node.is_valid():
        nodes.append(node)
      else:
        # Locations JSON is incorrect if we get here.
        return None

    # If these lengths are equal all nodes were matched.
    if len(nodes) == len(self.nodes):
      return nodes
    else:
      return None


  def valid(self, message = None):
    """Generates a dict that indicates that this NodeLayout is valid, optionally
    including the reason why it is valid.

    Returns:
      A dict representing a valid NodeLayout.
    """
    return { 'result' : True, 'message' : message }


  def invalid(self, message):
    """Generates a dict that indicates that this NodeLayout is not valid, along
    with the reason why it is invalid.

    Returns:
      A dict representing an invalid NodeLayout.
    """
    return { 'result' : False, 'message' : message }


class Node():
  """Nodes are a representation of a virtual machine in an AppScale deployment.
  Callers should not use this class directly, but should instead use SimpleNode
  or AdvancedNode, depending on the deployment type.
  """

  DUMMY_INSTANCE_ID = "i-APPSCALE"

  def __init__(self, public_ip, cloud, roles=[], disk=None):
    """Creates a new Node, representing the given id in the specified cloud.


    Args:
      id: A unique identifier for this Node. For virtualized deployments, id is
        the public IP address, and in cloud deployments, we use node-int (since
        we don't know the IP address)
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
    self.expand_roles()


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
    """Converts any composite roles in this Node to the roles that they
    represent. As this function should be implemented by SimpleNodes and
    AdvancedNodes, we do not implement it here.
    """
    raise NotImplementedError

  def to_json(self):
    return {
      'public_ip': self.public_ip,
      'private_ip': self.private_ip,
      'instance_id': self.instance_id,
      'jobs': self.roles,
      'disk': self.disk
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
          'jobs': self.roles,
          'disk': self.disk
        }
    """
    self.public_ip = node_dict.get('public_ip')
    self.private_ip = node_dict.get('private_ip')
    self.instance_id = node_dict.get('instance_id')
    self.roles = node_dict.get('jobs')
    self.disk = node_dict.get('disk')


class SimpleNode(Node):
  """SimpleNode represents a Node in a simple AppScale deployment, along with
  the roles that users can specify in simple deployments.
  """


  def expand_roles(self):
    """Converts the 'controller' and 'servers' composite roles into the roles
    that they represent.
    """
    if 'controller' in self.roles:
      self.roles.remove('controller')
      self.roles.append('shadow')
      self.roles.append('load_balancer')
      self.roles.append('database')
      self.roles.append('memcache')
      self.roles.append('login')
      self.roles.append('zookeeper')
      self.roles.append('taskqueue')

    # If they specify a servers role, expand it out to
    # be database, appengine, and memcache
    if 'servers' in self.roles:
      self.roles.remove('servers')
      self.roles.append('appengine')
      self.roles.append('memcache')
      self.roles.append('database')
      self.roles.append('taskqueue')

    # Remove any duplicate roles
    self.roles = list(set(self.roles))


class AdvancedNode(Node):
  """AdvancedNode represents a Node in an advanced AppScale deployment, along
  with the roles that users can specify in advanced deployments.
  """


  def expand_roles(self):
    """Converts the 'master' composite role into the roles it represents, and
    adds dependencies necessary for the 'login' and 'database' roles.
    """
    if 'master' in self.roles:
      self.roles.remove('master')
      self.roles.append('shadow')
      self.roles.append('load_balancer')

    if 'login' in self.roles:
      self.roles.append('load_balancer')

    # TODO(cgb): Look into whether or not the database still needs memcache
    # support. If not, remove this addition and the validation of it above.
    if 'database' in self.roles:
      self.roles.append('memcache')

    # Remove any duplicate roles
    self.roles = list(set(self.roles))
