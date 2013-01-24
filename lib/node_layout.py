#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import re
import yaml


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory
from custom_exceptions import BadConfigurationException


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
    'zookeeper', 'memcache', 'rabbitmq']


  # A tuple containing all of the roles (simple and advanced) that the
  # AppController recognizes. These include _master and _slave roles, which
  # the user may not be able to specify directly.
  VALID_ROLES = ('master', 'appengine', 'database', 'shadow', 'open',
    'load_balancer', 'login', 'db_master', 'db_slave', 'zookeeper', 'memcache',
    'rabbitmq', 'rabbitmq_master', 'rabbitmq_slave')


  # A regular expression that matches IP addresses, used in ips.yaml files for
  # virtualized cluster deployments.
  IP_REGEX = re.compile('\d+\.\d+\.\d+\.\d+')


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


  def __init__(self, input_yaml, options):
    """Creates a new NodeLayout from the given YAML file.

    Args:
      input_yaml: YAML that represents the placement strategy to use for
        this AppScale deployment. This YAML can be either raw YAML, or
        a str containing a path on the local filesystem that, when read,
        contains the YAML in question. It can also be set to None, for
        deployments when the user specifies (via 'options') how many VMs
        they wish to use.
      options: A Namespace or dict that represents information about the
        placement strategy not specifically relating to IP addresses or
        services (e.g., database-specific parameters).
    """
    if isinstance(input_yaml, str):
      with open(input_yaml, 'r') as file_handle:
        self.input_yaml = yaml.safe_load(file_handle.read())
    elif isinstance(input_yaml, dict):
      self.input_yaml = input_yaml
    else:
      self.input_yaml = None

    if not isinstance(options, dict):
      options = vars(options)

    if 'infrastructure' in options:
      self.infrastructure = options['infrastructure']
    else:
      self.infrastructure = None

    if 'min_images' in options:
      self.min_images = options['min_images']
    else:
      self.min_images = None

    if 'max_images' in options:
      self.max_images = options['max_images']
    else:
      self.max_images = None

    if 'replication' in options:
      self.replication = options['replication']
    else:
      self.replication = None

    self.database_type = options['table']
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


  """
USED_SIMPLE_AND_ADVANCED_KEYS = "Used both simple and advanced layout roles." +
  " Only simple (controller, servers) or advanced (master, appengine, etc) " +
  "can be used"
NO_INPUT_YAML_REQUIRES_MAX_IMAGES = "If no input yaml is specified, " +
  "max_images must be specified."
INPUT_YAML_REQUIRED = "An input yaml file is required for Xen, KVM, and " +
  "hybrid cloud deployments"

NODE_ID_REGEX = /(node|cloud(\d+))-(\d+)/
DEFAULT_NUM_NODES = 1
VALID_ROLES = [:master, :appengine, :database, :shadow, :open] + 
  [:load_balancer, :login, :db_master, :db_slave, :zookeeper, :memcache] +
  [:rabbitmq, :rabbitmq_master, :rabbitmq_slave]

class NodeLayout
  SIMPLE_FORMAT_KEYS = [:controller, :servers]

  # supported? is a method that checks to see if AppScale has normally
  # been tested and successfully run over this deployment strategy.
  # All simple deployments are supported, but only two specific types
  # of advanced deployments are supported.
  # Returns:
  #   true if AppScale has been run with this deployment strategy,
  #     false otherwise.
  def supported?
    if is_simple_format?
      return true
    elsif is_advanced_format?
      return is_supported_advanced_format?
    else
      return false
    end
  end

  # is_supported_advanced_format? checks to see if AppScale has been
  # tested and successfully run over this advanced deployment strategy.
  # Specifically, we only support two advanced deployment strategies,
  # one with a minimal number of nodes (each with one service), and
  # one that doubles the number of nodes of the minimal strategy
  # (except for ZooKeeper, which we triple since it requires a consensus
  # to function).
  def is_supported_advanced_format?
    if @nodes.length == 1
      return true
    elsif @nodes.length == 4
      # in a four node deployment, we are looking for one node to
      # be a load balancer, one to be an appserver, one to be a
      # database, and one to be zookeeper
      num_roles = count_roles
      if num_roles[:login] == 1 and num_roles[:appengine] == 1 and
        num_roles[:database] == 1 and num_roles[:zookeeper] == 1
        return true
      else
        return false
      end
    elsif @nodes.length == 8
      # in an eight node deployment, we are looking for one node to
      # be a load balancer, two to be appservers, two to be databases,
      # and three to be zookeepers
      num_roles = count_roles
      if num_roles[:login] == 1 and num_roles[:appengine] == 2 and
        num_roles[:database] == 2 and num_roles[:zookeeper] == 3
        return true
      else
        return false
      end
    else
      return false
    end
  end

  
  # Counts the number of roles that are hosted within the current
  # deployment strategy. In particular, we're interested in counting
  # one of the roles that make up a standard 'three-tier' web
  # deployment strategy per node, so that we can tell if the deployment
  # is officially supported or not.
  # Returns:
  #   A Hash that maps each of the main three-tier deployment roles to
  #     how many nodes host that role.
  def count_roles
    num_roles = {
      :login => 0,
      :appengine => 0,
      :database => 0,
      :zookeeper => 0
    }

    @nodes.each { |node|
      roles = node.roles
      found_three_tier_role = false
      roles.each { |role|
        break if found_three_tier_role
        case role.to_sym
        when :login then 
          num_roles[:login] += 1
          found_three_tier_role = true
        when :appengine then 
          num_roles[:appengine] += 1
          found_three_tier_role = true
        when :db_master then 
          num_roles[:database] += 1
          found_three_tier_role = true
        when :db_slave then 
          num_roles[:database] += 1
          found_three_tier_role = true
        when :zookeeper then 
          num_roles[:zookeeper] += 1
          found_three_tier_role = true
        end
      }
    }
    return num_roles
  end
"""

  def is_simple_format(self):
    """Determines if this NodeLayout represents a simple AppScale deployment.

    Returns:
      True if the deployment is simple, False otherwise.
    """
    if self.input_yaml:
      for key, value in self.input_yaml.iteritems():
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
    if not self.input_yaml:
      return False

    for key in self.input_yaml.keys():
      if key not in self.ADVANCED_FORMAT_KEYS:
        return False

    return True


  def parse_ip(self, ip):
    """Parses the given IP address or node ID and returns it and a str
    indicating whether or not we are in a cloud deployment.

    Args:
      ip: A str that represents the IP address or node ID (of the format
        node-int) to parse.
    Returns:
      id: A str that represents the IP address of this machine (if running in a
        virtualized cluster) or the index of this node (if running in a cloud).
      cloud: A str that indicates if we believe that machine is in a virtualized
        cluster or in a cloud.
    """
    id, cloud = None, None

    match = self.NODE_ID_REGEX.match(ip)
    if not match:
      id = ip
      cloud = "not-cloud"
    else:
      id = match[0]
      cloud = match[1]
    return id, cloud


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
        if not self.min_images:
          return self.invalid(self.NO_YAML_REQUIRES_MIN)

        if not self.max_images:
          return self.invalid(self.NO_YAML_REQUIRES_MAX)

        # No layout was created, so create a generic one and then allow it
        # to be validated.
        self.input_yaml = self.generate_cloud_layout()
      else:
        return self.invalid(self.INPUT_YAML_REQUIRED)

    nodes = []
    for role, ips in self.input_yaml.iteritems():
      if not ips:
        next

      if isinstance(ips, str):
        ips = [ips]
      for ip in ips:
        print "\n\n" + ip  +"\n\n"
        id, cloud = self.parse_ip(ip)
        node = SimpleNode(id, cloud, [role])

        # In simple deployments the db master and rabbitmq master is always on
        # the shadow node, and db slave / rabbitmq slave is always on the other
        # nodes
        is_master = node.is_role('shadow')
        node.add_db_role(self.database_type, is_master)
        node.add_rabbitmq_role(is_master)

        if not node.is_valid():
          return self.invalid(node.errors().join(","))

        if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
          if not self.NODE_ID_REGEX.match(node.id):
            return self.invalid("{0} is not a valid node ID (must be node-int)".format(node.id))
        else:
          # Virtualized cluster deployments use IP addresses as node IDs
          if not self.IP_REGEX.match(node.id):
            return self.invalid("{0} must be an IP address".format(node.id))

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

    # TODO(cgb): Revisit this later and see if it's necessary.
    #if self.skip_replication:
    #  self.nodes = nodes
    #  return self.valid()

    rep = self.is_database_replication_valid(nodes)

    if not rep['result']:
      return rep

    self.nodes = nodes
    return self.valid()


  def is_valid_advanced_format(self):
    if self.nodes:
      return self.valid()

    node_hash = {}
    for role, ips in self.input_yaml.iteritems():
      
      if isinstance(ips, str):
        ips = [ips]

      for index, ip in enumerate(ips):
        node = None
        if ip in node_hash:
          node = node_hash[ip]
        else:
          id, cloud = self.parse_ip(ip)
          node = AdvancedNode(id, cloud)

        if role == 'database':
          # The first database node is the master
          if index == 0:
            is_master = True
          else:
            is_master = False
          node.add_db_role(database_type, is_master)
        elif role == 'db_master':
          node.add_role('zookeeper')
          node.add_role('role')
        elif role == 'rabbitmq':
          # Like the database, the first rabbitmq node is the master
          if index == 0:
            is_master = True
          else:
            is_master = False
          node.add_role('rabbitmq')
          node.add_rabbitmq_role(is_master)
        else:
          node.add_role(role)
        
        node_hash[ip] = node

    # Dont need the hash any more, make a nodes list
    nodes = node_hash.values()

    for node in nodes:
      if not node.is_valid():
        return self.invalid(",".join(node.errors()))

      if self.infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
        if not self.NODE_ID_REGEX.match(node.id):
          return self.invalid("{0} is not a valid node ID (must be node-int)".format(node.id))
      else:
        # Virtualized cluster deployments use IP addresses as node IDs
        if not self.IP_REGEX.match(node.id):
          return self.invalid("{0} must be an IP address".format(node.id))

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
      if not self.min_images:
        self.min_images = len(nodes)
      if not self.max_images:
        self.max_images = len(nodes)

      # TODO(cgb): I think these checks aren't necessary.
      #if len(nodes) < @min_images
      #  return invalid("Too few nodes were provided, #{nodes.length} were specified but #{@min_images} was the minimum")
 
      #if nodes.length > @max_images
      #  return invalid("Too many nodes were provided, #{nodes.length} were specified but #{@max_images} was the maximum")

    zookeeper_count = 0
    for node in nodes:
      if node.is_role('zookeeper'):
        zookeeper_count += 1
    if not zookeeper_count:
      master_node.add_role('zookeeper')

    # If no rabbitmq nodes are specified, make the shadow the rabbitmq_master
    rabbitmq_count = 0
    for node in nodes:
      if node.is_role('rabbitmq'):
        rabbitmq_count += 1

    if not rabbitmq_count:
      master_node.add_role('rabbitmq')
      master_node.add_role('rabbitmq_master')

    # Any node that runs appengine needs rabbitmq to dispatch task requests to
    # It's safe to add the slave role since we ensure above that somebody
    # already has the master role
    for node in nodes:
      if node.is_role('appengine') and not node.is_role('rabbitmq'):
        node.add_role('rabbitmq_slave')

    database_count = 0
    for node in nodes:
      if node.is_role('database'):
        database_count += 1

    # TODO(cgb): Revisit if this is necessary later.
    #if @skip_replication
    #  @nodes = nodes
    #  return valid
    #end

    rep = self.is_database_replication_valid(nodes)

    if not rep['result']:
      return rep

    self.nodes = nodes

    return self.valid()


  def is_database_replication_valid(self, nodes):
    database_node_count = 0
    for node in nodes:
      if node.is_role('database') or node.is_role('db_master'):
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
      return self.invalid("Replication factor cannot exceed number of databases")

    # Perform all the database specific checks here
    if self.database_type == 'mysql' and database_node_count % self.replication:
      return self.invalid("MySQL requires that the amount of replication " + \
        "be divisible by the number of nodes") 

    return self.valid()

  """
  # Generates an yaml file for non-hybrid cloud layouts which don't have them
  def generate_cloud_layout
    layout = {:controller => "node-0"}
    servers = []
    num_slaves = @min_images - 1
    num_slaves.times do |i|
      servers << "node-#{i+1}"
    end

    layout[:servers] = servers
    YAML.load(layout.to_yaml)
  end

  def replication_factor
    return nil unless valid?

    @replication
  end

  # TODO: can we just replace the if w/ unless and change ! to = ?
  # or does that not exactly work due to the || ?

  def read_factor
    return nil if !valid? || @database_type != :voldemort

    @read_factor
  end

  def write_factor
    return nil if !valid? || @database_type != :voldemort

    @write_factor
  end

  def min_images
    return nil unless valid? 

    @min_images
  end

  def max_images
    return nil unless valid?
    
    @max_images
  end

  def nodes
    return [] unless valid?
    
    # Since the valid? check has succeded @nodes has been initialized
    @nodes
  end
  
  # head node -> shadow
  def head_node
    return nil unless valid?

    head_node = @nodes.select { |n| n.is_shadow? }.compact
    
    # TODO: is the last guard necessary?
    head_node.empty? ? nil : head_node[0]
  end

  def other_nodes
    return [] unless valid?

    other_nodes = @nodes.select { |n| !n.is_shadow? }.compact
    
    other_nodes.empty? ? [] : other_nodes
  end

  def db_master
    return nil unless valid?

    db_master = @nodes.select { |n| n.is_db_master? }.compact
    
    db_master.empty? ? nil : db_master[0]
  end

  def login_node
    return nil unless valid?

    login = @nodes.select { |n| n.is_login? }.compact
    
    login.empty? ? nil : login[0]
  end


  def to_hash
    result = {}
    # Put all nodes except the head node in the hash
    other_nodes.each do |node|
      result[node.id] = node.roles.join(":")
    end
    result
  end
  """

  def valid(self, message = None):
    return { 'result' : True, 'message' : message }


  def invalid(self, message):
    return { 'result' : False, 'message' : message }


class Node():


  def __init__(self, id, cloud, roles=[]):
    # For virtualized deployments, id is the public IP address, and in cloud
    # deployments, we use node-int (since we don't know the IP address)
    self.id = id
    self.cloud = cloud
    self.roles = roles
    self.expand_roles()


  def add_db_role(self, db_type, is_master):
    if is_master:
      self.add_role('db_master')
    else:
      self.add_role('db_slave')


  def add_rabbitmq_role(self, is_master):
    if is_master:
      self.add_role('rabbitmq_master')
    else:
      self.add_role('rabbitmq_slave')


  def add_role(self, role):
    self.roles.append(role)
    self.expand_roles()


  def is_role(self, role):
    if role in self.roles:
      return True
    else:
      return False

  
  def is_valid(self):
    if self.errors():
      return False
    else:
      return True


  def errors(self):
    errors = []
    for role in self.roles:
      if not role in NodeLayout.VALID_ROLES:
        errors.append("Invalid role: {0}".format(role))
    return errors


  def expand_roles(self):
    error_msg = "Expand roles should never be called on a node type." + \
      " All nodes should be either a SimpleNode or AdvancedNode"
    raise Exception(error_msg)


class SimpleNode(Node):


  def expand_roles(self):
    if 'controller' in self.roles:
      self.roles.remove('controller')
      self.roles.append('shadow')
      self.roles.append('load_balancer')
      self.roles.append('database')
      self.roles.append('memcache')
      self.roles.append('login')
      self.roles.append('zookeeper')
      self.roles.append('rabbitmq')

    # If they specify a servers role, expand it out to
    # be database, appengine, and memcache
    if 'servers' in self.roles:
      self.roles.remove('servers')
      self.roles.append('appengine')
      self.roles.append('memcache')
      self.roles.append('database')
      self.roles.append('rabbitmq')

    # Remove any duplicate roles
    self.roles = list(set(self.roles))


class AdvancedNode(Node):


  def expand_roles(self):
    if 'master' in self.roles:
      self.roles.remove('master')
      self.roles.append('shadow')
      self.roles.append('load_balancer')

    if 'login' in self.roles:
      self.roles.append('load_balancer')

    if 'database' in self.roles:
      self.roles.append('memcache')

    # Remove any duplicate roles
    self.roles = list(set(self.roles))
