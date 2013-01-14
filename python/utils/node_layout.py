import re
import yaml
from utils import commons, cli
from utils.cloud import is_valid_cloud_type
from utils.commons import AppScaleToolsException

__author__ = 'hiranya'

ROLE_CONTROLLER = ':controller'
ROLE_SERVERS = ':servers'

ROLE_MASTER = ':master'
ROLE_SHADOW = ':shadow'
ROLE_LOAD_BALANCER = ':load_balancer'
ROLE_DATABASE = ':database'
ROLE_DATABASE_MASTER = ':db_master'
ROLE_DATABASE_SLAVE = ':db_slave'
ROLE_MEMCACHE = ':memcache'
ROLE_LOGIN = ':login'
ROLE_ZOOKEEPER = ':zookeeper'
ROLE_RABBITMQ = ':rabbitmq'
ROLE_RABBITMQ_MASTER = ':rabbitmq_master'
ROLE_RABBITMQ_SLAVE = ':rabbitmq_slave'
ROLE_APPENGINE = ':appengine'
ROLE_OPEN = ':open'

VALID_ROLES = frozenset([
  ROLE_MASTER, ROLE_SHADOW, ROLE_LOAD_BALANCER, ROLE_DATABASE,
  ROLE_DATABASE_MASTER, ROLE_DATABASE_SLAVE, ROLE_MEMCACHE, ROLE_LOGIN,
  ROLE_ZOOKEEPER, ROLE_RABBITMQ, ROLE_RABBITMQ_MASTER, ROLE_RABBITMQ_SLAVE,
  ROLE_APPENGINE, ROLE_OPEN
])

class NodeLayout:

  SIMPLE_FORMAT_KEYS = frozenset([ ':controller', ':servers' ])
  ADVANCED_FORMAT_KEYS = frozenset([
    ':master', ':database', ':appengine', ':open',
    ':login', ':zookeeper', ':memcache', ':rabbitmq'
  ])

  NODE_ID_REGEX = r'node-(\d+)'
  IP_REGEX = r'\d+\.\d+\.\d+\.\d+'

  ERROR_DUPLICATE_IPS = 100100
  ERROR_NO_CONTROLLER = 100101
  ERROR_MULTIPLE_CONTROLLERS = 100102
  ERROR_UNSUPPORTED_LAYOUT = 100103
  ERROR_MISSING_REQUIRED_OPTIONS = 100104
  ERROR_MISSING_INPUT_YAML = 100105

  def __init__(self, yaml_file_path, options=None, skip_replication=False):
    if yaml_file_path is not None and len(yaml_file_path) > 0:
      yaml_file = open(yaml_file_path, 'r')
      self.yaml = yaml.load(yaml_file)
      yaml_file.close()
    else:
      self.yaml = None

    if options is None: options = {}
    self.infrastructure = options.get(cli.OPTION_INFRASTRUCTURE)
    self.database_type = options.get(cli.OPTION_DATABASE)
    self.min_images = options.get(cli.OPTION_MIN_IMAGES)
    self.max_images = options.get(cli.OPTION_MAX_IMAGES)
    self.replication = options.get(cli.OPTION_REPLICATION)
    self.read_factor = options.get(cli.OPTION_READ_FACTOR)
    self.write_factor = options.get(cli.OPTION_WRITE_FACTOR)
    self.skip_replication = skip_replication
    self.nodes = []
    self.__populate_nodes()

  def get_head_node(self):
    for node in self.nodes:
      if node.has_role(ROLE_SHADOW):
        return node
    return None

  def __populate_nodes(self):
    if self.__is_simple_format():
      self.__populate_simple_format()
    elif self.__is_advanced_format():
      self.__populate_advanced_format()
    else:
      raise AppScaleToolsException(
        'Node layout does not conform to any of the supported specs.',
        self.ERROR_UNSUPPORTED_LAYOUT)

  def __populate_simple_format(self):
    cloud = is_valid_cloud_type(self.infrastructure)
    if self.yaml is None:
      if cloud:
        if self.min_images is None or self.max_images is None:
          raise AppScaleToolsException(
            'Both min and max options must be specified when no '
            'input yaml is provided', self.ERROR_MISSING_REQUIRED_OPTIONS)
        else:
          self.yaml = self.__generate_default_layout()
      else:
        raise AppScaleToolsException(
          'Input yaml must be provided for deployments on virtualized clusters',
          self.ERROR_MISSING_INPUT_YAML)
    else:
      all_ips = commons.flatten(self.yaml.values())
      unique_ips = set(all_ips)
      if len(all_ips) != len(unique_ips):
        msg = 'Duplicate IP addresses found in input yaml'
        raise AppScaleToolsException(msg, self.ERROR_DUPLICATE_IPS)

    nodes = []
    for role,ips in self.yaml.items():
      if ips is None:
        continue

      if isinstance(ips, str):
        ips = [ ips ]

      for ip in ips:
        node = SimpleAppScaleNode(ip, [role])
        if node.has_role(ROLE_SHADOW):
          node.add_role(ROLE_DATABASE_MASTER)
          node.add_role(ROLE_RABBITMQ_MASTER)
        else:
          node.add_role(ROLE_DATABASE_SLAVE)
          node.add_role(ROLE_RABBITMQ_SLAVE)
        node.validate()

        if cloud and not re.match(self.NODE_ID_REGEX, node.id):
          raise AppScaleToolsException('Invalid cloud node ID: %s. '
                                       'Cloud node IDs must be in the '
                                       'format node-{ID}.' % node.id)
        elif not cloud and not re.match(self.IP_REGEX, node.id):
          raise AppScaleToolsException('Invalid virtualized node ID: %s. '
                                       'Virtualized node IDs must be valid IP '
                                       'addresses.' % node.id)
        else:
          nodes.append(node)

    if len(nodes) == 1:
      nodes[0].add_role(ROLE_APPENGINE)
      nodes[0].add_role(ROLE_MEMCACHE)

    controllers = 0
    for node in nodes:
      if node.has_role(ROLE_SHADOW):
        controllers += 1

    if controllers > 1:
      raise AppScaleToolsException('Only one controller node is allowed',
        self.ERROR_MULTIPLE_CONTROLLERS)
    elif not controllers:
      raise AppScaleToolsException('No controller node has been assigned',
        self.ERROR_NO_CONTROLLER)

    if not self.skip_replication:
      self.__validate_data_replication(nodes)
    self.nodes = nodes

  def __populate_advanced_format(self):
    nodes = {}
    for role, ips in self.yaml.items():
      if ips is None:
        continue

      if isinstance(ips, str):
        ips = [ ips ]

      index = 0
      for ip in ips:
        if not nodes.has_key(ip):
          node = AdvancedAppScaleNode(ip)
        else:
          node = nodes[ip]

        if role == ROLE_DATABASE:
          if not index:
            node.add_role(ROLE_DATABASE_MASTER)
          else:
            node.add_role(ROLE_DATABASE_SLAVE)
        elif role == ROLE_DATABASE_MASTER:
          node.add_role(ROLE_ZOOKEEPER)
          node.add_role(role)
        elif role == ROLE_RABBITMQ:
          if not index:
            node.add_role(ROLE_RABBITMQ_MASTER)
          else:
            node.add_role(ROLE_RABBITMQ_SLAVE)
        else:
          node.add_role(role)
        nodes[ip] = node
        index += 1

    nodes = nodes.values()
    cloud = is_valid_cloud_type(self.infrastructure)
    for node in nodes:
      if cloud and not re.match(self.NODE_ID_REGEX, node.id):
        raise AppScaleToolsException('Invalid cloud node ID: %s. '
                                     'Cloud node IDs must be in the '
                                     'format node-{ID}.' % node.id)
      elif not cloud and not re.match(self.IP_REGEX, node.id):
        raise AppScaleToolsException('Invalid virtualized node ID: %s. '
                                     'Virtualized node IDs must be valid IP '
                                     'addresses.' % node.id)

    controllers = 0
    memcache_nodes = 0
    zk_nodes = 0
    rabbit_mq_nodes = 0
    db_nodes = 0
    master_node = None
    login_node = None
    app_engine_nodes = []
    for node in nodes:
      if node.has_role(ROLE_SHADOW):
        master_node = node
        controllers += 1
      if node.has_role(ROLE_LOGIN):
        login_node = node
      if node.has_role(ROLE_APPENGINE):
        app_engine_nodes.append(node)
      if node.has_role(ROLE_MEMCACHE):
        memcache_nodes += 1
      if node.has_role(ROLE_ZOOKEEPER):
        zk_nodes += 1
      if node.has_role(ROLE_RABBITMQ):
        rabbit_mq_nodes += 1
      if node.has_role(ROLE_DATABASE):
        db_nodes += 1

    if controllers > 1:
      raise AppScaleToolsException('Only one controller node is allowed')
    elif not controllers:
      raise AppScaleToolsException('No controller node has been assigned')

    if not app_engine_nodes:
      raise AppScaleToolsException('Not enough appengine nodes were provided')

    if not login_node:
      master_node.add_role(ROLE_LOGIN)

    if not memcache_nodes:
      for app_engine in app_engine_nodes:
        app_engine.add_role(ROLE_MEMCACHE)

    if not zk_nodes:
      master_node.add_role(ROLE_ZOOKEEPER)

    if not rabbit_mq_nodes:
      master_node.add_role(ROLE_RABBITMQ)
      master_node.add_role(ROLE_RABBITMQ_MASTER)

    for node in nodes:
      if node.has_role(ROLE_APPENGINE) and not node.has_role(ROLE_RABBITMQ):
        node.add_role(ROLE_RABBITMQ_SLAVE)

    if cloud:
      if self.min_images is None: self.min_images = len(nodes)
      if self.max_images is None: self.max_images = len(nodes)
      if len(nodes) < self.min_images:
        raise AppScaleToolsException('Too few nodes were provided. %s '
                                     'provided, but %s is the minimum.' %
                                     (len(nodes), self.min_images))
      if len(nodes) > self.max_images:
        raise AppScaleToolsException('Too many nodes were provided. %s '
                                     'provided, but %s is the maximum.' %
                                     (len(nodes), self.max_images))

    if not self.skip_replication:
      self.__validate_data_replication(nodes)
    self.nodes = nodes

  def __validate_data_replication(self, nodes):
    db_nodes = 0
    for node in nodes:
      if node.has_role(ROLE_DATABASE) or node.has_role(ROLE_DATABASE_MASTER):
        db_nodes += 1

    if not db_nodes:
      raise AppScaleToolsException('At least 1 DB node must be available')

    if self.replication is None:
      if db_nodes > 3:
        self.replication = 3
      else:
        self.replication = db_nodes
    elif self.replication > db_nodes:
      raise AppScaleToolsException('Specified replication factor is too high'
                                   'to be satisfied by the available DB nodes')

    # TODO: DB specific checks
    pass

  def __is_simple_format(self):
    if self.yaml is None:
      return is_valid_cloud_type(self.infrastructure)
    else:
      return set(self.yaml.keys()).issubset(self.SIMPLE_FORMAT_KEYS)

  def __is_advanced_format(self):
    if self.yaml is None:
      return False
    else:
      return set(self.yaml.keys()).issubset(self.ADVANCED_FORMAT_KEYS)

  def __generate_default_layout(self):
    layout = { ROLE_CONTROLLER : 'node-0' }
    servers = []
    slaves = self.min_images - 1
    for i in range(slaves):
      servers.append('node-%s' % (i + 1))
    layout[ROLE_SERVERS] = servers
    return layout

class AppScaleNode:
  def __init__(self, id, roles=None):
    self.id = id
    if roles:
      self.roles = set(roles)
    else:
      self.roles = set([])
    self.expand_roles()

  def add_role(self, role):
    self.roles.add(role)
    self.expand_roles()

  def has_role(self, role):
    return role in self.roles

  def validate(self):
    invalid_roles = self.roles - VALID_ROLES
    if invalid_roles:
      raise AppScaleToolsException('Invalid roles: ' + ', '.join(invalid_roles))

  def expand_roles(self):
    raise NotImplemented

class SimpleAppScaleNode(AppScaleNode):
  def expand_roles(self):
    if ROLE_CONTROLLER in self.roles:
      self.roles.remove(ROLE_CONTROLLER)
      self.roles.add(ROLE_SHADOW)
      self.roles.add(ROLE_LOAD_BALANCER)
      self.roles.add(ROLE_DATABASE)
      self.roles.add(ROLE_MEMCACHE)
      self.roles.add(ROLE_LOGIN)
      self.roles.add(ROLE_ZOOKEEPER)
      self.roles.add(ROLE_RABBITMQ)

    if ROLE_SERVERS in self.roles:
      self.roles.remove(ROLE_SERVERS)
      self.roles.add(ROLE_APPENGINE)
      self.roles.add(ROLE_MEMCACHE)
      self.roles.add(ROLE_DATABASE)
      self.roles.add(ROLE_LOAD_BALANCER)
      self.roles.add(ROLE_RABBITMQ)

class AdvancedAppScaleNode(AppScaleNode):
  def expand_roles(self):
    if ROLE_MASTER in self.roles:
      self.roles.remove(ROLE_MASTER)
      self.roles.add(ROLE_SHADOW)
      self.roles.add(ROLE_LOAD_BALANCER)

    if ROLE_LOGIN in self.roles:
      self.roles.add(ROLE_LOAD_BALANCER)

    if ROLE_APPENGINE in self.roles:
      self.roles.add(ROLE_LOAD_BALANCER)

    if ROLE_DATABASE in self.roles:
      self.roles.add(ROLE_MEMCACHE)
