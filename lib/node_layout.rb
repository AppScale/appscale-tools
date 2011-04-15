#!/usr/bin/ruby
# Programmer: Jonathan Kupferman
# Updated by Chris Bunch to add hybrid cloud support

NODE_ID_REGEX = /(node|cloud(\d+))-(\d+)/

VALID_ROLES = [:master, :appengine, :database, :shadow, :open] + 
  [:load_balancer, :login, :db_master, :db_slave, :zookeeper]

class NodeLayout
  SIMPLE_FORMAT_KEYS = [:controller, :servers]
  ADVANCED_FORMAT_KEYS = [:master, :database, :appengine, :open, :login, :zookeeper]

  # Required options are: database_type
  def initialize(input_yaml, options, skip_replication=false)
    @input_yaml = (input_yaml.kind_of?(String) ? YAML.load(input_yaml) : input_yaml)

    @infrastructure = options[:infrastructure]
    @database_type = options[:database]
    @database_type = @database_type.to_sym if !@database_type.nil?
    @min_images = options[:min_images]
    @max_images = options[:max_images]
    @replication = options[:replication]
    @read_factor = options[:read_factor]
    @write_factor = options[:write_factor]
    
    @nodes = []
    @skip_replication = skip_replication
  end

  def valid?
    if is_simple_format? 
      valid_simple_format?[:result]
    elsif is_advanced_format?
      valid_advanced_format?[:result]
    else
      false
    end
  end

  def errors
    return [] if valid?

    if is_simple_format? 
      valid_simple_format?[:message]
    elsif is_advanced_format?
      valid_advanced_format?[:message]
    elsif @input_yaml.nil?
      ["An IPs yaml file must be specified when running on Xen"]
    else
      keys = @input_yaml.keys
      any_valid_keys = false
      keys.each { |key| any_valid_keys = true if SIMPLE_FORMAT_KEYS.include?(key) || ADVANCED_FORMAT_KEYS.include?(key) }
      if any_valid_keys
        ["Used both simple and advanced layout roles. Only simple (controller, servers) or advanced (master, appengine, etc) can be used"]
      else
        ["Invalid roles! You must specify nodes using valid roles (e.g. controller, servers)"]
      end
    end
  end

  def is_simple_format?
    if @input_yaml.nil?
      if VALID_CLOUD_TYPES.include?(@infrastructure) and @infrastructure != "hybrid"
        # When used with the cloud, the simple format doesn't require a yaml
        # Note this is not so in the hybrid model - a yaml is required in
        # that scenario.
        return true
      else
        return false
      end
    end

    @input_yaml.keys.each do |key|
      return false if !SIMPLE_FORMAT_KEYS.include?(key)
    end

   true
  end

  def is_advanced_format?
    return false if @input_yaml.nil?

    @input_yaml.keys.each do |key|
      return false if !ADVANCED_FORMAT_KEYS.include?(key)
    end

    true
  end

  def parse_ip(ip)
    id, cloud = nil, nil

    match = NODE_ID_REGEX.match(ip)
    if match.nil?
      id = ip
      cloud = "not-cloud"
    else
      id = match[0]
      cloud = match[1]
    end

    return id, cloud
  end

  def valid_simple_format?
    # We already computed the nodes, its valid
    # cgb: an optimization to ensure we don't keep calling this
    # when it always returns the same thing anyways
    return valid if !@nodes.empty?

    if @input_yaml.nil?
      if VALID_CLOUD_TYPES.include?(@infrastructure) and @infrastructure != "hybrid"
        # No yaml was created so we will create a generic one and then allow it to be validated
        @input_yaml = generate_cloud_layout
      else
        return invalid("IPs yaml file is required for xen deployments")
      end
    end

    nodes = []
    @input_yaml.each_pair do |role, ips|
      next if ips.nil?

      ips.each do |ip|
        id, cloud = parse_ip(ip)
        node = SimpleNode.new id, cloud, [role]

        # In simple deployments the db master is always on the shadow
        is_master = node.is_shadow?
        node.add_db_role @database_type, is_master
        node.add_role :zookeeper if is_master

        return invalid(node.errors.join(",")) if !node.valid?

        if VALID_CLOUD_TYPES.include?(@infrastructure)
          error_message = "Invalid cloud node ID: #{node.id} \n" +
            "Cloud node IDs must be in the format 'node-{IDNUMBER}'" +
            "\nor of the form cloud{CLOUDNUMBER}-{IDNUMBER} for hybrid deployments"
          return invalid(error_message) if NODE_ID_REGEX.match(node.id.to_s).nil?
        else
          # Xen/KVM should be using the ip address as the node id
          error_message = "Invalid virtualized node ID: #{node.id} \n" + 
            "Virtualized node IDs must be a valid IP address"
          return invalid(error_message) if IP_REGEX.match(node.id.to_s).nil?
        end

        nodes << node
      end
    end

    if nodes.length == 1
      # Singleton node should be master and app engine
      nodes.first.add_role :appengine
    end

    # controller -> shadow
    controller_count = nodes.count { |node| node.is_shadow? }

    if controller_count == 0
      return invalid("No controller was specified")
    elsif controller_count > 1
      return invalid("Only one controller is allowed")
    end

    database_count = nodes.count { |node| node.is_database? }

    if @skip_replication
      @nodes = nodes
      return valid
    end

    rep = valid_database_replication? nodes
    return rep unless rep[:result]

    # Wait until it is validated to assign it
    @nodes = nodes
    valid
  end

  def valid_advanced_format?
    # We already computed the nodes, its valid
    return valid if !@nodes.empty?

    node_hash = {}
    @input_yaml.each_pair do |role, ips|
      
      ips.each_with_index do |ip, index|
        node = nil
        if node_hash[ip].nil?
          id, cloud = parse_ip(ip)
          node = AdvancedNode.new(id, cloud)
        else
          node = node_hash[ip]
        end

        if role.to_sym == :database
          # The first database node is the master
          is_master = index.zero?
          node.add_db_role @database_type, is_master
        else
          node.add_role role
        end
        
        node_hash[ip] = node
      end
    end

    # Dont need the hash any more, make a nodes list
    nodes = node_hash.values

    nodes.each do |node|
      return invalid(node.errors.join(",")) unless node.valid?

      if VALID_CLOUD_TYPES.include?(@infrastructure)
        error_message = "Invalid cloud node ID: #{node.id} \n" + 
          "Cloud node IDd must be in the format 'node-{IDNUMBER}'" +
          "\nor of the form cloud{CLOUDNUMBER}-{IDNUMBER} for hybrid deployments"
        return invalid(error_message) if NODE_ID_REGEX.match(node.id.to_s).nil?
      else
        # Xen/KVM should be using the ip address as the node id
        error_message = "Invalid virtualized node ID: #{node.id} \n" + 
          "Virtualized node IDs must be a valid IP address"
        return invalid(error_message) if IP_REGEX.match(node.id.to_s).nil?
      end
    end

    master_nodes = nodes.select { |node| node.is_shadow? }.compact

    # need exactly one master
    if master_nodes.length == 0
      return invalid("No master was specified")
    elsif master_nodes.length > 1
      return invalid("Only one master is allowed")
    end

    master_node = master_nodes.first

    login_node = nodes.select { |node| node.is_login? }.compact
    # If a login node was not specified, make the master into the login node
    if login_node.empty?
      master_node.add_role :login
    end

    appengine_count = nodes.count { |node| node.is_appengine? }

    if appengine_count < 1
      return invalid("Not enough appengine nodes were provided.")
    end

    if VALID_CLOUD_TYPES.include?(@infrastructure)
      # If min and max aren't specified, they default to the number of nodes in the system
      @min_images ||= nodes.length
      @max_images ||= nodes.length

      # TODO: look into if that first guard is really necessary with the preceding lines

      if @min_images && nodes.length < @min_images
        return invalid("Too few nodes were provided, #{nodes.length} were specified but #{@min_images} was the minimum")
      end
 
      if @max_images && nodes.length > @max_images
        return invalid("Too many nodes were provided, #{nodes.length} were specified but #{@max_images} was the maximum")
      end
    end

    zookeeper_count = nodes.count { |node| node.is_zookeeper? }
    master_node.add_role :zookeeper if zookeeper_count < 1

    database_count = nodes.count { |node| node.is_database? }

    if @skip_replication
      @nodes = nodes
      return valid
    end

    rep = valid_database_replication? nodes
    return rep unless rep[:result]

    # Wait until it is validated to assign it
    @nodes = nodes

    return valid
  end

  def valid_database_replication? nodes
    database_node_count = nodes.count { |node| node.is_database? }

    if @replication.nil?
      if database_node_count > 3
        # If there are a lot of database nodes, we default to 3x replication
        @replication = 3
      else
        # If there are only a few nodes, replicate to each one of the nodes
        @replication = database_node_count
      end
    end

    if @replication > database_node_count
      return invalid("The provided replication factor is too high. The replication factor (-n flag) cannot be greater than the number of database nodes.")
    end

    # Perform all the database specific checks here
    if @database_type == :mysql && database_node_count % @replication != 0
      return invalid("MySQL requires that the amount of replication be divisible by the number of nodes (e.g. with 6 nodes, 2 or 3 times replication). You specified #{database_node_count} database nodes which is not divisible by #{@replication} times replication.")
    end

    if @database_type == :voldemort
      @read_factor ||= @replication
      @write_factor ||= @replication

      if @read_factor > @replication
        return invalid("The provided read factor is too high. The read factor (-r flag) cannot be greater than the replication factor.")
      elsif @write_factor > @replication
        return invalid("The provided write factor is too high. The write factor (-w flag) cannot be greater than the replication factor.")
      end
    end

    if @database_type == :simpledb
      if ENV['SIMPLEDB_ACCESS_KEY'].nil?
        return invalid("SimpleDB deployments require that the environment variable SIMPLEDB_ACCESS_KEY be set to your AWS access key.")
      end

      if ENV['SIMPLEDB_SECRET_KEY'].nil?
        return invalid("SimpleDB deployments require that the environment variable SIMPLEDB_SECRET_KEY be set to your AWS secret key.")
      end
    end
    
    valid
  end

  # Generates an yaml file for non-hybrid cloud layouts which don't have them
  def generate_cloud_layout
    layout = {}
    
    layout[:controller] = "node-0"

    servers = []

    # If min and max aren't specified we default them to four
    @min_images ||= 4
    @max_images ||= 4

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

  private
  def valid message=nil
    { :result => true, :message => message }
  end

  def invalid message
    { :result => false, :message => message }
  end
end

class Node
  attr_accessor :roles, :id, :cloud

  def initialize id, cloud, roles=[]
    # For Xen/KVM id is the public ip address
    # For clouds, id is node-X since the ip is not known
    @id = id
    @cloud = cloud
    @roles = roles.map { |r| r.to_sym }

    expand_roles
  end

  def add_db_role db_type, is_master
    db_role = is_master ? 'db_master' : 'db_slave'
    add_role :database
    add_role db_role
  end

  def add_role role
    @roles << role.to_sym
    expand_roles
  end

  VALID_ROLES.each do |role|
    method = "is_#{role.to_s}?"
    send :define_method, method do
      @roles.include?(role)
    end
  end
  
  def valid?
    self.errors.empty?
  end

  def errors
    @roles.map { |r| "Invalid role: #{r}" if !VALID_ROLES.include?(r) }.compact
  end

  def expand_roles
    error_msg = "Expand roles should never be called on a node type." + \
      " All nodes should be either a SimpleNode or AdvancedNode"
    raise RuntimeError error_msg
  end
end


class SimpleNode < Node
  private
  def expand_roles
    if @roles.include?(:controller)
      @roles.delete(:controller)
      @roles << :shadow
      @roles << :load_balancer
      @roles << :database
      @roles << :login
      @roles << :zookeeper
    end

    # If they specify a servers role, expand it out to
    # be database and appengine
    if @roles.include?(:servers)
      @roles.delete(:servers)
      @roles << :appengine
      @roles << :database
      @roles << :load_balancer
    end

    @roles.uniq!
  end
end

class AdvancedNode < Node
  private
  def expand_roles
    # make sure that deleting here doesn't screw things up
    if @roles.include?(:master)
      @roles.delete(:master)
      @roles << :shadow
      @roles << :load_balancer
      #@roles << :login
      @roles << :zookeeper
    end

    if @roles.include?(:login)
      @roles << :load_balancer
    end

    if @roles.include?(:appengine)
      @roles << :load_balancer
    end

    @roles.uniq!
  end
end
