#!/usr/bin/ruby -w
# Programmer: Jonathan Kupferman

require 'test_helper'
require 'node_layout'

class NodeLayoutTest < Test::Unit::TestCase
  context "simple format single node" do
    setup do
      @input_yaml = { :controller => "1.2.3.4" }.to_yaml
      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "be a simple format" do
      assert @node_layout.is_simple_format?
    end

    should "not be a advanced format" do
      assert_false @node_layout.is_advanced_format?
    end

    should "be valid" do
      assert @node_layout.valid?
    end

    should "default to a replication factor equal to the number of database nodes" do
      assert_equal 1, @node_layout.replication_factor
    end

    should "have a single node which runs all the necessary roles" do
      assert_equal @node_layout.nodes.length, 1

      head_node = @node_layout.nodes.first
      [:load_balancer, :shadow, :db_master, :appengine].each do |role| 
        assert head_node.roles.include?(role), "the head node should have the role: #{role}"
      end      
    end
  end

  context "simple format with three nodes" do
    setup do
      @input_yaml = { 
        :controller => "10.2.3.4",
        :servers => ["10.2.3.5", "10.2.3.6"]
      }.to_yaml

      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "be a simple format" do
      assert @node_layout.is_simple_format?
    end

    should "not be an advanced format" do
      assert_false @node_layout.is_advanced_format?
    end

    should "be valid" do
      assert @node_layout.valid?
    end

    should "have three nodes" do
      assert_equal 3, @node_layout.nodes.length
    end

    should "default to replication factor equal to the number of database nodes" do
      assert_equal 3, @node_layout.replication_factor
    end

    should "make the head node into the login node by default" do
      login_node = @node_layout.login_node
      assert_false login_node.nil?
      
      assert_equal login_node.id, @node_layout.head_node.id
    end
    
    should "have a head node which is the shadow and database master" do
      head_node = @node_layout.head_node
      assert head_node

      [:load_balancer, :shadow, :db_master].each do |role| 
        assert head_node.roles.include?(role), "the head node should have the role: #{role}, currently: #{head_node.roles.to_s}"
      end      
    end

    should "have a two nodes running appengines and are the database slaves" do
      other_nodes = @node_layout.nodes
      other_nodes.delete(@node_layout.head_node)

      assert_equal 2, other_nodes.length

      [:load_balancer, :appengine, :db_slave].each do |role| 
        other_nodes.each do |node|
          assert node.roles.include?(role), "the other nodes should have the role: #{role}"
        end
      end      
    end
  end

  context "simple format single node on cloud" do
    setup do
      @input_yaml = nil
      @options = { :database => :voldemort, :infrastructure => "ec2", :min_images => 1, :max_images => 3 }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "be a simple format" do
      assert @node_layout.is_simple_format?
    end

    should "not be a advanced format" do
      assert_false @node_layout.is_advanced_format?
    end

    should "be valid" do
      assert @node_layout.valid?
    end

    should "default to a replication factor equal to the number of database nodes" do
      assert_equal 1, @node_layout.replication_factor
    end

    should "have a single node which runs all the necessary roles" do
      assert_equal @node_layout.nodes.length, 1

      head_node = @node_layout.nodes.first
      [:load_balancer, :shadow, :db_master, :appengine].each do |role| 
        assert head_node.roles.include?(role), "the head node should have the role: #{role}"
      end      
    end
  end

  context "simple format with three nodes on cloud" do
    setup do
      @input_yaml = nil

      @options = { :database => :voldemort, :infrastructure => "euca", :min_images => 3, :max_images => 3 }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "be a simple format" do
      assert @node_layout.is_simple_format?
    end

    should "not be an advanced format" do
      assert_false @node_layout.is_advanced_format?
    end

    should "be valid" do
      assert @node_layout.valid?
    end

    should "have three nodes" do
      assert_equal 3, @node_layout.nodes.length
    end

    should "default to replication factor equal to the number of database nodes" do
      assert_equal 3, @node_layout.replication_factor
    end
    
    should "have a head node which is the shadow and database master" do
      head_node = @node_layout.head_node
      assert head_node

      [:load_balancer, :shadow, :db_master].each do |role| 
        assert head_node.roles.include?(role), "the head node should have the role: #{role}, currently: #{head_node.roles.to_s}"
      end      
    end

    should "have a two nodes running appengines and are the database slaves" do
      other_nodes = @node_layout.nodes
      other_nodes.delete(@node_layout.head_node)

      assert_equal 2, other_nodes.length

      [:load_balancer, :appengine, :db_slave].each do |role| 
        other_nodes.each do |node|
          assert node.roles.include?(role), "the other nodes should have the role: #{role}"
        end
      end      
    end
  end

  context "simple format default min/max images" do
    setup do
      @input_yaml = nil

      @options = { :database => :voldemort, :infrastructure => "euca" }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "be a simple format" do
      assert @node_layout.is_simple_format?
    end

    should "be valid" do
      assert @node_layout.valid?
    end

    should "default to four nodes" do
      assert_equal 4, @node_layout.nodes.length
    end

    should "set max images to four" do
      assert_equal 4, @node_layout.max_images
    end

    should "set min images to four" do
      assert_equal 4, @node_layout.min_images
    end
  end

  context "simple format missing controller" do
    setup do
      @input_yaml = { 
        :servers => ["10.2.3.5", "10.2.3.6"]
      }.to_yaml

      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid" do
      assert_false @node_layout.valid?
    end

    should "have an error message stating no controller was specified" do
      assert_contains @node_layout.errors, /No controller was specified/
    end
  end

  context "simple format missing controller ip" do
    setup do
      @input_yaml = { 
        :controller => ""
      }.to_yaml

      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid" do
      assert_false @node_layout.valid?
    end

    should "have an error message stating no controller was specified" do
      assert_contains @node_layout.errors, /No controller was specified/
    end
  end

  context "simple format multiple controllers" do
    setup do
      @input_yaml = { 
        :controller => ["10.2.3.1", "10.2.3.1"],
        :servers => ["10.2.3.5", "10.2.3.6"]
      }.to_yaml

      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid" do
      assert_false @node_layout.valid?
    end

    should "have an error message stating that only one controller is allowed" do
      assert_contains @node_layout.errors, /Only one controller is allowed/
    end
  end

  context "simple format on xen without a ips yaml" do
    setup do
      @input_yaml = nil

      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid" do
      assert_false @node_layout.valid?
    end

    should "have an error message stating that a input yaml is required for xen/kvm deployments" do
      assert_contains @node_layout.errors, /IPs yaml file must be specified/
    end
  end

  context "simple format on cloud infrastructure without a ips yaml" do
    ["ec2", "euca"].each do |infra|
      setup do
        @input_yaml = nil

        @options = { :database => :voldemort, :infrastructure => infra }
        @node_layout = NodeLayout.new(@input_yaml, @options)
      end

      should "be valid on #{infra}" do
        assert @node_layout.valid?
      end
    end
  end

  context "mixing simple and advanced format" do
    setup do
      @input_yaml = { 
        :controller => ["10.2.3.1", "10.2.3.2"],
        :servers => ["10.2.3.5", "10.2.3.6"],
        :appengine => ["10.2.3.5"],
        :database => ["10.2.3.1"]
      }.to_yaml

      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid" do
      assert_false @node_layout.valid?
    end

    should "have an error message stating that simple and advanced format cannot be mixed" do
      assert_contains @node_layout.errors, /Used both simple and advanced layout roles/
    end
  end

  context "simple format mysql database replication" do
    setup do
      @input_yaml = { 
        :controller => ["10.2.3.1"],
        :servers => ["10.2.3.5", "10.2.3.6", "10.2.3.7", "10.2.3.8", "10.2.3.9"]
      }.to_yaml
      # There should be 6 database nodes using the above input_yaml (5 servers + 1 controller)
    end

    should "be valid with a replication factor that is a multiple of the number of databases" do
      # 6 % 3 == 0 so 3 is a valid replication factor
      @options = { :database => :mysql, :replication => 3 }
      @node_layout = NodeLayout.new(@input_yaml, @options)

      assert @node_layout.valid?
    end

    should "not be valid with a replication factor that is not a multiple of the number of databases" do
      # 6 % 4 != 0 so 4 is not a valid replication factor
      @options = { :database => :mysql, :replication => 4 }
      @node_layout = NodeLayout.new(@input_yaml, @options)

      assert_false @node_layout.valid?
      assert_contains @node_layout.errors, /MySQL requires that the amount of replication be a factor of the number of nodes/
    end

    should "not be valid with a replication factor that is greater than the number of databases" do
      @options = { :database => :mysql, :replication => 8 }
      @node_layout = NodeLayout.new(@input_yaml, @options)

      assert_false @node_layout.valid?
      assert_contains @node_layout.errors, /The provided replication factor is too high./
    end
  end

  context "advanced format with three nodes" do
    setup do
      @first_db_ip = "192.4.30.9"
      @master_node_ip = "128.2.3.1"
      # Input data like this so it looks exactly like an input file would.
input_data = <<YAML
---
:master: #{@master_node_ip}
:database:
 - #{@first_db_ip}
 - 192.2.4.1
 - 192.2.2.2
:appengine:
 - 192.4.30.9
 - 192.2.4.1
 - 192.2.2.2
YAML

      @input_yaml = YAML.load(input_data)
      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be a simple format" do
      assert_false @node_layout.is_simple_format?
    end

    should "be an advanced format" do
      assert @node_layout.is_advanced_format?
    end

    should "be valid" do
      assert @node_layout.valid?
    end

    should "have four nodes" do
      assert_equal 4, @node_layout.nodes.length
    end

    should "default to a replication factor equal to the number of database nodes" do
      assert_equal 3, @node_layout.replication_factor
    end

    should "default login to the master node since none was specified" do
      login_node = @node_layout.login_node
      assert_false login_node.nil?
      
      assert_equal login_node.id, @master_node_ip
    end
    
    should "have a head node which is the shadow and a load balancer" do
      head_node = @node_layout.head_node
      assert head_node

      [:shadow, :load_balancer].each do |role| 
        assert head_node.roles.include?(role), "the head node should have the role: #{role}"
      end      
    end

    should "have three nodes running appengines" do
      appengine_count = @node_layout.nodes.count { |node| node.is_appengine? }
      assert_equal 3, appengine_count
    end

    should "make the master database node the first one listed in the yaml file" do
      db_master = @node_layout.nodes.select { |node| node.is_db_master? }.compact
      assert_equal 1, db_master.length

      assert_equal @first_db_ip, db_master.first.id
    end

    should "have two slave database nodes" do
      slave_db_count = @node_layout.nodes.count { |node| node.is_db_slave? }
      assert_equal 2, slave_db_count
    end
  end

  context "advanced format with four nodes on cloud infrastructure" do
    ["ec2", "euca"].each do |infra|
      setup do
        @first_db_id = "node-2"
        @input_yaml = {
          :master => "node-17",
          :database => [@first_db_id, "node-75912", "node-3123"],
          :appengine => ["node-2", "node-75912", "node-3123"],
        }.to_yaml

        @options = { :database => :voldemort, :infrastructure => infra }
        @node_layout = NodeLayout.new(@input_yaml, @options)
      end

      should "not be a simple format #{infra}" do
        assert_false @node_layout.is_simple_format?
      end

      should "be an advanced format #{infra}" do
        assert @node_layout.is_advanced_format?
      end

      should "be valid #{infra}" do
        assert @node_layout.valid?
      end

      should "have four nodes #{infra}" do
        assert_equal 4, @node_layout.nodes.length
      end

      should "default min images to be the numbner of nodes in system #{infra}" do
        assert_equal @node_layout.nodes.length, @node_layout.min_images
      end

      should "default max images to be the numbner of nodes in system #{infra}" do
        assert_equal @node_layout.nodes.length, @node_layout.max_images
      end
      
      should "have a head node which is the shadow and a load balancer #{infra}" do
        head_node = @node_layout.head_node
        assert head_node

        [:shadow, :load_balancer].each do |role| 
          assert head_node.roles.include?(role), "the head node should have the role: #{role}"
        end      
      end

      should "have three nodes running appengines #{infra}" do
        appengine_count = @node_layout.nodes.count { |node| node.is_appengine? }
        assert_equal 3, appengine_count
      end

      should "have a master database node which was the first database listed #{infra}" do
        db_master = @node_layout.nodes.select { |node| node.is_db_master? }.compact
        assert_equal 1, db_master.length

        assert_equal @first_db_id, db_master.first.id
      end

      should "have two slave database nodes #{infra}" do
        slave_db_count = @node_layout.nodes.count { |node| node.is_db_slave? }
        assert_equal 2, slave_db_count
      end
    end
  end

  context "advanced format with five nodes on cloud infrastructure" do
    ["ec2", "euca"].each do |infra|
      setup do
        @input_yaml = {
          :master => "node-17",
          :database => ["node-2", "node-75912", "node-3123"],
          :appengine => ["node-2", "node-75912", "node-3123", "node-662"],
        }.to_yaml

        @options = { :database => :voldemort, :infrastructure => infra }
        @node_layout = NodeLayout.new(@input_yaml, @options)
      end

      should "have five nodes #{infra}" do
        assert_equal 5, @node_layout.nodes.length
      end

      should "default min images to be the same as the number of nodes in system #{infra}" do
        assert_equal @node_layout.nodes.length, @node_layout.min_images
      end

      should "default max images to be the same as the number of nodes in system #{infra}" do
        assert_equal @node_layout.nodes.length, @node_layout.max_images
      end
    end
  end

  context "advanced format with three nodes and a login" do
    setup do
      @input_yaml = {
        :master => "192.2.3.1",
        :database => ["192.2.4.2", "192.2.4.1", "192.2.3.30"],
        :login => "192.2.3.25",
        :appengine => ["192.2.4.2", "192.2.4.1", "192.2.3.30"]
      }.to_yaml

      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "have a head node which is the shadow" do
      head_node = @node_layout.head_node
      assert head_node

      assert head_node.roles.include?(:shadow), "head node should have the role: shadow"
    end

    should "have a login node running the load balancer" do
      login_node = @node_layout.login_node
      assert_false login_node.nil?

      assert login_node.roles.include?(:load_balancer), "the login node should have the role: load_balancer"

      assert_not_equal login_node, @node_layout.head_node, "the head node and login node should NOT be the same"
    end
  end

  context "advanced format not enough database nodes" do
    setup do
      @input_yaml = { 
        :master => "192.2.3.1",
        :database => ["192.2.4.2"],
        :appengine => ["192.2.4.2", "192.2.4.1", "192.2.3.30"]
      }.to_yaml
    end

    [:hbase, :hypertable].each do |database|
      should "not be valid since each #{database.to_s} requires a minimum of two database nodes" do
        @options = { :database => database }
        @node_layout = NodeLayout.new(@input_yaml, @options)
        
        assert @node_layout.valid?

      end
    end
  end

  context "advanced format too high replication factor" do
    setup do
      @input_yaml = {
        :master => "192.2.3.1",
        :database => ["192.2.4.2", "192.2.4.1", "192.2.3.30"],
        :appengine => ["192.2.4.2", "192.2.4.1", "192.2.3.30"]
      }.to_yaml

      @options = { :database => :cassandra, :replication => 4 }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end
    
    should "not be valid since the replication factor is larger than the number of database nodes"  do
      assert_false @node_layout.valid?
      
      assert_contains @node_layout.errors, /The provided replication factor is too high./
    end
  end

  context "advanced format voldemort read/write factor" do
    setup do
      @input_yaml = {
        :master => "192.2.3.1",
        :database => ["192.2.4.2", "192.2.4.1", "192.2.3.30"],
        :appengine => ["192.2.4.2", "192.2.4.1", "192.2.3.30"]
      }.to_yaml

      @options = { :database => :voldemort, :replication => 4 }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid since the read factor is greater than the number of databases" do
      @options = { :database => :voldemort, :read_factor => 7, :write_factor => 2 }
      @node_layout = NodeLayout.new(@input_yaml, @options)
      
      assert_false @node_layout.valid?
      assert_contains @node_layout.errors, /The provided read factor is too high./
    end

    should "not be valid since the write factor is greater than the number of databases" do
      @options = { :database => :voldemort, :read_factor => 2, :write_factor => 7 }
      @node_layout = NodeLayout.new(@input_yaml, @options)
      
      assert_false @node_layout.valid?
      assert_contains @node_layout.errors, /The provided write factor is too high./
    end

    should "be valid since the read and write factor are less than the number of databases" do
      @options = { :database => :voldemort, :read_factor => 3, :write_factor => 2 }
      @node_layout = NodeLayout.new(@input_yaml, @options)
      
      assert @node_layout.valid?
    end
  end


  context "advanced format fewer than minimum nodes" do
    setup do
      @input_yaml = {
        :master => "node-1",
        :appengine => ["node-44", "node-11", "node-54"],
        :database => ["node-44", "node-11", "node-54"]
      }.to_yaml

      @options = { :database => :voldemort, :min_images => 5, :infrastructure => "ec2" }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid, too few nodes specified" do
      assert_false @node_layout.valid?
      assert_contains @node_layout.errors, /Too few nodes were provided/
    end
  end

  context "advanced format more then maximum nodes" do
    setup do
      @input_yaml = {
        :master => "node-1",
        :appengine => ["node-44", "node-11", "node-54"],
        :database => ["node-44", "node-11", "node-54"]
      }.to_yaml

      @options = { :database => :voldemort, :max_images => 3, :infrastructure => "ec2" }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid, too many nodes specified" do
      assert_false @node_layout.valid?
      assert_contains @node_layout.errors, /Too many nodes were provided/
    end
  end

  context "advanced format open flag" do
    setup do
      @input_yaml = {
        :master => "192.2.3.1",
        :database => ["192.2.4.2", "192.2.4.1", "192.2.3.30"],
        :appengine => ["192.2.4.2", "192.2.4.1", "192.2.3.30"],
        :open => "192.2.3.40"
      }.to_yaml

    end

    should "be valid for non-cloud deployments" do
      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
      
      assert @node_layout.valid?
      assert_equal 5, @node_layout.nodes.length, "it should have all five nodes"
    end

    should "not be valid for cloud deployments" do
      @options = { :database => :voldemort, :infrastructure => "ec2" }
      @node_layout = NodeLayout.new(@input_yaml, @options)
      
      assert_false @node_layout.valid?
    end
  end

  context "advanced format invalid node id for cloud" do
    setup do
      @input_yaml = {
        :master => "node-1",
        :appengine => ["node-2", "TOTALLY_NODE_VALID", "node-4"],
        :database => ["TOTALLY_NOT_VALID", "node-4"]
      }.to_yaml

      @options = { :database => :voldemort, :infrastructure => "ec2" }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid becuase of the invalid node id" do
        assert_false @node_layout.valid?
        assert_contains @node_layout.errors, /Invalid node ID/
    end
  end

  context "advanced format invalid node id for non-cloud" do
    setup do
      @input_yaml = {
        :master => "192.2.3.1",
        :database => ["192.2.4.2", "192.2.4.1", "192.2.3.NOT_VALID.30"],
        :appengine => ["192.2.4.2", "192.2.4.1", "192.2.3.NOT_VALID.30"]
      }.to_yaml

      @options = { :database => :voldemort }
      @node_layout = NodeLayout.new(@input_yaml, @options)
    end

    should "not be valid becuase of the invalid node id" do
        assert_false @node_layout.valid?
        assert_contains @node_layout.errors, /Invalid node ID/
    end
  end
end


