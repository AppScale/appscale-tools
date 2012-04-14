$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'common_functions'


require 'flexmock/test_unit'


class TestCommonFunctions < Test::Unit::TestCase
  def setup
    @secret = "baz"
    @fake_yaml = {
      :load_balancer => "public_ip1",
      :shadow => "public_ip1",
      :secret => @secret,
      :table => "cassandra",
      :infrastructure => "xen",
      :ips => ["public_ip1", "public_ip2"]
    }
    yaml = flexmock(YAML)
    yaml.should_receive(:load_file).and_return(@fake_yaml)

    # taken from the standard two node deployment
    node1 = {
      'public_ip' => 'public_ip1',
      'private_ip' => 'private_ip1',
      'jobs' => ['load_balancer', 'shadow', 'db_master', 'zookeeper', 'login', 'memcache', 'rabbitmq_master'],
      'instance_id' => 'instance_id1',
      'cloud' => 'cloud1',
      'creation_time' => nil,
      'destruction_time' => nil
    }

    node2 = {
      'public_ip' => 'public_ip2',
      'private_ip' => 'private_ip2',
      'jobs' => ['load_balancer', 'db_slave', 'memcache', 'rabbitmq_slave', 'appengine'],
      'instance_id' => 'instance_id2',
      'cloud' => 'cloud2',
      'creation_time' => nil,
      'destruction_time' => nil
    }

    @role_info = [node1, node2]
    @key = "appscale"
  end


  def test_get_ips_for_roles
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:read_file).
      with(File.expand_path("~/.appscale/locations-#{@key}.json")).
      and_return(JSON.dump(@role_info))

    assert_equal("public_ip1", CommonFunctions.get_load_balancer_ip(@key))
  end
end
