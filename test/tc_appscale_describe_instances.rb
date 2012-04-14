$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleDescribeInstances < Test::Unit::TestCase
  def setup
    kernel = flexmock(Kernel)
    kernel.should_receive(:puts).and_return()

    @key = "booscale"
    @options = { "keyname" => @key }

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
 
    @role_info = [node1]
 
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:read_file).
      with(File.expand_path("~/.appscale/locations-#{@key}.json")).
      and_return(JSON.dump(@role_info))

    # mocks for get_role_info, which will return the node's state
    appcontroller = flexmock('appcontroller')
    appcontroller.should_receive(:get_role_info).and_return(@role_info)
    appcontroller.should_receive(:status).and_return("ALL OK")
    flexmock(AppControllerClient).should_receive(:new).
      and_return(appcontroller)
 
    commonfunctions.should_receive(:write_file).with(
      File.expand_path("~/.appscale/locations-#{@key}.json"),
      JSON.dump(@role_info)).and_return()
  end

  def test_all_ok
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:get_secret_key).and_return("")
    commonfunctions.should_receive(:get_head_node_ip).and_return("127.0.0.1")

    flexmock(AppControllerClient).new_instances { |instance|
      instance.should_receive(:get_all_public_ips).and_return(["127.0.0.1"])
      instance.should_receive(:status).and_return("ALL OK")
    }

    instance_info = AppScaleTools.describe_instances(@options)
    assert_equal(nil, instance_info[:error])
    assert_equal(["ALL OK"], instance_info[:result])
  end

  def test_usage_is_up_to_date
    AppScaleTools::DESCRIBE_INSTANCES_FLAGS.each { |flag|
      assert_equal(true, 
        AppScaleTools::DESCRIBE_INSTANCES_USAGE.include?("-#{flag}"), 
        "No usage text for #{flag}.")
    } 
  end
end
