$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleTerminateInstances < Test::Unit::TestCase
  def setup
    kernel = flexmock(Kernel)
    kernel.should_receive(:print).and_return()
    kernel.should_receive(:puts).and_return()
    kernel.should_receive(:sleep).and_return()

    stdout = flexmock(STDOUT)
    stdout.should_receive(:flush).and_return()

    fileutils = flexmock(FileUtils)
    fileutils.should_receive(:rm_f).and_return()
 
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

    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:read_file).
      with(File.expand_path("~/.appscale/locations-#{@key}.json")).
      and_return(JSON.dump(@role_info))
  end

  def test_no_locations_yaml
    file = flexmock(File)
    file.should_receive(:exists?).and_return(false)

    options = {"keyname" => @key}
    assert_raises(AppScaleException) {
      AppScaleTools.terminate_instances(options)
    }
  end

  def test_terminate_xen_boxes
    file = flexmock(File)
    file.should_receive(:exists?).and_return(true)

    @secret = "booooo"
    @fake_yaml = {
      :shadow => "public_ip",
      :secret => @secret,
      #:table => "cassandra",
      :infrastructure => "xen",
      :ips => "public_ip"
    }
    yaml = flexmock(YAML)
    yaml.should_receive(:load_file).and_return(@fake_yaml)

    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:run_remote_command).and_return()
    commonfunctions.should_receive(:shell).and_return("service appscale-controller stop", "")

    # mocks for get_role_info, which will return the node's state
    appcontroller = flexmock('appcontroller')
    appcontroller.should_receive(:get_role_info).and_return(@role_info)
    flexmock(AppControllerClient).should_receive(:new).
      and_return(appcontroller)

    commonfunctions.should_receive(:write_file).with(
      File.expand_path("~/.appscale/locations-appscale.json"),
      JSON.dump(@role_info)).and_return()

    options = {"keyname" => "appscale"}
    assert_nothing_raised(Exception) {
      AppScaleTools.terminate_instances(options)
    }
  end

  def test_usage_is_up_to_date
    AppScaleTools::TERMINATE_INSTANCES_FLAGS.each { |flag|
      assert_equal(true, 
        AppScaleTools::TERMINATE_INSTANCES_USAGE.include?("-#{flag}"), 
        "No usage text for #{flag}.")
    } 
  end
end
