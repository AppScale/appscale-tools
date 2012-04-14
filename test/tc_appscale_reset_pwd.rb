$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'

require 'test/unit'


class TestAppScaleResetPassword < Test::Unit::TestCase
  def setup
    @keyname = "booscale"
    @options = {"keyname" => @keyname}

    kernel = flexmock(Kernel)
    kernel.should_receive(:print).and_return()
    kernel.should_receive(:puts).and_return()

    stdout = flexmock(STDOUT)
    stdout.should_receive(:flush).and_return()
  end

  def test_appscale_not_running
    file = flexmock(File)
    file.should_receive(:exists?).and_return(true)

    @secret = "booooo"
    @fake_yaml = {:load_balancer => "",
      :shadow => "127.0.0.1",
      :secret => @secret,
      :db_master => "node-1",
      :table => "cassandra",
      :instance_id => "i-FOOBARZ"}
    yaml = flexmock(YAML)
    yaml.should_receive(:load_file).and_return(@fake_yaml)

    # taken from the standard two node deployment
    node1 = {
      'public_ip' => 'public_ip1',
      'private_ip' => 'private_ip1',
      'jobs' => ['shadow', 'db_master', 'zookeeper', 'login', 'memcache', 'rabbitmq_master'],
      'instance_id' => 'instance_id1',
      'cloud' => 'cloud1',
      'creation_time' => nil,
      'destruction_time' => nil
    }
 
    node2 = {
      'public_ip' => 'public_ip2',
      'private_ip' => 'private_ip2',
      'jobs' => ['db_slave', 'memcache', 'rabbitmq_slave', 'appengine'],
      'instance_id' => 'instance_id2',
      'cloud' => 'cloud2',
      'creation_time' => nil,
      'destruction_time' => nil
    }

    @role_info = [node1, node2]

    appcontroller = flexmock('appcontroller')
    appcontroller.should_receive(:get_role_info).and_return(@role_info)
    flexmock(AppControllerClient).should_receive(:new).and_return(appcontroller)
 
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:read_file).
      with(File.expand_path("~/.appscale/locations-#{@keyname}.json")).
      and_return(JSON.dump(@role_info))
    commonfunctions.should_receive(:write_file).with(
      File.expand_path("~/.appscale/locations-#{@keyname}.json"),
      JSON.dump(@role_info)).and_return()

    assert_raises(BadConfigurationException) {
      AppScaleTools.reset_password(@options)
    }
  end

  def test_all_ok
    file = flexmock(File)
    file.should_receive(:exists?).and_return(true)

    @secret = "booooo"
    @fake_yaml = {:load_balancer => "127.0.0.1",
      :shadow => "127.0.0.1",
      :secret => @secret,
      :db_master => "node-1",
      :table => "cassandra",
      :instance_id => "i-FOOBARZ"}
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
 
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:read_file).
      with(File.expand_path("~/.appscale/locations-#{@keyname}.json")).
      and_return(JSON.dump(@role_info))

    @user = "a@a.a"
    @password = "aaaaaa"

    stdin = flexmock(STDIN)
    stdin.should_receive(:gets).and_return(@user + "\n", @password + "\n")

    kernel = flexmock(Kernel)
    kernel.should_receive(:system).with("stty -echo").and_return()
    kernel.should_receive(:system).with("stty echo").and_return()

    appcontroller = flexmock('appcontroller')
    appcontroller.should_receive(:get_role_info).and_return(@role_info)
    appcontroller.should_receive(:get_userappserver_ip).and_return("127.0.0.1")
    flexmock(AppControllerClient).should_receive(:new).and_return(appcontroller)
 
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:read_file).
      with(File.expand_path("~/.appscale/locations-#{@keyname}.json")).
      and_return(JSON.dump(@role_info))
    commonfunctions.should_receive(:write_file).with(
      File.expand_path("~/.appscale/locations-#{@keyname}.json"),
      JSON.dump(@role_info)).and_return()

    userappclient = flexmock(UserAppClient)
    userappclient.new_instances { |instance|
      instance.should_receive(:change_password).and_return("OK")
    }

    assert_nothing_raised(Exception) {
      AppScaleTools.reset_password(@options)
    }
  end

  def test_usage_is_up_to_date
    AppScaleTools::RESET_PASSWORD_FLAGS.each { |flag|
      assert_equal(true, 
        AppScaleTools::RESET_PASSWORD_USAGE.include?("-#{flag}"), 
        "No usage text for #{flag}.")
    } 
  end
end
