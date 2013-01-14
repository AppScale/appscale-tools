$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleRemoveApp < Test::Unit::TestCase
  def setup
    @key = "appscale"
    @options = {"appname" => "boo", "keyname" => @key}

    @secret = "booooo"
    @fake_yaml = {
      :load_balancer => "127.0.0.1",
      :shadow => "127.0.0.1",
      :secret => @secret,
      :db_master => "node-1",
      :table => "cassandra",
      :instance_id => "i-FOOBARZ"
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
 
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:read_file).
      with(File.expand_path("~/.appscale/locations-#{@key}.json")).
      and_return(JSON.dump(@role_info))
    commonfunctions.should_receive(:write_file).with(
      File.expand_path("~/.appscale/locations-#{@key}.json"),
      JSON.dump(@role_info)).and_return()

    # mocks for get_role_info, which will return the node's state
    appcontroller = flexmock('appcontroller')
    appcontroller.should_receive(:get_role_info).and_return(@role_info)
    appcontroller.should_receive(:get_userappserver_ip).and_return("127.0.0.1")
    appcontroller.should_receive(:stop_app).and_return("true")
    appcontroller.should_receive(:app_is_running?).and_return(true, false)
    flexmock(AppControllerClient).should_receive(:new).
      and_return(appcontroller)
    
    kernel = flexmock(Kernel)
    kernel.should_receive(:print).and_return()
    kernel.should_receive(:puts).and_return()
    kernel.should_receive(:sleep).and_return()
  end

  def test_no_appname_given
    options = {"keyname" => @key}
    assert_raises(BadConfigurationException) {
      AppScaleTools.remove_app(options)
    }
  end

  def test_user_cancels_removal
    stdin = flexmock(STDIN)
    stdin.should_receive(:gets).and_return("no\n")

    assert_raises(AppScaleException) {
      AppScaleTools.remove_app(@options)
    }
  end

  def test_remove_app_that_doesnt_exist
    stdin = flexmock(STDIN)
    stdin.should_receive(:gets).and_return("yes\n")
    
    file = flexmock(File)
    file.should_receive(:exists?).and_return(true)

    userappclient = flexmock(UserAppClient)
    userappclient.new_instances { |instance|
      instance.should_receive(:does_app_exist?).and_return(false)
    }

    assert_raises(AppEngineConfigException) {
      AppScaleTools.remove_app(@options)
    }
  end

  def test_remove_app_that_does_exist
    stdin = flexmock(STDIN)
    stdin.should_receive(:gets).and_return("yes\n")
    
    file = flexmock(File)
    file.should_receive(:exists?).and_return(true)

    userappclient = flexmock(UserAppClient)
    userappclient.new_instances { |instance|
      instance.should_receive(:does_app_exist?).and_return(true)
    }

    assert_nothing_raised(Exception) {
      AppScaleTools.remove_app(@options)
    }
  end

  def test_usage_is_up_to_date
    AppScaleTools::REMOVE_APP_FLAGS.each { |flag|
      assert_equal(true, AppScaleTools::REMOVE_APP_USAGE.include?("-#{flag}"),
        "No usage text for #{flag}.")
    } 
  end
end
