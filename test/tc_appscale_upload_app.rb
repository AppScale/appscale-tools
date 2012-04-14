$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleUploadApp < Test::Unit::TestCase
  def setup
    @app_name = "boo"
    @file_location = "/tmp/boo.tar.gz"
    @language = "python"
    @user = "a@a.a"

    @key = "booscale"
    @options = { "file_location" => @file_location, "keyname" => @key,
      "test" => true}

    # common mocks, mostly involving reading files
    file = flexmock(File)
    file.should_receive(:exists?).and_return(true)

    @secret = "booooo"
    @fake_yaml = {:load_balancer => "public_ip1",
      :shadow => "public_ip1",
      :secret => @secret,
      :db_master => "public_ip1",
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
      with(File.expand_path("~/.appscale/locations-#{@key}.json")).
      and_return(JSON.dump(@role_info))

    # mocks for get_role_info, which will return the node's state
    appcontroller = flexmock('appcontroller')
    appcontroller.should_receive(:get_role_info).and_return(@role_info)
    appcontroller.should_receive(:get_userappserver_ip).and_return("127.0.0.1")
    flexmock(AppControllerClient).should_receive(:new).and_return(appcontroller)
    
    commonfunctions.should_receive(:write_file).with(
      File.expand_path("~/.appscale/locations-#{@key}.json"),
      JSON.dump(@role_info)).and_return()

    fileutils = flexmock(FileUtils)
    fileutils.should_receive(:rm_rf).and_return()

    kernel = flexmock(Kernel)
    kernel.should_receive(:print).and_return()
    kernel.should_receive(:puts).and_return()

    @app_info = {
      :app_name => @app_name,
      :file => @file_location,
      :language => @language
    }

    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:get_app_name_from_tar).and_return(@app_info)
  end

  def test_no_app_provided
    options = {"keyname" => @key}
    assert_raises(AppScaleException) {
      AppScaleTools.upload_app(options)
    }
  end

  def test_app_already_exists_and_user_does_not
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:create_user).and_return()

    appcontrollerclient = flexmock(AppControllerClient)
    appcontrollerclient.new_instances { |instance|
      instance.should_receive(:get_userappserver_ip).and_return("127.0.0.1")
    }

    userappclient = flexmock(UserAppClient)
    userappclient.new_instances { |instance|
      instance.should_receive(:does_user_exist?).and_return(false)
      instance.should_receive(:does_app_exist?).and_return(true)
    }

    assert_raises(AppScaleException) {
      AppScaleTools.upload_app(@options)
    }
  end

  def test_upload_user_not_app_administrator
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:create_user).and_return()

    appcontrollerclient = flexmock(AppControllerClient)
    appcontrollerclient.new_instances { |instance|
      instance.should_receive(:get_userappserver_ip).and_return("127.0.0.1")
    }

    userappclient = flexmock(UserAppClient)
    userappclient.new_instances { |instance|
      instance.should_receive(:does_user_exist?).and_return(true)
      instance.should_receive(:does_app_exist?).and_return(false)
      instance.should_receive(:get_app_admin).and_return(@user + "boo")
    }

    assert_raises(AppScaleException) {
      AppScaleTools.upload_app(@options)
    }
  end

  def test_app_uploads_successfully
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:scp_app_to_ip).and_return(@file_location)
    commonfunctions.should_receive(:update_appcontroller).and_return()
    commonfunctions.should_receive(:wait_for_app_to_start).and_return()

    appcontrollerclient = flexmock(AppControllerClient)
    appcontrollerclient.new_instances { |instance|
      instance.should_receive(:get_userappserver_ip).and_return("127.0.0.1")
    }

    userappclient = flexmock(UserAppClient)
    userappclient.new_instances { |instance|
      instance.should_receive(:does_user_exist?).and_return(true)
      instance.should_receive(:does_app_exist?).and_return(false)
      instance.should_receive(:get_app_admin).and_return(@user)
    }

    assert_nothing_raised(Exception) {
      AppScaleTools.upload_app(@options)
    }
  end

  def test_usage_is_up_to_date
    AppScaleTools::UPLOAD_APP_FLAGS.each { |flag|
      assert_equal(true, AppScaleTools::UPLOAD_APP_USAGE.include?("-#{flag}"), 
        "No usage text for #{flag}.")
    }
  end
end
