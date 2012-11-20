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

  def test_get_java_app_has_threadsafe
    # First, make sure that we throw an exception if there is no
    # threadsafe tag in the user's app.
    dir = "boo"
    web_xml_no_threadsafe = "file1.xml"
    file1 = "/tmp/#{dir}/#{web_xml_no_threadsafe}"
    file_without_threadsafe_contents = ""
    flexmock(File).should_receive(:open).with(file1, Proc).
      and_return(file_without_threadsafe_contents)

    assert_raises(AppEngineConfigException) {
      CommonFunctions.ensure_app_has_threadsafe(dir, web_xml_no_threadsafe)
    }

    # Next, make sure we throw an exception if there is a threadsafe
    # tag, but it's not set to true or false.
    web_xml_bad_threadsafe = "file2.xml"
    file2 = "/tmp/#{dir}/#{web_xml_bad_threadsafe}"
    file_with_bad_threadsafe_contents = "<threadsafe>boo</threadsafe>"
    flexmock(File).should_receive(:open).with(file2, Proc).
      and_return(file_with_bad_threadsafe_contents)

    assert_raises(AppEngineConfigException) {
      CommonFunctions.ensure_app_has_threadsafe(dir, web_xml_bad_threadsafe)
    }

    # Finally, make sure that if there is a threadsafe tag and it
    # is set to true or false, that no exception is thrown.
    web_xml_true_threadsafe = "file3.xml"
    file3 = "/tmp/#{dir}/#{web_xml_true_threadsafe}"
    file_with_true_threadsafe_contents = "<threadsafe>true</threadsafe>"
    flexmock(File).should_receive(:open).with(file3, Proc).
      and_return(file_with_true_threadsafe_contents)

    assert_nothing_raised(AppEngineConfigException) {
      CommonFunctions.ensure_app_has_threadsafe(dir, web_xml_true_threadsafe)
    }

    web_xml_false_threadsafe = "file4.xml"
    file4 = "/tmp/#{dir}/#{web_xml_false_threadsafe}"
    file_with_false_threadsafe_contents = "<threadsafe>false</threadsafe>"
    flexmock(File).should_receive(:open).with(file4, Proc).
      and_return(file_with_false_threadsafe_contents)

    assert_nothing_raised(AppEngineConfigException) {
      CommonFunctions.ensure_app_has_threadsafe(dir, web_xml_false_threadsafe)
    }
  end
end
