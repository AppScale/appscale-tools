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

    # mock out any writing to stdout
    flexmock(Kernel).should_receive(:print).and_return()
    flexmock(Kernel).should_receive(:puts).and_return()

    # disallow any writing to the filesystem that we haven't
    # specifically added mocks for
    flexmock(FileUtils).should_receive(:mkdir_p).with("").and_return()

    # also, make sleeps return immediately
    flexmock(Kernel).should_receive(:sleep).and_return()
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


  def test_get_credentials_from_options
    # if the user gives us the --test flag, then we should search
    # the environment for a username / password. let's say it's there:
    ENV['APPSCALE_USERNAME'] = 'b@b.b'
    ENV['APPSCALE_PASSWORD'] = 'bbbbbb'
    user, pass = CommonFunctions.get_credentials(testing=true)
    assert_equal('b@b.b', user)
    assert_equal('bbbbbb', pass)

    # now assume the environment variables aren't there - in this case
    # we should fall back to the default
    ENV['APPSCALE_USERNAME'] = nil
    ENV['APPSCALE_PASSWORD'] = nil
    user, pass = CommonFunctions.get_credentials(testing=true)
    assert_equal(DEFAULT_USERNAME, user)
    assert_equal(DEFAULT_PASSWORD, pass)
  end


  def test_obscure_creds
    creds = {
      'ec2_access_key' => 'ABCDEFG',
      'ec2_secret_key' => 'HIJKLMN',
      'CLOUD_EC2_ACCESS_KEY' => 'OPQRSTU',
      'CLOUD_EC2_SECRET_KEY' => 'VWXYZAB'
    }

    expected = {
      'ec2_access_key' => '***DEFG',
      'ec2_secret_key' => '***KLMN',
      'CLOUD_EC2_ACCESS_KEY' => '***RSTU',
      'CLOUD_EC2_SECRET_KEY' => '***YZAB'
    }

    actual = CommonFunctions.obscure_creds(creds)
    assert_equal(expected['ec2_access_key'], actual['ec2_access_key'])
    assert_equal(expected['ec2_secret_key'], actual['ec2_secret_key'])
    assert_equal(expected['CLOUD_EC2_ACCESS_KEY'],
      actual['CLOUD_EC2_ACCESS_KEY'])
    assert_equal(expected['CLOUD_EC2_SECRET_KEY'],
      actual['CLOUD_EC2_SECRET_KEY'])
  end


  def test_collect_and_send_logs_where_user_says_no
    # first, try a test where the user does not want to collect logs

    flexmock(STDIN).should_receive(:gets).and_return("no\n")
    exception = flexmock("Exception")
    exception.should_receive(:class).and_return("BooException")
    exception.should_receive(:backtrace).and_return("the stack trace")

    expected = {
      :collected_logs => false,
      :sent_logs => false,
      :reason => "aborted by user"
    }
    actual = CommonFunctions.collect_and_send_logs({}, exception)
    assert_equal(expected, actual)
  end


  def test_collect_and_send_logs_where_user_says_yes_but_collecting_fails
    # try a test where the user does want to collect logs, but
    # the AppController has failed

    flexmock(STDIN).should_receive(:gets).and_return("yes\n")
    exception = flexmock("Exception")
    exception.should_receive(:class).and_return("BooException")
    exception.should_receive(:backtrace).and_return("the stack trace")

    # mock out interacting with the local filesystem
    flexmock(Time).should_receive(:now).and_return("1234")
    logs_location = "/tmp/appscale-logs-1234"
    flexmock(File).should_receive(:exists?).with(logs_location).
      and_return(false)
    flexmock(FileUtils).should_receive(:mkdir_p).with(logs_location).
      and_return(true)

    # assume that appscale was started successfully, so the user has the
    # locations.yaml and locations.json files
    locations_file = File.expand_path("~/.appscale/locations-booscale.yaml")
    flexmock(File).should_receive(:exists?).with(locations_file).and_return(true)
    locations_contents = YAML.dump({
      :secret => "boosecret"
    })
    flexmock(File).should_receive(:open).with(locations_file, Proc).
      and_return(locations_contents)

    nodes_json_file = File.expand_path("~/.appscale/locations-booscale.json")
    nodes_json = JSON.dump([
      {
        "public_ip" => "ip1",
        "jobs" => "shadow"
      }
    ])
    flexmock(File).should_receive(:open).with(nodes_json_file, Proc).
      and_return(nodes_json)

    # next, assume that the appcontroller has failed on the head node
    flexmock(AppControllerClient).new_instances{ |instance|
      instance.should_receive(:get_all_public_ips).and_raise(AppScaleException)
    }

    # this means that we will only try to copy logs off the head node,
    # since we don't know where everyone else is located
    flexmock(FileUtils).should_receive(:mkdir_p).with("#{logs_location}/ip1").
      and_return(true)

    # finally, assume the node has completely failed, so we can't even
    # scp logs off of it
    flexmock(CommonFunctions).should_receive(:shell).with(/\Ascp/).and_return()
    flexmock(Kernel).should_receive(:rand).and_return("random")
    scp_return_val_path = File.expand_path("~/.appscale/retval-random")
    flexmock(File).should_receive(:exists?).with(scp_return_val_path).
      and_return(true)
    flexmock(File).should_receive(:open).with(scp_return_val_path, Proc).
      and_return("1\n")

    options = {
      'keyname' => 'booscale'
    }

    expected = {
      :collected_logs => false,
      :sent_logs => false,
      :reason => "unable to collect logs"
    }
    actual = CommonFunctions.collect_and_send_logs(options, exception)
    assert_equal(expected, actual)
  end


  def test_collect_and_send_logs_where_user_says_yes_to_both
    # try a test where the user does want to collect logs, and
    # the AppController has not failed

    flexmock(STDIN).should_receive(:gets).and_return("yes\n", "yes\n")
    exception = flexmock("Exception")
    exception.should_receive(:class).and_return("BooException")
    exception.should_receive(:backtrace).and_return("the stack trace")

    # mock out interacting with the local filesystem
    flexmock(Time).should_receive(:now).and_return("1234")
    logs_location = "/tmp/appscale-logs-1234"
    flexmock(File).should_receive(:exists?).with(logs_location).
      and_return(false)
    flexmock(FileUtils).should_receive(:mkdir_p).with(logs_location).
      and_return(true)

    # assume that appscale was started successfully, so the user has the
    # locations.yaml and locations.json files
    locations_file = File.expand_path("~/.appscale/locations-booscale.yaml")
    flexmock(File).should_receive(:exists?).with(locations_file).and_return(true)
    locations_contents = YAML.dump({
      :secret => "boosecret"
    })
    flexmock(File).should_receive(:open).with(locations_file, Proc).
      and_return(locations_contents)

    nodes_json_file = File.expand_path("~/.appscale/locations-booscale.json")
    nodes_json = JSON.dump([
      {
        "public_ip" => "ip1",
        "jobs" => "shadow"
      }
    ])
    flexmock(File).should_receive(:open).with(nodes_json_file, Proc).
      and_return(nodes_json)

    # next, assume that the appcontroller is running on the head node
    flexmock(AppControllerClient).new_instances{ |instance|
      instance.should_receive(:get_all_public_ips).and_return(['ip1'])
    }

    # this means that we will try to copy logs off ip1
    flexmock(FileUtils).should_receive(:mkdir_p).with("#{logs_location}/ip1").
      and_return(true)

    # assume the node is alive, so we can copy logs off of it
    flexmock(CommonFunctions).should_receive(:shell).with(/\Ascp/).and_return()
    flexmock(Kernel).should_receive(:rand).and_return("random")
    scp_return_val_path = File.expand_path("~/.appscale/retval-random")
    flexmock(File).should_receive(:exists?).with(scp_return_val_path).
      and_return(true)
    flexmock(File).should_receive(:open).with(scp_return_val_path, Proc).
      and_return("0\n")

    options = {
      'keyname' => 'booscale'
    }

    expected = {
      :collected_logs => true,
      :sent_logs => false,
      :reason => ""
    }
    actual = CommonFunctions.collect_and_send_logs(options, exception)
    assert_equal(expected, actual)
  end


end
