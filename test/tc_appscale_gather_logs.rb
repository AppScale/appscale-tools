$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleGatherLogs < Test::Unit::TestCase
  def setup
    # place in mocks for file reading and creation so that we
    # have to explicitly state in our tests which actions are
    # ok
    flexmock(File).should_receive(:exists?).with("").and_return()
    flexmock(FileUtils).should_receive(:mkdir_p).with("").and_return()
    flexmock(CommonFunctions).should_receive(:shell).with("").and_return()

    # mock out all sleep statements
    flexmock(Kernel).should_receive(:sleep).and_return()

    # and mock out all print statements
    flexmock(Kernel).should_receive(:puts).and_return()
  end

  def test_gather_logs_when_dir_already_exists
    # If we run gather_logs and specify a directory that already
    # exists, then it should fail
    location = "/baz/boo"
    options = {
      "location" => location
    }
    flexmock(File).should_receive(:exists?).with(location).
      and_return(true)
    assert_raises(AppScaleException) {
      AppScaleTools.gather_logs(options)
    }
  end

  def test_gather_logs_when_appscale_isnt_running
    # If we run gather_logs and AppScale isn't running with the
    # keyname that the user gave us, then it should fail
    location = "/baz/boo"
    keyname = "bookey"
    options = {
      "location" => location,
      "keyname" => keyname
    }

    # mock out filesystem accesses
    flexmock(File).should_receive(:exists?).with(location).
      and_return(false)
    flexmock(FileUtils).should_receive(:mkdir_p).with(location).
      and_return()

    appscale_locations_file = File.expand_path("~/.appscale/locations-#{keyname}.yaml")
    flexmock(File).should_receive(:exists?).
      with(appscale_locations_file).and_return(false)

    assert_raises(AppScaleException) {
      AppScaleTools.gather_logs(options)
    }
  end

  def test_gather_logs_when_appscale_is_running_one_node_no_soap
    # If we run gather_logs and AppScale is running with the
    # keyname that the user gave us, then it should succeed.
    # If there's no info on the nodes via SOAP, then only
    # grab the information about the first node in the system
    # (as it's the one that crashed and the only one we have
    # information about).
    location = "/baz/boo"
    keyname = "bookey"
    options = {
      "location" => location,
      "keyname" => keyname
    }

    # mock out filesystem accesses
    flexmock(File).should_receive(:exists?).with(location).
      and_return(false)
    flexmock(FileUtils).should_receive(:mkdir_p).with(location).
      and_return()
    flexmock(FileUtils).should_receive(:mkdir_p).with("#{location}/boopublic").
      and_return()

    appscale_yaml_file = File.expand_path("~/.appscale/locations-#{keyname}.yaml")
    appscale_yaml = {:secret => 'boosecret'}
    flexmock(File).should_receive(:exists?).
      with(appscale_yaml_file).and_return(true)
    flexmock(YAML).should_receive(:load_file).with(appscale_yaml_file).
      and_return(appscale_yaml)

    appscale_json_file = File.expand_path("~/.appscale/locations-#{keyname}.json")
    appscale_json = JSON.dump([{'jobs' => ['shadow'], 'public_ip' => 'boopublic'}])
    flexmock(File).should_receive(:open).with(appscale_json_file, Proc).
      and_return(appscale_json)

    # mock out SOAP calls - let's say they failed due to the remote
    # AppController crashing
    flexmock(AppControllerClient).new_instances { |i|
      i.should_receive(:make_call).and_raise(AppScaleException)
    }

    # mock out SCP calls - let's say that they fail the first time,
    # and then succeed the second time
    retval_file = File.expand_path("~/.appscale/retval-boo")
    flexmock(Kernel).should_receive(:rand).and_return("boo")
    flexmock(CommonFunctions).should_receive(:shell).with(/\Ascp/).
      and_return()
    flexmock(File).should_receive(:exists?).with(retval_file).
      and_return(true)
    flexmock(File).should_receive(:open).with(retval_file, Proc).
      and_return("1\n", "0\n")
    
    expected = {:success => true, :log_dirs => ["/baz/boo/boopublic"]}
    actual = AppScaleTools.gather_logs(options)
    assert_equal(expected, actual)
  end

  def test_gather_logs_when_appscale_is_running_four_nodes
    # If we run gather_logs and AppScale is running with the
    # keyname that the user gave us, then it should succeed.
    # If there is info on the nodes via SOAP, then we should
    # grab the information about all four nodes.
    location = "/baz/boo"
    keyname = "bookey"
    options = {
      "location" => location,
      "keyname" => keyname
    }

    # mock out filesystem accesses
    flexmock(File).should_receive(:exists?).with(location).
      and_return(false)
    flexmock(FileUtils).should_receive(:mkdir_p).with(location).
      and_return()
    flexmock(FileUtils).should_receive(:mkdir_p).
      with("#{location}/boopublic1").and_return()
    flexmock(FileUtils).should_receive(:mkdir_p).
      with("#{location}/boopublic2").and_return()
    flexmock(FileUtils).should_receive(:mkdir_p).
      with("#{location}/boopublic3").and_return()
    flexmock(FileUtils).should_receive(:mkdir_p).
      with("#{location}/boopublic4").and_return()

    appscale_yaml_file = File.expand_path("~/.appscale/locations-#{keyname}.yaml")
    appscale_yaml = {:secret => 'boosecret'}
    flexmock(File).should_receive(:exists?).
      with(appscale_yaml_file).and_return(true)
    flexmock(YAML).should_receive(:load_file).with(appscale_yaml_file).
      and_return(appscale_yaml)

    appscale_json_file = File.expand_path("~/.appscale/locations-#{keyname}.json")
    appscale_json = JSON.dump([{'jobs' => ['shadow'], 'public_ip' => 'boopublic1'}])
    flexmock(File).should_receive(:open).with(appscale_json_file, Proc).
      and_return(appscale_json)

    # mock out SOAP calls - let's say they failed due to the remote
    # AppController crashing
    all_ips = ["boopublic1", "boopublic2", "boopublic3", "boopublic4"]
    flexmock(AppControllerClient).new_instances { |i|
      i.should_receive(:make_call).and_return(all_ips)
    }

    # mock out SCP calls - let's say that they fail the first time,
    # and then succeed the second time
    retval_file = File.expand_path("~/.appscale/retval-boo")
    flexmock(Kernel).should_receive(:rand).and_return("boo")
    flexmock(CommonFunctions).should_receive(:shell).with(/\Ascp/).
      and_return()
    flexmock(File).should_receive(:exists?).with(retval_file).
      and_return(true)
    flexmock(File).should_receive(:open).with(retval_file, Proc).
      and_return("1\n", "0\n")
    
    expected = {:success => true, :log_dirs =>
      ["/baz/boo/boopublic1", "/baz/boo/boopublic2",
      "/baz/boo/boopublic3", "/baz/boo/boopublic4"]}
    actual = AppScaleTools.gather_logs(options)
    assert_equal(expected, actual)
  end

end
