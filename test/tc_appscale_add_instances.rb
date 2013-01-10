$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleAddNodes < Test::Unit::TestCase
  def setup
    # make user explicitly state which shell calls they want to mock
    flexmock(CommonFunctions).should_receive(:shell).with("").
      and_return()
  end

  def test_add_instances_with_bad_ips_file
    # First, test the case where the user didn't give us an ips.yaml
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_instances({})
    }

    # Next, test the case where it points somewhere that doesn't exist
    nonexistent_file = '/boo/bazfile'
    flexmock(File).should_receive(:exists?).with(nonexistent_file).
      and_return(false)
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_instances({'ips' => nil})
    }

    # Also consider if the YAML file given is just an empty file
    empty_file = '/boo/emptyfile'
    flexmock(File).should_receive(:exists?).with(empty_file).
      and_return(true)
    flexmock(YAML).should_receive(:load_file).with(empty_file).
      and_return(false)
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_instances({'ips' => ''})
    }
  end

  def test_add_single_master_node
    # Adding a 'master' node is not acceptable - there can only be one
    # running in an AppScale deployment, and AppScale starts with one.
    yaml_file = '/boo/ips.yaml'
    yaml_contents = { :master => '1.2.3.4' }

    flexmock(File).should_receive(:exists?).with(yaml_file).
      and_return(true)
    flexmock(YAML).should_receive(:load_file).with(yaml_file).
      and_return(yaml_contents)
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_instances({'ips' => yaml_contents})
    }
  end

  def test_add_single_node_but_ssh_keys_not_setup_on_xen
    # Adding a single AppServer is acceptable, but if the user hasn't
    # run appscale-add-keypair to sync up the keys, then that should
    # cause add-nodes to throw up and die
    yaml_file = '/boo/ips.yaml'
    yaml_contents = { :appengine => '1.2.3.4' }

    flexmock(File).should_receive(:exists?).with(yaml_file).
      and_return(true)
    flexmock(YAML).should_receive(:load_file).with(yaml_file).
      and_return(yaml_contents)

    # mock out the locations.yaml file so that we think we're on xen
    locations_yaml_file = File.expand_path("~/.appscale/locations-blarg.yaml")
    locations_yaml_contents = { :infrastructure => 'xen' }
    flexmock(File).should_receive(:exists?).with(locations_yaml_file).
      and_return(true)
    flexmock(YAML).should_receive(:load_file).with(locations_yaml_file).
      and_return(locations_yaml_contents)

    # mock out the ssh call so that it fails, indicating that the ssh
    # key given can't be used to log into that box
    flexmock(CommonFunctions).should_receive(:shell).with(/\Assh/).
      and_return("1\n")

    assert_raises(AppScaleException) {
      AppScaleTools.add_instances({
        "ips" => yaml_contents,
        "keyname" => "blarg"
      })
    }
  end  
  
  def test_add_two_nodes_on_ec2
    # Adding a single AppServer is acceptable, but if the user hasn't
    # run appscale-add-keypair to sync up the keys, then that should
    # cause add-nodes to throw up and die
    yaml_file = '/boo/ips.yaml'
    yaml_contents = { :appengine => ['node-1', 'node-2'] }

    flexmock(File).should_receive(:exists?).with(yaml_file).
      and_return(true)
    flexmock(YAML).should_receive(:load_file).with(yaml_file).
      and_return(yaml_contents)

    # mock out the locations.yaml file so that we think we're on ec2
    locations_yaml_file = File.expand_path("~/.appscale/locations-blarg.yaml")
    locations_yaml_contents = {
      :infrastructure => 'ec2',
      :secret => 'boosecret'
    }
    flexmock(File).should_receive(:exists?).with(locations_yaml_file).
      and_return(true)
    flexmock(YAML).should_receive(:load_file).with(locations_yaml_file).
      and_return(locations_yaml_contents)

    locations_json_file = File.expand_path("~/.appscale/locations-blarg.json")
    locations_json_contents = JSON.dump([{'public_ip' => '1.2.3.4', 'jobs' => 'shadow'}])
    flexmock(File).should_receive(:exists?).with(locations_json_file).
      and_return(true)
    flexmock(File).should_receive(:open).with(locations_json_file, Proc).
      and_return(locations_json_contents)

    # finally, mock out the AppController and assume the request to
    # add nodes succeeded
    flexmock(AppControllerClient).new_instances { |i|
      i.should_receive(:start_roles_on_nodes).
        with({'appengine' => ['node-1', 'node-2']}).
        and_return("OK")
    }

    expected = "OK"
    actual = AppScaleTools.add_instances({
      "ips" => yaml_contents,
      "keyname" => "blarg"
    })
    assert_equal(expected, actual)
  end
end
