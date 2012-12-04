$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleAddNodes < Test::Unit::TestCase
  def setup
  end

  def test_add_nodes_with_bad_ips_file
    # First, test the case where the user didn't give us an ips.yaml
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_nodes({})
    }

    # Next, test the case where it points somewhere that doesn't exist
    nonexistent_file = '/boo/bazfile'
    flexmock(File).should_receive(:exists?).with(nonexistent_file).
      and_return(false)
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_nodes({'ips' => nonexistent_file})
    }

    # Also consider if the YAML file given is just an empty file
    empty_file = '/boo/emptyfile'
    flexmock(File).should_receive(:exists?).with(empty_file).
      and_return(true)
    flexmock(YAML).should_receive(:load_file).with(empty_file).
      and_return(false)
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_nodes({'ips' => empty_file})
    }

    # Now, consider the case where it exists, but isn't YAML
    not_yaml_file = '/boo/barfile'
    flexmock(File).should_receive(:exists?).with(not_yaml_file).
      and_return(true)
    flexmock(YAML).should_receive(:load_file).with(not_yaml_file).
      and_raise(ArgumentError)
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_nodes({'ips' => not_yaml_file})
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
      AppScaleTools.add_nodes({'ips' => yaml_file})
    }
  end

end
