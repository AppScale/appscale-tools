$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleAddNodes < Test::Unit::TestCase
  def setup
  end

  def test_add_nodes_with_no_ips_file
    assert_raises(BadConfigurationException) {
      AppScaleTools.add_nodes({})
    }
  end
end
