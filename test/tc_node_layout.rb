$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'node_layout'

require 'test/unit'


class TestNodeLayout < Test::Unit::TestCase
  def setup
    @blank_input_yaml = nil
    @blank_options = {}

    @ip_1 = '192.168.1.1'
    @ip_2 = '192.168.1.2'
    @ip_3 = '192.168.1.3'
  end

  def test_simple_layout_yaml_only
    # Specifying one controller and one server should be ok
    input_yaml_1 = {:controller => @ip_1, :servers => [@ip_2]}
    layout_1 = NodeLayout.new(input_yaml_1, @blank_options)
    assert_equal(true, layout_1.valid?)

    # Specifying one controller should be ok
    input_yaml_2 = {:controller => @ip_1}
    layout_2 = NodeLayout.new(input_yaml_2, @blank_options)
    assert_equal(true, layout_2.valid?)

    # Specifying the same IP more than once is not ok
    input_yaml_3 = {:controller => @ip_1, :servers => [@ip_1]}
    layout_3 = NodeLayout.new(input_yaml_3, @blank_options)
    assert_equal(false, layout_3.valid?)
    assert_equal(DUPLICATE_IPS, layout_3.errors)

    # Failing to specify a controller is not ok
    input_yaml_4 = {:servers => [@ip_1, @ip_2]}
    layout_4 = NodeLayout.new(input_yaml_4, @blank_options)
    assert_equal(false, layout_4.valid?)
    assert_equal(NO_CONTROLLER, layout_4.errors)

    # Specifying more than one controller is not ok
    input_yaml_5 = {:controller => [@ip_1, @ip_2], :servers => [@ip_3]}
    layout_5 = NodeLayout.new(input_yaml_5, @blank_options)
    assert_equal(false, layout_5.valid?)
    assert_equal(ONLY_ONE_CONTROLLER, layout_5.errors)

    # Specifying something other than controller and servers in simple
    # deployments is not ok
    input_yaml_6 = {:controller => @ip_1, :servers => [@ip_2], :boo => @ip_3}
    layout_6 = NodeLayout.new(input_yaml_6, @blank_options)
    assert_equal(false, layout_6.valid?)
    assert_equal(["The flag boo is not a supported flag"], layout_6.errors)
  end

  def test_simple_layout_options
    # Using Euca with no input yaml, and no max or min images is not ok
    options_1 = {:infrastructure => "euca"}
    layout_1 = NodeLayout.new(@blank_input_yaml, options_1)
    assert_equal(false, layout_1.valid?)
    assert_equal(NO_INPUT_YAML_REQUIRES_MIN_IMAGES, layout_1.errors)

    options_2 = {:infrastructure => "euca", :max_images => 2}
    layout_2 = NodeLayout.new(@blank_input_yaml, options_2)
    assert_equal(false, layout_2.valid?)
    assert_equal(NO_INPUT_YAML_REQUIRES_MIN_IMAGES, layout_2.errors)

    options_3 = {:infrastructure => "euca", :min_images => 2}
    layout_3 = NodeLayout.new(@blank_input_yaml, options_3)
    assert_equal(false, layout_3.valid?)
    assert_equal(NO_INPUT_YAML_REQUIRES_MAX_IMAGES, layout_3.errors)

    # Using Euca with no input yaml, with max and min images set is ok
    options_4 = {:infrastructure => "euca", :min_images => 2, :max_images => 2}
    layout_4 = NodeLayout.new(@blank_input_yaml, options_4)
    assert_equal(true, layout_4.valid?)

    # Using Xen or hybrid cloud deployments with no input yaml is not ok
    options_5 = {:infrastructure => "xen"}
    layout_5 = NodeLayout.new(@blank_input_yaml, options_5)
    assert_equal(false, layout_5.valid?)
    assert_equal([INPUT_YAML_REQUIRED], layout_5.errors)

    options_6 = {:infrastructure => "hybrid"}
    layout_6 = NodeLayout.new(@blank_input_yaml, options_6)
    assert_equal(false, layout_6.valid?)
    assert_equal([INPUT_YAML_REQUIRED], layout_6.errors)
  end

  def test_advanced_format_yaml_only
    input_yaml_1 = {:master => @ip_1, :database => @ip_1, :appengine => @ip_1, :open => @ip_2}
    layout_1 = NodeLayout.new(input_yaml_1, @blank_options)
    assert_equal(true, layout_1.valid?)
  end
end
