$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleAddKeypair < Test::Unit::TestCase
  def setup
    @options_no_auto = {}
    @options_w_auto = {"auto" => "true"}
  end

  def test_not_having_ssh_copy_id_in_path
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:shell).with("which ssh-keygen").and_return("/usr/bin/ssh-keygen")
    commonfunctions.should_receive(:shell).with("which ssh-copy-id").and_return("")

    assert_raises(BadConfigurationException) {
      AppScaleTools.add_keypair(@options_no_auto)
    }
  end

  def test_not_having_expect_in_path
    commonfunctions = flexmock(CommonFunctions)
    commonfunctions.should_receive(:shell).with("which ssh-keygen").and_return("/usr/bin/ssh-keygen")
    commonfunctions.should_receive(:shell).with("which ssh-copy-id").and_return("/usr/bin/ssh-copy-id")
    commonfunctions.should_receive(:shell).with("which expect").and_return("")

    assert_raises(BadConfigurationException) {
      AppScaleTools.add_keypair(@options_w_auto)
    }

    # TODO(cgb) - add a test where auto isn't used - it shouldn't throw an error
  end

  def test_usage_is_up_to_date
    AppScaleTools::ADD_KEYPAIR_FLAGS.each { |flag|
      assert_equal(true, AppScaleTools::ADD_KEYPAIR_USAGE.include?("-#{flag}"),
        "No usage text for #{flag}.")
    } 
  end
end
