$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale'


require 'rubygems'
require 'flexmock/test_unit'


class TestAppScaleConfig < Test::Unit::TestCase
  def setup

  end


  def test_get_directive
    # calling any non-acceptable directive should throw an exception
    self.assert_raises(AppScaleException) {
      AppScale.get_directive(["boo"])
    }
  end


  def test_appscale_init
    # calling 'appscale init' in a directory should write an
    # AppScaleFile in that directory with a template file in it
  end

  def test_appscale_up_with_no_appscale_file
    # calling 'appscale up' in a directory with no AppScaleFile
    # in it should throw up and die
  end

  def test_appscale_up_with_xen_appscale_file
    # calling 'appscale up' in a directory with an AppScaleFile
    # in it should call add_keypair, then run_instances
  end

  def test_appscale_up_with_cloud_appscale_file
    # calling 'appscale up' in a directory with an AppScaleFile
    # in it should call run_instances
  end

  def test_appscale_deploy_no_appscale_file
    # calling 'appscale deploy <app>' in a directory with no
    # AppScaleFile should throw up and die
  end

  def test_appscale_deploy_with_appscale_file
    # calling 'appscale deploy <app>' in a directory with an
    # AppScaleFile should call upload_app
  end

  def test_appscale_destroy_no_appscale_file
    # calling 'appscale destroy' in a directory with no AppScaleFile
    # should throw up and die
  end

  def test_appscale_destroy_with_appscale_file
    # calling 'appscale destroy' in a directory with an AppScaleFile
    # should call terminate_instances
  end
end
