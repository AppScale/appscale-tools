$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'vm_tools'


require 'flexmock/test_unit'


class TestVMTools < Test::Unit::TestCase


  def setup
    # mock out anything potentially harmful to our filesystem
    flexmock(CommonFunctions).should_receive(:shell).with("").
      and_return()
  end


  def test_ami_validation_when_in_bad_format
    # if the user wants to run appscale and gives us a machine
    # image that isn't either a euca or ec2 image, we should
    # throw an exception
    assert_raises(InfrastructureException) {
      VMTools.validate_machine_image("blarg", "boocloud")
    }
  end


  def test_ami_validation_when_ami_does_not_exist
    # if the user wants us to run appscale on an ami that doesn't
    # exist, we should throw an exception

    flexmock(CommonFunctions).should_receive(:shell).
      with("boocloud-describe-images ami-image 2>&1").and_return()

    assert_raises(InfrastructureException) {
      VMTools.validate_machine_image("ami-image", "boocloud")
    }
  end

  
  def test_ami_validation_when_emi_does_exist
    # if the user wants us to run appscale on an emi that does
    # exist, that should be fine

    info = "IMAGE\temi-image"
    flexmock(CommonFunctions).should_receive(:shell).
      with("boocloud-describe-images emi-image 2>&1").and_return(info)

    assert_nothing_raised(InfrastructureException) {
      VMTools.validate_machine_image("emi-image", "boocloud")
    }
  end


end
