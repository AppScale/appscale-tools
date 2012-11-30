$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'vm_tools'


require 'flexmock/test_unit'


class TestVMTools < Test::Unit::TestCase


  def setup
    # mock out any writing to standard out
    flexmock(Kernel).should_receive(:puts).and_return()

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

  
  def test_run_instances_when_no_network_tags_are_free

    # mock out calls to the underlying infrastructure - have everything
    # return standard values except for run-instances, which will return
    # the 'no network tags' message
    flexmock(CommonFunctions).should_receive(:shell).
      with(/\Aeuca-describe-groups boogroup.*\Z/).
      and_return("")  # the group doesn't exist
    flexmock(CommonFunctions).should_receive(:shell).
      with(/\Aeuca-add-group boogroup.*\Z/).
      and_return("BOO")
    flexmock(CommonFunctions).should_receive(:shell).
      with(/\Aeuca-authorize.*\Z/).and_return("BOO")
    flexmock(CommonFunctions).should_receive(:shell).
      with(/\Aeuca-describe-instances.*\Z/).and_return("BOO")

    # ok, now inject the 'no network tags' message
    run_instances_result = "RunInstancesType: Failed to allocate network tag for network: arn:aws:euca:eucalyptus:759276108939:security-group/boogroup/: no network tags are free"
    flexmock(CommonFunctions).should_receive(:shell).
      with(/\Aeuca-run-instances.*\Z/).and_return(run_instances_result)

    assert_raises(InfrastructureException) {
      VMTools.spawn_vms(num_of_vms_to_spawn = 1,
        job = "boojob",
        image_id = "booimage",
        instance_type = "booinstance",
        keyname = "bookey",
        infrastructure = "euca",
        group = "boogroup",
        verbose = true
      )
    }
  end


end
