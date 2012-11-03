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
    flexmock(File).should_receive(:exists?).with(appscale_locations_file).and_return(false)

    assert_raises(AppScaleException) {
      AppScaleTools.gather_logs(options)
    }
  end
end
