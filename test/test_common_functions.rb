#!/usr/bin/ruby -w
# Programmer: Chris Bunch
# Test code for lib/common_functions.rb
# Still need to test the following functions:
# - is_port_open?
# - get_email
# - get_password
# - write_node_file
# Decided not to test the following functions:
# - shell: Only does the backticks, so nothing to test.
# - run_remote_command / scp_file: We currently don't check the return value on the ssh command, so we don't know if the remote command succeeds or not.
# - encrypt_password: Params are always validated to be non-nil, so result is always a string and thus always encrypts fine.
# - get_appname_via_xml: The only file it opens is already checked for existence, so nothing to test.

require 'rubygems'
require 'flexmock/test_unit'
require 'redgreen'
require 'shoulda'

$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'common_functions'
require 'fileutils'

class CommonFunctionsTest < Test::Unit::TestCase
  context "test wait until redirect" do
    should "return nothing when url is redirecting correctly" do
      output = flexmock(Net::HTTP)
      response = { 'location' => "http://192.168.0.1:8080"}
      
      output.should_receive(:get_response).and_return(response)

      uri = flexmock(URI)
      uri.should_receive(:parse).and_return("")
      
      assert_equal CommonFunctions.wait_until_redirect("", ""), nil
    end

    should "throw an exception when connection is refused" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")

      output = flexmock(Net::HTTP)
      output.should_receive(:get_response).and_raise(Errno::ECONNREFUSED)
      
      assert_raise(SystemExit) { CommonFunctions.wait_until_redirect("", "") }
    end
  end
  
  context "test user has command" do
    should "return true when the user has the command" do
      lib = flexmock(CommonFunctions)
      lib.should_receive(:shell).and_return("non-empty means they have it")
      
      assert_equal true, CommonFunctions.user_has_cmd?("baz")
    end

    should "return false when the user doesn't have the command" do
      lib = flexmock(CommonFunctions)
      lib.should_receive(:shell).and_return("")
      
      assert_equal false, CommonFunctions.user_has_cmd?("baz")
    end
  end

  context "test find real ssh key" do
    should "return a string with the key when a key works" do
      file = flexmock(File)
      file.should_receive(:expand_path).and_return("baz")
    
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("0\n")
      
      assert_equal "baz", CommonFunctions.find_real_ssh_key(["baz"], "host")
    end  

    should "return nil when all keys fail to work" do
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("255\n")
      
      assert_nil CommonFunctions.find_real_ssh_key(["baz"], "host")
    end
  end

  context "test out yaml related functions" do
    should "throw an exception when the yaml file doesn't exist" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")

      file = flexmock(File)
      file.should_receive(:exists?).and_return(false)
      
      assert_raise(SystemExit) { CommonFunctions.get_load_balancer_ip("") }    
      assert_raise(SystemExit) { CommonFunctions.get_load_balancer_id("") }
    end

    should "throw an exception when the yaml file is malformed" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")

      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)

      yaml = flexmock(YAML)
      yaml.should_receive(:load_file).and_raise(ArgumentError)
      
      assert_raise(SystemExit) { CommonFunctions.get_load_balancer_ip("") }    
      assert_raise(SystemExit) { CommonFunctions.get_load_balancer_id("") }    
    end

    should "throw an exception when the yaml file doesn't have the right tag" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")

      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)

      yaml = flexmock(YAML)
      yaml.should_receive(:load_file).and_return({})

      assert_raise(SystemExit) { CommonFunctions.get_load_balancer_ip("") }    
      assert_raise(SystemExit) { CommonFunctions.get_load_balancer_id("") }    
    end

    should "return the right value for the right tags when all is good" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)

      yaml = flexmock(YAML)
      yaml.should_receive(:load_file).and_return({ :load_balancer => "foo", :instance_id => "bar"})

      assert_equal "foo", CommonFunctions.get_load_balancer_ip("foo")
      assert_equal "bar", CommonFunctions.get_load_balancer_id("bar")
    end
  end
  
  context "test get appname from tar" do
    should "return appname, python when the app is a python app" do
      common = flexmock(CommonFunctions)
      common.should_receive(:get_app_info).and_return(["baz", "", "python"])
      
      assert_equal ["baz", "", "python"], CommonFunctions.get_appname_from_tar("")
    end

    should "return appname, java when the app is a java app" do
      common = flexmock(CommonFunctions)

      common.should_receive(:get_app_info).times(2).and_return([nil, nil, nil], ["baz", "", "java"])      
      assert_equal ["baz", "", "java"], CommonFunctions.get_appname_from_tar("")

      common.should_receive(:get_app_info).times(2).and_return(["", "", nil], ["baz", "", "java"])      
      assert_equal ["baz", "", "java"], CommonFunctions.get_appname_from_tar("")

      common.should_receive(:get_app_info).times(2).and_return([nil, "", ""], ["baz", "", "java"])      
      assert_equal ["baz", "", "java"], CommonFunctions.get_appname_from_tar("")
    end

    should "return throw an exception when the app's language is unknown" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")

      common = flexmock(CommonFunctions)
      
      common.should_receive(:get_app_info).and_return([nil, nil, nil])
      assert_raise(SystemExit) { CommonFunctions.get_appname_from_tar("") }
      
      common.should_receive(:get_app_info).and_return(["", "", nil])
      assert_raise(SystemExit) { CommonFunctions.get_appname_from_tar("") }      

      common.should_receive(:get_app_info).and_return([nil, "", ""])
      assert_raise(SystemExit) { CommonFunctions.get_appname_from_tar("") }
    end
  end
  
  context "test get appname from yaml" do
    should "throw an exception on malformed yaml" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")

      yaml = flexmock(YAML)
      yaml.should_receive(:load_file).and_raise(ArgumentError)
      
      assert_raise(SystemExit) { CommonFunctions.get_appname_via_yaml("", "") }    
    end
    
    should "return the app's name on good yaml" do
      yaml = flexmock(YAML)
      yaml.should_receive(:load_file).and_return({ "application" => "baz" })

      assert_equal "baz", CommonFunctions.get_appname_via_yaml("", "")
    end
  end
  
  context "test is port open / closed" do
    should "return immediately when the port is already open" do
      common = flexmock(CommonFunctions)
      common.should_receive(:is_port_open?).and_return(true)
      
      assert_nil CommonFunctions.sleep_until_port_is_open("", "")
    end

    should "return immediately when the port is already closed" do
      common = flexmock(CommonFunctions)
      common.should_receive(:is_port_open?).and_return(false)
      
      assert_nil CommonFunctions.sleep_until_port_is_closed("", "")
    end

    should "return when the port is eventually open" do
      common = flexmock(CommonFunctions)
      common.should_receive(:is_port_open?).times(3).and_return(false, false, true)
      
      kernel = flexmock(Kernel)
      kernel.should_receive(:sleep).and_return(1)
      
      assert_nil CommonFunctions.sleep_until_port_is_open("", "")
    end

    should "return when the port is eventually closed" do
      common = flexmock(CommonFunctions)
      common.should_receive(:is_port_open?).times(3).and_return(true, true, false)

      kernel = flexmock(Kernel)
      kernel.should_receive(:sleep).and_return(1)
            
      assert_nil CommonFunctions.sleep_until_port_is_closed("", "")
    end
  end
  
  context "test convert FQDN -> IP" do
    should "throw an exception when the FQDN can't be resolved" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")

      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("")
      
      assert_raise(SystemExit) { CommonFunctions.convert_fqdn_to_ip("") }
    end

    should "return an IP when the FQDN can be resolved" do
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("baz\nAddress: 192.168.1.1")
      
      assert_equal "192.168.1.1", CommonFunctions.convert_fqdn_to_ip("baz")
    end
  end
  
  context "test get app info" do
    setup do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")    
      
      PYTHON_CONFIG = "app.yaml"
      JAVA_CONFIG = "war/WEB-INF/appengine-web.xml"
    end
    
    should "throw an exception if the tar file doesn't exist" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(false)
      
      assert_raise(SystemExit) { CommonFunctions.get_app_info("", "") }
    end

    should "throw an exception if the tar file can't be copied to /tmp" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)
      
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("1\n")

      fileutils = flexmock(FileUtils)
      fileutils.should_receive(:cp).and_raise(Errno::EACCES)
      fileutils.should_receive(:mkdir_p).and_return("")
      fileutils.should_receive(:rm_rf).and_return("")
      
      assert_raise(SystemExit) { CommonFunctions.get_app_info("", "") }
    end

    should "throw an exception if the tar file can't be untar'ed to /tmp" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)
      
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).once.and_return("1\n")

      fileutils = flexmock(FileUtils)
      fileutils.should_receive(:cp).and_return("")
      fileutils.should_receive(:mkdir_p).and_return("")
      fileutils.should_receive(:rm_rf).and_return("")
      
      assert_raise(SystemExit) { CommonFunctions.get_app_info("", "") }
    end

    should "return nil, nil if no app.yaml / web.xml files are found" do
      [JAVA_CONFIG,PYTHON_CONFIG].each do |config|
        file = flexmock(File)
        file.should_receive(:exists?).once.with("").and_return(true)

        common = flexmock(CommonFunctions)
        common.should_receive(:shell).and_return("0\n")

        fileutils = flexmock(FileUtils)
        fileutils.should_receive(:cp).and_return("")
        fileutils.should_receive(:mkdir_p).and_return("")
        fileutils.should_receive(:rm_rf).and_return("")

        temp_directory = "TEMP_DIR"
        flexmock(CommonFunctions).should_receive(:get_random_alphanumeric).once.and_return(temp_directory)

        file.should_receive(:exists?).once.with("/tmp/#{temp_directory}/#{config}").and_return(false)
        
        assert_equal [nil, nil, nil], CommonFunctions.get_app_info("", config)
      end
    end

    should "throw an exception if the app name is not recognized" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)
      
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("app.haml\n0\n")

      fileutils = flexmock(FileUtils)
      fileutils.should_receive(:cp).and_return("")
      fileutils.should_receive(:mkdir_p).and_return("")
      fileutils.should_receive(:rm_rf).and_return("")

      assert_raise(SystemExit) { CommonFunctions.get_app_info("", "app.haml") }
    end

    should "throw an exception if there is no app name in app.yaml" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)
      
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("#{PYTHON_CONFIG}\n0\n")
      common.should_receive(:get_appname_via_yaml).and_return(nil)

      fileutils = flexmock(FileUtils)
      fileutils.should_receive(:cp).and_return("")
      fileutils.should_receive(:mkdir_p).and_return("")
      fileutils.should_receive(:rm_rf).and_return("")

      assert_raise(SystemExit) { CommonFunctions.get_app_info("", PYTHON_CONFIG) }
    end

    should "throw an exception if there is no app name in appengine-web.yaml" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)
      
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("#{JAVA_CONFIG}\n0\n")
      common.should_receive(:get_appname_via_xml).and_return(nil)

      fileutils = flexmock(FileUtils)
      fileutils.should_receive(:cp).and_return("")
      fileutils.should_receive(:mkdir_p).and_return("")
      fileutils.should_receive(:rm_rf).and_return("")

      assert_raise(SystemExit) { CommonFunctions.get_app_info("", JAVA_CONFIG) }
    end

    should "return python and the app's name when a python app is used" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)
      file.should_receive(:size).and_return(1)
      
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("#{PYTHON_CONFIG}\n0\n")
      common.should_receive(:get_appname_via_yaml).and_return("baz")

      fileutils = flexmock(FileUtils)
      fileutils.should_receive(:cp).and_return("")
      fileutils.should_receive(:mkdir_p).and_return("")
      fileutils.should_receive(:rm_rf).and_return("")

      assert_equal ["baz", "", "python"], CommonFunctions.get_app_info("", PYTHON_CONFIG)
    end

    should "return java and the app's name when a java app is used" do
      file = flexmock(File)
      file.should_receive(:exists?).and_return(true)
      file.should_receive(:size).and_return(1)
      
      common = flexmock(CommonFunctions)
      common.should_receive(:shell).and_return("#{JAVA_CONFIG}\n0\n")
      common.should_receive(:get_appname_via_xml).and_return("baz")
      common.should_receive(:get_random_alphanumeric).and_return("rand")

      fileutils = flexmock(FileUtils)
      fileutils.should_receive(:cp).and_return("")
      fileutils.should_receive(:mkdir_p).and_return("")
      fileutils.should_receive(:rm_rf).and_return("")

      assert_equal ["baz", "/tmp/rand/baz.tar.gz", "java"], CommonFunctions.get_app_info("", JAVA_CONFIG)
    end
  end
  
  context "test out validate appname" do
    should "throw an exception if the app has a name that isn't allowed" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")
      
      assert_raise(SystemExit) { CommonFunctions.validate_appname("none") }
      assert_raise(SystemExit) { CommonFunctions.validate_appname("load_balancer") }
    end

    should "throw an exception if the app has characters that aren't allowed" do
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")
      
      assert_raise(SystemExit) { CommonFunctions.validate_appname("baz@$$!") }
      assert_raise(SystemExit) { CommonFunctions.validate_appname("1212):") }
      assert_raise(SystemExit) { CommonFunctions.validate_appname("53az ") }
    end

    should "return the app's name on success" do
      ["guestbook", "my-app", "app.me", "baz@goo"].each { |app|
        assert_equal app, CommonFunctions.validate_appname(app)
      }
    end
  end
end
