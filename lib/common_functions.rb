#!/usr/bin/ruby -w
# Programmer: Chris Bunch

require 'digest/sha1'
require 'net/http'
require 'openssl'
require 'open-uri'
require 'socket'
require 'timeout'
require 'yaml'

require 'app_controller_client'

MAX_FILE_SIZE = 1000000

EMAIL_REGEX = /\A[[:print:]]+@[[:print:]]+\.[[:print:]]+\Z/
PASSWORD_REGEX = /\A[[:print:]]{6,}\Z/
IP_REGEX = /\d+\.\d+\.\d+\.\d+/
FQDN_REGEX = /[\w\d\.\-]+/
IP_OR_FQDN = /#{IP_REGEX}|#{FQDN_REGEX}/

CLOUDY_CREDS = ["ec2_access_key", "ec2_secret_key", 
  "aws_access_key_id", "aws_secret_access_key", 
  "SIMPLEDB_ACCESS_KEY", "SIMPLEDB_SECRET_KEY"]

VER_NUM = "1.5"
AS_VERSION = "AppScale Tools, Version #{VER_NUM}, http://appscale.cs.ucsb.edu"

PYTHON_CONFIG = "app.yaml"
JAVA_CONFIG = "war/WEB-INF/appengine-web.xml"

VALID_TABLE_TYPES = ["hbase", "hypertable", "mysql", "cassandra", "voldemort"] +
  ["mongodb", "memcachedb", "scalaris", "simpledb"]
VALID_CLOUD_TYPES = ["ec2", "euca", "hybrid"]

module CommonFunctions
  # cgb: added in shell function for backticks so that we can unit test it
  # since flexmock doesn't like backticks since its name is non-alphanumeric
  # e.g., its name is Kernel, :`
  def self.shell(command)
    `#{command}`
  end

  def self.rsync_files(dest_ip, ssh_key)
    controller = "appscale/AppController"
    server = "appscale/AppServer"
    loadbalancer = "appscale/AppLoadBalancer"
    monitoring = "appscale/AppMonitoring"
    appdb = "appscale/AppDB"
    neptune = "appscale/Neptune"
    loki = "appscale/Loki"

    `rsync -e 'ssh -i #{ssh_key}' -arv ~/#{controller}/* root@#{dest_ip}:/root/#{controller}`
    `rsync -e 'ssh -i #{ssh_key}' -arv ~/#{server}/* root@#{dest_ip}:/root/#{server}`
    `rsync -e 'ssh -i #{ssh_key}' -arv ~/#{loadbalancer}/* root@#{dest_ip}:/root/#{loadbalancer}`
    `rsync -e 'ssh -i #{ssh_key}' -arv ~/#{monitoring}/* root@#{dest_ip}:/root/#{monitoring}`
    `rsync -e 'ssh -i #{ssh_key}' -arv --exclude="logs/*" --exclude="hadoop-*" --exclude="hbase/hbase-*" --exclude="voldemort/voldemort/*" --exclude="cassandra/cassandra/*" ~/#{appdb}/* root@#{dest_ip}:/root/#{appdb}`
    `rsync -e 'ssh -i #{ssh_key}' -arv ~/#{neptune}/* root@#{dest_ip}:/root/#{neptune}`
    #`rsync -e 'ssh -i #{ssh_key}' -arv ~/#{loki}/* root@#{dest_ip}:/root/#{loki}`
  end

  def self.get_login_ip(head_node_ip, secret_key)
    acc = AppControllerClient.new(head_node_ip, secret_key)
    all_nodes = acc.get_all_public_ips()

    all_nodes.each { |node|
        acc_new = AppControllerClient.new(node, secret_key)
        roles = acc_new.status(print_output=false)
        return node if roles.match(/Is currently:(.*)login/)
    }

    abort("Unable to find login ip address!")
  end

  def self.clear_app(app_path, force=false)
    return if !File.exists?(app_path)
    return if app_path !~ /\A\/tmp/ and !force
    remove_me = app_path.scan(/(\A.*)\//).flatten.to_s
    FileUtils.rm_rf(remove_me, :secure => true)
  end

  def self.validate_appname(app_name)
    disallowed = ["none", "auth", "login", "new_user", "load_balancer"]
    disallowed.each { |not_allowed|
      abort("App can't be called '#{not_allowed}'") if app_name == not_allowed 
    }
    abort("App name can only contain alphanumerics and .-@") if app_name =~ /[^[:alnum:].@-]/
    return app_name
  end
  
  def self.get_ips_from_yaml(ips)
    return "using_tools" if ips.nil?

    ips_to_use = []
    if !ips[:servers].nil?
      ips[:servers].each { |ip|
        if ip =~ IP_REGEX
          ips_to_use << ip
        else
          ips_to_use << CommonFunctions.convert_fqdn_to_ip(ip)
        end
      }
      ips_to_use = ips_to_use.join(":")
    end
    
    return ips_to_use
  end
  
  def self.get_credentials(testing)
    if testing
      return "a@a.a", "aaaaaa"
    else
      return CommonFunctions.get_email, CommonFunctions.get_password
    end
  end

  def self.wait_until_redirect(host, url_suffix)
    uri = "http://#{host}#{url_suffix}"
    loop {
      response = ""
      begin
        response = Net::HTTP.get_response(URI.parse(uri))
      rescue Errno::ECONNREFUSED, EOFError
        sleep(1)
        next
      rescue Exception => e
        abort("[unexpected] We were unable to see if your app is running. We saw an exception of type #{e.class}")
      end
      
      return if response['location'] != "http://#{host}/status"
      sleep(1)
    }
  end

  def self.user_has_cmd?(command)
    output = CommonFunctions.shell("which #{command}")
    if output == ""
      return false
    else
      return true
    end
  end

  def self.convert_fqdn_to_ip(host)
    nslookup = CommonFunctions.shell("nslookup #{host}")
    ip = nslookup.scan(/#{host}\nAddress:\s+(#{IP_REGEX})/).flatten.to_s
    abort("Couldn't convert #{host} to an IP address. Result of nslookup was \n#{nslookup}") if ip.nil? or ip == ""
    return ip
  end

  def self.encrypt_password(user, pass)
    Digest::SHA1.hexdigest(user + pass)
  end

  def self.sleep_until_port_is_open(ip, port, use_ssl=false)
    loop {
      return if CommonFunctions.is_port_open?(ip, port, use_ssl)
      Kernel.sleep(1)
    }
  end

  def self.sleep_until_port_is_closed(ip, port, use_ssl=false)
    loop {
      return unless CommonFunctions.is_port_open?(ip, port, use_ssl)
      Kernel.sleep(1)
    }
  end

  def self.is_port_open?(ip, port, use_ssl=false)
    begin
      Timeout::timeout(1) do
        begin
          sock = TCPSocket.new(ip, port)
          if use_ssl
            ssl_context = OpenSSL::SSL::SSLContext.new() 
            unless ssl_context.verify_mode 
              ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE 
            end 
            sslsocket = OpenSSL::SSL::SSLSocket.new(sock, ssl_context) 
            sslsocket.sync_close = true 
            sslsocket.connect          
          end
          sock.close
          return true
        rescue Exception
          return false
        end
      end
    rescue Timeout::Error
    end
  
    return false
  end

  def self.run_remote_command(ip, command, public_key_loc, want_output)
    if public_key_loc.class == Array
      public_key_loc.each { |key|
        key = File.expand_path(key)
      }

      remote_cmd = "ssh -i #{public_key_loc.join(' -i ')} -o StrictHostkeyChecking=no 2>&1 root@#{ip} '#{command}"
    else
      public_key_loc = File.expand_path(public_key_loc)
      remote_cmd = "ssh -i #{public_key_loc} -o StrictHostkeyChecking=no root@#{ip} '#{command} "
    end
    
    if want_output
      remote_cmd << "> /tmp/#{ip}.log 2>&1 &' &"
    else
      remote_cmd << "> /dev/null 2>&1 &' &"
    end

    Kernel.system remote_cmd
    return remote_cmd
  end
  
  def self.find_real_ssh_key(ssh_keys, host)
    ssh_keys.each { |key|
      key = File.expand_path(key)
      return_value = CommonFunctions.shell("ssh -i #{key} -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no 2>&1 root@#{host} 'touch /tmp/foo'; echo $? ").chomp
      return key if return_value == "0"
    }
    
    return nil
  end

  def self.scp_file(local_file_loc, remote_file_loc, target_ip, public_key_loc)
    cmd = ""
    local_file_loc = File.expand_path(local_file_loc)
    retval_file = File.expand_path("~/.appscale/retval-#{rand()}")
 
    if public_key_loc.class == Array
      public_key_loc.each { |key|
        key = File.expand_path(key)
      }
      
      cmd = "scp -i #{public_key_loc.join(' -i ')} -o StrictHostkeyChecking=no 2>&1 #{local_file_loc} root@#{target_ip}:#{remote_file_loc}"
    else
      public_key_loc = File.expand_path(public_key_loc)
      cmd = "scp -i #{public_key_loc} -o StrictHostkeyChecking=no 2>&1 #{local_file_loc} root@#{target_ip}:#{remote_file_loc}"
    end

    cmd << "; echo $? > #{retval_file}"

    FileUtils.rm_f(retval_file)

    begin
      Timeout::timeout(-1) { CommonFunctions.shell("#{cmd}") }
    rescue Timeout::Error
      abort("Remotely copying over files failed. Is the destination machine on and reachable from this computer? We tried the following command:\n\n#{cmd}")
    end

    loop {
      break if File.exists?(retval_file)
      sleep(5)
    }

    retval = (File.open(retval_file) { |f| f.read }).chomp

    fails = 0
    loop {
      break if retval == "0"
      puts "\n\n[#{cmd}] returned #{retval} instead of 0 as expected. Will try to copy again momentarily..."
      fails += 1
      abort("SCP failed") if fails >= 5
      sleep(1)
      CommonFunctions.shell("#{cmd}")
      retval = (File.open(retval_file) { |f| f.read }).chomp
    }

    return cmd
  end

  def self.get_email
    email = nil
    puts "\nThis AppScale instance is linked to an e-mail address giving it administrator privileges."
    
    loop {
      print "Enter your desired administrator e-mail address: "
      STDOUT.flush
      email = STDIN.gets.chomp
      
      if email =~ EMAIL_REGEX
        break
      else
        puts "The response you typed in was not an e-mail address. Please try again.\n\n"
      end
    }
    
    return email
  end

  def self.get_password
    pass = nil
    puts "\nThe new administrator password must be at least six characters long and can include non-alphanumeric characters."
    
    loop {
      system "stty -echo" # Turn off character echoing
      print "Enter your new password: "
      STDOUT.flush
      new_pass = STDIN.gets.chomp
      print "\nEnter again to verify: "
      STDOUT.flush
      verify_pass = STDIN.gets.chomp
      system "stty echo" # Next release: find a platform independent solution
      
      if new_pass == verify_pass
        pass = new_pass
        
        if pass =~ PASSWORD_REGEX
          break
        else
          puts "\n\nThe password you typed in was not at least six characters long. Please try again.\n\n"
        end
      else
        puts "\n\nPasswords entered do not match. Please try again.\n\n"
      end
    }
    
    return pass
  end
  
  def self.get_from_yaml(keyname, tag, required=true)
    location_file = File.expand_path("~/.appscale/locations-#{keyname}.yaml")

    abort("An AppScale instance is not currently running with the provided keyname, \"#{keyname}\".") unless File.exists?(location_file)  
    
    begin
      tree = YAML.load_file(location_file)
    rescue ArgumentError
      if required
        abort("The yaml file you provided was malformed. Please correct any errors in it and try again.")
      else
        return nil
      end
    end
    
    value = tree[tag]
    
    bad_yaml_format_msg = "The file #{location_file} is in the wrong format and doesn't contain a #{tag} tag. Please make sure the file is in the correct format and try again"
    abort(bad_yaml_format_msg) if value.nil? and required
    return value
  end

  def self.get_load_balancer_ip(keyname, required=true)
    return CommonFunctions.get_from_yaml(keyname, :load_balancer)
  end

  def self.get_load_balancer_id(keyname, required=true)
    return CommonFunctions.get_from_yaml(keyname, :instance_id)  
  end

  def self.get_table(keyname, required=true)
    return CommonFunctions.get_from_yaml(keyname, :table, required)
  end

  def self.get_db_master_ip(keyname, required=true)
    return CommonFunctions.get_from_yaml(keyname, :db_master, required)
  end

  def self.get_head_node_ip(keyname, required=true)
    CommonFunctions.get_from_yaml(keyname, :shadow)
  end

  def self.get_secret_key(keyname, required=true)
    CommonFunctions.get_from_yaml(keyname, :secret)
  end

  def self.write_node_file(head_node_ip, instance_id, table, secret, db_master_ip)
    tree = { :load_balancer => head_node_ip, :instance_id => instance_id , 
             :table => table, :shadow => head_node_ip, 
             :secret => secret , :db_master => db_master_ip }
    loc_path = File.expand_path(LOCATIONS_YAML)
    File.open(loc_path, "w") {|file| YAML.dump(tree, file)}
  end

  def self.get_random_alphanumeric(length=10)
    random = ""
    possible = "0123456789abcdefghijklmnopqrstuvxwyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    possibleLength = possible.length

    length.times { |index|
      random << possible[rand(possibleLength)]
    }

    return random
  end

  def self.get_appname_from_tar(fullpath)
    appname, file, language = CommonFunctions.get_app_info(fullpath, PYTHON_CONFIG)

    if appname.nil? or file.nil? or language.nil?
      appname, file, language = CommonFunctions.get_app_info(fullpath, JAVA_CONFIG)
    end

    if appname.nil? or file.nil? or language.nil?
      abort("We could not find a valid app.yaml or web.xml file in your application.")
    end

    return appname, file, language
  end
  
  def self.move_app(temp_dir, filename, app_file, fullpath)
    if File.directory?(fullpath)
      begin
        `cp -r #{fullpath}/* /tmp/#{temp_dir}/`
      rescue Errno::EACCES
        abort("Copying the file to /tmp failed")
      end
      return
    else
      begin
        FileUtils.cp(fullpath, "/tmp/#{temp_dir}/#{filename}")
      rescue Errno::EACCES
        abort("Copying the file to /tmp failed")
      end

      FileUtils.rm_f("/tmp/#{temp_dir}/#{app_file}")
      tar_file = CommonFunctions.shell("cd /tmp/#{temp_dir}; tar zxvfm #{filename} 2>&1; echo $?").chomp
      tar_ret_val = tar_file.scan(/\d+\Z/).to_s
      abort("Untar'ing the given tar file in /tmp failed") if tar_ret_val != "0"
    end
    return
  end

  def self.warn_on_large_app_size(fullpath)
    size = File.size(fullpath)
    if size > MAX_FILE_SIZE
      puts "Warning: Your application is large enough that it may take a while to upload."
    end
  end

  def self.get_app_info(fullpath, app_file)
    abort("AppEngine file not found") unless File.exists?(fullpath)
    filename = fullpath.scan(/\/?([\w\.]+\Z)/).flatten.to_s

    temp_dir = CommonFunctions.get_random_alphanumeric
    FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
    FileUtils.mkdir_p("/tmp/#{temp_dir}")

    CommonFunctions.move_app(temp_dir, filename, app_file, fullpath)
    app_yaml_loc = app_file
    if !File.exists?("/tmp/#{temp_dir}/#{app_file}")
      FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
      return nil, nil, nil
    end

    if app_file == PYTHON_CONFIG
      appname = CommonFunctions.get_appname_via_yaml(temp_dir, app_yaml_loc)
      language = "python"
      if File.directory?(fullpath)
        temp_dir2 = CommonFunctions.get_random_alphanumeric
        FileUtils.rm_rf("/tmp/#{temp_dir2}", :secure => true)
        FileUtils.mkdir_p("/tmp/#{temp_dir2}")
        CommonFunctions.shell("cd /tmp/#{temp_dir}; tar -czf ../#{temp_dir2}/#{appname}.tar.gz .")
        file = "/tmp/#{temp_dir2}/#{appname}.tar.gz"
      else
        file = fullpath
      end
    elsif app_file == JAVA_CONFIG
      appname = CommonFunctions.get_appname_via_xml(temp_dir, app_yaml_loc)
      language = "java"
      # don't remove user's jar files, they may have their own jars in it
      #FileUtils.rm_rf("/tmp/#{temp_dir}/war/WEB-INF/lib/", :secure => true)
      FileUtils.mkdir_p("/tmp/#{temp_dir}/war/WEB-INF/lib")
      temp_dir2 = CommonFunctions.get_random_alphanumeric
      FileUtils.rm_rf("/tmp/#{temp_dir2}", :secure => true)
      FileUtils.mkdir_p("/tmp/#{temp_dir2}")
      FileUtils.rm_f("/tmp/#{temp_dir}/#{filename}")
      CommonFunctions.shell("cd /tmp/#{temp_dir}; tar -czf ../#{temp_dir2}/#{appname}.tar.gz .")
      file = "/tmp/#{temp_dir2}/#{appname}.tar.gz"
    else
      FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
      abort("appname was #{app_file}, which was not a recognized value.")
    end

    if appname.nil?
      FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
      abort("AppEngine tar file is invalid - Doesn't have an app name in #{app_file}")
    end

    FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
    CommonFunctions.warn_on_large_app_size(file)
    return appname, file, language 
  end

  def self.get_appname_via_yaml(temp_dir, app_yaml_loc)
    app_yaml_loc = "/tmp/" + temp_dir + "/" + app_yaml_loc
    
    begin
      tree = YAML.load_file(app_yaml_loc.chomp)
    rescue ArgumentError
      abort("The yaml file you provided was malformed. Please correct any errors in it and try again.")
    end
    
    appname = tree["application"]
    return appname
  end

  def self.get_appname_via_xml(temp_dir, xml_loc)
    xml_loc = "/tmp/" + temp_dir + "/" + xml_loc
    web_xml_contents = (File.open(xml_loc) { |f| f.read }).chomp
    appname = web_xml_contents.scan(/<application>([\w\d-]+)<\/application>/).flatten.to_s
    appname = nil if appname == ""
    return appname
  end

  private

  def self.grab_file filename
    filename = File.expand_path(filename)
    content = nil
    begin
      content = File.open(filename) { |f| f.read.chomp! }
    rescue Errno::ENOENT
    end
    content
  end

  def self.obscure_string(string)
    return string if string.length < 4
    last_four = string[string.length-4, string.length]
    obscured = "*" * (string.length-4)
    return obscured + last_four
  end

  def self.obscure_array(array)
    return array.map {|string| obscure_string(string)}
  end

  def self.obscure_creds(creds)
    obscured = {}
    creds.each { |k, v|
      if CLOUDY_CREDS.include?(k)
        obscured[k] = self.obscure_string(v)
      else
        obscured[k] = v
      end
    }

    return obscured
  end

  def self.does_image_have_location?(ip, location, key)
    ret_val = CommonFunctions.shell("ssh -i #{key} -o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no 2>&1 root@#{ip} 'ls #{location}'; echo $?").chomp[-1]
    return ret_val.chr == "0"
  end

  def self.ensure_image_is_appscale(ip, key)
    return if self.does_image_have_location?(ip, "/etc/appscale", key)
    fail_msg = "The image at #{ip} is not an AppScale image." + 
      " Please install AppScale on it and try again."
    abort(fail_msg)
  end

  def self.ensure_db_is_supported(ip, db, key)
    return if self.does_image_have_location?(ip, "/etc/appscale/#{VER_NUM}/#{db}", key)
    fail_msg = "The image at #{ip} does not have support for #{db}." +
      " Please install support for this database and try again."
    abort(fail_msg)
  end
end
