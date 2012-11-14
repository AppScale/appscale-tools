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
require 'custom_exceptions'
require 'user_app_client'


require 'rubygems'
require 'json'


NO_SSH_KEY_FOUND = "No SSH key was found that could be used to log in to " +
  "your machine."
MALFORMED_YAML = "The yaml file you provided was malformed. Please correct " +
  "any errors in it and try again."
NO_CONFIG_FILE = "We could not find a valid app.yaml or web.xml file in " +
  "your application."


# The username and password that will be used as the cloud administrator's
# credentials if the --test flag are used, which should only be used when
# developing AppScale (and not in production environments).
DEFAULT_USERNAME = "a@a.a"
DEFAULT_PASSWORD = "aaaaaa"


MAX_FILE_SIZE = 1000000


EMAIL_REGEX = /\A[[:print:]]+@[[:print:]]+\.[[:print:]]+\Z/
PASSWORD_REGEX = /\A[[:print:]]{6,}\Z/
IP_REGEX = /\d+\.\d+\.\d+\.\d+/
FQDN_REGEX = /[\w\d\.\-]+/
IP_OR_FQDN = /#{IP_REGEX}|#{FQDN_REGEX}/


CLOUDY_CREDS = ["ec2_access_key", "ec2_secret_key", 
  "aws_access_key_id", "aws_secret_access_key", 
  "SIMPLEDB_ACCESS_KEY", "SIMPLEDB_SECRET_KEY"]


VER_NUM = "1.6.3"
AS_VERSION = "AppScale Tools, Version #{VER_NUM}, http://appscale.cs.ucsb.edu"


PYTHON_CONFIG = "app.yaml"
JAVA_CONFIG = "war/WEB-INF/appengine-web.xml"


# When we try to ssh to other machines, we don't want to be asked for a password
# (since we always should have the right SSH key present), and we don't want to
# be asked to confirm the host's fingerprint, so set the options for that here.
SSH_OPTIONS = "-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no"


# A list of the databases that AppScale nodes can run, and a list of the cloud
# infrastructures that we can run over.
VALID_TABLE_TYPES = ["hbase", "hypertable", "mysql", "cassandra", "voldemort"] +
  ["mongodb", "memcachedb", "scalaris", "simpledb", "redisdb"]
VALID_CLOUD_TYPES = ["ec2", "euca", "hybrid"]


# Some operations use an infinite timeout, and while -1 or 1.0/0 work in older
# versions of Ruby 1.8.7 (default on Ubuntu Lucid and before), they don't work
# in newer versions of Ruby 1.8.7 and Ruby 1.9. Instead, just use a large 
# number, which will work on both.
INFINITY = 1000000


module CommonFunctions


  # A convenience function that can be used to write a string to a file.
  def self.write_file(location, contents)
    File.open(location, "w+") { |file| file.write(contents) }
  end


  # A convenience function that returns a file's contents as a string.
  def self.read_file(location, chomp=true)
    file = File.open(location) { |f| f.read }
    if chomp
      return file.chomp
    else
      return file
    end
  end


  # cgb: added in shell function for backticks so that we can unit test it
  # Flexmock doesn't like backticks since its name is non-alphanumeric
  # e.g., its name is Kernel:`
  def self.shell(command)
    `#{command}`
  end


  # Uses rsync to copy over a copy of the AppScale main codebase (e.g., not the
  # AppScale Tools) from this machine to a remote machine.
  # TODO(cgb): This function doesn't copy files in the main directory, like the
  # firewall rules. It should be changed accordingly.
  def self.rsync_files(dest_ip, ssh_key, local)
    local = File.expand_path(local)
    lib = "#{local}/lib"
    controller = "#{local}/AppController"
    appmanager = "#{local}/AppManager"
    server = "#{local}/AppServer"
    loadbalancer = "#{local}/AppLoadBalancer"
    monitoring = "#{local}/AppMonitoring"
    appdb = "#{local}/AppDB"
    neptune = "#{local}/Neptune"
    loki = "#{local}/Loki"
    iaas_manager = "#{local}/InfrastructureManager"

    if !File.exists?(controller)
      raise BadConfigurationException.new("The location you " +
        "specified to rsync from, #{local}, doesn't exist or contain " +
        "AppScale data.")
    end

    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{controller}/* root@#{dest_ip}:/root/appscale/AppController")
    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{lib}/* root@#{dest_ip}:/root/appscale/lib")
    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{appmanager}/* root@#{dest_ip}:/root/appscale/AppManager")
    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{server}/* root@#{dest_ip}:/root/appscale/AppServer")
    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{loadbalancer}/* root@#{dest_ip}:/root/appscale/AppLoadBalancer")
    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{monitoring}/* root@#{dest_ip}:/root/appscale/AppMonitoring")
    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv --exclude='logs/*' --exclude='hadoop-*' --exclude='hbase/hbase-*' --exclude='voldemort/voldemort/*' --exclude='cassandra/cassandra/*' #{appdb}/* root@#{dest_ip}:/root/appscale/AppDB")
    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{neptune}/* root@#{dest_ip}:/root/appscale/Neptune")
    #self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{loki}/* root@#{dest_ip}:/root/appscale/Loki")
    self.shell("rsync -e 'ssh -i #{ssh_key}' -arv #{iaas_manager}/* root@#{dest_ip}:/root/appscale/InfrastructureManager")
  end


  # This function tries to contact a node in the AppScale deployment to
  # get the most up-to-date information on the current state of the
  # deployment (as the number of nodes could change, or the roles that
  # nodes have taken on).
  def self.update_locations_file(keyname, ips=nil)
    secret = self.get_secret_key(keyname)

    # Don't worry about prioritizing the Shadow over any other nodes,
    # as all nodes should be checking ZooKeeper and keeping themselves
    # up-to-date already.
    new_role_info = nil

    if ips
      all_ips = ips
    else
      all_ips = self.get_all_public_ips(keyname)
    end

    all_ips.each { |ip|
      begin
        acc = AppControllerClient.new(ip, secret)
        new_role_info = acc.get_role_info()
        break
      rescue Exception
        Kernel.puts("Couldn't contact AppController at #{ip}, skipping...")
      end
    }

    if new_role_info.nil?
      abort("Couldn't contact any AppControllers - is AppScale running?")
    end

    CommonFunctions.write_nodes_json(new_role_info, keyname)
  end


  def self.get_login_ip(head_node_ip, secret_key)
    acc = AppControllerClient.new(head_node_ip, secret_key)
    all_nodes = acc.get_all_public_ips()
    
    all_nodes.each { |node|
      acc_new = AppControllerClient.new(node, secret_key)
      roles = acc_new.status()
      return node if roles.match(/Is currently:(.*)login/)
    }

    raise AppScaleException.new("Unable to find login ip address!")
  end


  def self.clear_app(app_path, force=false)
    return if !File.exists?(app_path)
    return if app_path !~ /\A\/tmp/ and !force
    path_to_remove = File.dirname(app_path)
    FileUtils.rm_f(path_to_remove)
  end


  def self.validate_app_name(app_name, database)
    disallowed = ["none", "auth", "login", "new_user", "load_balancer"]
    if disallowed.include?(app_name)
      raise AppEngineConfigException.new("App cannot be called " +
        "'#{not_allowed}' - this is a reserved name.")
    end

    if app_name =~ /[^[a-z]-]/
      raise AppEngineConfigException.new("App name can only contain " +
        "numeric and lowercase alphabetical characters.")
    end

    if app_name.include?("-") and database == "hypertable"
      raise AppEngineConfigException.new("App name cannot contain " +
        "dashes when Hypertable is the underlying database.") 
    end

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
      return DEFAULT_USERNAME, DEFAULT_PASSWORD
    else
      return CommonFunctions.get_email, CommonFunctions.get_password
    end
  end


  def self.create_user(user, test, head_node_ip, secret_key, uac, pass=nil)
    if pass
      pass = pass # TODO - can we just remove this?
    elsif test
      pass = "aaaaaa"
    else
      pass = CommonFunctions.get_password
    end

    encrypted_pass = CommonFunctions.encrypt_password(user, pass)
    uac.commit_new_user(user, encrypted_pass)

    login_ip = CommonFunctions.get_login_ip(head_node_ip, secret_key)
 
    # create xmpp account
    # for user a@a.a, this translates to a@login_ip

    pre = user.scan(/\A(.*)@/).flatten.to_s
    xmpp_user = "#{pre}@#{login_ip}"
    xmpp_pass = CommonFunctions.encrypt_password(xmpp_user, pass)
    uac.commit_new_user(xmpp_user, xmpp_pass)
    Kernel.puts "Your XMPP username is #{xmpp_user}"
  end


  def self.scp_app_to_ip(app_name, user, language, keyname, head_node_ip,
    file_location, uac)

    Kernel.puts "Uploading #{app_name}..."
    uac.commit_new_app_name(user, app_name, language)

    local_file_path = File.expand_path(file_location)

    app_dir = "/var/apps/#{app_name}/app"
    remote_file_path = "#{app_dir}/#{app_name}.tar.gz"
    make_app_dir = "mkdir -p #{app_dir}"
    true_key = File.expand_path("~/.appscale/#{keyname}.key")
    
    Kernel.puts "Creating remote directory to copy app into"
    CommonFunctions.run_remote_command(head_node_ip,
      make_app_dir, true_key, false)
    Kernel.sleep(1)
    Kernel.puts "Copying over app"
    CommonFunctions.scp_file(local_file_path, remote_file_path,
      head_node_ip, true_key)

    return remote_file_path
  end


  def self.update_appcontroller(head_node_ip, secret, app_name,
    remote_file_path)
  
    acc = AppControllerClient.new(head_node_ip, secret)
    acc.done_uploading(app_name, remote_file_path)
    Kernel.puts "Updating AppController"
    acc.update([app_name])
  end

  def self.wait_for_nodes_to_load(head_node_ip, secret)
    head_acc = AppControllerClient.new(head_node_ip, secret)
    
    Kernel.puts "Please wait for AppScale to finish starting up."
    all_ips = head_acc.get_all_public_ips()
    loop {
      done_starting = true
      all_ips.each { |ip|
        acc = AppControllerClient.new(ip, secret)
        if !acc.is_done_initializing?
          done_starting = false
        end
      }
      break if done_starting
      Kernel.sleep(5)
    }
  end

  def self.wait_for_app_to_start(head_node_ip, secret, app_name)
    acc = AppControllerClient.new(head_node_ip, secret)

    Kernel.puts "Please wait for your app to start up."
    loop {
      break if acc.app_is_running?(app_name)
      Kernel.sleep(5)
    }

    url_suffix = "/apps/#{app_name}"
    url = "http://#{head_node_ip}#{url_suffix}"
    Kernel.puts "\nYour app can be reached at the following URL: #{url}"
  end


  def self.wait_until_redirect(host, url_suffix)
    uri = "http://#{host}#{url_suffix}"
    loop {
      response = ""
      begin
        response = Net::HTTP.get_response(URI.parse(uri))
      rescue Errno::ECONNREFUSED, EOFError
        Kernel.sleep(1)
        next
      rescue Exception => e
        raise e
      end
      
      return if response['location'] != "http://#{host}/status"
      Kernel.sleep(1)
    }
  end


  def self.user_has_cmd?(command)
    output = CommonFunctions.shell("which #{command}")
    if output.empty?
      return false
    else
      return true
    end
  end


  def self.require_commands(commands)
    commands.each { |cmd|
      if !CommonFunctions.user_has_cmd?(cmd)
        raise BadConfigurationException.new("You do not have the '#{cmd}' " +
          "command in your PATH. Please ensure that it is in your path and " +
          "try again.")
      end
    }
  end


  def self.convert_fqdn_to_ip(host)
    nslookup = CommonFunctions.shell("nslookup #{host}")
    ip = nslookup.scan(/#{host}\nAddress:\s+(#{IP_REGEX})/).flatten.to_s
    if ip.nil? or ip.empty?
      raise AppScaleException.new("Couldn't convert #{host} to an IP " +
        "address. Result of nslookup was \n#{nslookup}")
    end
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

      remote_cmd = "ssh -i #{public_key_loc.join(' -i ')} #{SSH_OPTIONS} 2>&1 root@#{ip} '#{command}"
    else
      public_key_loc = File.expand_path(public_key_loc)
      remote_cmd = "ssh -i #{public_key_loc} #{SSH_OPTIONS} root@#{ip} '#{command} "
    end
    
    if want_output
      remote_cmd << "> /tmp/#{ip}.log 2>&1 &' &"
    else
      remote_cmd << "> /dev/null 2>&1 &' &"
    end

    Kernel.system remote_cmd
    return remote_cmd
  end


  def self.get_remote_appscale_home(ip, key)
    cat = "cat /etc/appscale/home"
    remote_cmd = "ssh -i #{key} #{SSH_OPTIONS} 2>&1 root@#{ip} '#{cat}'"
    possible_home = CommonFunctions.shell("#{remote_cmd}").chomp
    if possible_home.nil? or possible_home.empty?
      return "/root/appscale/"
    else
      return possible_home
    end
  end 


  def self.start_head_node(options, node_layout, apps_to_start)
    # since we changed the key's name sometimes it works with storing the key
    # in ssh.key and sometimes it needs to be in keyname.key{.private}
    # always do both just in case

    # TODO: check here to make sure that if hybrid, the keyname is free
    # in all clouds specified

    keyname = options['keyname']
    named_key_loc = "~/.appscale/#{keyname}.key"
    named_backup_key_loc = "~/.appscale/#{keyname}.private"
    ssh_key_location = named_key_loc
    ssh_keys = [ssh_key_location, named_key_loc, named_backup_key_loc]
    secret_key, secret_key_location = EncryptionHelper.generate_secret_key(keyname)
    self.verbose("New secret key is #{CommonFunctions.obscure_string(secret_key)}", options['verbose'])

    # TODO: serialize via json instead of this hacky way
    ips_hash = node_layout.to_hash
    ips_to_use = ips_hash.map { |node,roles| "#{node}--#{roles}" }.join("..")
     
    head_node = node_layout.head_node
    infrastructure = options['infrastructure']
    if infrastructure == "hybrid"   
      head_node_infra = VMTools.lookup_cloud_env(head_node.cloud)
      VMTools.set_hybrid_creds(node_layout)
      machine = VMTools.get_hybrid_machine(head_node_infra, "1")
    else
      head_node_infra = infrastructure
      machine = options['machine']
    end
     
    locations = VMTools.spawn_head_node(head_node, head_node_infra, keyname,
      ssh_key_location, ssh_keys, options['force'], machine,
      options['instance_type'], options['group'], options['verbose'])
 
    head_node_ip = locations.split(":")[0]
    instance_id = locations.scan(/i-\w+/).flatten.to_s
    locations = [locations]
 
    true_key = CommonFunctions.find_real_ssh_key(ssh_keys, head_node_ip)
 
    self.verbose("Log in to your head node: ssh -i #{true_key} " +
      "root@#{head_node_ip}", options['verbose'])
 
    CommonFunctions.ensure_image_is_appscale(head_node_ip, true_key)
    CommonFunctions.ensure_db_is_supported(head_node_ip, options['table'],
      true_key)
 
    scp = options['scp']
    if scp
      Kernel.puts "Copying over local copy of AppScale from #{scp}"
      CommonFunctions.rsync_files(head_node_ip, true_key, scp)
    end
 
    keypath = true_key.scan(/([\d|\w|\.]+)\Z/).flatten.to_s
    remote_key_location = "/root/.appscale/#{keyname}.key"
    CommonFunctions.scp_file(true_key, remote_key_location, head_node_ip, true_key)
 
    creds = CommonFunctions.generate_appscale_credentials(options, node_layout,
      head_node_ip, ips_to_use, true_key)
    self.verbose(CommonFunctions.obscure_creds(creds).inspect, options['verbose'])
 
    Kernel.puts "Head node successfully created at #{head_node_ip}. It is now " +
      "starting up #{options['table']} via the command line arguments given."
 
    RemoteLogging.remote_post(options['max_images'], options['table'],
      infrastructure, "started headnode", "success")
 
    Kernel.sleep(10) # sometimes this helps out with ec2 / euca deployments
      # gives them an extra moment to come up and accept scp requests
 
    CommonFunctions.copy_keys(secret_key_location, head_node_ip, true_key,
      options)
 
    CommonFunctions.start_appcontroller(head_node_ip, true_key,
      options['verbose'])
 
    acc = AppControllerClient.new(head_node_ip, secret_key)
    creds = creds.to_a.flatten
    acc.set_parameters(locations, creds, apps_to_start)

    return {:acc => acc, :head_node_ip => head_node_ip,
      :instance_id => instance_id, :true_key => true_key,
      :secret_key => secret_key}
  end


  def self.find_real_ssh_key(ssh_keys, host)
    ssh_keys.each { |key|
      key = File.expand_path(key)
      return_value = CommonFunctions.shell("ssh -i #{key} #{SSH_OPTIONS} 2>&1 root@#{host} 'touch /tmp/foo'; echo $? ").chomp
      if return_value == "0"
        return key
      end
    }
    
    raise AppScaleException.new(NO_SSH_KEY_FOUND)
  end


  def self.scp_file(local_file_loc, remote_file_loc, target_ip, public_key_loc)
    cmd = ""
    local_file_loc = File.expand_path(local_file_loc)
    retval_file = File.expand_path("~/.appscale/retval-#{rand()}")
 
    if public_key_loc.class == Array
      public_key_loc.each { |key|
        key = File.expand_path(key)
      }
      
      cmd = "scp -i #{public_key_loc.join(' -i ')} #{SSH_OPTIONS} 2>&1 #{local_file_loc} root@#{target_ip}:#{remote_file_loc}"
    else
      public_key_loc = File.expand_path(public_key_loc)
      cmd = "scp -i #{public_key_loc} #{SSH_OPTIONS} 2>&1 #{local_file_loc} root@#{target_ip}:#{remote_file_loc}"
    end

    cmd << "; echo $? > #{retval_file}"

    FileUtils.rm_f(retval_file)

    begin
      Timeout::timeout(INFINITY) { CommonFunctions.shell("#{cmd}") }
    rescue Timeout::Error
      raise AppScaleException.new("Remotely copying over files failed. Is " +
        "the destination machine on and reachable from this computer? We " +
        "tried the following command:\n\n#{cmd}")
    end

    loop {
      break if File.exists?(retval_file)
      Kernel.sleep(5)
    }

    retval = (File.open(retval_file) { |f| f.read }).chomp

    fails = 0
    loop {
      break if retval == "0"
      Kernel.puts "\n\n[#{cmd}] returned #{retval} instead of 0 as expected. Will try to copy again momentarily..."
      fails += 1
      if fails >= 5
        raise AppScaleException.new("SCP failed")
      end
      Kernel.sleep(1)
      CommonFunctions.shell("#{cmd}")
      retval = (File.open(retval_file) { |f| f.read }).chomp
    }

    FileUtils.rm_f(retval_file)
    return cmd
  end


  def self.get_username_from_options(options)
    if options['test']
      return DEFAULT_USERNAME
    elsif options['email']
      return options['email']
    else
      return CommonFunctions.get_email
    end
  end


  def self.get_email
    email = nil
    Kernel.puts "\nThis AppScale instance is linked to an e-mail address giving it administrator privileges."
    
    loop {
      Kernel.print "Enter your desired administrator e-mail address: "
      STDOUT.flush
      email = STDIN.gets.chomp
      
      if email =~ EMAIL_REGEX
        break
      else
        Kernel.puts "The response you typed in was not an e-mail address. Please try again.\n\n"
      end
    }
    
    return email
  end


  def self.get_password()
    pass = nil
    Kernel.puts "\nThe new administrator password must be at least six characters long and can include non-alphanumeric characters."
    
    loop {
      Kernel.print "Enter your new password: "
      new_pass = self.get_line_from_stdin_no_echo()
      Kernel.print "\nEnter again to verify: "
      verify_pass = self.get_line_from_stdin_no_echo()
      Kernel.print "\n"
      
      if new_pass == verify_pass
        pass = new_pass
        
        if pass =~ PASSWORD_REGEX
          break
        else
          Kernel.puts "\n\nThe password you typed in was not at least six characters long. Please try again.\n\n"
        end
      else
        Kernel.puts "\n\nPasswords entered do not match. Please try again.\n\n"
      end
    }
    
    return pass
  end


  def self.get_line_from_stdin_no_echo
    state = CommonFunctions.shell("stty -g")
    system "stty -echo" # Turn off character echoing
    STDOUT.flush
    line = STDIN.gets.chomp
    system "stty #{state}"
    return line
  end


  def self.get_from_yaml(keyname, tag, required=true)
    location_file = File.expand_path("~/.appscale/locations-#{keyname}.yaml")

    if !File.exists?(location_file)
      raise AppScaleException.new("An AppScale instance is not currently " +
        "running with the provided keyname, \"#{keyname}\".")
    end
    
    begin
      tree = YAML.load_file(location_file)
    rescue ArgumentError
      if required
        raise AppScaleException.new(MALFORMED_YAML)
      else
        return nil
      end
    end
    
    if !tree
      raise AppScaleException.new("The location file is in the wrong format.")
    end

    value = tree[tag]

    if value.nil? and required
      raise AppScaleException.new("The location file did not contain a #{tag} tag.")
    end

    return value
  end


  def self.get_role_from_nodes(keyname, role)
    nodes = self.read_nodes_json(keyname)
    nodes.each { |node|
      if node['jobs'].include?(role)
        return node['public_ip']
      end
    }

    return ""
  end


  def self.get_load_balancer_ip(keyname, required=true)
    return self.get_role_from_nodes(keyname, 'load_balancer')
  end


  def self.get_load_balancer_id(keyname, required=true)
    return CommonFunctions.get_from_yaml(keyname, :instance_id)  
  end


  def self.get_table(keyname, required=true)
    return CommonFunctions.get_from_yaml(keyname, :table, required)
  end


  def self.get_all_public_ips(keyname, required=true)
    ips = []
    nodes = self.read_nodes_json(keyname)
    nodes.each { |node|
      ips << node['public_ip']
    }
    return ips
  end


  def self.get_db_master_ip(keyname, required=true)
    return self.get_role_from_nodes(keyname, 'db_master')
  end


  def self.get_head_node_ip(keyname, required=true)
    return self.get_role_from_nodes(keyname, 'shadow')
  end


  def self.get_secret_key(keyname, required=true)
    CommonFunctions.get_from_yaml(keyname, :secret)
  end


  def self.get_infrastructure(keyname, required=true)
    CommonFunctions.get_from_yaml(keyname, :infrastructure)
  end


  def self.make_appscale_directory()
    # AppScale generates private keys for each cloud that machines are 
    # running in. It stores this data (and a YAML file detailing IP address 
    # mappings) in ~/.appscale - create this location if it doesn't exist.
    appscale_path = File.expand_path("~/.appscale")
    if !File.exists?(appscale_path)
      FileUtils.mkdir(appscale_path)
    end
  end


  # Reads the JSON file that stores information about which roles run on
  # which nodes.
  def self.read_nodes_json(keyname)
    filename = File.expand_path("~/.appscale/locations-#{keyname}.json")
    return JSON.load(self.read_file(filename))
  end


  # Writes the given JSON to the ~/.appscale directory so that we can read
  # it later and determine what nodes run what services.
  def self.write_nodes_json(new_role_info, keyname)
    filename = File.expand_path("~/.appscale/locations-#{keyname}.json")
    self.write_file(filename, JSON.dump(new_role_info))
  end


  def self.write_and_copy_node_file(options, node_layout, head_node_result)
    keyname = options['keyname']
    head_node_ip = head_node_result[:head_node_ip]

    all_ips = head_node_result[:acc].get_all_public_ips()
    db_master_ip = node_layout.db_master.id

    locations_yaml = File.expand_path("~/.appscale/locations-#{keyname}.yaml")
    CommonFunctions.write_node_file(head_node_ip,
      head_node_result[:instance_id], options['table'],
      head_node_result[:secret_key], db_master_ip, all_ips,
      options['infrastructure'], locations_yaml)
    remote_locations_file = "/root/.appscale/locations-#{keyname}.yaml"
    CommonFunctions.scp_file(locations_yaml, remote_locations_file,
      head_node_ip, head_node_result[:true_key])
  end


  def self.write_node_file(head_node_ip, instance_id, table, secret, db_master,
    ips, infrastructure, locations_yaml)

    infrastructure ||= "xen"
    tree = { :load_balancer => head_node_ip, :instance_id => instance_id , 
             :table => table, :shadow => head_node_ip, 
             :secret => secret , :db_master => db_master,
             :ips => ips , :infrastructure => infrastructure }
    loc_path = File.expand_path(locations_yaml)
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


  def self.get_app_info_from_options(options)
    file_location = options['file_location']
    table = options['table']

    if file_location.nil?
      apps_to_start = ["none"]
      return apps_to_start, {}
    else
      app_info = CommonFunctions.get_app_name_from_tar(file_location)
      apps_to_start = [CommonFunctions.validate_app_name(app_info[:app_name], table)]
      return apps_to_start, app_info
    end
  end


  def self.get_app_name_from_tar(fullpath)
    app_name, file, language = CommonFunctions.get_app_info(fullpath, PYTHON_CONFIG)

    if app_name.nil? or file.nil? or language.nil?
      app_name, file, language = CommonFunctions.get_app_info(fullpath, JAVA_CONFIG)
    end

    if app_name.nil? or file.nil? or language.nil?
      raise AppScaleException.new(NO_CONFIG_FILE)
    end

    return {:app_name => app_name, :file => file, :language => language}
  end


  def self.move_app(temp_dir, filename, app_file, fullpath)
    if File.directory?(fullpath)
      CommonFunctions.shell("cp -r #{fullpath}/* /tmp/#{temp_dir}/")
      return
    else
      FileUtils.cp(fullpath, "/tmp/#{temp_dir}/#{filename}")
      FileUtils.rm_f("/tmp/#{temp_dir}/#{app_file}")
      tar_file = CommonFunctions.shell("cd /tmp/#{temp_dir}; tar zxvfm #{filename} 2>&1; echo $?").chomp
      tar_ret_val = tar_file.scan(/\d+\Z/).to_s
      if tar_ret_val != "0"
        raise AppScaleException.new("Untar'ing the given tar file in /tmp failed")
      end
    end
    return
  end


  def self.warn_on_large_app_size(fullpath)
    size = File.size(fullpath)
    if size > MAX_FILE_SIZE
      Kernel.puts "Warning: Your application is large enough that it may take a while to upload."
    end
  end


  def self.get_app_info(fullpath, app_file)
    if !File.exists?(fullpath)
      raise AppEngineConfigException.new("AppEngine file not found")
    end
    filename = fullpath.scan(/\/?([\w\.]+\Z)/).flatten.to_s

    temp_dir = CommonFunctions.get_random_alphanumeric
    FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
    FileUtils.mkdir_p("/tmp/#{temp_dir}")

    CommonFunctions.move_app(temp_dir, filename, app_file, fullpath)
    app_config_loc = app_file
    if !File.exists?("/tmp/#{temp_dir}/#{app_file}")
      FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
      return nil, nil, nil
    end

    if app_file == PYTHON_CONFIG
      app_name = CommonFunctions.get_app_name_via_yaml(temp_dir, app_config_loc)
      language = "python"
      if File.directory?(fullpath)
        temp_dir2 = CommonFunctions.get_random_alphanumeric
        FileUtils.rm_rf("/tmp/#{temp_dir2}", :secure => true)
        FileUtils.mkdir_p("/tmp/#{temp_dir2}")
        CommonFunctions.shell("cd /tmp/#{temp_dir}; tar -czf ../#{temp_dir2}/#{app_name}.tar.gz .")
        file = "/tmp/#{temp_dir2}/#{app_name}.tar.gz"
      else
        file = fullpath
      end
    elsif app_file == JAVA_CONFIG
      app_name = CommonFunctions.get_app_name_via_xml(temp_dir, app_config_loc)
      CommonFunctions.ensure_app_has_threadsafe(temp_dir, app_config_loc)
      language = "java"
      # don't remove user's jar files, they may have their own jars in it
      #FileUtils.rm_rf("/tmp/#{temp_dir}/war/WEB-INF/lib/", :secure => true)
      FileUtils.mkdir_p("/tmp/#{temp_dir}/war/WEB-INF/lib")
      temp_dir2 = CommonFunctions.get_random_alphanumeric
      FileUtils.rm_rf("/tmp/#{temp_dir2}", :secure => true)
      FileUtils.mkdir_p("/tmp/#{temp_dir2}")
      FileUtils.rm_f("/tmp/#{temp_dir}/#{filename}")
      CommonFunctions.shell("cd /tmp/#{temp_dir}; tar -czf ../#{temp_dir2}/#{app_name}.tar.gz .")
      file = "/tmp/#{temp_dir2}/#{app_name}.tar.gz"
    else
      FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
      raise AppEngineConfigException.new("app_name was #{app_file}, " +
        "which was not a recognized value.")
    end

    if app_name.nil?
      FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
      raise AppEngineConfigException.new("AppEngine tar file is invalid - " +
        "Doesn't have an app name in #{app_file}")
    end

    FileUtils.rm_rf("/tmp/#{temp_dir}", :secure => true)
    CommonFunctions.warn_on_large_app_size(file)
    return app_name, file, language 
  end


  def self.get_app_name_via_yaml(temp_dir, app_yaml_loc)
    app_yaml_loc = "/tmp/" + temp_dir + "/" + app_yaml_loc
    
    begin
      tree = YAML.load_file(app_yaml_loc.chomp)
    rescue ArgumentError
      raise AppScaleException.new(MALFORMED_YAML)
    end
    
    app_name = String(tree["application"])
    return app_name
  end


  def self.get_app_name_via_xml(temp_dir, xml_loc)
    xml_loc = "/tmp/" + temp_dir + "/" + xml_loc
    web_xml_contents = (File.open(xml_loc) { |f| f.read }).chomp
    app_name = web_xml_contents.scan(/<application>([\w\d-]+)<\/application>/).flatten.to_s
    app_name = nil if app_name == ""
    return app_name
  end


  # Checks the named file to validate its <threadsafe> parameter,
  # which should be set to either true or false.
  # Args:
  #   xml_loc: A String that points to the location on the local
  #     filesystem where the appengine-web.xml file for the user's
  #     Java Google App Engine app can be located.
  # Raises:
  #   AppEngineConfigException: If the given XML file did not
  #     have a <threadsafe> tag, or it was not a boolean value.
  # Returns:
  #   Nothing, if there was a <threadsafe> tag with a boolean value.
  def self.ensure_app_has_threadsafe(temp_dir, xml_loc)
    xml_loc = "/tmp/" + temp_dir + "/" + xml_loc
    web_xml_contents = self.read_file(xml_loc)
    threadsafe = web_xml_contents.scan(/<threadsafe>([\w]+)<\/threadsafe>/).flatten.to_s
    if threadsafe == "true" or threadsafe == "false"
      return
    else
      raise AppEngineConfigException.new("Your application did not " +
        "have a <threadsafe> tag, with a value of either true or false.")
    end
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
    ret_val = CommonFunctions.shell("ssh -i #{key} #{SSH_OPTIONS} 2>&1 root@#{ip} 'ls #{location}'; echo $?").chomp[-1]
    return ret_val.chr == "0"
  end


  def self.ensure_image_is_appscale(ip, key)
    return if self.does_image_have_location?(ip, "/etc/appscale", key)
    raise AppScaleException.new("The image at #{ip} is not an AppScale image." +
      " Please install AppScale on it and try again.")
  end


  def self.ensure_db_is_supported(ip, db, key)
    return if self.does_image_have_location?(ip, "/etc/appscale/#{VER_NUM}/#{db}", key)
    raise AppScaleException.new("The image at #{ip} does not have support for #{db}." +
      " Please install support for this database and try again.")
  end


  def self.confirm_app_removal(confirm, app_name)
    if confirm
      return "YES"
    end

    Kernel.print "We are about to attempt to remove your application, #{app_name}." +
      "\nAre you sure you want to remove this application (Y/N)? "
    STDOUT.flush
    
    loop {
      result = STDIN.gets.chomp.upcase
      if result == "Y" or result == "YES" 
        return "YES"
      end
      if result == "N" or result == "NO"
        return "NO"
      end
      Kernel.print "Please type in 'yes' or 'no'.\nAre you sure you want to remove this application (Y/N)? "
    }
  end


  def self.remove_app(app_name, keyname)
    secret_key = CommonFunctions.get_secret_key(keyname)
    head_node_ip = CommonFunctions.get_head_node_ip(keyname)
    acc = AppControllerClient.new(head_node_ip, secret_key)
    userappserver_ip = acc.get_userappserver_ip()

    uac = UserAppClient.new(userappserver_ip, secret_key)
    app_exists = uac.does_app_exist?(app_name, retry_on_except=true)

    if !app_exists
      raise AppEngineConfigException.new(AppScaleTools::APP_NOT_RUNNING)
    end

    load_balancer_ip = CommonFunctions.get_load_balancer_ip(keyname)
    acc.stop_app(app_name)

    Kernel.puts "Please wait for your app to shut down."
    loop {
      if !acc.app_is_running?(app_name)
        break
      end
      Kernel.sleep(5)
    }
  end


  def self.scp_ssh_key_to_ip(ip, ssh_key, pub_key)
    Kernel.puts CommonFunctions.shell("scp -i #{ssh_key} #{ssh_key} root@#{ip}:.ssh/id_rsa")
    # this is needed for EC2 integration.
    Kernel.puts CommonFunctions.shell("scp -i #{ssh_key} #{ssh_key} root@#{ip}:.ssh/id_dsa")
    Kernel.puts CommonFunctions.shell("scp -i #{ssh_key} #{pub_key} root@#{ip}:.ssh/id_rsa.pub")
  end


  def self.generate_rsa_key(keyname)
    path = File.expand_path("~/.appscale/#{keyname}")
    backup_key = File.expand_path("~/.appscale/#{keyname}.key")
    pub_key = File.expand_path("~/.appscale/#{keyname}.pub")

    #FileUtils.rm_f([path, backup_key, pub_key])
    unless File.exists?(path) and File.exists?(pub_key)
      FileUtils.rm_f([path, backup_key, pub_key])
      Kernel.puts CommonFunctions.shell("ssh-keygen -t rsa -N '' -f #{path}")
    end
    FileUtils.chmod(0600, [path, pub_key])
    return pub_key, backup_key
  end


  def self.ssh_copy_id(ip, path, auto, expect_script, password)
    Kernel.puts "\n\n"
    Kernel.puts "Executing ssh-copy-id for host : " + ip
    Kernel.puts "------------------------------"

    if auto
      Kernel.puts CommonFunctions.shell("#{expect_script} root@#{ip} #{path} #{password}")
    else
      Kernel.puts CommonFunctions.shell("ssh-copy-id -i #{path} root@#{ip}")
    end

    # Check the exit status of the above shell command
    if $?.to_i != 0
      raise AppScaleException.new("ERROR ! Unable to ssh-copy-id to host : #{ip}")
    end
  end


  def self.validate_run_instances_options(options)
    infrastructure = options['infrastructure']
    machine = options['machine']
    # In non-hybrid cloud deployments, the user must specify the machine image
    # (emi or ami) to use. Abort if they didn't.
    if infrastructure && infrastructure != "hybrid" && machine.nil?
      raise BadConfigurationException.new(AppScaleTools::NO_MACHINE_SET)
    end

    if infrastructure && infrastructure != "hybrid"
      VMTools.verify_credentials_are_set_correctly(infrastructure)
    end

    # If the user hasn't given us an ips.yaml file, then they're running in a cloud
    # deployment. They need to give us a machine image id to spawn up - if they
    # haven't, fail.
    if options['ips'].nil? and machine.nil?
      raise BadConfigurationException.new(EC2_USAGE_MSG)
    end

    keyname = options['keyname']
    locations_yaml = File.expand_path("~/.appscale/locations-#{keyname}.yaml")
    if File.exists?(locations_yaml) and !options['force']
      error_msg = "An AppScale instance is already running with the given" +
        " keyname, #{keyname}. Please terminate that instance first with the" +
        " following command:\n\nappscale-terminate-instances --keyname " +
        "#{keyname} <--ips path-to-ips.yaml if using non-cloud deployment>"
      raise BadConfigurationException.new(error_msg)
    end
  end


  def self.print_starting_message(infrastructure, instance_type)
    if infrastructure and infrastructure != "hybrid"
      deployment = "cloud environment with the #{infrastructure} tools" +
        " with instance type #{instance_type}" 
    elsif infrastructure and infrastructure == "hybrid"
      # TODO - say which environments 
      deployment = "hybrid environment"
    else
      deployment = "non-cloud environment"
    end

    Kernel.puts "About to start AppScale over a #{deployment}."
  end

  def self.generate_node_layout(options)
    remote_options = { 
      :infrastructure => options['infrastructure'],
      :database => options['table'],
      :min_images => options['min_images'],
      :max_images => options['max_images'],
      :replication => options['replication'],
      :read_factor => options['voldemort_r'],
      :write_factor => options['voldemort_w'],
    }

    node_layout = NodeLayout.new(options['ips'], remote_options)

    if !node_layout.valid?
      raise BadConfigurationException.new("There were errors with the yaml " +
        "file: \n#{node_layout.errors}")
    end

    return node_layout
  end


  def self.generate_appscale_credentials(options, node_layout, head_node_ip,
    ips_to_use, ssh_key)

    table = options['table']
    keypath = ssh_key.scan(/([\d|\w|\.]+)\Z/).flatten.to_s

    creds = {
      "table" => "#{table}",
      "hostname" => "#{head_node_ip}",
      "ips" => "#{ips_to_use}",
      "keyname" => "#{options['keyname']}",
      "keypath" => "#{keypath}",
      "replication" => "#{node_layout.replication_factor}",
      "appengine" => "#{options['appengine']}",
      "autoscale" => "#{options['autoscale']}",
      "group" => "#{options['group']}"
    }

    if table == "voldemort"
      voldemort_creds = {
        "voldemortr" => "#{node_layout.read_factor}",
        "voldemortw" => "#{node_layout.write_factor}"
      }
      creds.merge!(voldemort_creds)
    end

    if table == "simpledb"
      simpledb_creds = {
        "SIMPLEDB_ACCESS_KEY" => ENV['SIMPLEDB_ACCESS_KEY'],
        "SIMPLEDB_SECRET_KEY" => ENV['SIMPLEDB_SECRET_KEY']
      }
      creds.merge!(simpledb_creds)
    end

    infrastructure = options['infrastructure']
    if VALID_CLOUD_TYPES.include?(infrastructure)
      if infrastructure == "hybrid"
        creds.merge!(VMTools.get_hybrid_creds(node_layout))
      else
        creds.merge!(VMTools.get_cloud_creds(node_layout, options))
      end
    end

    if options['restore_from_tar']
      db_backup_location = "/root/db-backup.tar.gz"
      tar_creds = {"restore_from_tar" => db_backup_location}
      creds.merge!(tar_creds)

      CommonFunctions.scp_file(options['restore_from_tar'], db_backup_location, head_node_ip, true_key)
    end

    if options['restore_from_ebs']
      ebs_creds = {"restore_from_tar" => options['restore_from_ebs']}
      creds.merge!(tar_creds)
    end

    if options['restore_neptune_info']
      remote_neptune_info_location = "/etc/appscale/neptune_info.txt"
      CommonFunctions.scp_file(options['restore_neptune_info'],
        remote_neptune_info_location, head_node_ip, ssh_key)
      Kernel.puts "Neptune data restored!"
    end

    return creds
  end


  def self.copy_keys(secret_key_location, ip, ssh_key, options)
    remote_secret_key_location = "/etc/appscale/secret.key"
    CommonFunctions.scp_file(secret_key_location, remote_secret_key_location,
      ip, ssh_key)

    remote_ssh_key_location = "/etc/appscale/ssh.key"
    CommonFunctions.scp_file(ssh_key, remote_ssh_key_location, ip, ssh_key)

    cert_loc, key_loc = VMTools.get_vmm_keys(options)

    remote_cert_loc = "/etc/appscale/certs/mycert.pem"
    CommonFunctions.scp_file(cert_loc, remote_cert_loc, ip, ssh_key)

    remote_key_loc = "/etc/appscale/certs/mykey.pem"
    CommonFunctions.scp_file(key_loc, remote_key_loc, ip, ssh_key)

    infrastructure = options["infrastructure"]
    if VALID_CLOUD_TYPES.include?(infrastructure) and infrastructure == "hybrid"
      cloud_num = 1

      loop {
        cloud_type = ENV["CLOUD#{cloud_num}_TYPE"]
        break if cloud_type.nil?

        Kernel.puts "Copying over credentials for cloud #{cloud_num}"
        cert = ENV["CLOUD#{cloud_num}_EC2_CERT"]
        private_key = ENV["CLOUD#{cloud_num}_EC2_PRIVATE_KEY"]
        CommonFunctions.copy_cloud_keys(cloud_num, ip, ssh_key,
          options['verbose'], cert, private_key)
        cloud_num += 1
      }
    elsif VALID_CLOUD_TYPES.include?(infrastructure)
      Kernel.puts "Copying over credentials for cloud"
      cloud_num = 1
      cert = ENV["EC2_CERT"]
      private_key = ENV["EC2_PRIVATE_KEY"]
      CommonFunctions.copy_cloud_keys(cloud_num, ip, ssh_key,
        options['verbose'], cert, private_key)
    else
      cloud_num = 1
      CommonFunctions.copy_cloud_keys(cloud_num, ip, ssh_key,
        options['verbose'], cert_loc, key_loc)
    end
  end


  def self.copy_cloud_keys(cloud_num, ip, ssh_key, verbose, cert, private_key)
    cloud_key_dir = "/etc/appscale/keys/cloud#{cloud_num}"
    make_cloud_key_dir = "mkdir -p #{cloud_key_dir}"
    CommonFunctions.run_remote_command(ip, make_cloud_key_dir, ssh_key, verbose)
    CommonFunctions.scp_file(cert, "#{cloud_key_dir}/mycert.pem", ip, ssh_key)
    CommonFunctions.scp_file(private_key, "#{cloud_key_dir}/mykey.pem", ip, ssh_key)
  end


  def self.start_appcontroller(ip, ssh_key, verbose)
    # TODO(cgb) - check the return value of the following command. a user could
    # accidentally remove that file and cause this to return a bad value
    remote_home = CommonFunctions.get_remote_appscale_home(ip, ssh_key)
    start = "ruby #{remote_home}/AppController/djinnServer.rb"
    stop = "ruby #{remote_home}/AppController/terminate.rb"

    Kernel.puts "Starting server at #{ip}"

    # remove any possible appcontroller state that may not have been
    # properly removed in non-cloud runs
    remove_state = "rm -rf /etc/appscale/appcontroller-state.json"
    CommonFunctions.run_remote_command(ip, remove_state, ssh_key, verbose)

    GodInterface.start_god(ip, ssh_key)
    Kernel.sleep(1)

    begin
      Timeout::timeout(60) {
        GodInterface.start(:controller, start, stop, 
          AppScaleTools::DJINN_SERVER_PORT,
          {'APPSCALE_HOME' => remote_home}, ip, ssh_key)

        Kernel.puts "Please wait for the controller to finish " +
          "pre-processing tasks."

        CommonFunctions.sleep_until_port_is_open(ip, 
          AppScaleTools::DJINN_SERVER_PORT, AppScaleTools::USE_SSL)
      }
    rescue Timeout::Error
      retry
    end
  end


  def self.backup_neptune_info(keyname, shadow_ip, backup_neptune_info)
    remote_file = "/etc/appscale/neptune_info.txt"
    command = "scp -i ~/.appscale/#{keyname}.key " +
      "root@#{shadow_ip}:#{remote_file} #{backup_neptune_info}"
    CommonFunctions.shell("#{command}")
    Kernel.puts "Your Neptune information has been backed up to #{backup_neptune_info}\n"
  end


  def self.terminate_via_infrastructure(infrastructure, keyname, shadow_ip, secret)
    Kernel.puts "About to terminate instances spawned via #{infrastructure} " +
      "with keyname '#{keyname}'..."
    Kernel.sleep(2)

    acc = AppControllerClient.new(shadow_ip, secret)
    if acc.is_live?
      acc.kill()
      # TODO(cgb): read the group from the locations.yaml file and delete that
      cmd = "#{infrastructure}-delete-group appscale"
      Kernel.puts CommonFunctions.shell("#{cmd}")
      Kernel.puts "Terminated AppScale in cloud deployment."
    else
      VMTools.terminate_infrastructure_machines(infrastructure, keyname)
    end
  end


  def self.terminate_via_vmm(keyname, verbose)
    Kernel.puts "About to terminate instances spawned via Xen/KVM with " +
      "keyname '#{keyname}'..."
    Kernel.sleep(2)

    ssh_key_location = "~/.appscale/#{keyname}"
    live_ips = CommonFunctions.stop_appcontrollers(keyname, ssh_key_location,
      verbose)
    CommonFunctions.wait_for_appcontrollers_to_stop(live_ips, ssh_key_location)
  end


  def self.stop_appcontrollers(keyname, ssh_key, verbose)
    command = "service appscale-controller stop"
 
    ips = CommonFunctions.get_all_public_ips(keyname)
    live_ips = []

    threads = []
    ips.each { |ip|
      threads << Thread.new {
        CommonFunctions.run_remote_command(ip, command, ssh_key, verbose)
        Kernel.sleep(5)
        CommonFunctions.run_remote_command(ip, command, ssh_key, verbose)
        live_ips << ip
      } 
    } 

    threads.each { |t| t.join }
    return live_ips
  end


  def self.wait_for_appcontrollers_to_stop(ips, ssh_key)
    boxes_shut_down = 0
    ips.each { |ip|
      Kernel.print "Shutting down AppScale components at #{ip}"
      STDOUT.flush
      loop {
        remote_cmd = "ssh root@#{ip} #{SSH_OPTIONS} -i #{ssh_key} 'ps x'"
        ps = CommonFunctions.shell(remote_cmd)
        processes_left = ps.scan(/appscale-controller stop/).length
        break if processes_left.zero?
        Kernel.print '.'
        STDOUT.flush
        Kernel.sleep(0.3)
      }
      boxes_shut_down += 1
      Kernel.print "\n"
    }

    if boxes_shut_down.zero?
      raise AppScaleException.new(
        AppScaleTools::UNABLE_TO_TERMINATE_ANY_MACHINES)
    end

    Kernel.puts "Terminated AppScale across #{boxes_shut_down} boxes."
  end


  def self.delete_appscale_files(keyname)
    locations_yaml = File.expand_path("~/.appscale/locations-#{keyname}.yaml")
    FileUtils.rm_f(locations_yaml) if File.exists?(locations_yaml)

    retval_file = File.expand_path("~/.appscale/retval")
    FileUtils.rm_f(retval_file) if File.exists?(retval_file)
  end


  def self.verbose(msg, verbose)
    Kernel.puts msg if verbose
  end
end
