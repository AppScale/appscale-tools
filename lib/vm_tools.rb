#!/usr/bin/ruby -w
# Programmer: Chris Bunch

require 'base64'
require 'socket'

require 'common_functions'
require 'custom_exceptions'

# The maximum amount of time we should wait for the first node in the system to
# go from 'pending' to 'running' and acquire a public IP. Our current VM size
# is about 10GB, so this means that in Eucalyptus it could take up to 30 minutes
# to start if the image wasn't cached.
MAX_VM_CREATION_TIME = 2700

# The amount of time to sleep between invocations of ec2-describe-instances when
# starting up the first node in the system. This should definitely not be lower
# than 5 seconds, as Eucalyptus 2.0.3 or newer will interpret it as a possible
# replay attack.
SLEEP_TIME = 20

# The regular expressions to use to find the public and private IPs (or FQDNs in
# case of EC2).
IP_REGEX = /\d+\.\d+\.\d+\.\d+/
FQDN_REGEX = /[\w\d\.\-]+/
IP_OR_FQDN = /#{IP_REGEX}|#{FQDN_REGEX}/

# When running over a cloud infrastructure, the user must set the following
# environment variables
EC2_ENVIRONMENT_VARIABLES = ["EC2_PRIVATE_KEY", "EC2_CERT", "EC2_SECRET_KEY"] +
 ["EC2_ACCESS_KEY"]

# When using Eucalyptus in a hybrid cloud deployment, the user must set the
# following environment variables (prefixed by CLOUDX_, where X is an integer)
REQUIRED_EUCA_CREDS_FOR_HYBRID = ["TYPE", "EMI", "S3_URL", "EC2_URL"] + 
  ["EC2_JVM_ARGS", "EUCALYPTUS_CERT", "EC2_USER_ID"] + EC2_ENVIRONMENT_VARIABLES

# When using EC2 in a hybrid cloud deployment, the user must set the
# following environment variables (prefixed by CLOUDX_, where X is an integer)
REQUIRED_EC2_CREDS_FOR_HYBRID = ["TYPE", "AMI", "S3_URL", "EC2_URL"] +
  ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"] + EC2_ENVIRONMENT_VARIABLES

module VMTools
  def self.get_initial_layout(head_node, separate, num_of_nodes, total_nodes)
    if head_node
      if separate
        raise NotImplementedError.new("haven't done head node, separate yet")
      else
        layout = "shadow:load_balancer:db_master"
        layout << ":appengine" if total_nodes == 1
      end
    else
      raise NotImplementedError.new("haven't done slave nodes, separate yet")
    end

    return layout
  end

  # Code for local_ip taken from 
  # http://coderrr.wordpress.com/2008/05/28/get-your-local-ip-address/
  def self.local_ip
    UDPSocket.open {|s| s.connect("64.233.187.99", 1); s.addr.last }
  end

  def self.get_creds_from_env
    creds = {}
    optional = {"ec2_url" => "https://us-east-1.ec2.amazonaws.com"}
    required = ["ec2_access_key", "ec2_secret_key"]

    optional.each { |k, v|
      creds[k] = ENV[k.upcase] or v
    }

    required.each { |var|
      if ENV[var.upcase]
        creds[var] = ENV[var.upcase]
      else
        raise BadConfigurationException.new("The required " +
          "environment variable #{var.upcase} was not set. Please set it " +
          "and try running AppScale again.")
      end
    }

    return creds
  end

  def self.ensure_tools_are_installed(infrastructure)
    commands = ["-add-group", "-authorize", "-describe-instances", "-run-instances", "-terminate-instances"]
    commands.each { |cmd|
      full_cmd = "#{infrastructure}#{cmd}"
      if !CommonFunctions.user_has_cmd?(full_cmd)
        raise BadConfigurationException.new("You do not appear to " +
          "have the command '#{full_cmd}'. Please put it in your PATH and " +
          "try again.")
      end
    }
  end
  
  def self.open_ports_in_cloud(infrastructure, group, verbose)
    retn = CommonFunctions.shell("#{infrastructure}-authorize #{group} -p 1-65535 -s 0.0.0.0/0 -P udp 2>&1")
    puts retn if verbose
    retn = CommonFunctions.shell("#{infrastructure}-authorize #{group} -p 1-65535 -s 0.0.0.0/0 -P tcp 2>&1")
    puts retn if verbose
    retn = CommonFunctions.shell("#{infrastructure}-authorize #{group} -s 0.0.0.0/0 -P icmp -t -1:-1 2>&1")
    puts retn if verbose
  end
  
  def self.ensure_keyname_not_in_use(keyname, infrastructure)
    describe_instances = CommonFunctions.shell("#{infrastructure}-describe-instances 2>&1")
    if describe_instances =~ /\s#{keyname}\s/
      raise InfrastructureException.new("The keyname you chose is " +
        "already in use. Please choose another keyname and try again.")
    end
  end

  def self.ensure_min_vms_available(min_vms_needed, instance_type, infrastructure)
    puts "warn: this doesn't work on ec2 - euca only"
    availability_zones = CommonFunctions.shell("#{infrastructure}-describe-availability-zones verbose 2>&1")
    # check for errors from last command
    vms_str = availability_zones.scan(/#{instance_type}\t([\d]+)/).flatten.to_s
    if vms_str.nil? or vms_str.empty?
      raise InfrastructureException.new("There was a problem seeing how many " +
        "virtual machines were available. We saw [#{availability_zones}].")
    end

    free_vms = Integer(vms_str)
    if free_vms < min_vms_needed
      raise InfrastructureException.new("Not enough VMs were free of the " +
        "type #{instance_type}. Needed #{min_vms_needed} but only #{free_vms}" +
        " were available.")
    end
  end


  # Queries the given cloud infrastructure to make sure that the machine
  # image the user wants to use actually exists.
  # Args:
  #   machine: The machine image (ami for Amazon EC2 and emi for
  #     Eucalyptus) that we should ensure exists.
  #   infrastructure: The cloud infrastructure that the given image
  #     should exist in.
  # Raises:
  #   InfrastructureException: If the machine image does not exist
  #     in the specified cloud infrastructure.
  def self.validate_machine_image(machine, infrastructure)
    if machine !~ /[a|e]mi/
      raise InfrastructureException.new("The machine image you " +
        "specified was not in the proper format. Please correct this " +
        "and try again.")
    end

    ec2_images = CommonFunctions.shell("#{infrastructure}-describe-images #{machine} 2>&1")
    # if the tools are not configured properly an error message will 
    # show up be sure to catch it and die if so
    if ec2_images =~ /\AServer:/
      raise InfrastructureException.new("Problem with " +
        "#{infrastructure}-tools: " + ec2_images)
    end

    if ec2_images =~ /IMAGE\t#{machine}/
      return
    else
      raise InfrastructureException.new("The machine image you " +
        "specified, #{machine}, was not found when querying " +
        "#{infrastructure}-describe-images. Please specify a machine " +
        "image that does exist and try again.")
    end
  end

  
  def self.get_ips(ips, verbose)
    if ips.length % 2 != 0
      raise InfrastructureException.new("ips not even length array")
    end
    reported_public = []
    reported_private = []
    ips.each_index { |index|
      if index % 2 == 0
        reported_public << ips[index]
      else
        reported_private << ips[index]
      end
    }
    
    if verbose
      puts "Reported Public IPs: [#{reported_public.join(', ')}]"
      puts "Reported Private IPs: [#{reported_private.join(', ')}]"
    end
    
    actual_public = []
    actual_private = []
    
    reported_public.each_index { |index|
      pub = reported_public[index]
      pri = reported_private[index]
      if pub != "0.0.0.0" and pri != "0.0.0.0"
        actual_public << pub
        actual_private << pri
      end
    }
    
    return actual_public, actual_private
  end
    
  def self.get_public_ips(ips, verbose)
    if ips.length % 2 != 0
      raise InfrastructureException.new("ips not even length array")
    end

    reported_public = []
    reported_private = []
    ips.each_index { |index|
      if index % 2 == 0
        reported_public << ips[index]
      else
        reported_private << ips[index]
      end
    }
    
    if verbose
      Kernel.puts("Reported Public IPs: [#{reported_public.join(', ')}]")
      Kernel.puts("Reported Private IPs: [#{reported_private.join(', ')}]")
    end

    public_ips = []
    reported_public.each_index { |index|
      if reported_public[index] != "0.0.0.0"
        public_ips << reported_public[index]
      elsif reported_private[index] != "0.0.0.0"
        public_ips << reported_private[index]
      end
    }
    
    return public_ips.flatten
  end
  
  def self.spawn_vms(num_of_vms_to_spawn, job, image_id, instance_type, keyname,
    infrastructure, group, verbose)
    # adding check first so that we don't do any of this if the 
    # infrastructure setting is wrong
    if !VALID_CLOUD_TYPES.include?(infrastructure)
      raise BadConfigurationException.new("Infrastructure must be " +
        "ec2, or euca, but instead was #{infrastructure}")
    end

    if infrastructure == "ec2"
    	check_group = CommonFunctions.shell("#{infrastructure}-describe-group #{group} 2>&1")
    	make_group = check_group.include? 'InvalidGroup.NotFound'
    elsif infrastructure == "euca"
    	check_group = CommonFunctions.shell("#{infrastructure}-describe-groups #{group} 2>&1")
    	make_group = check_group.empty?
    end
    if make_group
       Kernel.puts("Creating security group #{group}") if verbose
       create_sec_group = CommonFunctions.shell("#{infrastructure}-add-group #{group} -d #{group} 2>&1")
       Kernel.puts(create_sec_group) if verbose
    else # security group exists
      raise InfrastructureException.new("Security group #{group} exists, " +
        "delete this group via #{infrastructure}-delete-group #{group}, " +
        "prior to starting an AppScale cloud")
    end
    Kernel.puts("Security group #{group} in place") if verbose
    VMTools.open_ports_in_cloud(infrastructure, group, verbose)
    Kernel.puts("Ports set for security group #{group}") if verbose
    
    describe_instances = CommonFunctions.shell("#{infrastructure}-describe-instances 2>&1")
    Kernel.puts(describe_instances) if verbose
    all_ip_addrs = describe_instances.scan(/\s+(#{IP_OR_FQDN})\s+(#{IP_OR_FQDN})\s+running\s+#{keyname}\s/).flatten
    ips_up_already = VMTools.get_public_ips(all_ip_addrs, verbose)
    vms_up_already = ips_up_already.length  
  
    command_to_run = "#{infrastructure}-run-instances -k #{keyname} -n #{num_of_vms_to_spawn} --instance-type #{instance_type} --group #{group} #{image_id}" 
    
    Kernel.puts(command_to_run) if verbose
    run_instances = ""
    loop {
      run_instances = CommonFunctions.shell("#{command_to_run} 2>&1")
      Kernel.puts("run_instances: [#{run_instances}]") if verbose
      if run_instances =~ /Please try again later./
        Kernel.puts("Error with run_instances: #{run_instances}. Will " +
          "try again in a moment.")
      elsif run_instances =~ /try --addressing private/
        Kernel.puts("Need to retry with addressing private. Will try " +
          "again in a moment.")
        command_to_run << " --addressing private"
      elsif run_instances =~ /(PROBLEM)|(RunInstancesType: Failed to allocate network tag)/
        raise InfrastructureException.new("No network tags are currently free in your Eucalyptus deployment. Please delete some security groups and try again.")
      elsif run_instances =~ /(PROBLEM)|(RunInstancesType: Failed)/
        raise InfrastructureException.new("Saw the following error " +
          "message from iaas tools. Please resolve the issue and try " +
          "again:\n#{run_instances}")
      else
        Kernel.puts("Run instances message sent successfully. Waiting " +
          "for the image to start up.")
        break
      end
    }
    
    instance_ids = run_instances.scan(/INSTANCE\s+(i-\w+)\s+[\w\-\s\.]+#{keyname}\s/).flatten
     
    end_time = Time.now + MAX_VM_CREATION_TIME
    while (now = Time.now) < end_time
      describe_instances = CommonFunctions.shell("#{infrastructure}-describe-instances 2>&1")
      Kernel.puts("[#{Time.now}] #{end_time - now} seconds left until " +
        "timeout...")
      Kernel.puts(describe_instances) if verbose
      
      if describe_instances =~ /terminated\s#{keyname}\s/
        raise InfrastructureException.new("An instance was unexpectedly " +
          "terminated. Please contact your cloud administrator to determine " +
          "why and try again. \n#{describe_instances}")
      end
      
      all_ip_addrs = describe_instances.scan(/\s+(#{IP_OR_FQDN})\s+(#{IP_OR_FQDN})\s+running\s+#{keyname}\s/).flatten
      instance_ids = describe_instances.scan(/INSTANCE\s+(i-\w+)\s+[\w\-\s\.]+#{keyname}\s/).flatten
      public_ips, private_ips = VMTools.get_ips(all_ip_addrs, verbose)
      break if public_ips.length == num_of_vms_to_spawn + vms_up_already
      sleep(SLEEP_TIME)
    end
    
    if public_ips.length.zero?
      raise InfrastructureException.new("No public IPs were able to be " +
        "procured within the time limit.")
    end
       
    if public_ips.length != instance_ids.length
      Kernel.puts("Public IPs: #{public_ips.join(', ')}, Instance ids: " +
        "#{instance_ids.join(', ')}")
      raise InfrastructureException.new("Public IPs size didn't match " +
        "instance names size")
    end

    instances_created = []
    public_ips.each_index { |index|
      instances_created << "#{public_ips[index]}:#{private_ips[index]}:#{job}:#{instance_ids[index]}:cloud1"
    }
    
    return instances_created    
  end
    
  def self.terminate_all_vms(keyname, infrastructure)
    desc_instances = CommonFunctions.shell("#{infrastructure}-describe-instances 2>&1")
    instances = desc_instances.scan(/INSTANCE\s+(i-\w+)\s+[\w\-\s\.]+#{keyname}\s/).flatten
    return 0 if instances.length == 0
    puts CommonFunctions.shell("#{infrastructure}-terminate-instances #{instances.join(' ')} 2>&1")
    return instances.length
  end  

  def self.spawn_head_node(head_node, infrastructure, keyname, 
    ssh_key_location, ssh_keys, force, machine, instance_type, group, verbose)

    head_node_jobs = head_node.roles.join(":")
    if VALID_CLOUD_TYPES.include?(infrastructure)
      VMTools.spawn_head_node_via_cloud(infrastructure, keyname, 
        ssh_key_location, ssh_keys, force, head_node_jobs, machine, 
        instance_type, group, verbose)
    else
      VMTools.spawn_head_node_via_vmm(head_node, keyname, head_node_jobs)
    end
  end
  
  def self.spawn_head_node_via_cloud(infrastructure, keyname, 
    ssh_key_location, ssh_keys, force, head_node_jobs, machine, 
    instance_type, group, verbose)

    VMTools.ensure_tools_are_installed(infrastructure)
    #VMTools.verify_ids(machine, infrastructure)
    VMTools.ensure_keyname_not_in_use(keyname, infrastructure)
    #VMTools.ensure_min_vms_available(min_images, instance_type, infrastructure)
    EncryptionHelper.generate_ssh_key(verbose, ssh_keys, keyname, infrastructure, force)
    locations = VMTools.spawn_vms(1, head_node_jobs, machine, instance_type, keyname, infrastructure, group, verbose)
    puts "Please wait for your instance to complete the bootup process."
    head_node_ip = locations[0].split(":")[0]
    CommonFunctions.sleep_until_port_is_open(head_node_ip, AppScaleTools::SSH_PORT)
    sleep(10)
    options = "-o StrictHostkeyChecking=no -o NumberOfPasswordPrompts=0"
    enable_root_login = "sudo cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/"
    `ssh -i #{ssh_keys.join(" -i ")} #{options} 2>&1 ubuntu@#{head_node_ip} '#{enable_root_login}'` # kloogy ec2 fix
    CommonFunctions.scp_file(ssh_key_location, "/root/.ssh/id_dsa", head_node_ip, ssh_keys) # kloogy ec2 fix
    CommonFunctions.scp_file(ssh_key_location, "/root/.ssh/id_rsa", head_node_ip, ssh_keys)
    CommonFunctions.shell("scp -i #{ssh_keys.join(" -i ")} -o StrictHostkeyChecking=no 2>&1 root@#{head_node_ip}:/root/.ssh/authorized_keys /tmp/remote_keys")
    remote_keys = (File.open("/tmp/remote_keys") { |f| f.read }).chomp
    public_key_contents = remote_keys.scan(/ssh-rsa [\w+\/=]+ [\w@]+/).flatten.to_s
    File.open("/tmp/id_rsa.pub", "w+") { |file| file.write(public_key_contents) }  
    CommonFunctions.scp_file("/tmp/id_rsa.pub", "/root/.ssh/id_rsa.pub", head_node_ip, ssh_keys)  
    locations = locations.flatten.to_s
    return locations
  end
  
  def self.spawn_head_node_via_vmm(node, keyname, head_node_jobs)
    # We don't care about the instance's ID if not using cloud-tools
    # and for Xen, public ip = private ip
    head_node = "#{node.id}:#{node.id}:#{head_node_jobs}:i-ZFOOBARZ:cloud1"
    locations = [head_node].flatten.to_s
    return locations
  end

  def self.get_cloud_creds(node_layout, val_hash)
    cloud_creds = {
      "machine" => "#{val_hash['machine']}",
      "instance_type" => "#{val_hash['instance_type']}",
      "infrastructure" => "#{val_hash['infrastructure']}",
      "min_images" => "#{node_layout.min_images}",
      "max_images" => "#{node_layout.max_images}"
    }

    EC2_ENVIRONMENT_VARIABLES.each { |var|
      cloud_creds["CLOUD_#{var}"] = ENV[var]
    }

    if cloud_creds["infrastructure"] == "euca"
      ["EC2_URL", "S3_URL"].each { |var|
        cloud_creds["CLOUD_#{var}"] = ENV[var]
      }
    end

    cloud_creds.merge!(VMTools.get_creds_from_env)
    return cloud_creds
  end

  def self.get_vmm_keys(val_hash)
    puts "Generating certificate and private key"
    key, cert = EncryptionHelper.generate_pem_files(val_hash['keyname'])
    key = File.expand_path("~/.appscale/#{val_hash['keyname']}-key.pem")
    cert = File.expand_path("~/.appscale/#{val_hash['keyname']}-cert.pem")

    return cert, key
  end

  def self.lookup_cloud_env(cloud)
    cloud_type_var = cloud.upcase + "_TYPE"
    cloud_type = ENV[cloud_type_var]

    if cloud_type.nil?
      raise BadConfigurationException.new("The environment variable " +
        "#{cloud_type_var} was not set. Please set it and try again.")
    end

    return cloud_type
  end

  def self.get_hybrid_creds(node_layout, set_head_node_creds=false)
    cloud_creds = {
      "infrastructure" => "hybrid",
      "min_images" => "#{node_layout.min_images}",
      "max_images" => "#{node_layout.max_images}"
    }

    cloud_num = 1
    loop {
      cloud_type = ENV["CLOUD#{cloud_num}_TYPE"] 
      break if cloud_type.nil?

      if cloud_num == 1 and set_head_node_creds
        set_vars = true
      else
        set_vars = false
      end

      cloud_creds.merge!(self.get_hybrid_env_vars(cloud_type, cloud_num, set_vars))
      cloud_num += 1 
    }

    return cloud_creds
  end

  def self.set_hybrid_creds(node_layout)
    return self.get_hybrid_creds(node_layout, set_head_node_creds=true)
  end

  def self.get_hybrid_env_vars(cloud_type, cloud_num, set_vars=false)
    creds = {}

    if cloud_type == "euca"
      required = REQUIRED_EUCA_CREDS_FOR_HYBRID
    elsif cloud_type == "ec2"
      required = REQUIRED_EC2_CREDS_FOR_HYBRID
    else
      puts "Incorrect cloud type of #{cloud_type}"
      fail
    end

    required.each { |cred|
      key = "CLOUD#{cloud_num}_#{cred}"
      val = ENV[key]

      if val.nil?
        raise BadConfigurationException.new("The required " +
          "environment variable #{key} was not set. Please set it and " +
          "try again.")
      end

      if set_vars
        puts "Setting #{cred} to #{val}"
        ENV[cred] = val
      end

      creds[key] = val
    }

    return creds
  end

  def self.get_hybrid_machine(infra, cloud_num)
    if infra == "euca"
      key = "CLOUD#{cloud_num}_EMI"
    elsif infra == "ec2"
      key = "CLOUD#{cloud_num}_AMI"
    else
      raise BadConfigurationException.new("infrastructure #{infra} " +
        "is not a supported value.")
    end

    return ENV[key]
  end

  def self.verify_credentials_are_set_correctly(infrastructure)
    # In non-hybrid cloud environments, the user has to provide us with their
    # EC2 credentials. If they didn't, let them know and abort.
    EC2_ENVIRONMENT_VARIABLES.each { |var|
      if ENV[var].nil?
        raise BadConfigurationException.new("The required " +
          "environment variable #{var} was not set. Please set it and try " +
          "again.")
      end
    }
 
    VMTools.verify_credentials_exist()
 
    # The euca2ools default to using localhost as the EC2_URL and S3_URL if
    # it's not set, so make sure the user has explicitly set it.
    if infrastructure == "euca"
      ['EC2_URL', 'S3_URL'].each { |var|
        if ENV[var].nil?
          raise BadConfigurationException.new("When running over " +
            "Eucalyptus, the environment variable #{var} must be set.")
        end
      }
    end
  end

  # Validates that the private key and certificate for use with EC2 or
  # Eucalyptus both refer to files that exist, aborting if either do not exist.
  def self.verify_credentials_exist()
    ["EC2_PRIVATE_KEY", "EC2_CERT"].each { |var|
      file_path = File.expand_path(ENV[var])
      if !File.exists?(file_path)
        raise BadConfigurationException.new("The environment variable" +
          " #{var} pointed to the file #{file_path}, which didn't exist.")
      end
    }
  end

  def self.terminate_infrastructure_machines(infrastructure, keyname, group)
    # TODO: if we know all the other ips in the system, contact one
    # of them instead

    if keyname == "appscale"  # appscale keyname messes up the next command
      abort("Error seen trying to terminate your machines - please do so manually.")
    end

    # for now, just kill them the hard way
    desc = "#{infrastructure}-describe-instances"
    term = "#{infrastructure}-terminate-instances"
    cmd = "#{desc} | grep #{keyname} | grep -v RESERVATION | awk '{print $2}' | xargs #{term}"
    puts "Unable to contact shadow node, shutting down via tools..."
    puts `#{cmd}`
    cmd = "#{infrastructure}-delete-group #{group}"
    puts `#{cmd}`
  end
end
