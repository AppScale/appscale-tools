#!/usr/bin/ruby -w
# Programmer: Chris Bunch

require 'base64'
require 'socket'

$:.unshift File.dirname(__FILE__)
require 'common_functions'

# vm size ~10gb takes about ~20min to come up w/o caching
MAX_VM_CREATION_TIME = 1800
SLEEP_TIME = 20
IP_REGEX = /\d+\.\d+\.\d+\.\d+/
FQDN_REGEX = /[\w\d\.\-]+/
IP_OR_FQDN = /#{IP_REGEX}|#{FQDN_REGEX}/

REQUIRED_EUCA_CREDS = ["TYPE", "EMI", "S3_URL", "EC2_URL", "EC2_PRIVATE_KEY", "EC2_CERT"] +
  ["EC2_JVM_ARGS", "EUCALYPTUS_CERT", "EC2_ACCESS_KEY", "EC2_SECRET_KEY", "EC2_USER_ID"]

REQUIRED_EC2_CREDS = ["TYPE", "AMI", "S3_URL", "EC2_URL", "EC2_PRIVATE_KEY", "EC2_CERT"] +
  ["EC2_ACCESS_KEY", "EC2_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]

module VMTools
  def self.get_initial_layout(head_node, separate, num_of_nodes, total_nodes)
    if head_node
      if separate
        abort("haven't done head node, separate yet")
      else
        layout = "shadow:load_balancer:db_master"
        layout << ":appengine" if total_nodes == 1
      end
    else
      abort("haven't done slave nodes, separate yet")
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
        abort("The required environment variable #{var.upcase} was not set. Please set it and try running AppScale again.")
      end
    }

    return creds
  end

  def self.ensure_tools_are_installed(infrastructure)
    commands = ["-add-group", "-authorize", "-describe-instances", "-run-instances", "-terminate-instances"]
    commands.each { |cmd|
      full_cmd = "#{infrastructure}#{cmd}"
      abort("You do not appear to have the command '#{full_cmd}'. Please put it in your PATH and try again.") unless CommonFunctions.user_has_cmd?(full_cmd)
    }
  end
  
  def self.open_ports_in_cloud(infrastructure, verbose)
    CommonFunctions.shell("#{infrastructure}-authorize appscale -p 1-65000 -P udp 2>&1")
    CommonFunctions.shell("#{infrastructure}-authorize appscale -p 1-65000 -P tcp 2>&1")
    CommonFunctions.shell("#{infrastructure}-authorize appscale -p 1-65000 -P icmp -t -1:-1 2>&1")
  end
  
  def self.ensure_keyname_not_in_use(keyname, infrastructure)
    describe_instances = CommonFunctions.shell("#{infrastructure}-describe-instances 2>&1")
    if describe_instances =~ /\s#{keyname}\s/
      abort("The keyname you chose is already in use. Please choose another keyname and try again.")
    end
  end

  def self.ensure_min_vms_available(min_vms_needed, instance_type, infrastructure)
    puts "warn: this doesn't work on ec2 - euca only"
    availability_zones = CommonFunctions.shell("#{infrastructure}-describe-availability-zones verbose 2>&1")
    # check for errors from last command
    vms_str = availability_zones.scan(/#{instance_type}\t([\d]+)/).flatten.to_s
    abort("There was a problem seeing how many virtual machines were available. We saw [#{availability_zones}].") if vms_str.nil? or vms_str == ""
    free_vms = Integer(vms_str)
    abort("Not enough VMs were free of the type #{instance_type}. Needed #{min_vms_needed} but only #{free_vms} were available.") if free_vms < min_vms_needed
  end

  def self.verify_ids(disk, infrastructure)
    ec2_images = CommonFunctions.shell("#{infrastructure}-describe-images 2>&1")

    abort("The disk image you specified was not in the proper format. Please correct this and try again.") if disk !~ /[a|e]mi/
    
    # if the tools are not configured properly an error message will show up
    # be sure to catch it and die if so
    abort("Problem with #{infrastructure}-tools: " + ec2_images) if ec2_images =~ /\AServer:/ 

    id = "disk"
    id_value = eval(id)
    if ec2_images !~ /IMAGE\t#{id_value}/
      abort("The #{id} image you specified, #{id_value}, was not found when querying #{infrastructure}-describe-images. Please specify a #{id} image in the database and try again.")
    end
  end
  
  def self.get_ips(ips, verbose)
    abort("ips not even length array") if ips.length % 2 != 0
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
    abort("ips not even length array") if ips.length % 2 != 0
    reported_public = []
    reported_private = []
    ips.each_index { |index|
      if index % 2 == 0
        reported_public << ips[index]
      else
        reported_private << ips[index]
      end
    }
    
    puts "Reported Public IPs: [#{reported_public.join(', ')}]" if verbose
    puts "Reported Private IPs: [#{reported_private.join(', ')}]" if verbose
    
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
  
    def self.spawn_vms(num_of_vms_to_spawn, job, image_id, instance_type, keyname, infrastructure, verbose)
    create_sec_group = CommonFunctions.shell("#{infrastructure}-add-group appscale -d appscale 2>&1")
    puts create_sec_group if verbose
    
    describe_instances = CommonFunctions.shell("#{infrastructure}-describe-instances 2>&1")
    puts describe_instances if verbose
    all_ip_addrs = describe_instances.scan(/\s+(#{IP_OR_FQDN})\s+(#{IP_OR_FQDN})\s+running\s+#{keyname}\s/).flatten
    ips_up_already = VMTools.get_public_ips(all_ip_addrs, verbose)
    vms_up_already = ips_up_already.length  
  
    if VALID_CLOUD_TYPES.include?(infrastructure)
      command_to_run = "#{infrastructure}-run-instances -k #{keyname} -n #{num_of_vms_to_spawn} --instance-type #{instance_type} #{image_id} --group appscale"
    else
      abort("Infrastructure should have been ec2 or euca, but instead was #{infrastructure}")
    end
    
    puts command_to_run if verbose
    run_instances = ""
    loop {
      run_instances = CommonFunctions.shell("#{command_to_run} 2>&1")
      puts "run_instances: [#{run_instances}]" if verbose
      if run_instances =~ /Please try again later./
        puts "Error with run_instances: #{run_instances}. Will try again in a moment."
      elsif run_instances =~ /try --addressing private/
        puts "Need to retry with addressing private. Will try again in a moment."
        command_to_run << " --addressing private"
      elsif run_instances =~ /PROBLEM/
        abort("Saw the following error message from EC2 tools. Please resolve the issue and try again:\n#{run_instances}")
      else
        puts "Run instances message sent successfully. Waiting for the image to start up."
        break
      end
    }
    
    instance_ids = run_instances.scan(/INSTANCE\s+(i-\w+)\s+[\w\-\s\.]+#{keyname}\s/).flatten
     
    end_time = Time.now + MAX_VM_CREATION_TIME
    while (now = Time.now) < end_time
      describe_instances = CommonFunctions.shell("#{infrastructure}-describe-instances 2>&1")
      puts "[#{Time.now}] #{end_time - now} seconds left until timeout..."
      puts describe_instances if verbose
      
      if describe_instances =~ /terminated\s#{keyname}\s/
        abort("An instance was unexpectedly terminated. Please contact your cloud administrator to determine why and try again. \n#{describe_instances}")
      end
      
      all_ip_addrs = describe_instances.scan(/\s+(#{IP_OR_FQDN})\s+(#{IP_OR_FQDN})\s+running\s+#{keyname}\s/).flatten
      instance_ids = describe_instances.scan(/INSTANCE\s+(i-\w+)\s+[\w\-\s\.]+#{keyname}\s/).flatten
      public_ips, private_ips = VMTools.get_ips(all_ip_addrs, verbose)
      break if public_ips.length == num_of_vms_to_spawn + vms_up_already
      sleep(SLEEP_TIME)
    end
    
    abort("No public IPs were able to be procured within the time limit.") if public_ips.length == 0
       
    if public_ips.length != instance_ids.length
      puts "Public IPs: #{public_ips.join(', ')}, Instance ids: #{instance_ids.join(', ')}"
      abort("Public IPs size didn't match instance names size")
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
    ssh_key_location, ssh_keys, force, machine, instance_type, verbose)

    head_node_jobs = head_node.roles.join(":")
    if infrastructure == "hybrid"
      VMTools.spawn_head_node_via_hybrid(infrastructure, keyname,
        ssh_key_location, ssh_keys, force, head_node_jobs, instance_type,
        verbose)
    elsif VALID_CLOUD_TYPES.include?(infrastructure)
      VMTools.spawn_head_node_via_cloud(infrastructure, keyname, 
        ssh_key_location, ssh_keys, force, head_node_jobs, machine, 
        instance_type, verbose)
    else
      VMTools.spawn_head_node_via_vmm(head_node, keyname, head_node_jobs)
    end
  end
  
  def self.spawn_head_node_via_cloud(infrastructure, keyname, 
    ssh_key_location, ssh_keys, force, head_node_jobs, machine, 
    instance_type, verbose)

    VMTools.ensure_tools_are_installed(infrastructure)
    #VMTools.verify_ids(machine, infrastructure)
    VMTools.ensure_keyname_not_in_use(keyname, infrastructure)
    #VMTools.ensure_min_vms_available(min_images, instance_type, infrastructure)
    EncryptionHelper.generate_ssh_key(verbose, ssh_keys, keyname, infrastructure, force)
    locations = VMTools.spawn_vms(1, head_node_jobs, machine, instance_type, keyname, infrastructure, verbose)
    VMTools.open_ports_in_cloud(infrastructure, verbose)
    puts "Please wait for your instance to complete the bootup process."
    head_node_ip = locations[0].split(":")[0]
    CommonFunctions.sleep_until_port_is_open(head_node_ip, SSH_PORT)
    sleep(10)
    `ssh -i #{ssh_keys.join(" -i ")} -o StrictHostkeyChecking=no 2>&1 ubuntu@#{head_node_ip} 'sudo cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/'` # kloogy ec2 fix
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

  def self.get_cloud_creds(node_layout)
    cloud_creds = {
      "machine" => "#{MACHINE}",
      "instance_type" => "#{INSTANCE_TYPE}",
      "infrastructure" => "#{INFRASTRUCTURE}",
      "min_images" => "#{node_layout.min_images}",
      "max_images" => "#{node_layout.max_images}"
    }
    cloud_creds.merge!(VMTools.get_creds_from_env)
    return cloud_creds
  end

  def self.get_vmm_keys()
    puts "Generating certificate and private key"
    key, cert = EncryptionHelper.generate_pem_files(KEYNAME)
    key = File.expand_path("~/.appscale/#{KEYNAME}-key.pem")
    cert = File.expand_path("~/.appscale/#{KEYNAME}-cert.pem")

    return cert, key
  end

  # cgb: hybrid cloud

  def self.lookup_cloud_env(cloud)
    cloud_type_var = cloud.upcase + "_TYPE"
    cloud_type = ENV[cloud_type_var]

    if cloud_type.nil?
      error_msg = "The environment variable #{cloud_type_var} was not set." +
        " Please set it and try again."
      abort(error_msg)
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
      required = REQUIRED_EUCA_CREDS
    elsif cloud_type == "ec2"
      required = REQUIRED_EC2_CREDS
    else
      fail
    end

    required.each { |cred|
      key = "CLOUD#{cloud_num}_#{cred}"
      val = ENV[key]

      if val.nil?
        error_msg = "The required environment variable #{key} was not set." + 
          " Please set it and try again."
        abort(error_msg)
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
      abort("infrastructure #{infra} is not a supported value.")
    end

    return ENV[key]
  end
end
