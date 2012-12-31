#!/usr/bin/env ruby
# Programmer: Chris Bunch


$VERBOSE = nil # to supress excessive SSL cert warnings


require 'fileutils'
require 'yaml'
require 'soap/rpc/driver'
require 'timeout'
require 'base64'
require 'openssl'


$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'app_controller_client'
require 'common_functions'
require 'custom_exceptions'
require 'encryption_helper'
require 'godinterface'
require 'node_layout'
require 'parse_args'
require 'remote_log'
require 'usage_text'
require 'user_app_client'
require 'vm_tools'


module AppScaleTools


  # The list of flags that can be used with the 'appscale-add-instances'
  # command.
  ADD_INSTANCES_FLAGS = ["ips", "keyname"]


  # The usage text that we display to users if they incorrectly invoke
  # 'appscale-add-instances'.
  ADD_INSTANCES_USAGE = UsageText.get_usage("appscale-add-instances",
    ADD_INSTANCES_FLAGS)


  ADD_KEYPAIR_FLAGS = ["help", "usage", "h", "ips", "keyname", "version", 
    "auto", "add_to_existing"]


  ADD_KEYPAIR_USAGE = UsageText.get_usage("appscale-add-keypair", 
    ADD_KEYPAIR_FLAGS)


  # A message that add-nodes can raise if the user does not indicate
  # which machines should be used to start new roles in their AppScale
  # deployment.
  NO_IPS_GIVEN = "Please specify a YAML file that indicates what nodes " +
    "should be used to start new roles in the currently running " +
    "AppScale deployment."


  IP_REGEX = /\d+\.\d+\.\d+\.\d+/


  FQDN_REGEX = /([\w\d\.\-]+\.){2,}/


  IP_OR_FQDN = /#{IP_REGEX}|#{FQDN_REGEX}/


  DESCRIBE_INSTANCES_FLAGS = ["help", "usage", "h", "keyname", "version"]


  DESCRIBE_INSTANCES_USAGE = UsageText.get_usage("appscale-describe-instances",
    DESCRIBE_INSTANCES_FLAGS)


  NO_APPNAME_GIVEN = "You failed to specify an application to remove."


  APP_NOT_RUNNING = "We could not stop your application because it was " +
    "not running."


  APP_REMOVAL_CANCELLED = "Application removal cancelled."


  REMOVE_APP_FLAGS = ["help", "h", "usage", "appname", "version", "keyname", 
    "confirm"]


  REMOVE_APP_USAGE = UsageText.get_usage("appscale-remove-app", 
    REMOVE_APP_FLAGS)


  APPSCALE_NOT_RUNNING = "We are not able to reset your password right now, as AppScale is not currently running."


  RESET_PASSWORD_FLAGS = ["help", "usage", "h", "keyname", "version"]


  RESET_PASSWORD_USAGE = UsageText.get_usage("appscale-reset-pwd", 
    RESET_PASSWORD_FLAGS)


  DJINN_SERVER_DIED_MSG = "\nEither the head node was unable to get IP" + 
    " addresses for any slave nodes or a bug in the head node's code" + 
    " caused it to crash. We have left your virtual machines running" + 
    " in case you wish to submit a bug report or investigate further" +
    " via the Troubleshooting page."


  NO_MACHINE_SET = "You failed to provide a machine image via the --machine" +
    " flag or the APPSCALE_MACHINE environment variable."


  RUN_INSTANCES_FLAGS = ["help", "h", "min", "max", "file", "table", "ips",
    "v", "verbose", "machine", "instance_type", "usage", "version", "keyname",
    "infrastructure", "n", "r", "w", "scp", "test", "appengine",
    "force", "restore_from_tar", "restore_neptune_info", "group"]


  RUN_INSTANCES_USAGE = UsageText.get_usage("appscale-run-instances", 
    RUN_INSTANCES_FLAGS)


  SSH_PORT = 22


  PBSERVER_PORT = 443


  DJINN_SERVER_PORT = 17443


  UA_SERVER_PORT = 4343


  USE_SSL = true


  TERMINATE_INSTANCES_FLAGS = ["help", "h", "usage", "version", "verbose",
    "keyname", "backup_neptune_info"]


  TERMINATE_INSTANCES_USAGE = UsageText.get_usage(
    "appscale-terminate-instances", TERMINATE_INSTANCES_FLAGS)


  UNABLE_TO_TERMINATE_ANY_MACHINES = "We were unable to shut down any of " +
    "your machines running AppScale. \nPlease verify that the machines are " +
    "live, running AppScale, and reachable from your current location."


  APPSCALE_NOT_RUNNING = "AppScale does not appear to be running. If you are " +
    "using a cloud deployment, please manually terminate any running instances."


  NO_FILE_PROVIDED_MSG = "You failed to provide a file to upload. Please do " +
    "so via the --file flag and try again."


  APP_ALREADY_EXISTS = "An app with the name you provided in app.yaml " +
    "already exists. Please change the provided name in app.yaml and retry " +
    "uploading your app. If you want to upload a new version of your " +
    "application, use appscale-remove-app to remove the old version, then " +
    "use this tool to upload the new version."


  USER_NOT_ADMIN = "An app with the name you provided in app.yaml has already" +
    " been reserved by a different user. Please change the provided name in " +
    "app.yaml and retry uploading your application."


  DJINN_SERVER_PORT = 17443


  UPLOAD_APP_FLAGS = ["help", "h", "usage", "file", "version", "keyname", 
    "test", "email"]


  UPLOAD_APP_USAGE = UsageText.get_usage("appscale-upload-app", 
    UPLOAD_APP_FLAGS)


  def self.add_keypair(options)
    keyname = options['keyname'] || "appscale"
    ips_yaml = options['ips']
    auto = options['auto']

    if ips_yaml.nil?
      raise BadConfigurationException.new(ADD_KEYPAIR_USAGE)
    end

    node_layout = NodeLayout.new(ips_yaml, { :database => "cassandra" } )

    required_commands = ["ssh-keygen", "ssh-copy-id"]
    if auto
      required_commands << "expect"
    end
    CommonFunctions.require_commands(required_commands)

    CommonFunctions.make_appscale_directory()

    path = File.expand_path("~/.appscale/#{keyname}")

    if options['add_to_existing']
      pub_key = File.expand_path("~/.appscale/#{keyname}.pub")
      backup_key = File.expand_path("~/.appscale/#{keyname}.key")
    else
      pub_key, backup_key = CommonFunctions.generate_rsa_key(keyname)
    end

    if auto
      if options["root_password"].nil?
        print "\nEnter SSH password of root: "
        password = CommonFunctions.get_line_from_stdin_no_echo()
      else
        puts "Using the provided root password to login to AppScale machines"
        password = options["root_password"]
      end
    end

    if node_layout.valid?
      ips = node_layout.nodes.collect { |node| node.id }
    else
      ips = []
      ips_yaml.each { |role, ip|
        ips << ip
      }
      ips.flatten!
      ips.uniq!
    end

    ips.each { |ip|
      CommonFunctions.ssh_copy_id(ip, path, auto, password)
      CommonFunctions.scp_ssh_key_to_ip(ip, path, pub_key)
    }
 
    FileUtils.cp(path, backup_key)
    Kernel.puts "A new ssh key has been generated for you and placed at" +
      " #{path}. You can now use this key to log into any of the " +
      "machines you specified without providing a password."
    return {'success' => true}
  end

  
  # Works in conjunction with an already running AppScale deployment to
  # add additional nodes. The nodes must be specified via a YAML file
  # (of the same format used in run-instances).
  # Args:
  #   options: A Hash with the following keys:
  #     ips: A Hash that maps roles to start on new nodes to the IPs
  #       that they should be started on. For cloud deployments, IPs
  #       need not be used - any unique identifier will suffice.
  #     keyname (optional): The name of the key that is associated with
  #       machines in this AppScale deployment.
  def self.add_instances(options)
    ips_yaml = options['ips']
    if ips_yaml.nil? or ips_yaml.empty?
      raise BadConfigurationException.new(NO_IPS_GIVEN)
    end

    if ips_yaml.keys.include?(:master)
      raise BadConfigurationException.new("Cannot add a master node to " +
        "an already running AppScale deployment.")
    end

    # Skip checking for -n (replication) because we don't allow the user
    # to specify it here (only allowed in run-instances).
    additional_nodes_layout = NodeLayout.new(ips_yaml, options,
      skip_replication=true)

    # In non-cloud scenarios, we need to make sure that the user has
    # set up SSH keys with the new nodes to add.
    keyname = options['keyname'] || "appscale"
    ssh_key = File.expand_path("~/.appscale/#{keyname}.key")

    infrastructure = CommonFunctions.get_infrastructure(keyname)
    if infrastructure == "xen"
      new_ips = ips_yaml.values.flatten
      new_ips.each { |ip|
        # throws an AppScaleException if the SSH key doesn't work
        CommonFunctions.find_real_ssh_key([ssh_key], ip)
      }
    end

    # Finally, find an AppController and send it a message to add
    # the given nodes with the new roles.
    head_node_ip = CommonFunctions.get_head_node_ip(keyname)
    secret = CommonFunctions.get_secret_key(keyname)
    acc = AppControllerClient.new(head_node_ip, secret)

    # Convert the keys in ips.yaml from Symbols to Strings, which
    # are acceptable to pass via SOAP.
    converted_ips_yaml = {}
    ips_yaml.each { |k, v|
      converted_ips_yaml[k.to_s] = v
    }

    # Return whatever the result of the SOAP request to the AppController
    # is.
    acc.start_roles_on_nodes(converted_ips_yaml)
  end


  def self.describe_instances(options)
    keyname = options['keyname']
    CommonFunctions.update_locations_file(keyname)
    secret_key = CommonFunctions.get_secret_key(keyname)

    instance_info = []
    all_ips = CommonFunctions.get_all_public_ips(keyname)
    all_ips.each { |ip|
      acc = AppControllerClient.new(ip, secret_key)
      instance_info << acc.status()
    }

    return {:error => nil, :result => instance_info }
  end


  def self.remove_app(options)
    if options['appname'].nil?
      raise BadConfigurationException.new(NO_APPNAME_GIVEN)
    end

    CommonFunctions.update_locations_file(options['keyname'])
    result = CommonFunctions.confirm_app_removal(options['confirm'],
      options['appname'])
    if result == "NO"
      raise AppScaleException.new(APP_REMOVAL_CANCELLED)
    end

    CommonFunctions.remove_app(options['appname'], options['keyname'])
    Kernel.puts "Done shutting down app #{options['appname']}"
  end


  def self.reset_password(options)
    keyname = options['keyname']
    CommonFunctions.update_locations_file(keyname)
    secret = CommonFunctions.get_secret_key(keyname)

    head_node_ip = CommonFunctions.get_load_balancer_ip(keyname)
    if head_node_ip.empty?
      raise BadConfigurationException.new(APPSCALE_NOT_RUNNING)
    end

    user = CommonFunctions.get_email
    pass = CommonFunctions.get_password
    puts "\n"
    encrypted_pass = CommonFunctions.encrypt_password(user, pass)

    acc = AppControllerClient.new(head_node_ip, secret)
    userappserver_ip = acc.get_userappserver_ip

    uac = UserAppClient.new(userappserver_ip, secret)
    uac.change_password(user, encrypted_pass)
  end


  # Deploys AppScale over virtual machines located in Amazon EC2, Eucalyptus,
  # or Xen/KVM. To do so, this function spawns an initial virtual machine
  # and then delegates the rest of the responsibilities of starting AppScale
  # to that machine.
  # Args:
  #   options: A Hash that contains parameters that can be used to customize
  #     the given AppScale deployment.
  # Returns:
  #   Nothing.
  def self.run_instances(options)
    infrastructure = options['infrastructure']
    instance_type = options['instance_type']
    machine = options['machine']
    max_images = options['max_images']
    table = options['table']

    CommonFunctions.make_appscale_directory()
    CommonFunctions.validate_run_instances_options(options)
    CommonFunctions.print_starting_message(infrastructure, instance_type)
    RemoteLogging.remote_post(max_images, table, infrastructure, "starting", "unknown")
    sleep(2)

    apps_to_start, app_info = CommonFunctions.get_app_info_from_options(options)
    node_layout, result = CommonFunctions.generate_node_layout(options)
    head_node_result = CommonFunctions.start_head_node(options, node_layout,
      apps_to_start)

    print "\nPlease wait for AppScale to prepare your machines for use."
    STDOUT.flush
    puts "\n"

    acc = head_node_result[:acc]
    secret_key = head_node_result[:secret_key]
    head_node_ip = head_node_result[:head_node_ip]
    CommonFunctions.write_and_copy_node_file(options, node_layout,
      head_node_result)

    userappserver_ip = acc.get_userappserver_ip(LOGS_VERBOSE)
    CommonFunctions.update_locations_file(options['keyname'], [head_node_ip])
    CommonFunctions.copy_nodes_json(options['keyname'], head_node_ip,
      head_node_result[:true_key])
    CommonFunctions.verbose("Run instances: UserAppServer is at #{userappserver_ip}", options['verbose'])
    uac = UserAppClient.new(userappserver_ip, secret_key)
    if options["admin_user"].nil? and options["admin_pass"].nil?
      user, pass = CommonFunctions.get_credentials(options['test'])
    else
      puts "Using the provided admin username and password"
      user, pass = options["admin_user"], options["admin_pass"]
    end
    CommonFunctions.create_user(user, options['test'], head_node_ip,
      secret_key, uac, pass)

    uac.set_cloud_admin_status(user, new_status="true")
    uac.set_cloud_admin_capabilities(user)

    CommonFunctions.wait_for_nodes_to_load(head_node_ip, secret_key)
    if options['file_location'].nil?
      puts "No app uploaded. Use appscale-upload-app to upload an app later."
    else
      remote_file_path = CommonFunctions.scp_app_to_ip(app_info[:app_name], 
        user, app_info[:language], options['keyname'], head_node_ip, 
        app_info[:file], uac)

      acc.done_uploading(app_info[:app_name], remote_file_path)

      CommonFunctions.wait_for_app_to_start(head_node_ip, secret_key,
        app_info[:app_name])
      CommonFunctions.clear_app(app_info[:file])
    end

    login_ip = CommonFunctions.get_login_ip(head_node_ip, secret_key)
    puts "The status of your AppScale instance is at the following" + 
      " URL: http://#{login_ip}/status"

    CommonFunctions.write_and_copy_node_file(options, node_layout,
      head_node_result)
    RemoteLogging.remote_post(max_images, table, infrastructure, "started", "success")
  end


  def self.terminate_instances(options)
    keyname = options['keyname']
    locations_yaml = File.expand_path("~/.appscale/locations-#{keyname}.yaml")
    if !File.exists?(locations_yaml)
      raise AppScaleException.new(APPSCALE_NOT_RUNNING)
    end

    CommonFunctions.update_locations_file(keyname)
    shadow_ip = CommonFunctions.get_head_node_ip(keyname)
    secret = CommonFunctions.get_secret_key(keyname)

    if options['backup_neptune_info']
      CommonFunctions.backup_neptune_info(keyname, shadow_ip,
        options['backup_neptune_info'])
    end

    infrastructure = CommonFunctions.get_infrastructure(keyname, required=true)
    if VALID_CLOUD_TYPES.include?(infrastructure)
      CommonFunctions.terminate_via_infrastructure(infrastructure, keyname, shadow_ip, secret)
    else
      CommonFunctions.terminate_via_vmm(keyname, options['verbose'])
    end

    CommonFunctions.delete_appscale_files(keyname)
  end


  def self.upload_app(options)
    file_location = options['file_location']
    if file_location.nil?
      raise AppScaleException.new(NO_FILE_PROVIDED_MSG)
    end

    keyname = options['keyname']
    CommonFunctions.update_locations_file(keyname)
    secret_key = CommonFunctions.get_secret_key(keyname)
    head_node_ip = CommonFunctions.get_head_node_ip(keyname)
    database = CommonFunctions.get_table(keyname)

    app_info = CommonFunctions.get_app_name_from_tar(file_location)
    app_name, file_location, language = app_info[:app_name], app_info[:file], app_info[:language]
    CommonFunctions.validate_app_name(app_name, database)

    acc = AppControllerClient.new(head_node_ip, secret_key)
    user = CommonFunctions.get_username_from_options(options)
    userappserver_ip = acc.get_userappserver_ip(LOGS_VERBOSE)
    uac = UserAppClient.new(userappserver_ip, secret_key)
    if !uac.does_user_exist?(user)
      CommonFunctions.create_user(user, options['test'], head_node_ip,
        secret_key, uac)
    end

    Kernel.puts ""

    if uac.does_app_exist?(app_name)
      raise AppScaleException.new(APP_ALREADY_EXISTS)
    end

    app_admin = uac.get_app_admin(app_name)
    if !app_admin.empty? and user != app_admin
      raise AppScaleException.new(USER_NOT_ADMIN)
    end

    remote_file_path = CommonFunctions.scp_app_to_ip(app_name, user, language,
      keyname, head_node_ip, file_location, uac)
    CommonFunctions.update_appcontroller(head_node_ip, secret_key, app_name,
      remote_file_path)
    CommonFunctions.wait_for_app_to_start(head_node_ip, secret_key, app_name)
    CommonFunctions.clear_app(file_location)
  end
end
