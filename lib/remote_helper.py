#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import socket
import time


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory
from appscale_logger import AppScaleLogger
from local_state import LocalState


class RemoteHelper():
  """RemoteHelper provides a simple interface to interact with other machines
  (typically, AppScale virtual machines).

  This includes the ability to start services on remote machines and copy files
  to them.
  """


  # The default port that the ssh daemon runs on.
  SSH_PORT = 22


  @classmethod
  def start_head_node(cls, options, node_layout):
    """Starts the first node in an AppScale deployment and instructs it to start
    API services on its own node, as well as the other nodes in the deployment.

    This includes spawning the first node in the deployment, copying over all
    deployment-specific files to it, and starting its AppController service.

    Args:
      options: A Namespace that includes parameters passed in by the user that
        define non-placement-strategy-related deployment options (e.g., keypair
        names, security group names).
      node_layout: A NodeLayout that describes the placement strategy that
        should be used for this AppScale deployment.
    """
    secret_key = LocalState.generate_secret_key()
    AppScaleLogger.log("Secret key is {0}".format(secret_key))

    """
    named_key_loc = "~/.appscale/#{keyname}.key"
    named_backup_key_loc = "~/.appscale/#{keyname}.private"
    ssh_key_location = named_key_loc
    ssh_keys = [ssh_key_location, named_key_loc, named_backup_key_loc]
    """

    if options.infrastructure:
      cls.spawn_node_in_cloud(options)
      cls.copy_ssh_keys_to_node(options)
    else:
      # construct locations
      pass


  @classmethod
  def spawn_node_in_cloud(cls, options):
    agent = InfrastructureAgentFactory.create_agent(options.infrastructure)
    params = agent.get_params_from_args(options)
    agent.configure_instance_security(params)
    instance_ids, public_ips, private_ips = agent.run_instances(count=1,
      parameters=params, security_configured=True)
    AppScaleLogger.log("Please wait for your instance to boot up.")
    cls.sleep_until_port_is_open(public_ips[0], cls.SSH_PORT)
    time.sleep(10)
    cls.enable_root_login(public_ips[0], options.keyname)
    return public_ips[0]


  @classmethod
  def sleep_until_port_is_open(cls, host, port):
    while not cls.is_port_open(host, port):
      AppScaleLogger.log("Waiting for {0}:{1} to open".format(host, port))
      time.sleep(2)


  @classmethod
  def is_port_open(cls, host, port):
    try:
      sock = socket.socket()
      sock.connect((host, port))
      return True
    except Exception as exception:
      AppScaleLogger.log(str(exception))
      return False


  @classmethod
  def enable_root_login(cls, host, keyname):
    pass


  @classmethod
  def copy_ssh_keys_to_node(cls, options):
    pass


    """

    # TODO: serialize via json instead of this hacky way
    ips_hash = node_layout.to_hash
    ips_to_use = ips_hash.map { |node,roles| "#{node}--#{roles}" }.join("..")

    head_node = node_layout.head_node
    infrastructure = options['infrastructure']
    head_node_infra = infrastructure
    machine = options['machine']

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
    CommonFunctions.ensure_version_is_supported(head_node_ip, true_key)
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
    """
