#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import socket
import subprocess
import time


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory
from appscale_logger import AppScaleLogger
from custom_exceptions import AppScaleException
from custom_exceptions import ShellException
from local_state import LocalState


class RemoteHelper():
  """RemoteHelper provides a simple interface to interact with other machines
  (typically, AppScale virtual machines).

  This includes the ability to start services on remote machines and copy files
  to them.
  """


  # The default port that the ssh daemon runs on.
  SSH_PORT = 22


  # The options that should be used when making ssh and scp calls.
  SSH_OPTIONS = "-o LogLevel=quiet -o NumberOfPasswordPrompts=0 " + \
    "-o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null"


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

    if options.infrastructure:
      instance_id, public_ip, private_ip = cls.spawn_node_in_cloud(options)
    else:
      # construct locations
      pass

    AppScaleLogger.log("Log in to your head node: ssh -i {0} root@#{1}".format(
      LocalState.get_key_path_from_name(options.keyname), public_ip))

    cls.ensure_image_is_compatible(public_ip, options.keyname, options.table)


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
    cls.copy_ssh_keys_to_node(public_ips[0], options.keyname)
    return instance_ids[0], public_ips[0], private_ips[0]


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
    cls.ssh(host, keyname, 'sudo cp ~/.ssh/authorized_keys /root/.ssh/',
      user='ubuntu')


  @classmethod
  def ssh(cls, host, keyname, command, user='root'):
    ssh_key = LocalState.get_key_path_from_name(keyname)
    return cls.shell("ssh -i {0} {1} {2}@{3} '{4}'".format(ssh_key,
      cls.SSH_OPTIONS, user, host, command))


  @classmethod
  def scp(cls, host, keyname, source, dest, user='root'):
    ssh_key = LocalState.get_key_path_from_name(keyname)
    return cls.shell("scp -i {0} {1} {2} {3}@{4}:{5}".format(ssh_key,
      cls.SSH_OPTIONS, source, user, host, dest))


  @classmethod
  def shell(cls, command):
    AppScaleLogger.log("shell> ".format(command))
    tries_left = 5
    while tries_left:
      if subprocess.call(command, shell=True):
        return
      AppScaleLogger.log("[{0}] failed. Trying again momentarily." \
        .format(command))
      tries_left -= 1
      time.sleep(1)
    raise ShellException('Could not execute command: {0}'.format(command))


  @classmethod
  def copy_ssh_keys_to_node(cls, host, keyname):
    ssh_key = LocalState.get_key_path_from_name(keyname)
    cls.scp(host, keyname, ssh_key, '/root/.ssh/id_dsa')
    cls.scp(host, keyname, ssh_key, '/root/.ssh/id_rsa')


  @classmethod
  def ensure_image_is_compatible(cls, host, keyname, database):
    # first, make sure the image is an appscale image
    if not cls.does_host_have_location(host, keyname, '/etc/appscale'):
      raise AppScaleException("The machine at {0} does not have AppScale " + \
        "installed. Please install AppScale on it and try again.")

    # next, make sure it has the same version of appscale installed as the tools

    # finally, make sure it has the database installed that the user requests

    # fin!
    pass


  @classmethod
  def does_host_have_location(cls, host, keyname, location):
    try:
      cls.ssh(cls, host, keyname, 'ls {0}'.format(location))
      return True
    except ShellException:
      return False

    """
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
