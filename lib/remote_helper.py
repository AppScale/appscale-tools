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
from local_state import APPSCALE_VERSION
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

    cls.ensure_machine_is_compatible(public_ip, options.keyname, options.table)


  @classmethod
  def spawn_node_in_cloud(cls, options):
    """Starts a single virtual machine in a cloud infrastructure.

    This method also prepares the virual machine for use by the AppScale Tools.
    Specifically, it enables root logins on the machine, enables SSH access,
    and copies the user's SSH key to that machine.

    Args:
      options: A Namespace that specifies the cloud infrastructure to use, as
        well as how to interact with that cloud.
    Returns:
      The instance ID, public IP address, and private IP address of the machine
        that was started.
    """
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
    """Queries the given host to see if the named port is open, and if not,
    waits until it is.

    Args:
      host: A str representing the host whose port we should be querying.
      port: An int representing the port that should eventually be open.
    """
    while not cls.is_port_open(host, port):
      AppScaleLogger.log("Waiting for {0}:{1} to open".format(host, port))
      time.sleep(2)


  @classmethod
  def is_port_open(cls, host, port):
    """Queries the given host to see if the named port is open.

    Args:
      host: A str representing the host whose port we should be querying.
      port: An int representing the port that should eventually be open.
    Returns:
      True if the port is open, False otherwise.
    """
    try:
      sock = socket.socket()
      sock.connect((host, port))
      return True
    except Exception as exception:
      AppScaleLogger.log(str(exception))
      return False


  @classmethod
  def enable_root_login(cls, host, keyname):
    """Logs into the named host and alters its ssh configuration to enable the
    root user to directly log in.

    Args:
      host: A str representing the host to enable root logins on.
      keyname: A str representing the name of the SSH keypair to login with.
    """
    cls.ssh(host, keyname, 'sudo cp ~/.ssh/authorized_keys /root/.ssh/',
      user='ubuntu')


  @classmethod
  def ssh(cls, host, keyname, command, user='root'):
    """Logs into the named host and executes the given command.

    Args:
      host: A str representing the machine that we should log into.
      keyname: A str representing the name of the SSH keypair to log in with.
      command: A str representing what to execute on the remote host.
      user: A str representing the user to log in as.
    Returns:
      A str representing the standard output of the remote command and a str
        representing the standard error of the remote command.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    return cls.shell("ssh -i {0} {1} {2}@{3} '{4}'".format(ssh_key,
      cls.SSH_OPTIONS, user, host, command))


  @classmethod
  def scp(cls, host, keyname, source, dest, user='root'):
    """Securely copies a file from this machine to the named machine.

    Args:
      host: A str representing the machine that we should log into.
      keyname: A str representing the name of the SSH keypair to log in with.
      source: A str representing the path on the local machine where the
        file should be copied from.
      dest: A str representing the path on the remote machine where the file
        should be copied to.
      user: A str representing the user to log in as.
    Returns:
      A str representing the standard output of the secure copy and a str
        representing the standard error of the secure copy.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    return cls.shell("scp -i {0} {1} {2} {3}@{4}:{5}".format(ssh_key,
      cls.SSH_OPTIONS, source, user, host, dest))


  @classmethod
  def shell(cls, command):
    """Executes a command on this machine, retrying it up to five times if it
    initially fails.

    Args:
      The command to execute.
    Returns:
      The standard output and standard error produced when the command executes.
    Raises:
      ShellException: If, after five attempts, executing the named command
      failed.
    """
    AppScaleLogger.log("shell> ".format(command))
    tries_left = 5
    while tries_left:
      result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      result.wait()
      if result.returncode == 0:
        stdout = result.stdout.read()
        stderr = result.stderr.read()
        result.stdout.close()
        result.stderr.close()
        return stdout, stderr
      AppScaleLogger.log("[{0}] failed. Trying again momentarily." \
        .format(command))
      tries_left -= 1
      time.sleep(1)
    raise ShellException('Could not execute command: {0}'.format(command))


  @classmethod
  def copy_ssh_keys_to_node(cls, host, keyname):
    """Sets the given SSH keypair as the default key for the named host,
    enabling it to log into other machines in the AppScale deployment without
    being prompted for a password or explicitly requiring the key to be
    provided.

    Args:
      host: A str representing the machine that we should log into.
      keyname: A str representing the name of the SSH keypair to log in with.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    cls.scp(host, keyname, ssh_key, '/root/.ssh/id_dsa')
    cls.scp(host, keyname, ssh_key, '/root/.ssh/id_rsa')


  @classmethod
  def ensure_machine_is_compatible(cls, host, keyname, database):
    """Verifies that the specified host has AppScale installed on it.

    This also validates that the host has the right version of AppScale
    installed on it, as well as the database that the user has asked for.

    Args:
      host: A str representing the host that may or may not be
        AppScale-compatible.
      keyname: A str representing the SSH keypair name that can log into the
        named host.
      database: A str representing the database that the user wants to run
        with.
    Raises:
      AppScaleException: If the specified host does not have AppScale installed,
        has the wrong version of AppScale installed, or does not have the
        correct database installed.
    """
    # first, make sure the image is an appscale image
    if not cls.does_host_have_location(host, keyname, '/etc/appscale'):
      raise AppScaleException("The machine at {0} does not have AppScale " + \
        "installed. Please install AppScale on it and try again.".format(host))

    # next, make sure it has the same version of appscale installed as the tools
    if not cls.does_host_have_location(host, keyname,
      '/etc/appscale/{0}'.format(APPSCALE_VERSION)):
      raise AppScaleException("The machine at {0} does not have AppScale " + \
        "{1} installed. Please install AppScale {1} on it and try again." \
          .format(host, APPSCALE_VERSION))

    # finally, make sure it has the database installed that the user requests
    if not cls.does_host_have_location(host, keyname,
      '/etc/appscale/{0}/{1}'.format(APPSCALE_VERSION, database)):
      raise AppScaleException("The machine at {0} does not have support for" + \
        " {1} installed. Please provide a machine image that does and try " + \
        "again.".format(host, database))


  @classmethod
  def does_host_have_location(cls, host, keyname, location):
    """Logs into the specified host with the given keyname and checks to see if
    the named directory exists there.

    Args:
      host: A str representing a host that should be accessible from this
        machine.
      keyname: A str representing the name of the SSH keypair that can log into
        the specified machine.
      location: The path on the remote filesystem that we should be checking
        for.
    Returns:
      True if the remote host has a file or directory at the specified location,
        False otherwise.
    """
    print 'looking for location ' + str(location)
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
