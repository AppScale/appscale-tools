#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import socket
import subprocess
import time


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory
from appscale_logger import AppScaleLogger
from custom_exceptions import AppScaleException
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException
from local_state import APPSCALE_VERSION
from local_state import LocalState


class RemoteHelper():
  """RemoteHelper provides a simple interface to interact with other machines
  (typically, AppScale virtual machines).

  This includes the ability to start services on remote machines and copy files
  to them.
  """


  # The default port that the AppController daemon runs on.
  APPCONTROLLER_PORT = 17443


  # The default port that the ssh daemon runs on.
  SSH_PORT = 22


  # The options that should be used when making ssh and scp calls.
  SSH_OPTIONS = "-o LogLevel=quiet -o NumberOfPasswordPrompts=0 " + \
    "-o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null"


  TEMPLATE_GOD_CONFIG_FILE = os.path.dirname(__file__) + os.sep + ".." + \
    os.sep + "templates" + os.sep + "appcontroller.god"


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
    secret_key = LocalState.generate_secret_key(options.keyname)
    AppScaleLogger.log("Secret key is {0}".format(secret_key))

    if options.infrastructure:
      instance_id, public_ip, private_ip = cls.spawn_node_in_cloud(options)
    else:
      # construct locations
      pass

    AppScaleLogger.log("Log in to your head node: ssh -i {0} root@#{1}".format(
      LocalState.get_key_path_from_name(options.keyname), public_ip))

    cls.ensure_machine_is_compatible(public_ip, options.keyname, options.table)
    if options.scp:
      AppScaleLogger.log("Copying over local copy of AppScale from {0}".format(
        options.scp))
      cls.rsync_files(public_ip, options.keyname, options.scp)

    deployment_params = LocalState.generate_deployment_params(options,
      node_layout, public_ip)
    AppScaleLogger.log(str(LocalState.obscure_dict(deployment_creds)))
    AppScaleLogger.log("Head node successfully initialized at {0}. It is " + \
      "now starting up {1}.".format(public_ip, options.table))

    AppScaleLogger.remote_log_tools_state(options, "started head node")
    time.sleep(10)  # gives machines in cloud extra time to boot up

    cls.copy_deployment_credentials(public_ip, options)
    cls.start_remote_appcontroller(public_ip, options.keyname)

    """
    acc = AppControllerClient.new(head_node_ip, secret_key)
    creds = creds.to_a.flatten
    acc.set_parameters(locations, creds, apps_to_start)

    return {:acc => acc, :head_node_ip => head_node_ip,
      :instance_id => instance_id, :true_key => true_key,
      :secret_key => secret_key}
    """

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
    cls.scp(host, keyname, ssh_key, '/root/.appscale/{0}.key'.format(keyname))


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
    try:
      cls.ssh(cls, host, keyname, 'ls {0}'.format(location))
      return True
    except ShellException:
      return False

  
  @classmethod
  def rsync_files(cls, host, keyname, local_appscale_dir):
    """Copies over an AppScale source directory from this machine to the
    specified host.

    Args:
      host: A str representing a host that should be accessible from this
        machine.
      keyname: A str representing the name of the SSH keypair that can log into
        the specified machine.
      local_appscale_dir: A str representing the path on the local filesystem
        where the AppScale source to copy over can be found.
    Raises:
      BadConfigurationException: If local_appscale_dir does not exist locally,
        or if any of the standard AppScale module folders do not exist.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    appscale_dirs = ["lib", "AppController", "AppManager", "AppServer",
      "AppLoadBalancer", "AppMonitoring", "Neptune", "InfrastructureManager"]
    for dir_name in appscale_dirs:
      local_path = os.path.expanduser(local_appscale_dir) + os.sep + dir_name
      if not os.path.exists(local_path):
        raise BadConfigurationException("The location you specified to copy " +
          "from, {0}, doesn't contain a {1} folder.".format(local_appscale_dir,
          local_path))
      cls.shell("rsync -e 'ssh -i {0} {1}' -arv {2}/* root@{3}:" + \
        "/root/appscale/{2}".format(ssh_key, cls.SSH_OPTIONS, dir_name, host))

    # Rsync AppDB separately, as it has a lot of paths we may need to exclude
    # (e.g., built database binaries).
    cls.shell("rsync -e 'ssh -i {0} #{1}' -arv --exclude='logs/*' " + \
      "--exclude='hadoop-*' --exclude='hbase/hbase-*' " + \
      "--exclude='voldemort/voldemort/*' --exclude='cassandra/cassandra/*' " + \
      "AppDB/* root@#{2}:/root/appscale/AppDB".format(ssh_key, cls.SSH_OPTIONS,
      host))


  @classmethod
  def copy_deployment_credentials(cls, host, options):
    """Copies credentials needed to start the AppController and have it create
    other instances (in cloud deployments).

    Args:
      host: A str representing the machine (reachable from this computer) to
        copy our deployment credentials to.
      options: A Namespace that indicates which SSH keypair to use, and whether
        or not we are running in a cloud infrastructure.
    """
    cls.scp(host, options.keyname, LocalState.get_secret_key_location(
      options.keyname), '/etc/appscale/secret.key')
    cls.scp(host, options.keyname, LocalState.get_key_path_from_name(
      options.keyname), '/etc/appscale/ssh.key')

    LocalState.generate_ssl_cert(options.keyname)
    cls.scp(host, options.keyname, LocalState.get_certificate_location(
      options.keyname), '/etc/appscale/certs/mycert.pem')
    cls.scp(host, options.keyname, LocalState.get_private_key_location(
      options.keyname), '/etc/appscale/certs/mykey.pem')

    AppScaleLogger.log("Copying over deployment credentials")
    if options.infrastructure:
      cert = os.environ["EC2_CERT"]
      private_key = os.environ["EC2_PRIVATE_KEY"]
    else:
      cert = '/etc/appscale/certs/mycert.pem'
      private_key = '/etc/appscale/certs/mykey.pem'

    cls.ssh(host, options.keyname, 'mkdir -p /etc/appscale/keys/cloud1')
    cls.scp(host, options.keyname, cert, "/etc/appscale/keys/cloud1/mycert.pem")
    cls.scp(host, options.keyname, private_key, "/etc/appscale/keys/cloud1/mykey.pem")


  @classmethod
  def start_remote_appcontroller(cls, host, keyname):
    AppScaleLogger.log("Starting AppController at {0}".format(host))

    # remove any possible appcontroller state that may not have been
    # properly removed in virtualized clusters
    cls.ssh(host, LocalState.get_key_path_from_name(keyname),
      'rm -rf /etc/appscale/appcontroller-state.json')

    # start up god, who will start up the appcontroller once we give it the
    # right config file
    cls.ssh(host, LocalState.get_key_path_from_name(keyname), 'god &')
    time.sleep(1)

    # scp over that config file
    cls.scp(host, LocalState.get_key_path_from_name(keyname),
      cls.TEMPLATE_GOD_CONFIG_FILE, '/tmp/appcontroller.god')

    # finally, tell god to start the appcontroller and then wait for it to start
    cls.ssh(host, LocalState.get_key_path_from_name(keyname),
      'god load /tmp/appcontroller.god')

    AppScaleLogger.log("Please wait for the AppController to finish " + \
      "pre-processing tasks.")

    cls.sleep_until_port_is_open(host, cls.APPCONTROLLER_PORT)
