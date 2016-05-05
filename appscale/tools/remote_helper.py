#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import getpass
import os
import re
import socket
import subprocess
import threading
import tempfile
import time
import uuid


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory
from appcontroller_client import AppControllerClient
from appengine_helper import AppEngineHelper
from appscale_logger import AppScaleLogger
from custom_exceptions import AppControllerException
from custom_exceptions import AppScaleException
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException
from agents.gce_agent import CredentialTypes
from agents.gce_agent import GCEAgent
from local_state import APPSCALE_VERSION
from local_state import LocalState


class RemoteHelper(object):
  """RemoteHelper provides a simple interface to interact with other machines
  (typically, AppScale virtual machines).

  This includes the ability to start services on remote machines and copy files
  to them.
  """


  DUMMY_INSTANCE_ID = "i-ZFOOBARZ"


  # The port the AppDashboard runs on, by default.
  APP_DASHBOARD_PORT = 1080


  # The default port that the ssh daemon runs on.
  SSH_PORT = 22


  # The options that should be used when making ssh and scp calls.
  SSH_OPTIONS = "-o LogLevel=quiet -o NumberOfPasswordPrompts=0 " + \
    "-o StrictHostkeyChecking=no -o UserKnownHostsFile=/dev/null"


  # The location on the local filesystem where a monit configuration file can
  # be found that can be used to start the AppController service.
  MONIT_APPCONTROLLER_CONFIG_FILE = os.path.dirname(__file__) + os.sep + \
    ".." + os.sep + "templates" + os.sep + "appcontroller.cfg"


  # The amount of time to wait when waiting for all API services to start on
  # a machine.
  WAIT_TIME = 10


  # The message that is sent if we try to log into a VM as the root user but
  # root login isn't enabled yet.
  LOGIN_AS_UBUNTU_USER = 'Please login as the user "ubuntu" rather than ' + \
    'the user "root".'


  APPCONTROLLER_CRASHLOG_PATH = "/var/log/appscale/appcontroller_crashlog.txt"


  # The location on AppScale VMs where we should mount and unmount the
  # persistent disk.
  PERSISTENT_MOUNT_POINT = "/opt/appscale"


  # The location on AppScale VMs where Google App Engine applications should be
  # uploaded to.
  REMOTE_APP_DIR = "{0}/apps".format(PERSISTENT_MOUNT_POINT)


  # A regular expression that matches AppScale version numbers.
  VERSION_REGEX = "\A\d+\.\d+\.\d+\Z"


  # The directory on AppScale nodes used for storing configuration.
  CONFIG_DIR = '/etc/appscale'


  @classmethod
  def start_head_node(cls, options, my_id, node_layout):
    """Starts the first node in an AppScale deployment and instructs it to start
    API services on its own node, as well as the other nodes in the deployment.

    This includes spawning the first node in the deployment, copying over all
    deployment-specific files to it, and starting its AppController service.

    Args:
      options: A Namespace that includes parameters passed in by the user that
        define non-placement-strategy-related deployment options (e.g., keypair
        names, security group names).
      my_id: A str that is used to uniquely identify this AppScale deployment
        with the remote start application.
      node_layout: A NodeLayout that describes the placement strategy that
        should be used for this AppScale deployment.
    Returns:
      The public IP and instance ID (a dummy value in non-cloud deployments)
      corresponding to the node that was started.
    Raises:
      AppControllerException: If the AppController on the head node crashes.
        The message in this exception indicates why the crash occurred.
    """
    secret_key = LocalState.generate_secret_key(options.keyname)
    AppScaleLogger.verbose("Secret key is {0}".format(secret_key),
      options.verbose)

    if options.infrastructure:
      instance_id, public_ip, private_ip = cls.spawn_node_in_cloud(options)
    else:
      instance_id = cls.DUMMY_INSTANCE_ID
      public_ip = node_layout.head_node().public_ip
      private_ip = node_layout.head_node().private_ip

    AppScaleLogger.log("Log in to your head node: ssh -i {0} root@{1}".format(
      LocalState.get_key_path_from_name(options.keyname), public_ip))

    try:
      cls.ensure_machine_is_compatible(public_ip, options.keyname,
        options.table, options.verbose)
    except AppScaleException as ase:
      # On failure shutdown the cloud instances, cleanup the keys, but only
      # if --test is not set.
      if options.infrastructure:
        if not options.test:
          try:
            cls.terminate_cloud_instance(instance_id, options)
          except Exception as tcie:
            AppScaleLogger.log("Error terminating instances: {0}"
              .format(str(tcie)))
        raise AppScaleException("{0} Please ensure that the "\
          "image {1} has AppScale {2} installed on it."
          .format(str(ase), options.machine, APPSCALE_VERSION))
      else:
        raise AppScaleException("{0} Please login to that machine and ensure "\
          "that AppScale {1} is installed on it."
          .format(str(ase), APPSCALE_VERSION))

    if options.scp:
      AppScaleLogger.log("Copying over local copy of AppScale from {0}".format(
        options.scp))
      cls.rsync_files(public_ip, options.keyname, options.scp, options.verbose)

    # On Euca, we've seen issues where attaching the EBS volume right after
    # the instance starts doesn't work. This sleep lets the instance fully
    # start up and get volumes attached to it correctly.
    if options.infrastructure and options.infrastructure == 'euca' and \
      options.disks:
      time.sleep(30)

    if options.infrastructure:
      agent = InfrastructureAgentFactory.create_agent(options.infrastructure)
      params = agent.get_params_from_args(options)
      additional_params = {}

      if agent.PARAM_CREDENTIALS in params:
        additional_params = params[agent.PARAM_CREDENTIALS]

      if options.use_spot_instances:
        additional_params[agent.PARAM_SPOT_PRICE] = \
          str(params[agent.PARAM_SPOT_PRICE])

      if agent.PARAM_REGION in params:
        additional_params[agent.PARAM_REGION] = params[agent.PARAM_REGION]
    else:
      additional_params = {}

    deployment_params = LocalState.generate_deployment_params(options,
      node_layout, public_ip, additional_params)
    AppScaleLogger.verbose(str(LocalState.obscure_dict(deployment_params)),
      options.verbose)
    AppScaleLogger.log("Head node successfully initialized at {0}.".format(public_ip))

    AppScaleLogger.remote_log_tools_state(options, my_id, "started head node",
      APPSCALE_VERSION)
    time.sleep(10)  # gives machines in cloud extra time to boot up

    cls.copy_deployment_credentials(public_ip, options)
    cls.run_user_commands(public_ip, options.user_commands, options.keyname,
      options.verbose)
    cls.start_remote_appcontroller(public_ip, options.keyname, options.verbose)

    acc = AppControllerClient(public_ip, secret_key)
    locations = [{
      'public_ip' : public_ip,
      'private_ip' : private_ip,
      'jobs' : node_layout.head_node().roles,
      'instance_id' : instance_id,
      'disk' : node_layout.head_node().disk
    }]
    try:
      acc.set_parameters(locations, LocalState.map_to_array(deployment_params))
    except Exception as exception:
      AppScaleLogger.warn('Saw Exception while setting AC parameters: {0}' \
        .format(str(exception)))
      message = RemoteHelper.collect_appcontroller_crashlog(public_ip,
        options.keyname, options.verbose)
      raise AppControllerException(message)

    return public_ip, instance_id


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

    if options.static_ip:
      agent.associate_static_ip(params, instance_ids[0], options.static_ip)
      public_ips[0] = options.static_ip

    AppScaleLogger.log("Please wait for your instance to boot up.")
    cls.sleep_until_port_is_open(public_ips[0], cls.SSH_PORT, options.verbose)

    # Since GCE v1beta15, SSH keys don't immediately get injected to newly
    # spawned VMs. It takes around 30 seconds, so sleep a bit longer to be
    # sure.
    if options.infrastructure == 'gce':
      AppScaleLogger.log("Waiting for SSH keys to get injected to your "
        "machine.")
      time.sleep(60)

    cls.enable_root_login(public_ips[0], options.keyname,
      options.infrastructure, options.verbose)
    cls.copy_ssh_keys_to_node(public_ips[0], options.keyname, options.verbose)
    return instance_ids[0], public_ips[0], private_ips[0]


  @classmethod
  def sleep_until_port_is_open(cls, host, port, is_verbose):
    """Queries the given host to see if the named port is open, and if not,
    waits until it is.

    Args:
      host: A str representing the host whose port we should be querying.
      port: An int representing the port that should eventually be open.
      verbose: A bool that indicates if we should print failure messages to
        stdout (e.g., connection refused messages that can occur when we wait
        for services to come up).
    """
    sleep_time = 1
    while not cls.is_port_open(host, port, is_verbose):
      AppScaleLogger.verbose("Waiting {2} second(s) for {0}:{1} to open".\
        format(host, port, sleep_time), is_verbose)
      time.sleep(sleep_time)
      sleep_time = min(sleep_time * 2, 20)


  @classmethod
  def is_port_open(cls, host, port, is_verbose):
    """Queries the given host to see if the named port is open.

    Args:
      host: A str representing the host whose port we should be querying.
      port: An int representing the port that should eventually be open.
      verbose: A bool that indicates if we should print failure messages to
        stdout (e.g., connection refused messages that can occur when we wait
        for services to come up).
    Returns:
      True if the port is open, False otherwise.
    """
    try:
      sock = socket.socket()
      sock.connect((host, port))
      return True
    except Exception as exception:
      AppScaleLogger.verbose(str(exception), is_verbose)
      return False

  @classmethod
  def merge_authorized_keys(cls, host, keyname, user, is_verbose):
    """ Adds the contents of the user's authorized_keys file to the root's
    authorized_keys file.

    Args:
      host: A str representing the host to enable root logins on.
      keyname: A str representing the name of the SSH keypair to login with.
      user: A str representing the name of the user to login as.
      is_verbose: A bool indicating if we should print the command we execute to
        enable root login to stdout.
    """
    AppScaleLogger.log('Root login not enabled - enabling it now.')

    create_root_keys = 'sudo touch /root/.ssh/authorized_keys'
    cls.ssh(host, keyname, create_root_keys, is_verbose, user=user)

    set_permissions = 'sudo chmod 600 /root/.ssh/authorized_keys'
    cls.ssh(host, keyname, set_permissions, is_verbose, user=user)

    temp_file = cls.ssh(host, keyname, 'mktemp', is_verbose, user=user)

    merge_to_tempfile = 'sudo sort -u ~/.ssh/authorized_keys '\
      '/root/.ssh/authorized_keys -o {}'.format(temp_file)
    cls.ssh(host, keyname, merge_to_tempfile, is_verbose, user=user)

    overwrite_root_keys = "sudo sed -n '/.*Please login/d; "\
      "w/root/.ssh/authorized_keys' {}".format(temp_file)
    cls.ssh(host, keyname, overwrite_root_keys, is_verbose, user=user)

    remove_tempfile = 'rm -f {0}'.format(temp_file)
    cls.ssh(host, keyname, remove_tempfile, is_verbose, user=user)
    return

  @classmethod
  def enable_root_login(cls, host, keyname, infrastructure, is_verbose):
    """Logs into the named host and alters its ssh configuration to enable the
    root user to directly log in.

    Args:
      host: A str representing the host to enable root logins on.
      keyname: A str representing the name of the SSH keypair to login with.
      infrastructure: A str representing the name of the cloud infrastructure
        we're running on.
      is_verbose: A bool indicating if we should print the command we execute to
        enable root login to stdout.
    """
    # First, see if we need to enable root login at all (some VMs have it
    # already enabled).
    try:
      output = cls.ssh(host, keyname, 'ls', is_verbose, user='root')
    except ShellException as exception:
      # Google Compute Engine creates a user with the same name as the currently
      # logged-in user, so log in as that user to enable root login.
      if infrastructure == "gce":
        cls.merge_authorized_keys(host, keyname, getpass.getuser(),
          is_verbose)
        return
      else:
        raise exception

    # Amazon EC2 rejects a root login request and tells the user to log in as
    # the ubuntu user, so do that to enable root login.
    if re.search(cls.LOGIN_AS_UBUNTU_USER, output):
      cls.merge_authorized_keys(host, keyname, 'ubuntu', is_verbose)
    else:
      AppScaleLogger.log("Root login already enabled - not re-enabling it.")


  @classmethod
  def ssh(cls, host, keyname, command, is_verbose, user='root', \
            num_retries=LocalState.DEFAULT_NUM_RETRIES):
    """Logs into the named host and executes the given command.

    Args:
      host: A str representing the machine that we should log into.
      keyname: A str representing the name of the SSH keypair to log in with.
      command: A str representing what to execute on the remote host.
      is_verbose: A bool indicating if we should print the ssh command to
        stdout.
      user: A str representing the user to log in as.
    Returns:
      A str representing the standard output of the remote command and a str
        representing the standard error of the remote command.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    return LocalState.shell("ssh -F /dev/null -i {0} {1} {2}@{3} bash".format(
      ssh_key, cls.SSH_OPTIONS, user, host),
      is_verbose, num_retries, stdin=command)


  @classmethod
  def scp(cls, host, keyname, source, dest, is_verbose, user='root',
    num_retries=LocalState.DEFAULT_NUM_RETRIES):
    """Securely copies a file from this machine to the named machine.

    Args:
      host: A str representing the machine that we should log into.
      keyname: A str representing the name of the SSH keypair to log in with.
      source: A str representing the path on the local machine where the
        file should be copied from.
      dest: A str representing the path on the remote machine where the file
        should be copied to.
      is_verbose: A bool that indicates if we should print the scp command to
        stdout.
      user: A str representing the user to log in as.
    Returns:
      A str representing the standard output of the secure copy and a str
        representing the standard error of the secure copy.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    return LocalState.shell("scp -r -i {0} {1} {2} {3}@{4}:{5}".format(ssh_key,
      cls.SSH_OPTIONS, source, user, host, dest), is_verbose, num_retries)


  @classmethod
  def scp_remote_to_local(cls, host, keyname, source, dest, is_verbose,
    user='root'):
    """Securely copies a file from a remote machine to this machine.

    Args:
      host: A str representing the machine that we should log into.
      keyname: A str representing the name of the SSH keypair to log in with.
      source: A str representing the path on the remote machine where the
        file should be copied from.
      dest: A str representing the path on the local machine where the file
        should be copied to.
      is_verbose: A bool that indicates if we should print the scp command to
        stdout.
      user: A str representing the user to log in as.
    Returns:
      A str representing the standard output of the secure copy and a str
        representing the standard error of the secure copy.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    return LocalState.shell("scp -r -i {0} {1} {2}@{3}:{4} {5}".format(ssh_key,
      cls.SSH_OPTIONS, user, host, source, dest), is_verbose)


  @classmethod
  def copy_ssh_keys_to_node(cls, host, keyname, is_verbose):
    """Sets the given SSH keypair as the default key for the named host,
    enabling it to log into other machines in the AppScale deployment without
    being prompted for a password or explicitly requiring the key to be
    provided.

    Args:
      host: A str representing the machine that we should log into.
      keyname: A str representing the name of the SSH keypair to log in with.
      is_verbose: A bool that indicates if we should print the SCP commands
        needed to copy the SSH keys over to stdout.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    cls.scp(host, keyname, ssh_key, '/root/.ssh/id_dsa', is_verbose)
    cls.scp(host, keyname, ssh_key, '/root/.ssh/id_rsa', is_verbose)
    cls.scp(host, keyname, ssh_key, '/root/.appscale/{0}.key'.format(keyname),
      is_verbose)


  @classmethod
  def ensure_machine_is_compatible(cls, host, keyname, database, is_verbose):
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
      is_verbose: A bool that indicates if we should print the commands we
        execute to validate the machine to stdout.
    Raises:
      AppScaleException: If the specified host does not have AppScale installed,
        has the wrong version of AppScale installed, or does not have the
        correct database installed.
    """
    # first, make sure the image is an appscale image
    if not cls.does_host_have_location(host, keyname, cls.CONFIG_DIR,
      is_verbose):
      raise AppScaleException("The machine at {0} does not have " \
        "AppScale installed.".format(host))

    # Make sure the remote version matches the tools version.
    version_dir = '{}/{}'.format(cls.CONFIG_DIR, APPSCALE_VERSION)
    if not cls.does_host_have_location(host, keyname, version_dir, is_verbose):
      host_version = cls.get_host_appscale_version(host, keyname, is_verbose)
      if host_version:
        raise AppScaleException("The machine at {0} has AppScale {1} installed,"
          " but you are trying to use it with version {2} of the AppScale "
          "Tools. Please use the same version of the AppScale Tools that the "
          "host machine runs.".format(host, host_version, APPSCALE_VERSION))
      else:
        raise AppScaleException("The machine at {0} does not have AppScale "  \
          "{1} installed.".format(host, APPSCALE_VERSION))

    # Make sure we have the requested database installed.
    db_file = '{}/{}/{}'.format(cls.CONFIG_DIR, APPSCALE_VERSION, database)
    if not cls.does_host_have_location(host, keyname, db_file, is_verbose):
      raise AppScaleException("The machine at {0} does not have support for"
        " {1} installed.".format(host, database))


  @classmethod
  def does_host_have_location(cls, host, keyname, location, is_verbose):
    """Logs into the specified host with the given keyname and checks to see if
    the named directory exists there.

    Args:
      host: A str representing a host that should be accessible from this
        machine.
      keyname: A str representing the name of the SSH keypair that can log into
        the specified machine.
      location: The path on the remote filesystem that we should be checking
        for.
      is_verbose: A bool that indicates if we should print the command we
        execute to check the remote host's location to stdout.
    Returns:
      True if the remote host has a file or directory at the specified location,
        False otherwise.
    """
    try:
      cls.ssh(host, keyname, 'ls {0}'.format(location), is_verbose)
      return True
    except ShellException:
      return False


  @classmethod
  def get_host_appscale_version(cls, host, keyname, is_verbose):
    """Logs into the specified host with the given keyname and checks to see
    what version of AppScale is installed there.

    Args:
      host: A str representing a host that should be accessible from this
        machine.
      keyname: A str representing the name of the SSH keypair that can log into
        the specified machine.
      is_verbose: A bool that indicates if we should print the command we
        execute to check the remote host's location to stdout.
    Returns:
      A str containing the version of AppScale installed on host, or None if
      (1) AppScale isn't installed on host, or (2) host has more than one
      version of AppScale installed.
    """
    try:
      etc_appscale_files = cls.ssh(host, keyname,
       'ls {}'.format(cls.CONFIG_DIR), is_verbose)

      # If the host doesn't have an config directory, then the ls command
      # will be empty, so catch that special case here.
      if etc_appscale_files:
        etc_appscale_files = etc_appscale_files.split()
      else:
        return None

      # Only check version files.
      versions_installed = [name for name in etc_appscale_files
        if re.match(cls.VERSION_REGEX, name)]
      if len(versions_installed) == 1:
        return versions_installed[0]
      else:
        return None
    except ShellException:
      return None


  @classmethod
  def rsync_files(cls, host, keyname, local_appscale_dir, is_verbose):
    """Copies over an AppScale source directory from this machine to the
    specified host.

    Args:
      host: A str representing a host that should be accessible from this
        machine.
      keyname: A str representing the name of the SSH keypair that can log into
        the specified machine.
      local_appscale_dir: A str representing the path on the local filesystem
        where the AppScale source to copy over can be found.
      is_verbose: A bool that indicates if we should print the rsync commands
        we exec to stdout.
    Raises:
      BadConfigurationException: If local_appscale_dir does not exist locally,
        or if any of the standard AppScale module folders do not exist.
    """
    ssh_key = LocalState.get_key_path_from_name(keyname)
    local_path = os.path.expanduser(local_appscale_dir)
    if not os.path.exists(local_path):
      raise BadConfigurationException("The location you specified to copy " \
        "from, {0}, doesn't exist.".format(local_path))
    LocalState.shell("rsync -e 'ssh -i {0} {1}' -arv "
      "--exclude='AppDB/logs/*' " \
      "--exclude='AppDB/cassandra/cassandra/*' " \
      "{2}/* root@{3}:/root/appscale/".format(ssh_key, cls.SSH_OPTIONS,
      local_path, host), is_verbose)

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
    local_secret_key = LocalState.get_secret_key_location(options.keyname)
    cls.scp(host, options.keyname, local_secret_key,
      '{}/secret.key'.format(cls.CONFIG_DIR), options.verbose)

    local_ssh_key = LocalState.get_key_path_from_name(options.keyname)
    cls.scp(host, options.keyname, local_ssh_key,
      '{}/ssh.key'.format(cls.CONFIG_DIR), options.verbose)

    LocalState.generate_ssl_cert(options.keyname, options.verbose)

    local_cert = LocalState.get_certificate_location(options.keyname)
    cls.scp(host, options.keyname, local_cert,
      '{}/certs/mycert.pem'.format(cls.CONFIG_DIR), options.verbose)

    local_private_key = LocalState.get_private_key_location(options.keyname)
    cls.scp(host, options.keyname, local_private_key,
      '{}/certs/mykey.pem'.format(cls.CONFIG_DIR), options.verbose)

    hash_id = subprocess.Popen(["openssl", "x509", "-hash", "-noout", "-in",
      LocalState.get_certificate_location(options.keyname)],
      stdout=subprocess.PIPE).communicate()[0]
    symlink_cert = 'ln -fs {}/certs/mycert.pem /etc/ssl/certs/{}.0'.\
      format(cls.CONFIG_DIR, hash_id.rstrip())
    cls.ssh(host, options.keyname, symlink_cert, options.verbose)

    AppScaleLogger.log("Copying over deployment credentials")
    cert = LocalState.get_certificate_location(options.keyname)
    private_key = LocalState.get_private_key_location(options.keyname)

    cls.ssh(host, options.keyname,
      'mkdir -p {}/keys/cloud1'.format(cls.CONFIG_DIR), options.verbose)
    cls.scp(host, options.keyname, cert,
      '{}/keys/cloud1/mycert.pem'.format(cls.CONFIG_DIR), options.verbose)
    cls.scp(host, options.keyname, private_key,
      '{}/keys/cloud1/mykey.pem'.format(cls.CONFIG_DIR), options.verbose)

    # In Google Compute Engine, we also need to copy over our client_secrets
    # file and the OAuth2 file that the user has approved for use with their
    # credentials, otherwise the AppScale VMs won't be able to interact with
    # GCE.
    if options.infrastructure and options.infrastructure == 'gce':
      secrets_location = LocalState.get_client_secrets_location(options.keyname)
      if not os.path.exists(secrets_location):
        raise AppScaleException('{} does not exist.'.format(secrets_location))
      secrets_type = GCEAgent.get_secrets_type(secrets_location)
      cls.scp(host, options.keyname, secrets_location,
        '{}/client_secrets.json'.format(cls.CONFIG_DIR), options.verbose)
      if secrets_type == CredentialTypes.OAUTH:
        local_oauth = LocalState.get_oauth2_storage_location(options.keyname)
        cls.scp(host, options.keyname, local_oauth,
          '{}/oauth2.dat'.format(cls.CONFIG_DIR), options.verbose)

  @classmethod
  def run_user_commands(cls, host, commands, keyname, is_verbose):
    """Runs any commands specified by the user before the AppController is
    started.

    Args:
      host: A str representing the host to start the AppController on.
      commands: A list of strs, where each str is a command that will be
        executed on the remote machine.
      keyname: A str representing the name of the SSH keypair that can log into
        the specified host.
      is_verbose: A bool that indicates if we should print the commands needed
        to start the AppController to stdout.
    """
    if commands:
      AppScaleLogger.log("Running user-specified commands at {0}".format(host))

    for command in commands:
      cls.ssh(host, keyname, command, is_verbose)


  @classmethod
  def start_remote_appcontroller(cls, host, keyname, is_verbose):
    """Starts the AppController daemon on the specified host.

    Args:
      host: A str representing the host to start the AppController on.
      keyname: A str representing the name of the SSH keypair that can log into
        the specified host.
      is_verbose: A bool that indicates if we should print the commands needed
        to start the AppController to stdout.
    """
    AppScaleLogger.log("Starting AppController at {0}".format(host))

    # Remove any previous state. TODO: Don't do this with the tools.
    cls.ssh(host, keyname,
      'rm -rf {}/appcontroller-state.json'.format(cls.CONFIG_DIR), is_verbose)

    # Remove any monit configuration files from previous AppScale deployments.
    cls.ssh(host, keyname, 'rm -rf /etc/monit/conf.d/appscale-*.cfg', is_verbose)

    # Copy over the config file that indicates how the AppController should be
    # started up.
    cls.scp(host, keyname, cls.MONIT_APPCONTROLLER_CONFIG_FILE,
      '/etc/monit/conf.d/appscale-controller-17443.cfg', is_verbose)

    # Start up monit.
    cls.ssh(host, keyname, 'monit quit; ', is_verbose)
    cls.ssh(host, keyname, 'service monit start', is_verbose)
    time.sleep(1)

    # Start the AppController.
    cls.ssh(host, keyname, 'monit start -g controller', is_verbose)
    time.sleep(1)

    AppScaleLogger.log("Please wait for the AppController to finish " + \
      "pre-processing tasks.")

    cls.sleep_until_port_is_open(host, AppControllerClient.PORT, is_verbose)


  @classmethod
  def copy_local_metadata(cls, host, keyname, is_verbose):
    """Copies the locations.yaml and locations.json files found locally (which
    contain metadata about this AppScale deployment) to the specified host.

    Args:
      host: The machine that we should copy the metadata files to.
      keyname: The name of the SSH keypair that we can use to log into the given
        host.
      is_verbose: A bool that indicates if we should print the SCP commands we
        exec to stdout.
    """
    # copy the metadata files for AppScale itself to use
    cls.scp(host, keyname, LocalState.get_locations_yaml_location(keyname),
      '{}/locations-{}.yaml'.format(cls.CONFIG_DIR, keyname), is_verbose)
    cls.scp(host, keyname, LocalState.get_locations_json_location(keyname),
      '{}/locations-{}.json'.format(cls.CONFIG_DIR, keyname), is_verbose)

    # and copy the json file if the tools on that box wants to use it
    cls.scp(host, keyname, LocalState.get_locations_json_location(keyname),
      '/root/.appscale/locations-{0}.json'.format(keyname), is_verbose)

    # and copy the secret file if the tools on that box wants to use it
    cls.scp(host, keyname, LocalState.get_secret_key_location(keyname),
      '/root/.appscale/', is_verbose)


  @classmethod
  def create_user_accounts(cls, email, password, public_ip, keyname,
    clear_datastore):
    """Registers two new user accounts with the UserAppServer.

    One account is the standard account that users log in with (via their
    e-mail address. The other is their XMPP account, so that they can log into
    any jabber-compatible service and send XMPP messages to their application
    (and receive them).

    Args:
      email: The e-mail address that should be registered for the user's
        standard account.
      password: The password that should be used for both the standard and XMPP
        accounts.
      public_ip: The location where the AppController can be found.
      keyname: The name of the SSH keypair used for this AppScale deployment.
      clear_datastore: A bool that indicates if we expect the datastore to be
        emptied, and thus not contain any user accounts.
    """
    acc = AppControllerClient(public_ip, LocalState.get_secret_key(keyname))

    # first, create the standard account
    encrypted_pass = LocalState.encrypt_password(email, password)
    if not clear_datastore and acc.does_user_exist(email):
      AppScaleLogger.log("User {0} already exists, so not creating it again.".
        format(email))
    else:
      acc.create_user(email, encrypted_pass)

    # next, create the XMPP account. if the user's e-mail is a@a.a, then that
    # means their XMPP account name is a@login_ip
    username_regex = re.compile('\A(.*)@')
    username = username_regex.match(email).groups()[0]
    xmpp_user = "{0}@{1}".format(username, LocalState.get_login_host(keyname))
    xmpp_pass = LocalState.encrypt_password(xmpp_user, password)

    if not clear_datastore and acc.does_user_exist(xmpp_user):
      AppScaleLogger.log(
        "XMPP User {0} already exists, so not creating it again.".
        format(xmpp_user))
    else:
      acc.create_user(xmpp_user, xmpp_pass)
    AppScaleLogger.log("Your XMPP username is {0}".format(xmpp_user))


  @classmethod
  def wait_for_machines_to_finish_loading(cls, host, keyname):
    """Queries all of the AppControllers in this AppScale deployment to see if
    they have started all of the API services on their machine, and if not,
    waits until they have.

    Args:
      host: The location where an AppController can be found, who will then have
        the locations of all the other AppControllers in this AppScale
        deployment.
      keyname: The name of the SSH keypair used for this AppScale deployment.
    """
    acc = AppControllerClient(host, LocalState.get_secret_key(keyname))
    all_ips = acc.get_all_public_ips()

    for ip in all_ips:
      while True:
        acc = AppControllerClient(ip, LocalState.get_secret_key(keyname))
        if acc.is_initialized():
          break
        else:
          time.sleep(cls.WAIT_TIME)


  @classmethod
  def terminate_cloud_instance(cls, instance_id, options):
    """ Powers off a single instance in the currently AppScale deployment and
    cleans up AppScale metadata from the local filesystem.

    Args:
      instance_id: A str containing the instance id that should be terminated.
      options: A Namespace containing the credentials necessary to terminate
        the named instance.
    """
    AppScaleLogger.log("About to terminate instance {0}"
      .format(instance_id))
    agent = InfrastructureAgentFactory.create_agent(options.infrastructure)
    params = agent.get_params_from_args(options)
    params['IS_VERBOSE'] = options.verbose
    params[agent.PARAM_INSTANCE_IDS] = [instance_id]
    agent.terminate_instances(params)
    agent.cleanup_state(params)
    os.remove(LocalState.get_secret_key_location(options.keyname))


  @classmethod
  def terminate_cloud_infrastructure(cls, keyname, is_verbose):
    """Powers off all machines in the currently running AppScale deployment.

    Args:
      keyname: The name of the SSH keypair used for this AppScale deployment.
      is_verbose: A bool that indicates if we should print the commands executed
        to stdout.
    """
    AppScaleLogger.log("About to terminate instances spawned with keyname {0}"
      .format(keyname))
    # This sleep is here to allow a moment for user to Ctrl-C
    time.sleep(2)

    # get all the instance IDs for machines in our deployment
    agent = InfrastructureAgentFactory.create_agent(
      LocalState.get_infrastructure(keyname))
    params = agent.get_params_from_yaml(keyname)
    params['IS_VERBOSE'] = is_verbose

    # We want to terminate also the pending instances.
    pending = True
    _, _, instance_ids = agent.describe_instances(params, pending=pending)

    # If using persistent disks, unmount them and detach them before we blow
    # away the instances.
    cls.terminate_virtualized_cluster(keyname, is_verbose)
    nodes = LocalState.get_local_nodes_info(keyname)
    for node in nodes:
      if node.get('disk'):
        AppScaleLogger.log("Unmounting persistent disk at {0}".format(
          node['public_ip']))
        cls.unmount_persistent_disk(node['public_ip'], keyname, is_verbose)
        agent.detach_disk(params, node['disk'], node['instance_id'])

    # terminate all the machines
    params[agent.PARAM_INSTANCE_IDS] = instance_ids
    agent.terminate_instances(params)

    # delete the keyname and group
    agent.cleanup_state(params)


  @classmethod
  def unmount_persistent_disk(cls, host, keyname, is_verbose):
    """Unmounts the persistent disk that was previously mounted on the named
    machine.

    Args:
      host: A str that names the IP address or FQDN where the machine whose
        disk needs to be unmounted can be found.
      keyname: The name of the SSH keypair used for this AppScale deployment.
      is_verbose: A bool that indicates if we should print the commands executed
        to stdout.
    """
    try:
      remote_output = cls.ssh(host, keyname, 'umount {0}'.format(
        cls.PERSISTENT_MOUNT_POINT), is_verbose)
      AppScaleLogger.verbose(remote_output, is_verbose)
    except ShellException:
      pass


  @classmethod
  def terminate_virtualized_cluster(cls, keyname, is_verbose):
    """Stops all API services running on all nodes in the currently running
    AppScale deployment.

    Args:
      keyname: The name of the SSH keypair used for this AppScale deployment.
      is_verbose: A bool that indicates if we should print the commands executed
        to stdout.
    """
    AppScaleLogger.log("Terminating instances in a virtualized cluster with " +
      "keyname {0}".format(keyname))
    time.sleep(2)

    shadow_host = LocalState.get_host_with_role(keyname, 'shadow')
    acc = AppControllerClient(shadow_host, LocalState.get_secret_key(keyname))

    try:
      all_ips = acc.get_all_public_ips()
    except Exception as exception:
      AppScaleLogger.warn('Saw Exception while getting deployments IPs {0}' \
        .format(str(exception)))
      all_ips = LocalState.get_all_public_ips(keyname)

    threads = []
    for ip in all_ips:
      thread = threading.Thread(target=cls.stop_remote_appcontroller, args=(ip,
        keyname, is_verbose))
      thread.start()
      threads.append(thread)

    for thread in threads:
      thread.join()

    boxes_shut_down = 0
    is_running_regex = re.compile("appscale-controller stop")
    for ip in all_ips:
      AppScaleLogger.log("Shutting down AppScale API services at {0}".format(
        ip))
      while True:
        remote_output = cls.ssh(ip, keyname, 'ps x', is_verbose)
        AppScaleLogger.verbose(remote_output, is_verbose)
        if not is_running_regex.match(remote_output):
          break
        time.sleep(0.3)
      boxes_shut_down += 1

    if boxes_shut_down != len(all_ips):
      raise AppScaleException("Couldn't terminate your AppScale deployment " + \
        "on all machines - please do so manually.")

    AppScaleLogger.log("Terminated AppScale on {0} machines."
      .format(boxes_shut_down))


  @classmethod
  def stop_remote_appcontroller(cls, host, keyname, is_verbose):
    """Stops the AppController daemon on the specified host.

    Tries the stop command twice, just to make sure that the AppController gets
    the message.

    Args:
      host: The location of the AppController to stop.
      keyname: The name of the SSH keypair used for this AppScale deployment.
      is_verbose: A bool that indicates if we should print the stop commands we
        exec to stdout.
    """
    cls.ssh(host, keyname, 'ruby /root/appscale/AppController/terminate.rb',
      is_verbose)


  @classmethod
  def copy_app_to_host(cls, app_location, keyname, is_verbose):
    """Copies the given application to a machine running the Login service
    within an AppScale deployment.

    Args:
      app_location: The location on the local filesystem where the application
        can be found.
      keyname: The name of the SSH keypair that uniquely identifies this
        AppScale deployment.
      is_verbose: A bool that indicates if we should print the commands we exec
        to copy the app to the remote host to stdout.

    Returns:
      A str corresponding to the location on the remote filesystem where the
        application was copied to.
    """
    app_id = AppEngineHelper.get_app_id_from_app_config(app_location)

    AppScaleLogger.log("Tarring application")
    rand = str(uuid.uuid4()).replace('-', '')[:8]
    local_tarred_app = "{0}/appscale-app-{1}-{2}.tar.gz".format(tempfile.gettempdir(),
      app_id, rand)
    LocalState.shell("cd '{0}' && COPYFILE_DISABLE=1 tar -czhf {1} --exclude='*.pyc' *".format(
      app_location, local_tarred_app), is_verbose)

    AppScaleLogger.log("Copying over application")
    remote_app_tar = "{0}/{1}.tar.gz".format(cls.REMOTE_APP_DIR, app_id)
    cls.scp(LocalState.get_login_host(keyname), keyname, local_tarred_app,
      remote_app_tar, is_verbose)

    os.remove(local_tarred_app)
    return remote_app_tar


  @classmethod
  def collect_appcontroller_crashlog(cls, host, keyname, is_verbose):
    """ Reads the crashlog that the AppController writes on its own machine
    indicating why it crashed, so that we can pass this information on to the
    user.

    Args:
      host: A str indicating the FQDN or IP address where the crashed
        AppController can be found.
      keyname: The name of the SSH keypair that uniquely identifies this
        AppScale deployment.
      is_verbose: A bool that indicates if we should print the commands we exec
        to get the crashlog info.

    Returns:
      A str corresponding to the message that indicates why the AppController
        crashed.
    """
    message = ""
    try:
      local_crashlog = "{0}/appcontroller-log-{1}".format(
        tempfile.gettempdir(), uuid.uuid4())
      cls.scp_remote_to_local(host, keyname, cls.APPCONTROLLER_CRASHLOG_PATH,
        local_crashlog, is_verbose)
      with open(local_crashlog, 'r') as file_handle:
        message = "AppController at {0} crashed because: {1}".format(host,
          file_handle.read())
      os.remove(local_crashlog)
    except ShellException:
      message = "AppController at {0} crashed for reasons unknown.".format(host)

    return message
