#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import re
import socket
import subprocess
import sys
import tempfile
import time


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory
from appcontroller_client import AppControllerClient
from appscale_logger import AppScaleLogger
from custom_exceptions import AppScaleException
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException
from local_state import APPSCALE_VERSION
from local_state import LocalState
from user_app_client import UserAppClient


class RemoteHelper():
  """RemoteHelper provides a simple interface to interact with other machines
  (typically, AppScale virtual machines).

  This includes the ability to start services on remote machines and copy files
  to them.
  """


  # The number of times to execute shell commands before aborting, by default.
  DEFAULT_NUM_RETRIES = 5


  DUMMY_INSTANCE_ID = "i-ZFOOBARZ"


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
    Returns:
      The public IP and instance ID (a dummy value in non-cloud deployments)
      corresponding to the node that was started.
    """
    secret_key = LocalState.generate_secret_key(options.keyname)
    AppScaleLogger.verbose("Secret key is {0}".format(secret_key),
      options.verbose)

    if options.infrastructure:
      instance_id, public_ip, private_ip = cls.spawn_node_in_cloud(options)
    else:
      instance_id = cls.DUMMY_INSTANCE_ID
      public_ip = node_layout.head_node().id
      private_ip = node_layout.head_node().id

    AppScaleLogger.log("Log in to your head node: ssh -i {0} root@{1}".format(
      LocalState.get_key_path_from_name(options.keyname), public_ip))

    cls.ensure_machine_is_compatible(public_ip, options.keyname, options.table,
      options.verbose)
    if options.scp:
      AppScaleLogger.log("Copying over local copy of AppScale from {0}".format(
        options.scp))
      cls.rsync_files(public_ip, options.keyname, options.scp, options.verbose)

    if options.infrastructure:
      agent = InfrastructureAgentFactory.create_agent(options.infrastructure)
      params = agent.get_params_from_args(options)
      additional_params = params[agent.PARAM_CREDENTIALS]
    else:
      additional_params = {}

    deployment_params = LocalState.generate_deployment_params(options,
      node_layout, public_ip, additional_params)
    AppScaleLogger.verbose(str(LocalState.obscure_dict(deployment_params)),
      options.verbose)
    AppScaleLogger.log("Head node successfully initialized at {0}. It is now starting up {1}.".format(public_ip, options.table))

    AppScaleLogger.remote_log_tools_state(options, "started head node")
    time.sleep(10)  # gives machines in cloud extra time to boot up

    cls.copy_deployment_credentials(public_ip, options)
    cls.start_remote_appcontroller(public_ip, options.keyname, options.verbose)

    acc = AppControllerClient(public_ip, secret_key)
    locations = ["{0}:{1}:{2}:{3}:cloud1".format(public_ip, private_ip,
      ":".join(node_layout.head_node().roles), instance_id)]
    acc.set_parameters(locations, LocalState.map_to_array(deployment_params))

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
    AppScaleLogger.log("Please wait for your instance to boot up.")
    cls.sleep_until_port_is_open(public_ips[0], cls.SSH_PORT, options.verbose)
    time.sleep(10)

    cls.enable_root_login(public_ips[0], options.keyname, options.infrastructure,
      options.verbose)
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
      AppScaleLogger.verbose("Waiting for {0}:{1} to open".format(host, port),
        is_verbose)
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
    try:
      cls.ssh(host, keyname, 'sudo cp ~/.ssh/authorized_keys /root/.ssh/',
        is_verbose, user='ubuntu')
    except ShellException as exception:
      if infrastructure == 'euca':
        AppScaleLogger.warn("Couldn't enable root login - it may already " + \
          "be enabled")
      else:
        raise exception


  @classmethod
  def ssh(cls, host, keyname, command, is_verbose, user='root'):
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
    return cls.shell("ssh -i {0} {1} {2}@{3} '{4}'".format(ssh_key,
      cls.SSH_OPTIONS, user, host, command), is_verbose)


  @classmethod
  def scp(cls, host, keyname, source, dest, is_verbose, user='root'):
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
    return cls.shell("scp -i {0} {1} {2} {3}@{4}:{5}".format(ssh_key,
      cls.SSH_OPTIONS, source, user, host, dest), is_verbose)


  @classmethod
  def shell(cls, command, is_verbose, num_retries=DEFAULT_NUM_RETRIES):
    """Executes a command on this machine, retrying it up to five times if it
    initially fails.

    Args:
      command: A str representing the command to execute.
      is_verbose: A bool that indicates if we should print the command we are
        executing to stdout.
      num_retries: The number of times we should try to execute the given
        command before aborting.
    Returns:
      The standard output and standard error produced when the command executes.
    Raises:
      ShellException: If, after five attempts, executing the named command
      failed.
    """
    tries_left = num_retries
    while tries_left:
      AppScaleLogger.verbose("shell> {0}".format(command), is_verbose)
      the_temp_file = tempfile.TemporaryFile()
      result = subprocess.Popen(command, shell=True, stdout=the_temp_file,
        stderr=sys.stdout)
      result.wait()
      if result.returncode == 0:
        output = the_temp_file.read()
        the_temp_file.close()
        return output
      AppScaleLogger.verbose("Command failed. Trying again momentarily." \
        .format(command), is_verbose)
      tries_left -= 1
      time.sleep(1)
    raise ShellException('Could not execute command: {0}'.format(command))


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
    if not cls.does_host_have_location(host, keyname, '/etc/appscale',
      is_verbose):
      raise AppScaleException("The machine at {0} does not have AppScale " + \
        "installed. Please install AppScale on it and try again.".format(host))

    # next, make sure it has the same version of appscale installed as the tools
    if not cls.does_host_have_location(host, keyname,
      '/etc/appscale/{0}'.format(APPSCALE_VERSION), is_verbose):
      raise AppScaleException("The machine at {0} does not have AppScale " + \
        "{1} installed. Please install AppScale {1} on it and try again." \
          .format(host, APPSCALE_VERSION))

    # finally, make sure it has the database installed that the user requests
    if not cls.does_host_have_location(host, keyname,
      '/etc/appscale/{0}/{1}'.format(APPSCALE_VERSION, database), is_verbose):
      raise AppScaleException("The machine at {0} does not have support for" + \
        " {1} installed. Please provide a machine image that does and try " + \
        "again.".format(host, database))


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
    appscale_dirs = ["lib", "AppController", "AppManager", "AppServer",
      "AppLoadBalancer", "AppMonitoring", "Neptune", "InfrastructureManager"]
    for dir_name in appscale_dirs:
      local_path = os.path.expanduser(local_appscale_dir) + os.sep + dir_name
      if not os.path.exists(local_path):
        raise BadConfigurationException("The location you specified to copy " +
          "from, {0}, doesn't contain a {1} folder.".format(local_appscale_dir,
          local_path))
      cls.shell("rsync -e 'ssh -i {0} {1}' -arv {2}/* root@{3}:/root/appscale/{4}" \
        .format(ssh_key, cls.SSH_OPTIONS, local_path, host, dir_name), is_verbose)

    # Rsync AppDB separately, as it has a lot of paths we may need to exclude
    # (e.g., built database binaries).
    local_app_db = os.path.expanduser(local_appscale_dir) + os.sep + "AppDB/*"
    cls.shell("rsync -e 'ssh -i {0} {1}' -arv --exclude='logs/*' --exclude='hadoop-*' --exclude='hbase/hbase-*' --exclude='voldemort/voldemort/*' --exclude='cassandra/cassandra/*' {2} root@{3}:/root/appscale/AppDB".format(ssh_key, cls.SSH_OPTIONS, local_app_db, host), is_verbose)


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
      options.keyname), '/etc/appscale/secret.key', options.verbose)
    cls.scp(host, options.keyname, LocalState.get_key_path_from_name(
      options.keyname), '/etc/appscale/ssh.key', options.verbose)

    LocalState.generate_ssl_cert(options.keyname)
    cls.scp(host, options.keyname, LocalState.get_certificate_location(
      options.keyname), '/etc/appscale/certs/mycert.pem', options.verbose)
    cls.scp(host, options.keyname, LocalState.get_private_key_location(
      options.keyname), '/etc/appscale/certs/mykey.pem', options.verbose)

    AppScaleLogger.log("Copying over deployment credentials")
    if options.infrastructure:
      cert = os.environ["EC2_CERT"]
      private_key = os.environ["EC2_PRIVATE_KEY"]
    else:
      cert = LocalState.get_certificate_location(options.keyname)
      private_key = LocalState.get_private_key_location(options.keyname)

    cls.ssh(host, options.keyname, 'mkdir -p /etc/appscale/keys/cloud1',
      options.verbose)
    cls.scp(host, options.keyname, cert, "/etc/appscale/keys/cloud1/mycert.pem",
      options.verbose)
    cls.scp(host, options.keyname, private_key,
      "/etc/appscale/keys/cloud1/mykey.pem", options.verbose)


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

    # remove any possible appcontroller state that may not have been
    # properly removed in virtualized clusters
    cls.ssh(host, keyname, 'rm -rf /etc/appscale/appcontroller-state.json',
      is_verbose)

    # start up god, who will start up the appcontroller once we give it the
    # right config file
    cls.ssh(host, keyname, 'god &', is_verbose)
    time.sleep(1)

    # scp over that config file
    cls.scp(host, keyname, cls.TEMPLATE_GOD_CONFIG_FILE,
      '/tmp/appcontroller.god', is_verbose)

    # finally, tell god to start the appcontroller and then wait for it to start
    cls.ssh(host, keyname, 'god load /tmp/appcontroller.god', is_verbose)

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
      '/etc/appscale/locations-{0}.yaml'.format(keyname), is_verbose)
    cls.scp(host, keyname, LocalState.get_locations_json_location(keyname),
      '/etc/appscale/locations-{0}.json'.format(keyname), is_verbose)

    # and copy the json file if the tools on that box wants to use it
    cls.scp(host, keyname, LocalState.get_locations_json_location(keyname),
      '/root/.appscale/locations-{0}.json'.format(keyname), is_verbose)

  
  @classmethod
  def create_user_accounts(cls, email, password, uaserver_host, keyname):
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
      uaserver_host: The location of a UserAppClient, that can create new user
        accounts.
      keyname: The name of the SSH keypair used for this AppScale deployment.
    """
    uaserver = UserAppClient(uaserver_host, LocalState.get_secret_key(keyname))

    # first, create the standard account
    encrypted_pass = LocalState.encrypt_password(email, password)
    uaserver.create_user(email, encrypted_pass)

    # next, create the XMPP account. if the user's e-mail is a@a.a, then that
    # means their XMPP account name is a@login_ip
    username_regex = re.compile('\A(.*)@')
    username = username_regex.match(email).groups()[0]
    xmpp_user = "{0}@{1}".format(username, LocalState.get_login_host(keyname))
    xmpp_pass = LocalState.encrypt_password(xmpp_user, password)
    uaserver.create_user(xmpp_user, xmpp_pass)
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
          time.sleep(10)
