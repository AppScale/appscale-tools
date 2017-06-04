#!/usr/bin/env python

# General-purpose Python library imports
import datetime
import errno
import getpass
import json
import os
import Queue
import re
import shutil
import socket
import sys
import threading
import time
import traceback
import urllib2
import uuid

from collections import Counter
from itertools import chain

# AppScale-specific imports
from tabulate import tabulate
from SOAPpy import faultType

from agents.factory import InfrastructureAgentFactory
from appcontroller_client import AppControllerClient
from appengine_helper import AppEngineHelper
from appscale_logger import AppScaleLogger
from cluster_stats import NodeStats, AppInfo
from custom_exceptions import AppControllerException
from custom_exceptions import AppEngineConfigException
from custom_exceptions import AppScaleException
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException
from local_state import APPSCALE_VERSION
from local_state import LocalState
from node_layout import NodeLayout
from remote_helper import RemoteHelper
from version_helper import latest_tools_version
from .admin_client import AdminClient


def async_layout_upgrade(ip, keyname, script, error_bucket, verbose=False):
  """ Run a command over SSH and place exceptions in a bucket.

  Args:
    ip: A string containing and IP address.
    keyname: A string containing the deployment keyname.
    script: A string to run as a command over SSH.
    error_bucket: A thread-safe queue.
    verbose: A boolean indicating whether or not to log verbosely.
  """
  try:
    RemoteHelper.ssh(ip, keyname, script, verbose)
  except ShellException as ssh_error:
    error_bucket.put(ssh_error)


MIN_FREE_DISK_DB = 40.0
MIN_FREE_DISK = 10.0
MIN_AVAILABLE_MEMORY = 7.0
MAX_LOADAVG = 3.0


class AppScaleTools(object):
  """AppScaleTools provides callers with a way to start, stop, and interact
  with AppScale deployments, on virtualized clusters or on cloud
  infrastructures.

  These methods provide an interface for users who wish to start and control
  AppScale through a dict of parameters. An alternative to this method is to
  use the AppScale class, which stores state in an AppScalefile in the
  current working directory (as opposed to a dict), but under the hood these
  methods get called anyways.
  """


  # The number of seconds to wait to give services time to start up or shut
  # down.
  SLEEP_TIME = 5


  # The maximum number of times we should retry for methods that take longer.
  MAX_RETRIES = 20


  # The number of seconds to wait before giving up on an operation.
  MAX_OPERATION_TIME = 100


  # The location of the expect script, used to interact with ssh-copy-id
  EXPECT_SCRIPT = os.path.join(
    os.path.dirname(sys.modules['appscale.tools'].__file__),
    'templates/sshcopyid')


  # A regular expression that matches files compressed in the tar.gz format.
  TAR_GZ_REGEX = re.compile(r'.tar.gz\Z')


  # A regular expression that matches files compressed in the zip format.
  ZIP_REGEX = re.compile(r'.zip\Z')


  # A str that contains all of the authorizations that an AppScale cloud
  # administrator should be granted.
  ADMIN_CAPABILITIES = "upload_app"


  # AppScale repository location on an AppScale image.
  APPSCALE_REPO = "~/appscale"


  # Bootstrap command to run.
  BOOTSTRAP_CMD = '{}/bootstrap.sh >> /var/log/appscale/bootstrap.log'.\
    format(APPSCALE_REPO)


  # Command to run the upgrade script from /appscale/scripts directory.
  UPGRADE_SCRIPT = "python " + APPSCALE_REPO + "/scripts/upgrade.py"


  # Template used for GitHub API calls.
  GITHUB_API = 'https://api.github.com/repos/{owner}/{repo}'


  # Location of the upgrade status file on the remote machine.
  UPGRADE_STATUS_FILE_LOC = '/var/log/appscale/upgrade-status-'

  @classmethod
  def add_instances(cls, options):
    """Adds additional machines to an AppScale deployment.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    """
    if 'master' in options.ips.keys():
      raise BadConfigurationException("Cannot add master nodes to an " + \
        "already running AppScale deployment.")

    # Skip checking for -n (replication) because we don't allow the user
    # to specify it here (only allowed in run-instances).
    additional_nodes_layout = NodeLayout(options)

    # In virtualized cluster deployments, we need to make sure that the user
    # has already set up SSH keys.
    if LocalState.get_infrastructure_option(keyname=options.keyname,
                                            tag='infrastructure') == "xen":
      ips_to_check = []
      for ip_group in options.ips.values():
        ips_to_check.extend(ip_group)
      for ip in ips_to_check:
        # throws a ShellException if the SSH key doesn't work
        RemoteHelper.ssh(ip, options.keyname, "ls", options.verbose)

    # Finally, find an AppController and send it a message to add
    # the given nodes with the new roles.
    AppScaleLogger.log("Sending request to add instances")
    login_ip = LocalState.get_login_host(options.keyname)
    acc = AppControllerClient(login_ip, LocalState.get_secret_key(
      options.keyname))
    acc.start_roles_on_nodes(json.dumps(options.ips))

    # TODO(cgb): Should we wait for the new instances to come up and get
    # initialized?
    AppScaleLogger.success("Successfully sent request to add instances " + \
      "to this AppScale deployment.")


  @classmethod
  def add_keypair(cls, options):
    """Sets up passwordless SSH login to the machines used in a virtualized
    cluster deployment.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    Raises:
      AppScaleException: If any of the machines named in the ips_layout are
        not running, or do not have the SSH daemon running.
    """
    LocalState.require_ssh_commands(options.auto, options.verbose)
    LocalState.make_appscale_directory()

    path = LocalState.LOCAL_APPSCALE_PATH + options.keyname
    if options.add_to_existing:
      public_key = path + ".pub"
      private_key = path
    else:
      public_key, private_key = LocalState.generate_rsa_key(options.keyname,
        options.verbose)

    if options.auto:
      if 'root_password' in options:
        AppScaleLogger.log("Using the provided root password to log into " + \
          "your VMs.")
        password = options.root_password
      else:
        AppScaleLogger.log("Please enter the password for the root user on" + \
          " your VMs:")
        password = getpass.getpass()

    node_layout = NodeLayout(options)
    if not node_layout.is_valid():
      raise BadConfigurationException("There were problems with your " + \
        "placement strategy: " + str(node_layout.errors()))

    all_ips = [node.public_ip for node in node_layout.nodes]
    for ip in all_ips:
      # first, make sure ssh is actually running on the host machine
      if not RemoteHelper.is_port_open(ip, RemoteHelper.SSH_PORT,
        options.verbose):
        raise AppScaleException("SSH does not appear to be running at {0}. " \
          "Is the machine at {0} up and running? Make sure your IPs are " \
          "correct!".format(ip))

      # next, set up passwordless ssh
      AppScaleLogger.log("Executing ssh-copy-id for host: {0}".format(ip))
      if options.auto:
        LocalState.shell("{0} root@{1} {2} {3}".format(cls.EXPECT_SCRIPT, ip,
          private_key, password), options.verbose)
      else:
        LocalState.shell("ssh-copy-id -i {0} root@{1}".format(private_key, ip),
          options.verbose)

    AppScaleLogger.success("Generated a new SSH key for this deployment " + \
      "at {0}".format(private_key))


  @classmethod
  def print_cluster_status(cls, options):
    """
    Gets cluster stats and prints it nicely.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    """
    try:
      login_host = LocalState.get_login_host(options.keyname)
      login_acc = AppControllerClient(login_host,
        LocalState.get_secret_key(options.keyname))
      all_private_ips = login_acc.get_all_private_ips()
      cluster_stats = login_acc.get_cluster_stats()
    except (faultType, AppControllerException, BadConfigurationException):
      AppScaleLogger.warn("AppScale deployment is probably down")
      raise

    # Convert cluster stats to useful structures
    node_stats = {
      ip: next((n for n in cluster_stats if n["private_ip"] == ip), None)
      for ip in all_private_ips
    }
    apps_dict = next((n["apps"] for n in cluster_stats if n["apps"]), {})
    apps = [AppInfo(name, app_info) for name, app_info in apps_dict.iteritems()]
    nodes = [NodeStats(ip, node) for ip, node in node_stats.iteritems() if node]
    invisible_nodes = [ip for ip, node in node_stats.iteritems() if not node]

    if options.verbose:
      AppScaleLogger.log("-"*76)
      cls._print_nodes_info(nodes, invisible_nodes)
      cls._print_roles_info(nodes)
    else:
      AppScaleLogger.log("-"*76)

    cls._print_cluster_summary(nodes, invisible_nodes, apps)
    cls._print_apps(apps)
    cls._print_status_alerts(nodes)

    dashboard = next(
      (app for app in apps if app.http == RemoteHelper.APP_DASHBOARD_PORT), None
    )
    if dashboard and dashboard.appservers > 1:
      AppScaleLogger.success(
        "\nView more about your AppScale deployment at http://{}:{}/status"
        .format(login_host, RemoteHelper.APP_DASHBOARD_PORT)
      )
    else:
      AppScaleLogger.log(
        "\nAs soon as AppScale Dashboard is started you can visit it at "
        "http://{0}:{1}/status and see more about your deployment"
        .format(login_host, RemoteHelper.APP_DASHBOARD_PORT)
      )

  @classmethod
  def _print_nodes_info(cls, nodes, invisible_nodes):
    """ Prints table with details about cluster nodes
    Args:
      nodes: a list of NodeStats
      invisible_nodes: a list of IPs of nodes which didn't report its stats
    """
    header = (
      "PUBLIC IP", "PRIVATE IP", "I/L*", "CPU%xCORES", "MEMORY%", "DISK%",
      "LOADAVG", "ROLES"
    )
    table = [
      (n.public_ip, n.private_ip,
       "{}/{}".format("+" if n.is_initialized else "-",
                      "+" if n.is_loaded else "-"),
       "{:.1f}x{}".format(n.cpu.load, n.cpu.count),
       100.0 - n.memory.available_percent,
       " ".join("{:.1f}".format(p.used_percent) for p in n.disk.partitions),
       "{:.1f} {:.1f} {:.1f}".format(
         n.loadavg.last_1_min, n.loadavg.last_5_min, n.loadavg.last_15_min),
       " ".join(n.roles))
      for n in nodes
    ]
    table += [("?", ip, "?", "?", "?", "?", "?", "?") for ip in invisible_nodes]
    table_str = tabulate(table, header, tablefmt="plain", floatfmt=".1f")
    AppScaleLogger.log(table_str)
    AppScaleLogger.log("* I/L means 'Is node Initialized'/'Is node Loaded'")

  @classmethod
  def _print_roles_info(cls, nodes):
    """ Prints table with roles and number of nodes serving each specific role
    Args:
      nodes: a list of NodeStats
    """
    # Report number of nodes and roles running in the cluster
    roles_counter = Counter(chain(*[node.roles for node in nodes]))
    header = ("ROLE", "COUNT")
    table = roles_counter.iteritems()
    AppScaleLogger.log("\n" + tabulate(table, headers=header, tablefmt="plain"))

  @classmethod
  def _print_cluster_summary(cls, nodes, invisible_nodes, apps):
    """ Prints summary about deployment state
    Args:
      nodes: a list of NodeStats
      invisible_nodes: IPs of nodes which didn't report its status yet
      apps: a list of AppInfo
    """
    loaded = sum(1 for node in nodes if node.is_loaded)
    initialized = sum(1 for node in nodes if node.is_initialized)
    started_apps = sum(1 for app in apps if app.appservers > 0)
    total = len(nodes)

    if invisible_nodes:
      # We don't have full information about cluster
      AppScaleLogger.warn(
        "\nThere are {nodes} nodes that didn't report it's state"
        .format(nodes=len(invisible_nodes))
      )
      if nodes:
        AppScaleLogger.log(
          "Available stats for {n} nodes: {init} are initialized, {loaded} "
          "are loaded, {started} of {apps} apps are started".format(
            init=initialized, loaded=loaded, n=total, started=started_apps,
            apps=len(apps))
        )
      else:
        AppScaleLogger.log("No stats is available yet.")
      return

    if loaded < total or initialized < total or started_apps < len(apps):
      AppScaleLogger.log(
        "\nAppScale is starting: {init} of {n} nodes are initialized, {loaded} "
        "of {n} nodes are loaded, {started} of {apps} apps are started"
        .format(init=initialized, loaded=loaded, n=total, started=started_apps,
                apps=len(apps))
      )
    else:
      AppScaleLogger.success(
        "\nAppScale is up. All {n} nodes are loaded".format(n=total)
      )

  @classmethod
  def _print_apps(cls, apps):
    """ Prints main information about deployed apps
    Args:
      apps: a list AppInfo
    """
    header = (
      "APP NAME", "HTTP/HTTPS", "APPSERVERS/PENDING",
      "REQS. ENQUEUED/TOTAL", "STATE"
    )
    table = (
      (app.name, "{}/{}".format(app.http, app.https),
       "{}/{}".format(app.appservers, app.pending_appservers),
       "{}/{}".format(app.reqs_enqueued, app.total_reqs),
       "Ready" if app.appservers > 0 else "Starting")
      for app in apps
    )
    AppScaleLogger.log("\n" + tabulate(table, headers=header, tablefmt="plain"))

  @classmethod
  def _print_status_alerts(cls, nodes):
    """ Detects if there are hardware issues in the cluster and prints
        all detected problems
    Args:
      nodes: a list of NodeStats
    """
    hardware_alerts = []
    for node in nodes:
      # Check disk space
      db_roles = ["db_master", "db_slave", "database"]
      is_db_node = any(role in node.roles for role in db_roles)
      partition = node.disk.most_loaded
      if is_db_node and partition.free_percent < MIN_FREE_DISK_DB:
        msg = ("Only {free:.1f}% of '{part}' partition at db node is free"
               .format(free=partition.free_percent, part=partition.mountpoint))
        hardware_alerts.append((node, msg))
      elif partition.free_percent < MIN_FREE_DISK:
        msg = ("Only {free:.1f}% of '{part}' partition is free"
               .format(free=partition.free_percent, part=partition.mountpoint))
        hardware_alerts.append((node, msg))

      # Check memory
      if node.memory.available_percent < MIN_AVAILABLE_MEMORY:
        msg = ("Only {available:.1f}% of memory is available"
               .format(available=node.memory.available_percent))
        hardware_alerts.append((node, msg))

      # Check average load
      is_overloaded = any((
        node.loadavg.last_1_min / node.cpu.count > MAX_LOADAVG,
        node.loadavg.last_5_min / node.cpu.count > MAX_LOADAVG,
        node.loadavg.last_15_min / node.cpu.count > MAX_LOADAVG,
      ))
      if is_overloaded:
        msg = ("Average load is too high for {} CPUs: {:.1f} {:.1f} {:.1f}"
               .format(node.cpu.count, node.loadavg.last_1_min,
                       node.loadavg.last_5_min,
                       node.loadavg.last_15_min))
        hardware_alerts.append((node, msg))

    if hardware_alerts:
      AppScaleLogger.warn("\nSome nodes are in alarm state:")
      header = ("PUBLIC IP", "PRIVATE IP", "ALERT MESSAGE")
      table = ((n.public_ip, n.private_ip, msg) for n, msg in hardware_alerts)
      AppScaleLogger.warn(tabulate(table, headers=header, tablefmt="plain"))


  @classmethod
  def gather_logs(cls, options):
    """Collects logs from each machine in the currently running AppScale
    deployment.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    """
    # First, make sure that the place we want to store logs doesn't
    # already exist.
    if os.path.exists(options.location):
      raise AppScaleException("Can't gather logs, as the location you " + \
        "specified, {0}, already exists.".format(options.location))

    acc = AppControllerClient(LocalState.get_login_host(options.keyname),
      LocalState.get_secret_key(options.keyname))

    try:
      all_ips = acc.get_all_public_ips()
    except socket.error:  # Occurs when the AppController has failed.
      AppScaleLogger.warn("Couldn't get an up-to-date listing of the " + \
        "machines in this AppScale deployment. Using our locally cached " + \
        "info instead.")
      all_ips = LocalState.get_all_public_ips(options.keyname)

    # do the mkdir after we get the secret key, so that a bad keyname will
    # cause the tool to crash and not create this directory
    os.mkdir(options.location)

    # The log paths that we collect logs from.
    log_paths = [
      {'remote': '/opt/cassandra/cassandra/logs/*', 'local': 'cassandra'},
      {'remote': '/var/log/appscale'},
      {'remote': '/var/log/haproxy.log*'},
      {'remote': '/var/log/kern.log*'},
      {'remote': '/var/log/monit.log*'},
      {'remote': '/var/log/nginx'},
      {'remote': '/var/log/rabbitmq/*', 'local': 'rabbitmq'},
      {'remote': '/var/log/syslog*'},
      {'remote': '/var/log/zookeeper'}
    ]

    failures = False
    for ip in all_ips:
      # Get the logs from each node, and store them in our local directory
      local_dir = "{0}/{1}".format(options.location, ip)
      os.mkdir(local_dir)

      for log_path in log_paths:
        sub_dir = local_dir

        if 'local' in log_path:
          sub_dir = os.path.join(local_dir, log_path['local'])
          try:
            os.mkdir(sub_dir)
          except OSError as os_error:
            if os_error.errno == errno.EEXIST and os.path.isdir(sub_dir):
              pass
            else:
              raise

        try:
          RemoteHelper.scp_remote_to_local(
            ip, options.keyname, log_path['remote'], sub_dir, options.verbose)
        except ShellException as shell_exception:
          failures = True
          AppScaleLogger.warn('Unable to collect logs from {} for host {}'.
                              format(log_path['remote'], ip))
          AppScaleLogger.verbose(
            'Encountered exception: {}'.format(str(shell_exception)),
            options.verbose)

    if failures:
      AppScaleLogger.log("Done copying to {0}. There were "
        "failures while collecting AppScale logs.".format(
        options.location))
    else:
      AppScaleLogger.success("Successfully collected all AppScale logs into "
        "{0}".format(options.location))


  @classmethod
  def get_property(cls, options):
    """Queries AppScale for a list of system properties matching the provided
    regular expression, as well as the values associated with each matching
    property.

    Args:
      options: A Namespace that has fields for each parameter that can be passed
        in via the command-line interface.
    Returns:
      A dict mapping each property matching the given regex to its associated
      value.
    """
    shadow_host = LocalState.get_host_with_role(options.keyname, 'shadow')
    acc = AppControllerClient(shadow_host, LocalState.get_secret_key(
      options.keyname))

    return acc.get_property(options.property)


  @classmethod
  def relocate_app(cls, options):
    """Instructs AppScale to move the named application to a different port.

    Args:
      options: A Namespace that has fields for each parameter that can be passed
        in via the command-line interface.
    Raises:
      AppScaleException: If the named application isn't running in this AppScale
        cloud, if the destination port is in use by a different application, or
        if the AppController rejects the request to relocate the application (in
        which case it includes the reason why the rejection occurred).
    """
    login_host = LocalState.get_login_host(options.keyname)
    acc = AppControllerClient(login_host, LocalState.get_secret_key(
      options.keyname))

    app_info_map = acc.get_app_info_map()
    if options.appname not in app_info_map.keys():
      raise AppScaleException("The given application, {0}, is not currently " \
        "running in this AppScale cloud, so we can't move it to a different " \
        "port.".format(options.appname))

    relocate_result = acc.relocate_app(options.appname, options.http_port,
      options.https_port)
    if relocate_result == "OK":
      AppScaleLogger.success("Successfully issued request to move {0} to " \
        "ports {1} and {2}.".format(options.appname, options.http_port,
        options.https_port))
      RemoteHelper.sleep_until_port_is_open(login_host, options.http_port,
        options.verbose)
      AppScaleLogger.success("Your app serves unencrypted traffic at: " +
        "http://{0}:{1}".format(login_host, options.http_port))
      AppScaleLogger.success("Your app serves encrypted traffic at: " +
        "https://{0}:{1}".format(login_host, options.https_port))
    else:
      raise AppScaleException(relocate_result)


  @classmethod
  def remove_app(cls, options):
    """Instructs AppScale to no longer host the named application.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    """
    if not options.confirm:
      response = raw_input(
        'Are you sure you want to remove this application? (y/N) ')
      if response.lower() not in ['y', 'yes']:
        raise AppScaleException("Cancelled application removal.")

    login_host = LocalState.get_login_host(options.keyname)
    secret = LocalState.get_secret_key(options.keyname)
    admin_client = AdminClient(login_host, secret)

    operation_id = admin_client.delete_version(options.appname)
    deadline = time.time() + cls.MAX_OPERATION_TIME
    while True:
      if time.time() > deadline:
        raise AppScaleException('The undeploy operation took too long.')

      operation = admin_client.get_operation(options.appname, operation_id)
      if not operation['done']:
        time.sleep(1)
        continue

      if 'error' in operation:
        raise AppScaleException(operation['error']['message'])
      break

    AppScaleLogger.success('Done shutting down {}.'.format(options.appname))


  @classmethod
  def reset_password(cls, options):
    """Resets a user's password the currently running AppScale deployment.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    """
    secret = LocalState.get_secret_key(options.keyname)
    login_host = LocalState.get_login_host(options.keyname)
    username, password = LocalState.get_credentials(is_admin=False)
    encrypted_password = LocalState.encrypt_password(username, password)

    acc = AppControllerClient(login_host,secret)

    try:
      acc.reset_password(username, encrypted_password)
      AppScaleLogger.success("The password was successfully changed for the " \
        "given user.")
    except Exception as exception:
      AppScaleLogger.warn("Could not change the user's password for the " + \
        "following reason: {0}".format(str(exception)))
      sys.exit(1)


  @classmethod
  def run_instances(cls, options):
    """Starts a new AppScale deployment with the parameters given.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    Raises:
      AppControllerException: If the AppController on the head node crashes.
        When this occurs, the message in the exception contains the reason why
        the AppController crashed.
      BadConfigurationException: If the user passes in options that are not
        sufficient to start an AppScale deployment (e.g., running on EC2 but
        not specifying the AMI to use), or if the user provides us
        contradictory options (e.g., running on EC2 but not specifying EC2
        credentials).
    """
    LocalState.make_appscale_directory()
    LocalState.ensure_appscale_isnt_running(options.keyname, options.force)
    if options.infrastructure:
      if not options.disks and not options.test and not options.force:
        LocalState.ensure_user_wants_to_run_without_disks()

    reduced_version = '.'.join(x for x in APPSCALE_VERSION.split('.')[:2])
    AppScaleLogger.log("Starting AppScale " + reduced_version)

    my_id = str(uuid.uuid4())
    AppScaleLogger.remote_log_tools_state(options, my_id, "started",
      APPSCALE_VERSION)

    node_layout = NodeLayout(options)
    if not node_layout.is_valid():
      raise BadConfigurationException("There were errors with your " + \
                                      "placement strategy:\n{0}".format(str(node_layout.errors())))

    head_node = node_layout.head_node()
    # Start VMs in cloud via cloud agent.
    if options.infrastructure:
      node_layout = RemoteHelper.start_all_nodes(options, node_layout)

      # Enables root logins and SSH access on the head node.
      RemoteHelper.enable_root_ssh(options, head_node.public_ip)
    AppScaleLogger.verbose("Node Layout: {}".format(node_layout.to_list()),
                           options.verbose)

    # Ensure all nodes are compatible.
    RemoteHelper.ensure_machine_is_compatible(
      head_node.public_ip, options.keyname, options.verbose)

    # Use rsync to move custom code into the deployment.
    if options.scp:
      AppScaleLogger.log("Copying over local copy of AppScale from {0}".
        format(options.scp))
      RemoteHelper.rsync_files(head_node.public_ip, options.keyname, options.scp,
        options.verbose)

    # Start services on head node.
    RemoteHelper.start_head_node(options, my_id, node_layout)

    # Write deployment metadata to disk (facilitates SSH operations, etc.)
    db_master = node_layout.db_master().private_ip
    head_node = node_layout.head_node().public_ip
    LocalState.update_local_metadata(options, db_master, head_node)

    # Copy the locations.json to the head node
    RemoteHelper.copy_local_metadata(node_layout.head_node().public_ip,
                                     options.keyname, options.verbose)

    # Wait for services on head node to start.
    secret_key = LocalState.get_secret_key(options.keyname)
    acc = AppControllerClient(head_node, secret_key)
    try:
      while not acc.is_initialized():
        AppScaleLogger.log('Waiting for head node to initialize...')
        # This can take some time in particular the first time around, since
        # we will have to initialize the database.
        time.sleep(cls.SLEEP_TIME*3)
    except socket.error as socket_error:
      AppScaleLogger.warn('Unable to initialize AppController: {}'.
                          format(socket_error.message))
      message = RemoteHelper.collect_appcontroller_crashlog(
        head_node, options.keyname, options.verbose)
      raise AppControllerException(message)

    # Set up admin account.
    try:
      # We don't need to have any exception information here: we do expect
      # some anyway while the UserAppServer is coming up.
      acc.does_user_exist("non-existent-user", True)
    except Exception:
      AppScaleLogger.log('UserAppServer not ready yet. Retrying ...')
      time.sleep(cls.SLEEP_TIME)

    if options.admin_user and options.admin_pass:
      AppScaleLogger.log("Using the provided admin username/password")
      username, password = options.admin_user, options.admin_pass
    elif options.test:
      AppScaleLogger.log("Using default admin username/password")
      username, password = LocalState.DEFAULT_USER, LocalState.DEFAULT_PASSWORD
    else:
      username, password = LocalState.get_credentials()

    RemoteHelper.create_user_accounts(username, password, head_node,
                                      options.keyname)
    acc.set_admin_role(username, 'true', cls.ADMIN_CAPABILITIES)

    # Wait for machines to finish loading and AppScale Dashboard to be deployed.
    RemoteHelper.wait_for_machines_to_finish_loading(head_node, options.keyname)
    RemoteHelper.sleep_until_port_is_open(LocalState.get_login_host(
      options.keyname), RemoteHelper.APP_DASHBOARD_PORT, options.verbose)

    AppScaleLogger.success("AppScale successfully started!")
    AppScaleLogger.success("View status information about your AppScale " + \
                           "deployment at http://{0}:{1}".format(LocalState.get_login_host(
                           options.keyname), RemoteHelper.APP_DASHBOARD_PORT))
    AppScaleLogger.remote_log_tools_state(options, my_id,
      "finished", APPSCALE_VERSION)


  @classmethod
  def set_property(cls, options):
    """Instructs AppScale to replace the value it uses for a particular
    AppController instance variable (property) with a new value.

    Args:
      options: A Namespace that has fields for each parameter that can be passed
        in via the command-line interface.
    """
    shadow_host = LocalState.get_host_with_role(options.keyname, 'shadow')
    acc = AppControllerClient(shadow_host, LocalState.get_secret_key(
      options.keyname))
    result = acc.set_property(options.property_name, options.property_value)
    if result == 'OK':
      AppScaleLogger.success("Successfully updated the given property.")
    else:
      raise AppControllerException("Unable to update the given property " +
        "because: {0}".format(result))


  @classmethod
  def terminate_instances(cls, options):
    """Stops all services running in an AppScale deployment, and in cloud
    deployments, also powers off the instances previously spawned.

    Raises:
      AppScaleException: If AppScale is not running, and thus can't be
      terminated.
    """
    try:
      infrastructure = LocalState.get_infrastructure(options.keyname)
    except IOError:
      raise AppScaleException("Cannot find AppScale's configuration for keyname {0}".
        format(options.keyname))

    if infrastructure == "xen" and options.terminate:
      raise AppScaleException("Terminate option is invalid for cluster mode.")

    if infrastructure == "xen" or not options.terminate:
      # We are in cluster mode: let's check if AppScale is running.
      if not os.path.exists(LocalState.get_secret_key_location(options.keyname)):
        raise AppScaleException("AppScale is not running with the keyname {0}".
          format(options.keyname))

    # Stop gracefully the AppScale deployment.
    try:
      RemoteHelper.terminate_virtualized_cluster(options.keyname,
                                                 options.clean,
                                                 options.verbose)
    except (IOError, AppScaleException, AppControllerException,
            BadConfigurationException) as e:
      if not (infrastructure in InfrastructureAgentFactory.VALID_AGENTS and
            options.terminate):
        raise

      if options.test:
        AppScaleLogger.warn(e)
      else:
        AppScaleLogger.verbose(e, options.verbose)
        if isinstance(e, AppControllerException):
          response = raw_input(
            'AppScale may not have shut down properly, are you sure you want '
            'to continue terminating? (y/N) ')
        else:
          response = raw_input(
            'AppScale could not find the configuration files for this '
            'deployment, are you sure you want to continue terminating? '
            '(y/N) ')
        if response.lower() not in ['y', 'yes']:
          raise AppScaleException("Cancelled cloud termination.")


    # And if we are on a cloud infrastructure, terminate instances if
    # asked.
    if (infrastructure in InfrastructureAgentFactory.VALID_AGENTS and
          options.terminate):
      RemoteHelper.terminate_cloud_infrastructure(options.keyname,
        options.verbose)
    elif infrastructure in InfrastructureAgentFactory.VALID_AGENTS and not \
        options.terminate:
      AppScaleLogger.log("AppScale did not terminate any of your cloud "
                         "instances, to terminate them run 'appscale "
                         "down --terminate'")
    if options.clean:
      LocalState.clean_local_metadata(keyname=options.keyname)


  @classmethod
  def upload_app(cls, options):
    """Uploads the given App Engine application into AppScale.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    Returns:
      A tuple containing the host and port where the application is serving
        traffic from.
    """
    if cls.TAR_GZ_REGEX.search(options.file):
      file_location = LocalState.extract_tgz_app_to_dir(options.file,
        options.verbose)
      created_dir = True
    elif cls.ZIP_REGEX.search(options.file):
      file_location = LocalState.extract_zip_app_to_dir(options.file,
        options.verbose)
      created_dir = True
    elif os.path.isdir(options.file):
      file_location = options.file
      created_dir = False
    else:
      raise AppEngineConfigException('{0} is not a tar.gz file, a zip file, ' \
        'or a directory. Please try uploading either a tar.gz file, a zip ' \
        'file, or a directory.'.format(options.file))

    try:
      app_id = AppEngineHelper.get_app_id_from_app_config(file_location)
    except AppEngineConfigException as config_error:
      AppScaleLogger.log(config_error)
      if 'yaml' in str(config_error):
        raise config_error

      # Java App Engine users may have specified their war directory. In that
      # case, just move up one level, back to the app's directory.
      file_location = file_location + os.sep + ".."
      app_id = AppEngineHelper.get_app_id_from_app_config(file_location)

    app_language = AppEngineHelper.get_app_runtime_from_app_config(
      file_location)
    threadsafe = None
    if app_language in ['python27', 'java']:
      threadsafe = AppEngineHelper.is_threadsafe(file_location)
    AppEngineHelper.validate_app_id(app_id)

    extras = {}
    if app_language == 'go':
      extras = LocalState.get_extra_go_dependencies(options.file, options.test)

    if app_language == 'java':
      if AppEngineHelper.is_sdk_mismatch(file_location):
        AppScaleLogger.warn('AppScale did not find the correct SDK jar ' +
          'versions in your app. The current supported ' +
          'SDK version is ' + AppEngineHelper.SUPPORTED_SDK_VERSION + '.')

    login_host = LocalState.get_login_host(options.keyname)
    secret_key = LocalState.get_secret_key(options.keyname)
    admin_client = AdminClient(login_host, secret_key)

    if options.test:
      username = LocalState.DEFAULT_USER
    elif options.email:
      username = options.email
    else:
      username = LocalState.get_username_from_stdin(is_admin=False)

    remote_file_path = RemoteHelper.copy_app_to_host(file_location,
      options.keyname, options.verbose, extras)

    AppScaleLogger.log('Deploying project: {}'.format(app_id))
    operation_id = admin_client.create_version(
      app_id, username, remote_file_path, app_language, threadsafe)

    # now that we've told the AppController to start our app, find out what port
    # the app is running on and wait for it to start serving
    AppScaleLogger.log("Please wait for your app to start serving.")

    deadline = time.time() + cls.MAX_OPERATION_TIME
    while True:
      if time.time() > deadline:
        raise AppScaleException('The deployment operation took too long.')
      operation = admin_client.get_operation(app_id, operation_id)
      if not operation['done']:
        time.sleep(1)
        continue

      if 'error' in operation:
        raise AppScaleException(operation['error']['message'])
      version_url = operation['response']['versionUrl']
      break

    AppScaleLogger.success(
      'Your app can be reached at the following URL: {}'.format(version_url))

    if created_dir:
      shutil.rmtree(file_location)

    http_port = int(version_url.split(':')[-1])
    return (login_host, http_port)

  @classmethod
  def upgrade(cls, options):
    """ Upgrades the deployment to the latest AppScale version.
    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    """
    node_layout = NodeLayout(options)
    if not node_layout.is_valid():
      raise BadConfigurationException(
        'Your ips_layout is invalid:\n{}'.format(node_layout.errors()))

    latest_tools = APPSCALE_VERSION
    try:
      AppScaleLogger.log(
        'Checking if an update is available for appscale-tools')
      latest_tools = latest_tools_version()
    except:
      # Prompt the user if version metadata can't be fetched.
      if not options.test:
        response = raw_input(
          'Unable to check for the latest version of appscale-tools. Would '
          'you like to continue upgrading anyway? (y/N) ')
        if response.lower() not in ['y', 'yes']:
          raise AppScaleException('Cancelled AppScale upgrade.')

    if latest_tools > APPSCALE_VERSION:
      raise AppScaleException(
        "There is a newer version ({}) of appscale-tools available. Please "
        "upgrade the tools package before running 'appscale upgrade'.".
        format(latest_tools))

    master_ip = node_layout.head_node().public_ip
    upgrade_version_available = cls.get_upgrade_version_available()

    current_version = RemoteHelper.get_host_appscale_version(
      master_ip, options.keyname, options.verbose)

    # Don't run bootstrap if current version is later that the most recent
    # public one. Covers cases of revoked versions/tags and ensures we won't
    # try to downgrade the code.
    if current_version >= upgrade_version_available:
      AppScaleLogger.log(
        'AppScale is already up to date. Skipping code upgrade.')
      AppScaleLogger.log(
        'Running upgrade script to check if any other upgrades are needed.')
      cls.shut_down_appscale_if_running(options)
      cls.run_upgrade_script(options, node_layout)
      return

    cls.shut_down_appscale_if_running(options)
    cls.upgrade_appscale(options, node_layout)

  @classmethod
  def run_upgrade_script(cls, options, node_layout):
    """ Runs the upgrade script which checks for any upgrades needed to be performed.
      Args:
        options: A Namespace that has fields for each parameter that can be
          passed in via the command-line interface.
        node_layout: A NodeLayout object for the deployment.
    """
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

    db_ips = [node.private_ip for node in node_layout.nodes
              if node.is_role('db_master') or node.is_role('db_slave')]
    zk_ips = [node.private_ip for node in node_layout.nodes
              if node.is_role('zookeeper')]

    upgrade_script_command = '{script} --keyname {keyname} '\
      '--log-postfix {timestamp} '\
      '--db-master {db_master} '\
      '--zookeeper {zk_ips} '\
      '--database {db_ips} '\
      '--replication {replication}'.format(
      script=cls.UPGRADE_SCRIPT,
      keyname=options.keyname,
      timestamp=timestamp,
      db_master=node_layout.db_master().private_ip,
      zk_ips=' '.join(zk_ips),
      db_ips=' '.join(db_ips),
      replication=node_layout.replication
    )
    master_public_ip = node_layout.head_node().public_ip

    AppScaleLogger.log("Running upgrade script to check if any other upgrade is needed.")
    # Run the upgrade command as a background process.
    error_bucket = Queue.Queue()
    threading.Thread(
      target=async_layout_upgrade,
      args=(master_public_ip, options.keyname, upgrade_script_command,
            error_bucket, options.verbose)
    ).start()

    last_message = None
    while True:
      # Check if the SSH thread has crashed.
      try:
        ssh_error = error_bucket.get(block=False)
        AppScaleLogger.warn('Error executing upgrade script')
        LocalState.generate_crash_log(ssh_error, traceback.format_exc())
      except Queue.Empty:
        pass

      upgrade_status_file = cls.UPGRADE_STATUS_FILE_LOC + timestamp + ".json"
      command = 'cat' + " " + upgrade_status_file
      upgrade_status = RemoteHelper.ssh(
        master_public_ip, options.keyname, command, options.verbose)
      json_status = json.loads(upgrade_status)

      if 'status' not in json_status or 'message' not in json_status:
        raise AppScaleException('Invalid status log format')

      if json_status['status'] == 'complete':
        AppScaleLogger.success(json_status['message'])
        break

      if json_status['status'] == 'inProgress':
        if json_status['message'] != last_message:
          AppScaleLogger.log(json_status['message'])
          last_message = json_status['message']
        time.sleep(cls.SLEEP_TIME)
        continue

      # Assume the message is an error.
      AppScaleLogger.warn(json_status['message'])
      raise AppScaleException(json_status['message'])

  @classmethod
  def shut_down_appscale_if_running(cls, options):
    """ Checks if AppScale is running and shuts it down as this is an offline upgrade.
      Args:
        options: A Namespace that has fields for each parameter that can be
          passed in via the command-line interface.
    """
    if os.path.exists(LocalState.get_secret_key_location(options.keyname)):
      AppScaleLogger.warn("AppScale needs to be down for this upgrade. "
        "Upgrade process could take a while and it is not reversible.")

      if not options.test:
        response = raw_input(
          'Are you sure you want to proceed with shutting down AppScale to '
          'continue the upgrade? (y/N) ')
        if response.lower() not in ['y', 'yes']:
          raise AppScaleException("Cancelled AppScale upgrade.")

      AppScaleLogger.log("Shutting down AppScale...")
      cls.terminate_instances(options)
    else:
      AppScaleLogger.warn("Upgrade process could take a while and it is not reversible.")

      if options.test:
        return

      response = raw_input(
        'Are you sure you want to proceed with the upgrade? (y/N) ')
      if response.lower() not in ['y', 'yes']:
        raise AppScaleException("Cancelled AppScale upgrade.")

  @classmethod
  def upgrade_appscale(cls, options, node_layout):
    """ Runs the bootstrap script on each of the remote machines.
      Args:
        options: A Namespace that has fields for each parameter that can be
          passed in via the command-line interface.
        node_layout: A NodeLayout object for the deployment.
    """
    unique_ips = [node.public_ip for node in node_layout.nodes]

    AppScaleLogger.log("Upgrading AppScale code to the latest version on "
      "these machines: {}".format(unique_ips))
    threads = []
    error_ips = []
    for ip in unique_ips:
      t = threading.Thread(target=cls.run_bootstrap, args=(ip, options, error_ips))
      threads.append(t)

    for x in threads:
      x.start()

    for x in threads:
      x.join()

    if not error_ips:
      cls.run_upgrade_script(options, node_layout)

  @classmethod
  def run_bootstrap(cls, ip, options, error_ips):
    try:
      RemoteHelper.ssh(ip, options.keyname, cls.BOOTSTRAP_CMD, options.verbose)
      AppScaleLogger.success(
        'Successfully updated and built AppScale on {}'.format(ip))
    except ShellException:
      error_ips.append(ip)
      AppScaleLogger.warn('Unable to upgrade AppScale code on {}.\n'
        'Please correct any errors listed in /var/log/appscale/bootstrap.log '
        'on that machine and re-run appscale upgrade.'.format(ip))
      return error_ips

  @classmethod
  def get_upgrade_version_available(cls):
    """ Gets the latest release tag version available.
    """
    github_api = cls.GITHUB_API.format(owner='AppScale', repo='appscale')
    response = urllib2.urlopen('{}/tags'.format(github_api))
    tag_list = json.loads(response.read())
    return tag_list[0]['name']
