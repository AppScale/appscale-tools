#!/usr/bin/env python


# General-purpose Python library imports
import getpass
import json
import os
import re
import shutil
import socket
import sys
import time
import uuid


# AppScale-specific imports
from agents.factory import InfrastructureAgentFactory
from appcontroller_client import AppControllerClient
from appengine_helper import AppEngineHelper
from appscale_logger import AppScaleLogger
from custom_exceptions import AppControllerException
from custom_exceptions import AppEngineConfigException
from custom_exceptions import AppScaleException
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException
from local_state import APPSCALE_VERSION
from local_state import LocalState
from node_layout import NodeLayout
from remote_helper import RemoteHelper


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

  # The location of the expect script, used to interact with ssh-copy-id
  EXPECT_SCRIPT = os.path.dirname(__file__) + os.sep + ".." + os.sep + \
    "templates" + os.sep + "sshcopyid"


  # A regular expression that matches files compressed in the tar.gz format.
  TAR_GZ_REGEX = re.compile(r'.tar.gz\Z')


  # A regular expression that matches files compressed in the zip format.
  ZIP_REGEX = re.compile(r'.zip\Z')

  # A str that contains all of the authorizations that an AppScale cloud
  # administrator should be granted.
  ADMIN_CAPABILITIES = "upload_app"


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
    if LocalState.get_from_yaml(options.keyname, 'infrastructure') == "xen":
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
  def describe_instances(cls, options):
    """Queries each node in the currently running AppScale deployment and
    reports on their status.

    Args:
      options: A Namespace that has fields for each parameter that can be
        passed in via the command-line interface.
    """
    login_host = LocalState.get_login_host(options.keyname)
    login_acc = AppControllerClient(login_host,
      LocalState.get_secret_key(options.keyname))

    for ip in login_acc.get_all_public_ips():
      acc = AppControllerClient(ip, LocalState.get_secret_key(options.keyname))
      AppScaleLogger.log("Status of node at {0}:".format(ip))
      try:
        AppScaleLogger.log(acc.get_status())
      except Exception as exception:
        AppScaleLogger.warn("Unable to contact machine: {0}\n".
          format(str(exception)))

    AppScaleLogger.success("View status information about your AppScale " + \
      "deployment at http://{0}:{1}/status".format(login_host,
      RemoteHelper.APP_DASHBOARD_PORT))


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
      '/var/log/appscale',
      '/var/log/kern.log*',
      '/var/log/monit.log*',
      '/var/log/nginx',
      '/var/log/syslog*',
      '/var/log/zookeeper'
    ]

    failures = False
    for ip in all_ips:
      # Get the logs from each node, and store them in our local directory
      local_dir = "{0}/{1}".format(options.location, ip)
      os.mkdir(local_dir)

      for log_path in log_paths:
        try:
          RemoteHelper.scp_remote_to_local(ip, options.keyname, log_path,
            local_dir, options.verbose)
        except ShellException as shell_exception:
          failures = True
          AppScaleLogger.warn("Unable to collect logs from '{}' for host '{}'".
            format(log_path, ip))
          AppScaleLogger.verbose("Encountered exception: {}".
            format(str(shell_exception)), options.verbose)

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
      response = raw_input("Are you sure you want to remove this " + \
        "application? (Y/N) ")
      if response not in ['y', 'yes', 'Y', 'YES']:
        raise AppScaleException("Cancelled application removal.")

    login_host = LocalState.get_login_host(options.keyname)
    secret = LocalState.get_secret_key(options.keyname)
    acc = AppControllerClient(login_host, secret)

    if not acc.does_app_exist(options.appname):
      raise AppScaleException("The given application is not currently running.")

    acc.stop_app(options.appname)
    AppScaleLogger.log("Please wait for your app to shut down.")
    while True:
      if acc.is_app_running(options.appname):
        time.sleep(cls.SLEEP_TIME)
      else:
        break
    AppScaleLogger.success("Done shutting down {0}".format(options.appname))


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
      AppScaleLogger.log("Starting AppScale " + APPSCALE_VERSION +
        " over the " + options.infrastructure + " cloud.")
    else:
      AppScaleLogger.log("Starting AppScale " + APPSCALE_VERSION +
        " over a virtualized cluster.")
    my_id = str(uuid.uuid4())
    AppScaleLogger.remote_log_tools_state(options, my_id, "started",
      APPSCALE_VERSION)

    node_layout = NodeLayout(options)
    if not node_layout.is_valid():
      raise BadConfigurationException("There were errors with your " + \
        "placement strategy:\n{0}".format(str(node_layout.errors())))

    public_ip, instance_id = RemoteHelper.start_head_node(options, my_id,
      node_layout)
    AppScaleLogger.log("\nPlease wait for AppScale to prepare your machines " +
      "for use. This can take few minutes.")

    # Write our metadata as soon as possible to let users SSH into those
    # machines via 'appscale ssh'.
    LocalState.update_local_metadata(options, node_layout, public_ip,
      instance_id)
    RemoteHelper.copy_local_metadata(public_ip, options.keyname,
      options.verbose)

    acc = AppControllerClient(public_ip, LocalState.get_secret_key(
      options.keyname))

    # Let's now wait till the server is initialized.
    while not acc.is_initialized():
      AppScaleLogger.log('Waiting for head node to initialize...')
      # This can take some time in particular the first time around, since
      # we will have to initialize the database.
      time.sleep(cls.SLEEP_TIME*3)

    try:
      # We don't need to have any exception information here: we do expect
      # some anyway while the UserAppServer is coming up.
      acc.does_user_exist("non-existent-user", True)
    except Exception as exception:
      AppScaleLogger.log('UserAppServer not ready yet. Retrying ...')
      time.sleep(cls.SLEEP_TIME)

    # Update our metadata again so that users can SSH into other boxes that
    # may have been started.
    LocalState.update_local_metadata(options, node_layout, public_ip,
      instance_id)
    RemoteHelper.copy_local_metadata(public_ip, options.keyname,
      options.verbose)

    if options.admin_user and options.admin_pass:
      AppScaleLogger.log("Using the provided admin username/password")
      username, password = options.admin_user, options.admin_pass
    elif options.test:
      AppScaleLogger.log("Using default admin username/password")
      username, password = LocalState.DEFAULT_USER, LocalState.DEFAULT_PASSWORD
    else:
      username, password = LocalState.get_credentials()

    RemoteHelper.create_user_accounts(username, password, public_ip,
      options.keyname, options.clear_datastore)
    acc.set_admin_role(username, 'true', cls.ADMIN_CAPABILITIES)

    RemoteHelper.wait_for_machines_to_finish_loading(public_ip, options.keyname)
    # Finally, update our metadata once we know that all of the machines are
    # up and have started all their API services.
    LocalState.update_local_metadata(options, node_layout, public_ip,
      instance_id)
    RemoteHelper.copy_local_metadata(public_ip, options.keyname,
      options.verbose)

    RemoteHelper.sleep_until_port_is_open(LocalState.get_login_host(
      options.keyname), RemoteHelper.APP_DASHBOARD_PORT, options.verbose)
    AppScaleLogger.success("AppScale successfully started!")
    AppScaleLogger.success("View status information about your AppScale " + \
      "deployment at http://{0}:{1}/status".format(LocalState.get_login_host(
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
    if not os.path.exists(LocalState.get_secret_key_location(options.keyname)):
      raise AppScaleException("AppScale is not running with the keyname {0}".
        format(options.keyname))

    infrastructure = LocalState.get_infrastructure(options.keyname)

    # If the user is on a cloud deployment, and not backing their data to
    # persistent disks, warn them before shutting down AppScale.
    # Also, if we're in developer mode, skip the warning.
    if infrastructure != "xen" and not LocalState.are_disks_used(
      options.keyname) and not options.test:
      LocalState.ensure_user_wants_to_terminate()

    if infrastructure in InfrastructureAgentFactory.VALID_AGENTS:
      RemoteHelper.terminate_cloud_infrastructure(options.keyname,
        options.verbose)
    else:
      RemoteHelper.terminate_virtualized_cluster(options.keyname,
        options.verbose)

    LocalState.cleanup_appscale_files(options.keyname)
    AppScaleLogger.success("Successfully shut down your AppScale deployment.")


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
    AppEngineHelper.validate_app_id(app_id)

    if app_language == 'java':
      if AppEngineHelper.is_sdk_mismatch(file_location):
        AppScaleLogger.warn('AppScale did not find the correct SDK jar ' +
          'versions in your app. The current supported ' +
          'SDK version is ' + AppEngineHelper.SUPPORTED_SDK_VERSION + '.')

    login_host = LocalState.get_login_host(options.keyname)
    secret_key = LocalState.get_secret_key(options.keyname)
    acc = AppControllerClient(login_host, secret_key)

    if options.test:
      username = LocalState.DEFAULT_USER
    elif options.email:
      username = options.email
    else:
      username = LocalState.get_username_from_stdin(is_admin=False)

    if not acc.does_user_exist(username):
      password = LocalState.get_password_from_stdin()
      RemoteHelper.create_user_accounts(username, password,
        login_host, options.keyname, clear_datastore=False)

    app_exists = acc.does_app_exist(app_id)
    app_admin = acc.get_app_admin(app_id)
    if app_admin is not None and username != app_admin:
      raise AppScaleException("The given user doesn't own this application" + \
        ", so they can't upload an app with that application ID. Please " + \
        "change the application ID and try again.")

    if app_exists:
      AppScaleLogger.log("Uploading new version of app {0}".format(app_id))
    else:
      AppScaleLogger.log("Uploading initial version of app {0}".format(app_id))
      acc.reserve_app_id(username, app_id, app_language)

    # Ignore all .pyc files while tarring.
    if app_language == 'python27':
      AppScaleLogger.log("Ignoring .pyc files")

    remote_file_path = RemoteHelper.copy_app_to_host(file_location,
      options.keyname, options.verbose)

    acc.done_uploading(app_id, remote_file_path)
    acc.update([app_id])

    # now that we've told the AppController to start our app, find out what port
    # the app is running on and wait for it to start serving
    AppScaleLogger.log("Please wait for your app to start serving.")

    if app_exists:
      time.sleep(20)  # give the AppController time to restart the app

    # Makes a call to the AppController to get all the stats and looks
    # through them for the http port the app can be reached on.
    sleep_time = 2 * cls.SLEEP_TIME
    current_app = None
    for i in range(cls.MAX_RETRIES):
      try:
        result = acc.get_all_stats()
        json_result = json.loads(result)
        apps_result = json_result['apps']
        current_app = apps_result[app_id]
        http_port = current_app['http']
        break
      except ValueError:
        pass
      except KeyError:
        pass
      AppScaleLogger.verbose("Waiting {0} second(s) for a port to be assigned to {1}".\
        format(sleep_time, app_id), options.verbose)
      time.sleep(sleep_time)
    if not current_app:
      raise AppScaleException("Unable to get the serving port for the application.")

    RemoteHelper.sleep_until_port_is_open(login_host, http_port, options.verbose)
    AppScaleLogger.success("Your app can be reached at the following URL: " +
      "http://{0}:{1}".format(login_host, http_port))

    if created_dir:
      shutil.rmtree(file_location)

    return (login_host, http_port)
