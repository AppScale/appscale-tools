#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import time


from local_state import APPSCALE_VERSION
from local_state import LocalState
from custom_exceptions import BadConfigurationException


class AppScaleTools():
  """AppScaleTools provides callers with a way to start,
  stop, and interact with AppScale deployments, on virtualized
  clusters or on cloud infrastructures.

  These methods provide an interface for users who wish to
  start and control AppScale through a dict of parameters. An
  alternative to this method is to use the AppScale class,
  which stores state in an AppScalefile in the current working
  directory (as opposed to a dict), but under the hood these
  methods get called anyways.
  """


  def run_instances(self, options):
    """Starts a new AppScale deployment with the parameters given.

    Args:
      options: A Namespace that has fields for each parameter that
        can be passed in via the command-line interface.
    Raises:
      BadConfigurationException: If the user passes in options
        that are not sufficient to start an AppScale deplyoment
        (e.g., running on EC2 but not specifying the AMI to use),
        or if the user provides us contradictory options (e.g.,
        running on EC2 but not specifying EC2 credentials).
    """
    LocalState.make_appscale_directory()
    LocalState.ensure_appscale_isnt_running(options.keyname, options.force)

    if args.infrastructure:
      AppScaleLogger.log("Starting AppScale " + APPSCALE_VERSION +
        " over the " + args.infrastructure + " cloud.")
    else:
      AppScaleLogger.log("Starting AppScale " + APPSCALE_VERSION +
        "over a virtualized cluster.")

    AppScaleLogger.remote_log_tools_state(options, "started")
    time.sleep(2)

    node_layout = NodeLayout(options)
    if not node_layout.is_valid():
      raise BadConfigurationException("There were errors with your " + \
        "placement strategy:\n{0}".format(str(node_layout.errors())))

    if not node_layout.is_supported():
      AppScaleLogger.warn("Warning: This deployment strategy is not " + \
        "officially supported.")
      time.sleep(1)

    public_ip, instance_id = RemoteHelper.start_head_node(options, node_layout)
    AppScaleLogger.log("\nPlease wait for AppScale to prepare your machines " +
      "for use.")

    # Write our metadata as soon as possible to let users SSH into those
    # machines via 'appscale ssh'
    LocalState.update_local_metadata(options, node_layout, public_ip,
      instance_id)
    RemoteHelper.copy_local_metadata(public_ip, options.keyname)

    acc = AppControllerClient(public_ip, LocalState.get_secret_key(
      options.keyname))
    uaserver_host = acc.get_uaserver_host()

    # Update our metadata again so that users can SSH into other boxes that
    # may have been started.
    LocalState.update_local_metadata(options, node_layout, public_ip,
      instance_id)
    RemoteHelper.copy_local_metadata(public_ip, options.keyname)

    AppScaleLogger.log("UserAppServer is at {0}".format(uaserver_host))

    uaserver_client = UserAppClient.new(uaserver_host,
      LocalState.get_secret_key(options.keyname))

    if options.admin_user and options.admin_pass:
      AppScaleLogger.log("Using the provided admin username/password")
      username, password = options.admin_user, options.admin_pass
    elif options.test:
      AppScaleLogger.log("Using default admin username/password")
      username, password = LocalState.DEFAULT_USER, LocalState.DEFAULT_PASSWORD
    else:
      username, password = LocalState.get_credentials()

    RemoteHelper.create_user_accounts(username, password, uaserver_host,
      keyname)
    """
    uac.set_cloud_admin_status(user, new_status="true")
    uac.set_cloud_admin_capabilities(user)

    CommonFunctions.wait_for_nodes_to_load(head_node_ip, secret_key)
    login_ip = CommonFunctions.get_login_ip(head_node_ip, secret_key)
    print "The status of your AppScale instance is at the following" + \
      " URL: http://#{login_ip}/status"

    CommonFunctions.write_and_copy_node_file(options, node_layout,
      head_node_result)
    RemoteLogging.remote_post(max_images, table, infrastructure, "started", "success")
"""
