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


  @classmethod
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
    uaserver_client.set_admin_role(username)

    RemoteHelper.wait_for_machines_to_finish_loading(public_ip, keyname)
    AppScaleLogger.log("View status information about your AppScale " + \
      "deployment at http://{0}/status".format(LocalState.get_login_host(
      options.keyname)))

    # Finally, update our metadata once we know that all of the machines are
    # up and have started all their API services.
    LocalState.update_local_metadata(options, node_layout, public_ip,
      instance_id)
    RemoteHelper.copy_local_metadata(public_ip, options.keyname)
    AppScaleLogger.remote_log_tools_state(options, "finished")
