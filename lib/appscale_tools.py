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
    node_layout, result = NodeLayout.generate_layout_from_options(options)

    """
    node_layout, result = CommonFunctions.generate_node_layout(options)
    head_node_result = CommonFunctions.start_head_node(options, node_layout,
      apps_to_start)

    print "\nPlease wait for AppScale to prepare your machines for use."
    STDOUT.flush
    print "\n"

    acc = head_node_result[:acc]
    secret_key = head_node_result[:secret_key]
    head_node_ip = head_node_result[:head_node_ip]
    CommonFunctions.write_and_copy_node_file(options, node_layout,
      head_node_result)
    CommonFunctions.update_locations_file(options['keyname'], [head_node_ip])
    CommonFunctions.copy_nodes_json(options['keyname'], head_node_ip,
      head_node_result[:true_key])

    userappserver_ip = acc.get_userappserver_ip(LOGS_VERBOSE)
    CommonFunctions.update_locations_file(options['keyname'], [head_node_ip])
    CommonFunctions.copy_nodes_json(options['keyname'], head_node_ip,
      head_node_result[:true_key])
    CommonFunctions.verbose("Run instances: UserAppServer is at #{userappserver_ip}", options['verbose'])
    uac = UserAppClient.new(userappserver_ip, secret_key)
    if options["admin_user"] and options["admin_pass"]:
      print "Using the provided admin username and password"
      user, password = options["admin_user"], options["admin_pass"]
    else:
      user, password = CommonFunctions.get_credentials(options['test'])

    CommonFunctions.create_user(user, options['test'], head_node_ip,
      secret_key, uac, password)

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
