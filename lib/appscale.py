#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# First party Python libraries
import base64
import json
import os
import shutil
import subprocess


# Third-party Python libraries
import yaml


# Custom exceptions that can be thrown by Python AppScale code
from appscale_logger import AppScaleLogger
from custom_exceptions import AppScaleException
from custom_exceptions import AppScalefileException
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException


# AppScale-specific imports
from appscale_tools import AppScaleTools
from local_state import LocalState
from parse_args import ParseArgs
from remote_helper import RemoteHelper


class AppScale():
  """AppScale provides a configuration-file-based alternative to the
  command-line interface that the AppScale Tools require.
  """

  # The name of the configuration file that is used for storing
  # AppScale deployment information.
  APPSCALEFILE = "AppScalefile"


  # The location of the template AppScalefile that should be used when
  # users execute 'appscale init cloud'.
  TEMPLATE_CLOUD_APPSCALEFILE = path = os.path.dirname(__file__) + os.sep + \
    "../templates/AppScalefile-cloud"


  # The location of the template AppScalefile that should be used when
  # users execute 'appscale init cluster'.
  TEMPLATE_CLUSTER_APPSCALEFILE = path = os.path.dirname(__file__) + os.sep + \
    "../templates/AppScalefile-cluster"


  APPSCALE_DIRECTORY = os.path.expanduser("~") + os.sep + ".appscale" + os.sep


  TERMINATE = "ruby /root/appscale/AppController/terminate.rb clean"


  # The usage that should be displayed to users if they call 'appscale'
  # with a bad directive or ask for help.
  USAGE = """Usage: appscale command [<args>]

Available commands:
  init: Writes a new configuration file for starting AppScale.
  up: Starts a new AppScale instance.
  ssh: Logs into a virtual machine in a currently running AppScale deployment.
  status: Reports on the state of a currently running AppScale deployment.
  deploy: Deploys a Google App Engine app to AppScale.
  undeploy: Removes a Google App Engine app from AppScale.
  remove: An alias for 'undeploy'.
  get: Gets all AppController properties matching the provided regex.
  set: Sets an AppController property to the provided value.
  tail: Follows the output of log files in a currently running AppScale deployment.
  logs: Collects the logs produced by an AppScale deployment.
  relocate: Moves a hosted app to different HTTP and HTTPS ports.
  destroy: Gracefully terminates the currently running AppScale deployment.
  down: An alias for 'destroy'.
  clean: Forcefully terminates all services in a cluster AppScale deployment.
  help: Displays this message.
"""


  def __init__(self):
    pass


  def get_appscalefile_location(self):
    """Constructs a string that corresponds to the location of the
    AppScalefile for this deployment.
    
    Returns:
      The location where the user's AppScalefile can be found.
    """
    return os.getcwd() + os.sep + self.APPSCALEFILE


  def read_appscalefile(self):
    """Checks the local directory for an AppScalefile and reads its
    contents.

    Raises:
      AppScalefileException: If there is no AppScalefile in the
        local directory.
    Returns:
      The contents of the AppScalefile in the current working directory.
    """
    try:
      with open(self.get_appscalefile_location()) as file_handle:
        return file_handle.read()
    except IOError:
      raise AppScalefileException("No AppScalefile found in this " +
        "directory. Please run 'appscale init' to generate one and try " +
        "again.")


  def get_locations_json_file(self, keyname):
    """Returns the location where the AppScale tools writes JSON data
    about where each virtual machine is located in the currently running
    AppScale deployment.

    Args:
      keyname: The name of the AppScale deployment to find the JSON filename
        for.
    Returns:
      The path on the local filesystem where the locations.json file can be
        found.
    """
    appscale_dir = os.path.expanduser("~") + os.sep + ".appscale"
    json_file = appscale_dir + os.sep + "locations-" + keyname + ".json"
    return json_file


  def get_key_location(self, keyname):
    """Returns the location where the AppScale tools places an SSH key that
    can be used to log into any virtual machine in the currently running
    AppScale deployment.

    Args:
      keyname: The name of the AppScale deployment to find the SSH key for.

    Returns:
      The path on the local filesystem where the SSH key can be found.
    """
    appscale_dir = os.path.expanduser("~") + os.sep + ".appscale"
    key_file = appscale_dir + os.sep + keyname + ".key"
    return key_file


  def init(self, environment):
    """Writes an AppScalefile in the local directory, that contains common
    configuration parameters.

    Args:
      environment: A str that indicates whether the AppScalefile to write should
      be tailed to a 'cloud' environment or a 'cluster' environment.

    Raises:
      AppScalefileException: If there already is an AppScalefile in the local
      directory.
    """
    # first, make sure there isn't already an AppScalefile in this
    # directory
    appscalefile_location = self.get_appscalefile_location()
    if os.path.exists(appscalefile_location):
      raise AppScalefileException("There is already an AppScalefile" +
        " in this directory. Please remove it and run 'appscale init'" +
        " again to generate a new AppScalefile.")

    # next, see if we're making a cloud template file or a cluster
    # template file
    if environment == 'cloud':
      template_file = self.TEMPLATE_CLOUD_APPSCALEFILE
    elif environment == 'cluster':
      template_file = self.TEMPLATE_CLUSTER_APPSCALEFILE
    else:
      raise BadConfigurationException("The environment you specified " +
        "was invalid. Valid environments are 'cloud' and " +
        "'cluster'.")

    # finally, copy the template AppScalefile there
    shutil.copy(template_file, appscalefile_location)


  def up(self):
    """Starts an AppScale deployment with the configuration options from the
    AppScalefile in the current directory.

    Raises:
      AppScalefileException: If there is no AppScalefile in the current
      directory.
    """
    contents = self.read_appscalefile()

    # If running in a cluster environment, we first need to set up SSH keys
    contents_as_yaml = yaml.safe_load(contents)
    if not LocalState.ensure_appscalefile_is_up_to_date():
      contents = self.read_appscalefile()
      contents_as_yaml = yaml.safe_load(contents)

    if "ips_layout" in contents_as_yaml:
      ips_layout = base64.b64encode(yaml.dump(contents_as_yaml["ips_layout"]))

    if "disks" in contents_as_yaml:
      disks = base64.b64encode(yaml.dump(contents_as_yaml["disks"]))

    if "user_commands" in contents_as_yaml:
      user_commands = base64.b64encode(yaml.dump(
        contents_as_yaml["user_commands"]))

    if not "infrastructure" in contents_as_yaml:
      # Only run add-keypair if there is no ssh key present,
      # or if it doesn't log into all the machines specified.
      if not self.valid_ssh_key(contents_as_yaml):
        add_keypair_command = []
        if "keyname" in contents_as_yaml:
          add_keypair_command.append("--keyname")
          add_keypair_command.append(str(contents_as_yaml["keyname"]))

        add_keypair_command.append("--ips_layout")
        add_keypair_command.append(ips_layout)
        options = ParseArgs(add_keypair_command, "appscale-add-keypair").args
        AppScaleTools.add_keypair(options)

    # Construct a run-instances command from the file's contents
    command = []
    for key, value in contents_as_yaml.items():
      if key in ["EC2_ACCESS_KEY", "EC2_SECRET_KEY", "EC2_URL"]:
        os.environ[key] = value
        continue

      if value is True:
        command.append(str("--%s" % key))
      elif value is False:
        pass
      else:
        if key == "ips_layout":
          command.append("--ips_layout")
          command.append(ips_layout)
        elif key == "disks":
          command.append("--disks")
          command.append(disks)
        elif key == "user_commands":
          command.append("--user_commands")
          command.append(user_commands)
        else:
          command.append(str("--%s" % key))
          command.append(str("%s" % value))

    # Finally, call AppScaleTools.run_instances
    options = ParseArgs(command, "appscale-run-instances").args
    AppScaleTools.run_instances(options)


  def valid_ssh_key(self, config):
    """Determines whether or not we should call appscale-add-keypair, by
    collecting all the IP addresses in the given IPs layout and attempting to
    SSH to each of them with the specified keyname.

    Args:
      config: A dictionary that includes the IPs layout (which itself is a dict
        mapping role names to IPs) and, optionally, the keyname to use.

    Returns:
      A bool indicating whether or not the specified keyname can be used to log
      into each IP address without a password.

    Raises:
      BadConfigurationException: If the IPs layout was not a dictionary.
    """
    keyname = config["keyname"]
    verbose = config.get('verbose', False)

    if not isinstance(config["ips_layout"], dict):
      raise BadConfigurationException("ips_layout should be a dictionary. " \
        "Please fix it and try again.")

    ssh_key_location = self.APPSCALE_DIRECTORY + keyname + ".key"
    if not os.path.exists(ssh_key_location):
      return False

    all_ips = self.get_all_ips(config["ips_layout"])
    for ip in all_ips:
      if not self.can_ssh_to_ip(ip, keyname, verbose):
        return False

    return True


  def get_all_ips(self, ips_layout):
    """Searches through the given IPs layout and finds all the unique IP
    addresses.

    Args:
      ips_layout: A dict that maps AppScale roles to either an IP address or a
        list of IP addresses that host that role.
    Returns:
      A list containing all of the IP addresses in the IPs layout, without
        duplicates.
    """
    all_ips = []
    for _, ip_or_ips in ips_layout.items():
      if isinstance(ip_or_ips, str):
        if not ip_or_ips in all_ips:
          all_ips.append(ip_or_ips)
      elif isinstance(ip_or_ips, list):
        for ip in ip_or_ips:
          if not ip in all_ips:
            all_ips.append(ip)

    return all_ips


  def can_ssh_to_ip(self, ip, keyname, is_verbose):
    """Attempts to SSH into the machine located at the given IP address with the
    given SSH key.

    Args:
      ip: The IP address to attempt to SSH into.
      keyname: The name of the SSH key that uniquely identifies this AppScale
        deployment.
      is_verbose: A bool that indicates if we should print the SSH command we
        execute to stdout.

    Returns:
      A bool that indicates whether or not the given SSH key can log in without
      a password to the given machine.
    """
    try:
      RemoteHelper.ssh(ip, keyname, 'ls', is_verbose, user='root')
      return True
    except ShellException:
      return False


  def ssh(self, node):
    """'ssh' provides a simple way to log into virtual machines in an AppScale
    deployment, using the SSH key provided in the user's AppScalefile.

    Args:
      node: An int that represents the node to SSH to. The value is used as an
        index into the list of nodes running in the AppScale deployment,
        starting with zero.
    Raises:
      AppScalefileException: If there is no AppScalefile in the current
        directory.
      TypeError: If the user does not provide an integer for 'node'.
    """
    contents = self.read_appscalefile()
    contents_as_yaml = yaml.safe_load(contents)

    # make sure the user gave us an int for node
    try:
      index = int(node)
    except ValueError:
      raise TypeError("Usage: appscale ssh <node id to ssh to>")

    # get a list of the nodes running
    if 'keyname' in contents_as_yaml:
      keyname = contents_as_yaml['keyname']
    else:
      keyname = "appscale"

    try:
      with open(self.get_locations_json_file(keyname)) as f:
        nodes_json_raw = f.read()
    except IOError:
      raise AppScaleException("AppScale does not currently appear to" +
        " be running. Please start it and try again.")

    # make sure there is a node at position 'index'
    nodes = json.loads(nodes_json_raw)
    try:
      ip = nodes[index]['public_ip']
    except IndexError:
      raise AppScaleException("Cannot ssh to node at index " +
        str(index) + ", as there are only " + str(len(nodes)) +
        " in the currently running AppScale deployment.")

    # construct the ssh command to exec with that IP address
    command = ["ssh", "-o", "StrictHostkeyChecking=no", "-i",
      self.get_key_location(keyname), "root@" + ip]

    # exec the ssh command
    subprocess.call(command)


  def status(self):
    """'status' is a more accessible way to query the state of the AppScale
    deployment than 'appscale-describe-instances', and calls it with the
    parameters in the user's AppScalefile.

    Raises:
      AppScalefileException: If there is no AppScalefile in the current
      directory.
    """
    contents = self.read_appscalefile()

    # Construct a describe-instances command from the file's contents
    command = []
    contents_as_yaml = yaml.safe_load(contents)
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])

    # Finally, exec the command. Don't worry about validating it -
    # appscale-describe-instances will do that for us.
    options = ParseArgs(command, "appscale-describe-instances").args
    AppScaleTools.describe_instances(options)


  def deploy(self, app):
    """'deploy' is a more accessible way to tell an AppScale deployment to run a
    Google App Engine application than 'appscale-upload-app'. It calls that
    command with the configuration options found in the AppScalefile in the
    current working directory.

    Args:
      app: The path (absolute or relative) to the Google App Engine application
        that should be uploaded.
    Returns:
      A tuple containing the host and port where the application is serving
        traffic from.
    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
      directory.
    """
    contents = self.read_appscalefile()

    # Construct an upload-app command from the file's contents
    command = []
    contents_as_yaml = yaml.safe_load(contents)
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])

    if 'test' in contents_as_yaml:
      command.append("--test")

    if 'verbose' in contents_as_yaml and contents_as_yaml['verbose'] == True:
      command.append("--verbose")

    command.append("--file")
    command.append(app)

    # Finally, exec the command. Don't worry about validating it -
    # appscale-upload-app will do that for us.
    options = ParseArgs(command, "appscale-upload-app").args
    return AppScaleTools.upload_app(options)


  def undeploy(self, appid):
    """'undeploy' is a more accessible way to tell an AppScale deployment to
    stop hosting a Google App Engine application than 'appscale-remove-app'. It
    calls that command with the configuration options found in the AppScalefile
    in the current working directory.

    Args:
      appid: The name of the application that we should remove.
    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
      directory.
    """
    contents = self.read_appscalefile()

    # Construct an remove-app command from the file's contents
    command = []
    contents_as_yaml = yaml.safe_load(contents)
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])

    if 'verbose' in contents_as_yaml and contents_as_yaml['verbose'] == True:
      command.append("--verbose")

    command.append("--appname")
    command.append(appid)

    # Finally, exec the command. Don't worry about validating it -
    # appscale-upload-app will do that for us.
    options = ParseArgs(command, "appscale-remove-app").args
    AppScaleTools.remove_app(options)


  def get(self, property_regex):
    """'get' provides a cleaner experience for users than the
    appscale-get-property command, by using the configuration options present in
    the AppScalefile found in the current working directory.

    Args:
      property_regex: A regular expression indicating which AppController
        properties should be retrieved.
    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
      directory.
    """
    contents = self.read_appscalefile()
    contents_as_yaml = yaml.safe_load(contents)

    # construct the appscale-get-property command
    command = []
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml["keyname"])

    command.append("--property")
    command.append(property_regex)

    # and exec it
    options = ParseArgs(command, "appscale-get-property").args
    return AppScaleTools.get_property(options)


  def set(self, property_name, property_value):
    """'set' provides a cleaner experience for users than the
    appscale-set-property command, by using the configuration options present in
    the AppScalefile found in the current working directory.

    Args:
      property_name: A str naming the AppController instance variable that
        should be overwritten.
      property_value: The new value that should be used for the named property.
    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
      directory.
    """
    contents = self.read_appscalefile()
    contents_as_yaml = yaml.safe_load(contents)

    # construct the appscale-set-property command
    command = []
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml["keyname"])

    command.append("--property_name")
    command.append(property_name)

    command.append("--property_value")
    command.append(property_value)

    # and exec it
    options = ParseArgs(command, "appscale-set-property").args
    AppScaleTools.set_property(options)


  def tail(self, node, file_regex):
    """'tail' provides a simple way to follow log files in an AppScale
    deployment, instead of having to ssh in to a machine, locate the logs
    directory, and then tail it.

    Args:
      node: An int that indicates the id of the machine to tail logs from.
      file_regex: The regular expression that should be used to indicate which
        logs to tail from on the remote host.
    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
        directory.
      TypeError: If index is not an int.
    """
    contents = self.read_appscalefile()
    contents_as_yaml = yaml.safe_load(contents)

    # ensure that index is an int
    # TODO(cgb): Consider node = *, to tail from all nodes.
    try:
      index = int(node)
    except ValueError:
      raise TypeError("Usage: appscale tail <node id to tail from> " + \
        "<regex of files to tail>\nExample: appscale tail 0 controller*")

    # get a list of the nodes running
    if 'keyname' in contents_as_yaml:
      keyname = contents_as_yaml['keyname']
    else:
      keyname = "appscale"

    try:
      with open(self.get_locations_json_file(keyname)) as f:
        nodes_json_raw = f.read()
    except IOError:
      raise AppScaleException("AppScale does not currently appear to" +
        " be running. Please start it and try again.")

    # make sure there is a node at position 'index'
    nodes = json.loads(nodes_json_raw)
    try:
      ip = nodes[index]['public_ip']
    except IndexError:
      raise AppScaleException("Cannot tail from node at index " +
        str(index) + ", as there are only " + str(len(nodes)) +
        " in the currently running AppScale deployment.")

    # construct the ssh command to exec with that IP address
    tail = "tail -F /var/log/appscale/{0}".format(file_regex)
    command = ["ssh", "-o", "StrictHostkeyChecking=no", "-i",
      self.get_key_location(keyname), "root@" + ip, tail]

    # exec the ssh command
    subprocess.call(command)


  def logs(self, location):
    """'logs' provides a cleaner experience for users than the
    appscale-gather-logs command, by using the configuration options present in
    the AppScalefile found in the current working directory.

    Args:
      location: The path on the local filesystem where logs should be copied to.
    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
      directory.
    """
    contents = self.read_appscalefile()
    contents_as_yaml = yaml.safe_load(contents)

    # construct the appscale-gather-logs command
    command = []
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml["keyname"])

    command.append("--location")
    command.append(location)

    # and exec it
    options = ParseArgs(command, "appscale-gather-logs").args
    AppScaleTools.gather_logs(options)


  def relocate(self, appid, http_port, https_port):
    """'relocate' provides a nicer experience for users than the
    appscale-terminate-instances command, by using the configuration options
    present in the AppScalefile found in the current working directory.

    Args:
      appid: A str indicating the name of the application to relocate.
      http_port: An int that indicates what port should serve HTTP traffic for
        this application.
      https_port: An int that indicates what port should serve HTTPS traffic for
        this application.
    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
      directory.
    """
    contents = self.read_appscalefile()
    contents_as_yaml = yaml.safe_load(contents)

    # Construct the appscale-relocate-app command from argv and the contents of
    # the AppScalefile.
    command = []
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml["keyname"])

    command.append("--appname")
    command.append(appid)

    command.append("--http_port")
    command.append(str(http_port))

    command.append("--https_port")
    command.append(str(https_port))

    # and exec it
    options = ParseArgs(command, "appscale-relocate-app").args
    AppScaleTools.relocate_app(options)


  def destroy(self):
    """'destroy' provides a nicer experience for users than the
    appscale-terminate-instances command, by using the configuration options
    present in the AppScalefile found in the current working directory.

    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
      directory.
    """
    contents = self.read_appscalefile()

    # Construct a terminate-instances command from the file's contents
    command = []
    contents_as_yaml = yaml.safe_load(contents)

    if "EC2_ACCESS_KEY" in contents_as_yaml:
      os.environ["EC2_ACCESS_KEY"] = contents_as_yaml["EC2_ACCESS_KEY"]

    if "EC2_SECRET_KEY" in contents_as_yaml:
      os.environ["EC2_SECRET_KEY"] = contents_as_yaml["EC2_SECRET_KEY"]

    if "EC2_URL" in contents_as_yaml:
      os.environ["EC2_URL"] = contents_as_yaml["EC2_URL"]

    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])

    if 'verbose' in contents_as_yaml and contents_as_yaml['verbose'] == True:
      command.append("--verbose")

    if 'test' in contents_as_yaml and contents_as_yaml['test'] == True:
      command.append("--test")

    # Finally, exec the command. Don't worry about validating it -
    # appscale-terminate-instances will do that for us.
    options = ParseArgs(command, "appscale-terminate-instances").args
    AppScaleTools.terminate_instances(options)


  def clean(self):
    """'clean' provides a mechanism that will forcefully shut down all AppScale-
    related services on virtual machines in a cluster deployment.

    Returns:
      A list of the IP addresses where AppScale was shut down.

    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
        directory.
      BadConfigurationException: If this method is invoked and the AppScalefile
        indicates that a cloud deployment is being used.
    """
    contents = self.read_appscalefile()

    contents_as_yaml = yaml.safe_load(contents)
    if 'ips_layout' not in contents_as_yaml:
      raise BadConfigurationException("Cannot use 'appscale clean' in a " \
        "cloud deployment.")

    if 'verbose' in contents_as_yaml and contents_as_yaml['verbose'] == True:
      is_verbose = contents_as_yaml['verbose']
    else:
      is_verbose = False

    if 'keyname' in contents_as_yaml:
      keyname = contents_as_yaml['keyname']
    else:
      keyname = 'appscale'

    all_ips = self.get_all_ips(contents_as_yaml["ips_layout"])

    if 'test' not in contents_as_yaml or contents_as_yaml['test'] != True:
      LocalState.ensure_user_wants_to_terminate()

    for ip in all_ips:
      RemoteHelper.ssh(ip, keyname, self.TERMINATE, is_verbose)

    LocalState.cleanup_appscale_files(keyname)
    AppScaleLogger.success("Successfully shut down your AppScale deployment.")
    return all_ips
