#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# First party Python libraries
import base64
import os
import shutil
import socket
import subprocess
import yaml


# Third party Python libraries
import paramiko


# Custom exceptions that can be thrown by Python AppScale code
from custom_exceptions import AppScalefileException
from custom_exceptions import BadConfigurationException
from custom_exceptions import UsageException


# AppScale provides a configuration-file-based alternative to the
# command-line interface that the AppScale Tools require.
class AppScale():


  # The name of the configuration file that is used for storing
  # AppScale deployment information.
  APPSCALEFILE = "AppScalefile"


  # The location of the template AppScalefile that should be used when
  # users execute 'appscale init cloud'.
  TEMPLATE_CLOUD_APPSCALEFILE = path = os.path.dirname(__file__) + os.sep + "../templates/AppScalefile-cloud"


  # The location of the template AppScalefile that should be used when
  # users execute 'appscale init cluster'.
  TEMPLATE_CLUSTER_APPSCALEFILE = path = os.path.dirname(__file__) + os.sep + "../templates/AppScalefile-cluster"


  APPSCALE_DIRECTORY = os.path.expanduser("~") + os.sep + ".appscale" + os.sep


  # The usage that should be displayed to users if they call 'appscale'
  # with a bad directive or ask for help.
  USAGE = """

Usage: appscale command [<args>]

Available commands:
  init: Writes a new configuration file for starting AppScale.
  up: Starts a new AppScale instance.
  status: Reports on the state of a currently running AppScale deployment.
  deploy: Deploys a Google App Engine app to AppScale.
  destroy: Terminates the currently running AppScale deployment.
  help: Displays this message.
"""


  def __init__(self):
    pass


  # Constructs a string that corresponds to the location of the
  # AppScalefile for this deployment.
  # Returns:
  #   The location where the user's AppScalefile can be found.
  def get_appscalefile_location(self):
    return os.getcwd() + os.sep + self.APPSCALEFILE


  # Checks the local directory for an AppScalefile and reads its
  # contents.
  # Raises:
  #   AppScalefileException: If there is no AppScalefile in the
  #     local directory.
  # Returns:
  #   The contents of the AppScalefile in the current working directory.
  def read_appscalefile(self):
    # Don't check for existence and then open it later - this lack of
    # atomicity is potentially a TOCTOU vulnerability.
    try:
      with open(self.get_appscalefile_location()) as f:
        return f.read()
    except IOError as e:
      raise AppScalefileException("No AppScalefile found in this " +
        "directory. Please run 'appscale init' to generate one and try " +
        "again.")


  # Aborts and prints out the directives allowed for this module.
  def help(self):
    raise UsageException(self.USAGE)


  # Writes an AppScalefile in the local directory, that contains
  # common configuration parameters.
  # Args:
  #   environment: A str that indicates whether the AppScalefile to
  #     write should be tailed to a 'cloud' environment or a 'cluster'
  #     environment.
  # Raises:
  #   AppScalefileException: If there already is an AppScalefile in the
  #     local directory.
  def init(self, environment):
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


  # Starts an AppScale deployment with the configuration options from
  # the AppScalefile in the current directory.
  # Raises:
  #   AppScalefileException: If there is no AppScalefile in the current
  #     directory.
  def up(self):
    contents = self.read_appscalefile()

    # If running in a cluster environment, we first need to set up SSH keys
    contents_as_yaml = yaml.safe_load(contents)
    if "ips_layout" in contents_as_yaml:
      ips_layout = base64.b64encode(yaml.dump(contents_as_yaml["ips_layout"]))

    if not "infrastructure" in contents_as_yaml:
      # Only run add-keypair if there is no ssh key present,
      # or if it doesn't log into all the machines specified.
      if not self.valid_ssh_key(contents_as_yaml):
        add_keypair_command = ["appscale-add-keypair"]
        if "keyname" in contents_as_yaml:
          add_keypair_command.append("--keyname")
          add_keypair_command.append(str(contents_as_yaml["keyname"]))

        add_keypair_command.append("--ips_layout")
        add_keypair_command.append(ips_layout)
        # TODO(cgb): Check the return value of running add-keypair. If
        # it fails, abort execution here.
        subprocess.call(add_keypair_command)

    # Construct a run-instances command from the file's contents
    command = ["appscale-run-instances"]
    for key, value in contents_as_yaml.items():
      if value is True:
        command.append(str("--%s" % key))
      else:
        if key == "ips_layout":
          command.append("--ips_layout")
          command.append(ips_layout)
        else:
          command.append(str("--%s" % key))
          command.append(str("%s" % value))

    # Finally, exec the command. Don't worry about validating it -
    # appscale-run-instances will do that for us.
    subprocess.call(command)


  # Determines whether or not we should call appscale-add-keypair,
  # by collecting all the IP addresses in the given IPs layout and
  # attempting to SSH to each of them with the specified keyname.
  # Args:
  #   config: A dictionary that includes the IPs layout (which itself
  #     is a dict mapping role names to IPs) and, optionally, the keyname
  #     to use.
  # Returns:
  #   A bool indicating whether or not the specified keyname can be
  #   used to log into each IP address without a password.
  def valid_ssh_key(self, config):
    if "keyname" in config:
      keyname = config["keyname"]
    else:
      keyname = "appscale"

    ssh_key_location = self.APPSCALE_DIRECTORY + keyname + ".key"
    if not os.path.exists(ssh_key_location):
      return False

    all_ips = []
    for role, ip_or_ips in config["ips_layout"].items():
      if isinstance(ip_or_ips, str):
        if not ip_or_ips in all_ips:
          all_ips.append(ip_or_ips)
      elif isinstance(ip_or_ips, list):
        for ip in ip_or_ips:
          if not ip in all_ips:
            all_ips.append(ip)

    for ip in all_ips:
      if not self.can_ssh_to_ip(ip, ssh_key_location):
        return False

    return True


  # Attempts to SSH into the machine located at the given IP address
  # with the given SSH key.
  # Args:
  #   ip: The IP address to attempt to SSH into.
  #   ssh_key_location: The location on the local filesystem where the
  #     SSH key to use is located.
  # Returns:
  #   A bool that indicates whether or not the given SSH key can log in
  #   without a password to the given machine.
  def can_ssh_to_ip(self, ip, ssh_key_location):
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect((ip, 22))
    except Exception:
      return False

    t = paramiko.Transport(sock)
    try:
      t.start_client()
    except paramiko.SSHException:
      return False

    key = paramiko.RSAKey.from_private_key_file(ssh_key_location)
    t.auth_publickey('root', key)
    success = t.is_authenticated()
    t.close()
    return success


  # 'status' is a more accessible way to query the state of the
  # AppScale deployment than 'appscale-describe-instances', and calls
  # it with the parameters in the user's AppScalefile.
  # Raises:
  #   AppScalefileException: If there is no AppScalefile in the current
  #     directory.
  def status(self):
    contents = self.read_appscalefile()

    # Construct a describe-instances command from the file's contents
    command = ["appscale-describe-instances"]
    contents_as_yaml = yaml.safe_load(contents)
    if contents_as_yaml['keyname']:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])

    # Finally, exec the command. Don't worry about validating it -
    # appscale-describe-instances will do that for us.
    subprocess.call(command)


  # 'deploy' is a more accessible way to tell an AppScale deployment to
  # run a Google App Engine application than 'appscale-upload-app'. It
  # calls that command with the configuration options found in the
  # AppScalefile in the current working directory.
  # Args:
  #   app: The path (absolute or relative) to the Google App Engine
  #     application that should be uploaded.
  # Raises:
  #   AppScalefileException: If there is no AppScalefile in the current
  #     working directory.
  def deploy(self, app):
    contents = self.read_appscalefile()

    # Construct an upload-app command from the file's contents
    command = ["appscale-upload-app"]
    contents_as_yaml = yaml.safe_load(contents)
    if contents_as_yaml['keyname']:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])

    command.append("--file")
    command.append(app)

    # Finally, exec the command. Don't worry about validating it -
    # appscale-upload-app will do that for us.
    subprocess.call(command)


  # 'destroy' provides a nicer experience for users than the
  # appscale-terminate-instances command, by using the configuration
  # options present in the AppScalefile found in the current working
  # directory.
  # Raises:
  #   AppScalefileException: If there is no AppScalefile in the current
  #     working directory.
  def destroy(self):
    contents = self.read_appscalefile()

    # Construct an upload-app command from the file's contents
    command = ["appscale-terminate-instances"]
    contents_as_yaml = yaml.safe_load(contents)
    if contents_as_yaml['keyname']:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])

    # Finally, exec the command. Don't worry about validating it -
    # appscale-terminate-app will do that for us.
    subprocess.call(command)
