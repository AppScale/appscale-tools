#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# First party Python libraries
import json
import os
import shutil


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
  # users execute 'appscale init'.
  TEMPLATE_APPSCALEFILE = path = os.path.dirname(__file__) + os.sep + "../templates/AppScalefile"


  # The usage that should be displayed to users if they call 'appscale'
  # with a bad directive or ask for help.
  USAGE = """
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


  # Aborts and prints out the directives allowed for this module.
  def help(self):
    raise UsageException(self.USAGE)


  # Writes an AppScalefile in the local directory, that contains
  # common configuration parameters.
  # Raises:
  #   AppScalefileException: If there already is an AppScalefile in the
  #     local directory.
  def init(self):
    # first, make sure there isn't already an AppScalefile in this
    # directory
    appscalefile_location = self.get_appscalefile_location()
    if os.path.exists(appscalefile_location):
       raise AppScalefileException("There is already an AppScalefile" +
         " in this directory. Please remove it and run 'appscale init'" +
         " again to generate a new AppScalefile.")

    # next, copy the template AppScalefile there
    shutil.copy(self.TEMPLATE_APPSCALEFILE, appscalefile_location)


  # Starts an AppScale deployment with the configuration options from
  # the AppScalefile in the current directory.
  # Raises:
  #   AppScalefileException: If there is no AppScalefile in the current
  #     directory.
  def up(self):
    # Don't check for existence and then open it later - this lack of
    # atomicity is potentially a TOCTOU vulnerability.
    contents = ""
    try:
      with open(self.get_appscalefile_location()) as f:
        contents = f.read()
    except IOError as e:
      raise AppScalefileException("No AppScalefile found in this " +
        "directory. Please run 'appscale init' to generate one and try " +
        "again.")

    # Construct a run-instances command from the file's contents
    contents_as_json = json.loads(contents)

    # Finally, exec the command. Don't worry about validating it -
    # appscale-run-instances will do that for us.
    pass
