#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# First party Python libraries
import os
import shutil


# Custom exceptions that can be thrown by Python AppScale code
from custom_exceptions import AppScalefileException
from custom_exceptions import BadConfigurationException
from custom_exceptions import UsageException


# AppScale provides a configuration-file-based alternative to the
# command-line interface that the AppScale Tools require.
class AppScale():


  # A list of the directives that users can specify to interact with
  # their AppScale deployments.
  ALLOWED_DIRECTIVES = ["init", "up", "status", "deploy", "destroy",
    "help"]


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


  def __init__(self, args):
    self.directive = self.get_directive(args)


  # Parses the arguments given to determine what command should be
  # executed.
  # Args:
  #   args: A list of strs that correspond to the arguments passed to
  #     the 'appscale' command.
  # Returns:
  #   A str corresponding to the directive that should be executed.
  # Raises:
  #   BadConfigurationException: If no directive was given, or if an
  #     invalid directive was given.
  def get_directive(self, args):
    if not args:
      raise BadConfigurationException

    directive = args[0]
    if directive in self.ALLOWED_DIRECTIVES:
      return directive
    else:
      raise BadConfigurationException(self.USAGE)


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
    appscalefile_location = self.get_appscalefile_location()
    if not os.path.exists(appscalefile_location):
      raise AppScalefileException("No AppScalefile found in this " +
        "directory. Please run 'appscale init' to generate one and try " +
        "again.")
