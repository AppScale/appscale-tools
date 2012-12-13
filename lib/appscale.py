#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# Custom exceptions that can be thrown by Python AppScale code
from custom_exceptions import BadConfigurationException
from custom_exceptions import UsageException


# AppScale provides a configuration-file-based alternative to the
# command-line interface that the AppScale Tools require.
class AppScale():


  # A list of the directives that users can specify to interact with
  # their AppScale deployments.
  ALLOWED_DIRECTIVES = ["init", "up", "status", "deploy", "destroy",
    "help"]


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


  # Aborts and prints out the directives allowed for this module.
  def help(self):
    raise UsageException(self.USAGE)


  # Writes an AppScalefile in the local directory, that contains
  # common configuration parameters.
  def init(self):
    pass
