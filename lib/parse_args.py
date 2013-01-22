#!/usr/bin/env python


# General-purpose Python library imports
import argparse


import common_functions
from custom_exceptions import BadConfigurationException


class ParseArgs():
  """ParseArgs provides the AppScale Tools with the ability
  to parse command-line arguments. Callers can customize
  the arguments that are acceptable for their executable
  as well as the description and usage printed for users
  in need of assistance.
  """


  def __init__(self, argv, function):
    """Creates a new ParseArgs for a set of acceptable flags.

    Args:
      argv: A list of strs, representing command-line arguments
        passed in by the user.
      function: A str that represents the executable we are
        parsing arguments for, which is used to make sure

    Raises:
      SystemExit: If the user asks us for just the version
        of the AppScale Tools, or gives us arguments that
        are not acceptable for the executable we are parsing
        arguments for.
    """
    self.parser = argparse.ArgumentParser(function)
    self.add_allowed_flags(function)
    self.args = self.parser.parse_args(argv)

    if self.args.version:
      raise SystemExit(common_functions.APPSCALE_VERSION)

    self.validate_allowed_flags(function)


  def add_allowed_flags(self, function):
    """Adds flag parsing capabilities based on the given function.

    Args:
      function: The name of the function that we're adding flags
        on behalf of.
    Raises:
      SystemExit: If function is not a supported function.
    """
    self.parser.add_argument('--version', action='store_true',
      help="shows the tools version and quits")

    if function == "appscale-run-instances":
      # flags relating to how many VMs we should spawn
      self.parser.add_argument('--min', type=int,
        help="the minimum number of VMs to use")
      self.parser.add_argument('--max', type=int,
        help="the maximum number of VMs to use")

      # flags relating to cloud infrastructures
      self.parser.add_argument('--infrastructure',
        help="the cloud infrastructure to use")

      # flags relating to the datastore used
      self.parser.add_argument('--table',
        default=common_functions.DEFAULT_DATASTORE,
        help="the datastore to use")
      self.parser.add_argument('-n', type=int,
        help="the database replication factor")

      # developer flags
      self.parser.add_argument('--force', action='store_true',
        help="forces tools to continue if keyname or group exist")
      self.parser.add_argument('--test', action='store_true',
        help="uses a default username and password for cloud admin")
    elif function == "appscale-gather-logs":
      self.parser.add_argument('--location',
        help="the location to store the collected logs")
    else:
      raise SystemExit


  def validate_allowed_flags(self, function):
    """Checks the values passed in by the user to ensure that
    they are valid for an AppScale deployment.

    Args:
      function: The name of the function that we should be
        validating parameters for.
    Raises:
      SystemExit: If function is not a supported function.
    """
    if function == "appscale-run-instances":
      self.validate_min_and_max_flags()
      self.validate_infrastructure_flag()
      self.validate_database_flags()
    elif function == "appscale-gather-logs":
      pass
    else:
      raise SystemExit


  def validate_min_and_max_flags(self):
    """Validates the values given to us by the user for the --min
    and --max flags, controlling how many virtual machines we spawn
    in a cloud deployment.

    Raises:
      BadConfigurationException: If the values for the min or max
        flags are invalid.
    """
    # if min is not set and max is, set min == max
    if self.args.min is None and self.args.max:
      self.args.min = self.args.max

    if self.args.min < 1:
      raise BadConfigurationException("Min cannot be less than 1.")

    if self.args.max < 1:
      raise BadConfigurationException("Max cannot be less than 1.")

    if self.args.min > self.args.max:
      raise BadConfigurationException("Min cannot exceed max.")

    return


  def validate_infrastructure_flag(self):
    """Validates the infrastructure flag given to us by the user.

    Raises:
      BadConfigurationException: If the value given to us for the
        infrastructure flag was invalid.
    """
    if self.args.infrastructure is not None and \
      self.args.infrastructure not in common_functions.ALLOWED_INFRASTRUCTURES:
      raise BadConfigurationException("Infrastructure must be a supported value.")


  def validate_database_flags(self):
    """Validates the values given to us by the user for any flag
    relating to the database used.

    Raises:
      BadConfigurationException: If the values for any of the
        database flags are not valid.
    """
    if self.args.table not in common_functions.ALLOWED_DATASTORES:
      raise BadConfigurationException("Table must be a supported datastore.")

    if self.args.n is not None and self.args.n < 1:
      raise BadConfigurationException("Replication factor cannot be less than 1.")
