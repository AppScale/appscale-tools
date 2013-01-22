#!/usr/bin/env python


# General-purpose Python library imports
import argparse


from common_functions import APPSCALE_VERSION
from custom_exceptions import BadConfigurationException


class ParseArgs():


  def __init__(self, argv, function, description):
    self.parser = argparse.ArgumentParser(description)
    self.add_allowed_flags(function)
    self.args = self.parser.parse_args(argv)

    if self.args.version:
      raise SystemExit(APPSCALE_VERSION)

    self.validate_allowed_flags(function)


  def add_allowed_flags(self, function):
    if function == "appscale-run-instances":
      self.parser.add_argument('--version', action='store_true')
      self.parser.add_argument('--min', type=int)
      self.parser.add_argument('--max', type=int)
    else:
      raise SystemExit


  def validate_allowed_flags(self, function):
    if function == "appscale-run-instances":
      # if min is not set and max is, set min == max
      if self.args.min is None and self.args.max:
        self.args.min = self.args.max

      if self.args.min < 1:
        raise BadConfigurationException

      if self.args.max < 1:
        raise BadConfigurationException

      if self.args.min > self.args.max:
        raise BadConfigurationException
    else:
      raise SystemExit
