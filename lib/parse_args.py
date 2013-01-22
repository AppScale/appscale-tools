#!/usr/bin/env python


# General-purpose Python library imports
import argparse


from common_functions import APPSCALE_VERSION


class ParseArgs():


  def __init__(self, argv, all_flags, description):
    self.parser = argparse.ArgumentParser(description)
    self.parser.add_argument('--version', help="show the version of the AppScale Tools present", action="store_true")
    self.args = self.parser.parse_args(argv)

    if self.args.version:
      raise SystemExit(APPSCALE_VERSION)
