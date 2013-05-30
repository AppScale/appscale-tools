#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)
""" version_helper defines methods that can be used to check underlying
assumptions we make about the platform we're running on.

Currently it only has a single method, used to make sure that the version of
Python we're running on is new enough to support the syntax used by the
AppScale Tools.
"""


# First-party Python libraries
import sys


# Third-party Python libraries
from termcolor import cprint


def ensure_valid_python_is_used():
  """ Makes sure that we are running a version of Python that the AppScale
  Tools supports.

  We use this check to ensure that if a user is running the AppScale Tools with
  Python 2.5 or older, then we can give them a more useful error message than
  the inevitable syntax errors that occur on lines like 'except Exception as e',
  which aren't Python 2.5-friendly.

  Raises:
    SystemExit: If the version of Python that is running the AppScale Tools is
      older than 2.6.
  """
  if not hasattr(sys, 'version_info'):
    cprint("Very old versions of Python are not supported. Please "
      "use version 2.6 or newer.", "red")
    sys.exit(1)

  version_tuple = tuple(sys.version_info[:2])
  if version_tuple < (2, 6):
    cprint("Error: Python {0}.{1} is not supported. Please use "
      "version 2.6 or newer.".format(version_tuple[0], version_tuple[1]), "red")
    sys.exit(1)
