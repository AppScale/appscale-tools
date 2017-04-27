#!/usr/bin/env python
""" version_helper defines methods that can be used to check underlying
assumptions we make about the platform we're running on.

Currently it only has a single method, used to make sure that the version of
Python we're running on is new enough to support the syntax used by the
AppScale Tools.
"""


# First-party Python libraries
import json
import sys
import urllib2

# The location of appscale-tools on PyPI.
PYPI_URL = 'https://pypi.python.org/pypi/appscale-tools'


def latest_tools_version():
  """ Fetches the latest tools version available on PyPI.

  Returns:
    A string containing a version number.
  """
  response = urllib2.urlopen('{}/json'.format(PYPI_URL))
  pypi_info = json.loads(response.read())
  return pypi_info['info']['version']


def ensure_valid_python_is_used(system=sys):
  """ Makes sure that we are running a version of Python that the AppScale
  Tools supports.

  We use this check to ensure that if a user is running the AppScale Tools with
  Python 2.5 or older, then we can give them a more useful error message than
  the inevitable syntax errors that occur on lines like 'except Exception as e',
  which aren't Python 2.5-friendly.

  Args:
    system: A reference to the sys module. We add this in as an argument to make
      it easy to mock out (as mocking out it or hasattr and tuple purely with
      flexmock is difficult).
  Raises:
    SystemExit: If the version of Python that is running the AppScale Tools is
      older than 2.6.
  """
  if not hasattr(system, 'version_info'):
    sys.stderr.write("Very old versions of Python are not supported. Please "
      "use version 2.6 or newer.\n")
    sys.exit(1)

  version_tuple = tuple(system.version_info[:2])
  if version_tuple < (2, 6):
    sys.stderr.write("Error: Python %d.%d is not supported. Please use "
      "version 2.6 or newer.\n" % version_tuple)
    sys.exit(1)
