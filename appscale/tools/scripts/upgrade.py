# General-purpose Python library imports
import sys
import traceback


# AppScale library imports
# Make sure we're on Python 2.6 or greater before importing any code
# that's incompatible with older versions.
from .. import version_helper
version_helper.ensure_valid_python_is_used()


from ..appscale_tools import AppScaleTools
from ..local_state import LocalState
from ..parse_args import ParseArgs


def main():
  """ Execute appscale-upgrade script. """
  options = ParseArgs(sys.argv[1:], "appscale-upgrade").args
  try:
    AppScaleTools.upgrade(options)
    sys.exit(0)
  except Exception as e:
    LocalState.generate_crash_log(e, traceback.format_exc())
    sys.exit(1)
