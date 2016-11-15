# General-purpose Python library imports
import sys
import traceback


# AppScale library imports
from .. import version_helper
from ..appscale_tools import AppScaleTools
from ..local_state import LocalState
from ..parse_args import ParseArgs


version_helper.ensure_valid_python_is_used()


def main():
  """ Execute appscale-relocate-app script.

  Tells an AppScale deployment that an already running application should be
  migrated to a different HTTP and HTTPS port.
  """
  options = ParseArgs(sys.argv[1:], "appscale-relocate-app").args
  try:
    AppScaleTools.relocate_app(options)
    sys.exit(0)
  except Exception, e:
    LocalState.generate_crash_log(e, traceback.format_exc())
    sys.exit(1)
