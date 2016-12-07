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
  """ Execute appscale-add-keypair script. """
  options = ParseArgs(sys.argv[1:], "appscale-add-keypair").args
  try:
    AppScaleTools.add_keypair(options)
    sys.exit(0)
  except Exception, e:
    LocalState.generate_crash_log(e, traceback.format_exc())
    sys.exit(1)
