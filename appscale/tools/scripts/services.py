import sys
import traceback

from .. import version_helper
from ..appscale_services import print_services
from ..local_state import LocalState
from ..parse_args import ParseArgs


version_helper.ensure_valid_python_is_used()


def main():
  """
  Execute appscale-services script.
  """
  options = ParseArgs(sys.argv[1:], "appscale-services")
  try:
    print_services(options)
    sys.exit(0)
  except Exception, e:
    LocalState.generate_crash_log(e, traceback.format_exc())
    sys.exit(1)
