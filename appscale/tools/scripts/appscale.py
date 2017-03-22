# First-party Python libraries
import sys
import traceback

# Third-party Python libraries
from termcolor import cprint

from .. import version_helper
from ..appscale import AppScale
from ..local_state import APPSCALE_VERSION
from ..local_state import LocalState
from ..registration_helper import RegistrationHelper

version_helper.ensure_valid_python_is_used()


def main():
  """ Execute appscale script. """
  appscale = AppScale()
  if len(sys.argv) < 2:
    print(AppScale.USAGE)
    sys.exit(1)

  command = sys.argv[1]
  if command == "init":
    if len(sys.argv) < 3:
      cprint("Usage: appscale init <cloud or cluster>", 'red')
      print("Specify 'cloud' for EC2, Eucalyptus, and Google Compute Engine " +
            "deployments, and 'cluster' if running over a virtualized cluster.")
      sys.exit(1)

    try:
      appscale.init(sys.argv[2])
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)

    cprint("AppScalefile successfully created! Be sure to " +
           "customize it for your particular cloud or cluster.", 'green')
    sys.exit(0)
  elif command == "up":
    try:
      appscale.up()
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "ssh":
    if len(sys.argv) < 3:
      index = None
    else:
      index = sys.argv[2]

    try:
      appscale.ssh(index)
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
    except KeyboardInterrupt:
      # don't print the stack trace on a Control-C
      pass
  elif command == "status":
    try:
      appscale.status(sys.argv[2:])
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "deploy":
    try:
      if len(sys.argv) < 3:
        cprint("Usage: appscale deploy <path to your app>", 'red')
        sys.exit(1)

      if len(sys.argv) == 3:
        appscale.deploy(sys.argv[2])
      else:
        appscale.deploy(sys.argv[2], sys.argv[3])
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "undeploy" or command == "remove":
    try:
      if len(sys.argv) != 3:
        cprint("Usage: appscale {0} <path to your app>".format(command), 'red')
        sys.exit(1)

      appscale.undeploy(sys.argv[2])
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "get":
    try:
      if len(sys.argv) != 3:
        cprint("Usage: appscale get <regex of properties to retrieve>", 'red')
        sys.exit(1)

      properties = appscale.get(sys.argv[2])
      for property_name, property_value in sorted(properties.iteritems()):
        print "{0} -> {1}".format(property_name, property_value)
      sys.exit(0)
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "set":
    try:
      if len(sys.argv) != 4:
        cprint("Usage: appscale set <property> <value>", 'red')
        sys.exit(1)

      appscale.set(sys.argv[2], sys.argv[3])
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "tail":
    if len(sys.argv) < 3:
      # by default, tail the first node's logs, since that node is
      # typically the head node
      index = 0
    else:
      index = sys.argv[2]

    if len(sys.argv) < 4:
      # by default, tail the AppController logs, since that's the
      # service we most often tail from
      regex = "controller*"
    else:
      regex = sys.argv[3]

    try:
      appscale.tail(index, regex)
    except KeyboardInterrupt:
      # don't print the stack trace on a Control-C
      pass
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "logs":
    if len(sys.argv) < 3:
      cprint("Usage: appscale logs <location to copy logs to>", 'red')
      sys.exit(1)

    try:
      appscale.logs(sys.argv[2])
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "destroy":
    cprint("Warning: destroy has been deprecated. Please use 'down'.", 'red')
    sys.exit(1)
  elif command == "clean":
    cprint("Warning: clean has been deprecated. Please use 'down --clean'.", 'red')
    sys.exit(1)
  elif command == "down":
    if len(sys.argv) > 4:
      cprint("Usage: appscale down [--clean][--terminate]", 'red')
      sys.exit(1)
    to_clean = False
    to_terminate = False
    for index in range(2, len(sys.argv)):
      if sys.argv[index] == "--terminate":
        to_terminate = True
      elif sys.argv[index] == "--clean":
        to_clean = True
      else:
        cprint("Usage: appscale down [--clean][--terminate]", 'red')
        sys.exit(1)

    try:
      appscale.down(clean=to_clean, terminate=to_terminate)
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "relocate":
    if len(sys.argv) != 5:
      cprint("Usage: appscale relocate appid http_port https_port", 'red')
      sys.exit(1)

    try:
      appscale.relocate(sys.argv[2], sys.argv[3], sys.argv[4])
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command == "register":
    try:
      if len(sys.argv) != 3:
        cprint("Usage: appscale register <deployment ID>", "red")
        print("You can obtain a deployment ID from {0}"
          .format(RegistrationHelper.ADD_DEPLOYMENT_URL))
        sys.exit(1)

      appscale.register(sys.argv[2])
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  elif command in ["--version", "-v"]:
    print APPSCALE_VERSION
    sys.exit(0)
  elif command == "upgrade":
    try:
        appscale.upgrade()
    except Exception as exception:
      LocalState.generate_crash_log(exception, traceback.format_exc())
      sys.exit(1)
  else:
    print(AppScale.USAGE)
    if command == "help":
      sys.exit(0)
    else:
      sys.exit(1)
