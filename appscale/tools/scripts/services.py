# General-purpose Python library imports
import sys
import traceback
import yaml

# Third-party Python libraries
from tabulate import tabulate
from termcolor import cprint

# AppScale library imports
from .. import version_helper
from ..appscale import AppScale
from ..appscale_tools import AppScaleTools
from ..local_state import LocalState
from ..parse_args import ParseArgs


version_helper.ensure_valid_python_is_used()

class AppScaleServices(object):
  # The usage that should be displayed to users if they call 'appscale services'
  # with a bad directive or ask for help.
  headers = ["\nUsage: appscale services command [<args>]\n\n" +
             "Available commands:\n", "\n"]
  table = [["delete <project_id> <service_id>",
            "Removes <project_id> <service_id> from the current deployment."],
           ["start <project_id> <service_id>",
            "Starts <project_id> <service_id> for the current deployment."],
           ["stop <project_id> <service_id>",
            "Stops <project_id> <service_id> for the current deployment."]]
  USAGE = tabulate(table, headers)

  def __init__(self):
    self.appscale = AppScale()
    self.appscale_tools = AppScaleTools()

  def delete_service(self, project_id, service_id):
    contents = self.appscale.read_appscalefile()

    # Construct an remove-app command from the file's contents
    command = []
    contents_as_yaml = yaml.safe_load(contents)
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])

    if 'verbose' in contents_as_yaml and contents_as_yaml['verbose'] == True:
      command.append("--verbose")

    if 'test' in contents_as_yaml and contents_as_yaml['test'] == True:
      command.append('--confirm')

    command.append("--project-id")
    command.append(project_id)
    command.append("--service-id")
    command.append(service_id)

    options = ParseArgs(command, "appscale-remove-service").args
    try:
      self.appscale_tools.remove_service(options)
      sys.exit(0)
    except Exception as e:
      LocalState.generate_crash_log(e, traceback.format_exc())
      sys.exit(1)

  def start_service(self, project_id, service_id):
    contents = self.appscale.read_appscalefile()

    # Construct a start-service command from the file's contents
    command = []
    contents_as_yaml = yaml.safe_load(contents)
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])
    if 'verbose' in contents_as_yaml and contents_as_yaml['verbose'] == True:
      command.append("--verbose")
    command.append("--project-id")
    command.append(project_id)
    command.append("--service-id")
    command.append(service_id)

    options = ParseArgs(command, "appscale-start-service").args
    try:
      self.appscale_tools.start_service(options)
      sys.exit(0)
    except Exception as e:
      LocalState.generate_crash_log(e, traceback.format_exc())
      sys.exit(1)

  def stop_service(self, project_id, service_id):
    contents = self.appscale.read_appscalefile()

    # Construct a stop-service command from the file's contents
    command = []
    contents_as_yaml = yaml.safe_load(contents)
    if 'keyname' in contents_as_yaml:
      command.append("--keyname")
      command.append(contents_as_yaml['keyname'])
    if 'verbose' in contents_as_yaml and contents_as_yaml['verbose'] == True:
      command.append("--verbose")
    if 'test' in contents_as_yaml and contents_as_yaml['test'] == True:
      command.append('--confirm')
    command.append("--project-id")
    command.append(project_id)
    command.append("--service-id")
    command.append(service_id)

    options = ParseArgs(command, "appscale-stop-service").args
    try:
      self.appscale_tools.stop_service(options)
      sys.exit(0)
    except Exception as e:
      LocalState.generate_crash_log(e, traceback.format_exc())
      sys.exit(1)

def main():
  """ Execute appscale-remove-app script. """
  if len(sys.argv) < 3:
    cprint(AppScaleServices.USAGE, 'red')
    sys.exit(1)
  services = AppScaleServices()
  command = sys.argv[2]

  if command == "delete":
    if len(sys.argv) != 5:
      cprint(services.USAGE, 'red')
      sys.exit(1)
    services.delete_service(sys.argv[3], sys.argv[4])
  elif command == "start":
    if len(sys.argv) != 5:
      cprint(services.USAGE, 'red')
      sys.exit(1)
    services.start_service(sys.argv[3], sys.argv[4])
  elif command == "stop":
    if len(sys.argv) != 5:
      cprint(services.USAGE, 'red')
      sys.exit(1)
    services.stop_service(sys.argv[3], sys.argv[4])
  elif command in ["help", "--help", "-h"]:
    print(AppScaleServices.USAGE)
    sys.exit(0)
  else:
    cprint(AppScaleServices.USAGE, 'red')
    sys.exit(1)
