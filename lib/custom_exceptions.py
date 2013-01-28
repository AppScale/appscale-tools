#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale)


# A special Exception class that should be thrown if the user tries to
# interact with an AppScale deployment, but it's not in the expected
# state. Examples of this include scenarios when AppScale configuration
# files aren't written locally, or if we expect AppScale to be running
# and it isn't.
class AppScaleException(Exception):
  pass


# A special Exception class that should be thrown if the user tries to
# run an appscale command that interacts with an AppScalefile and the
# file is either malformed or in an unexpected state.
class AppScalefileException(Exception):
  pass


# A special Exception class that should be thrown if the user attempts
# to execute a command with malformed arguments.
class BadConfigurationException(Exception):
  pass


# A special Exception class that should be thrown if a shell command is
# executed and has a non-zero return value.
class ShellException(Exception):
  pass


# A special Exception class that should be thrown if the user attempts
# to run the 'help' directive, which reports on the usage of this tool.
class UsageException(Exception):
  pass
