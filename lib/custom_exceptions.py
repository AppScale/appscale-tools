#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale)


# A special Exception class that should be thrown if the user tries to
# run an appscale command that interacts with an AppScalefile and the
# file is either malformed or in an unexpected state.
class AppScalefileException(Exception):
  pass


# A special Exception class that should be thrown if the user attempts
# to execute a command with malformed arguments.
class BadConfigurationException(Exception):
  pass


# A special Exception class that should be thrown if the user attempts
# to run the 'help' directive, which reports on the usage of this tool.
class UsageException(Exception):
  pass
