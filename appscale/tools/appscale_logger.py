#!/usr/bin/env python


# General-purpose Python library imports
import httplib


# Third party library imports
from termcolor import cprint


class AppScaleLogger():
  """This class receives requests to log message on behalf of callers, and in
  response, prints them to the user and saves them for debugging purposes.
  """


  # The location where we remotely dump logs to
  LOGS_HOST = "logs.appscale.com"


  # The headers necessary for posting data to the remote logs service.
  HEADERS = {
    'Content-Type' : 'application/x-www-form-urlencoded'
  }


  @classmethod
  def log(cls, message):
    """Prints the specified message to the user as well as to a file.

    Args:
      message: A str representing the message to log.
    """
    print message


  @classmethod
  def warn(cls, message):
    """Prints the specified message with red text as well as to a file.

    Args:
      message: A str representing the message to warn the user with.
    """
    cprint(message, 'red')


  @classmethod
  def success(cls, message):
    """Prints the specified message with green text as well as to a file.

    Args:
      message: A str representing the message to log.
    """
    cprint(message, 'green')


  @classmethod
  def verbose(cls, message, is_verbose):
    """Prints the specified message if we're running in 'verbose' mode, and
    always logs it.

    Args:
      message: A str representing the message to log.
      is_verbose: A bool that indicates whether or not the message should be
        printed to stdout.
    """
    if is_verbose:
      print message


  @classmethod
  def remote_log_tools_state(cls, options, my_id, state, version):
    """Converts the given debugging information to a message that we can
    remotely log, and then logs it.

    Args:
      options: A Namespace containing the arguments used to invoke an AppScale
        tool.
      state: A str that indicates if the given AppScale deployment is starting,
        has started successfully, or has failed to start.
      version: A str that indicates which version of AppScale we are deploying
        over.
    Returns:
      A dict containing the debugging information that was logged.
    """
    # turn namespace into a dict
    params = vars(options)

    # next, turn it into a string that we can send over the wire
    payload = "?boo=baz&my_id={0}&state={1}&version={2}".format(my_id, state,
      version)
    for key, value in params.iteritems():
      payload += "&{0}={1}".format(key, value)

    # http post the result
    try:
      conn = httplib.HTTPConnection(cls.LOGS_HOST)
      conn.request('POST', '/upload', payload, cls.HEADERS)
      _ = conn.getresponse()
      conn.close()
    except Exception as exception:
      cls.verbose("Unable to log {0} state: saw exception {1}".format(state,
        str(exception)), options.verbose)

    return params
