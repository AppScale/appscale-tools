#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import httplib


class AppScaleLogger():
  """This class receives requests to log message on behalf
  of callers, and in response, prints them to the user and
  saves them for later perusal and for debugging purposes.
  """


  # The location where we remotely dump logs to
  LOGS_HOST = "logs.appscale.com"


  # The headers that we should send when posting data to
  # the remote logs service.
  HEADERS = {
    'Content-Type' : 'application/x-www-form-urlencoded'
  }


  @classmethod
  def log(cls, message):
    """Prints the specified message to the user as well as to
    a file.

    Args:
      message: A str representing the message to log.
    """
    print message
    # TODO(cgb): Also write it to a file or buffer somewhere


  @classmethod
  def remote_log_tools_state(cls, options, state):
    """Converts the given debugging information to a message
    that we can remotely log, and then logs it.

    Args:
      options: A Namespace containing the arguments used to
        invoke an AppScale tool.
      state: A str that indicates if the given AppScale
        deployment is starting, has started successfully,
        or has failed to start.
    Returns:
      A dict containing the debugging information that was
      logged.
    """
    # turn namespace into a dict
    params = vars(options)

    # next, turn it into a string that we can send over the wire
    payload = "?boo=baz"
    for key, value in enumerate(params):
      payload += "&{0}={1}".format(key, value)

    # http post the result
    try:
      conn = httplib.HTTPSConnection(cls.LOGS_HOST)
      conn.request('POST', '/upload', payload, cls.HEADERS)
    except Exception:
      cls.log("Unable to log {0} state".format(state))

    return params
