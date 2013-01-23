#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


class AppScaleLogger():
  """This class receives requests to log message on behalf
  of callers, and in response, prints them to the user and
  saves them for later perusal and for debugging purposes.
  """


  @classmethod
  def log(cls, message):
    """Prints the specified message to the user as well as to
    a file.

    Args:
      message: A str representing the message to log.
    """
    print message
    # TODO(cgb): Also write it to a file or buffer somewhere
