#!/usr/bin/env python

import threading

def threaded(func):
  """ Decorator that allows a function to run in a separate thread.

  Args:
    func: The function to be run.
  """
  def _threaded(*args, **kwargs):
    """ Executes the given function in a thread. """
    thread = threading.Thread(target=func, args=args, kwargs=kwargs)
    thread.start()
    return thread
  return _threaded
