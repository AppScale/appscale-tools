#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)
# Adapted from Hiranya's version


# General-purpose Python library imports
import json
import re
import time


# Third-party imports
import SOAPpy


# AppScale-specific imports
from appscale_logger import AppScaleLogger


class AppControllerClient():


  # The port that the AppController runs on by default.
  PORT = 17443


  def __init__(self, host, secret):
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:%s' % (host,
      self.PORT))
    self.secret = secret


  def set_parameters(self, locations, credentials, app=None):
    if app is None:
      app = 'none'

    result = self.server.set_parameters(locations, credentials,
      [ app ], self.secret)
    if result.startswith('Error'):
      raise Exception(result)


  def get_all_public_ips(self):
    return json.loads(self.server.get_all_public_ips(self.secret))


  def get_role_info(self):
    return json.loads(self.server.get_role_info(self.secret))


  def get_uaserver_host(self, is_verbose):
    last_known_state = None
    while True:
      try:
        status = self.get_status()
        AppScaleLogger.verbose('Received status from head node: ' + status,
          is_verbose)
        match = re.search(r'Database is at (.*)', status)
        if match and match.group(1) != 'not-up-yet':
          return match.group(1)
        else:
          match = re.search(r'Current State: (.*)', status)
          if match:
            if last_known_state != match.group(1):
              last_known_state = match.group(1)
            AppScaleLogger.log(last_known_state)
          else:
            AppScaleLogger.log('Waiting for AppScale nodes to complete '
                             'the initialization process')
      except Exception as e:
        AppScaleLogger.warn('Saw {0}, waiting a few moments to try again'.format(str(e)))
      time.sleep(10)


  def get_status(self):
    return self.server.status(self.secret)


  def is_initialized(self):
    try:
      return self.server.is_done_initializing(self.secret)
    except Exception:
      return False
