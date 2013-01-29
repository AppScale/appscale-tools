#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)
# Adapted from Hiranya's version


# General-purpose Python library imports
import re
import time


# Third-party imports
import SOAPpy


class AppControllerClient():


  APP_CONTROLLER_PORT = 17443


  def __init__(self, host, secret):
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:%s' % (host,
      self.APP_CONTROLLER_PORT))
    self.secret = secret


  def set_parameters(self, locations, credentials, app=None):
    if app is None:
      app = 'none'

    result = self.server.set_parameters(locations, credentials,
      [ app ], self.secret)
    if result.startswith('Error'):
      raise Exception(result)


  def get_all_public_ips(self):
    nodes = []
    ips = self.server.get_all_public_ips(self.secret)
    for ip in ips:
      nodes.append(ip)
    return nodes


  def get_user_manager_host(self):
    last_known_state = None
    while True:
      try:
        status = self.get_status()
        self.logger.verbose('Received status from head node: ' + status)
        match = re.search(r'Database is at (.*)', status)
        if match and match.group(1) != 'not-up-yet':
          return match.group(1)
        else:
          match = re.search(r'Current State: (.*)', status)
          if match:
            if last_known_state != match.group(1):
              last_known_state = match.group(1)
            self.logger.info(last_known_state + "...")
          else:
            self.logger.info('Waiting for AppScale nodes to complete '
                             'the initialization process...')
      except Exception:
        pass
      time.sleep(10)


  def get_status(self):
    return self.server.status(self.secret)


  def is_initialized(self):
    try:
      return self.server.is_done_initializing(self.secret)
    except Exception:
      return False
