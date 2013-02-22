import re
from time import sleep
import SOAPpy
from utils import commons

__author__ = 'hiranya'

class AppControllerClient:

  APP_CONTROLLER_PORT = 17443

  def __init__(self, host, secret):
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:%s' % (
      host, self.APP_CONTROLLER_PORT))
    self.secret = secret
    self.logger = commons.get_logger()

  def is_port_open(self):
    if self.logger.is_verbose:
      msg = 'Checking if the port %s is open on %s' % (
        self.APP_CONTROLLER_PORT, self.host)
      self.logger.verbose(msg)
    return commons.is_port_open(self.host, self.APP_CONTROLLER_PORT)

  def is_live(self):
    try:
      self.server.status(self.secret)
      return True
    except Exception:
      return False

  def set_parameters(self, locations, credentials, app):
    try:
      if app is None:
        app = 'none'

      result = self.server.set_parameters(locations, credentials,
        [ app ], self.secret)
      if result.startswith('Error'):
        raise Exception(result)
    except Exception as exception:
      commons.error('Error while setting AppController parameters',
        exception=exception)

  def is_app_running(self, app):
    try:
      return self.server.is_app_running(app, self.secret)
    except Exception:
      return False

  def get_all_public_ips(self):
    try:
      nodes = []
      ips = self.server.get_all_public_ips(self.secret)
      for ip in ips:
        nodes.append(ip)
      return nodes
    except Exception as exception:
      commons.error('Error while obtaining list of IPs', exception=exception)

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
      sleep(10)

  def get_status(self):
    try:
      return self.server.status(self.secret)
    except Exception as exception:
      commons.error('Error while obtaining server status', exception=exception)

  def is_initialized(self):
    try:
      return self.server.is_done_initializing(self.secret)
    except Exception:
      return False

  def commit_application(self, application, location):
    try:
      self.server.done_uploading(application, location, self.secret)
    except Exception as exception:
      msg = 'Error while committing application %s to %s' % (
        application, location)
      commons.error(msg, exception=exception)

  def get_login_host(self):
    all_nodes = self.get_all_public_ips()
    for node in all_nodes:
      temp_client = AppControllerClient(node, self.secret)
      status = temp_client.get_status()
      self.logger.verbose(status)
      if re.search(r'Is currently:(.*)login', status):
        return node
    commons.error('Unable to find the login node in the cluster')
