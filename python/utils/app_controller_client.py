import SOAPpy
from utils.commons import AppScaleToolsException

__author__ = 'hiranya'

class AppControllerClient:

  def __init__(self, host, secret):
    self.server = SOAPpy.SOAPProxy('https://%s:17443' % host)
    self.secret = secret

  def is_live(self):
    try:
      self.server.status(self.secret)
      return True
    except Exception:
      return False

  def set_parameters(self, locations, credentials, app):
    try:
      result = self.server.set_parameters(locations, credentials,
        app, self.secret)
      if result.startswith('Error'):
        raise Exception(result)
    except Exception as e:
      raise AppScaleToolsException('Error contacting the remote '
                                   'AppController: ' + e.message)