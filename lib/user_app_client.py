#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)
# Adapted from Hiranya's version


# Third-party imports
import SOAPpy


# AppScale-specific imports
from appscale_logger import AppScaleLogger


class UserAppClient():


  PORT = 4343


  ADMIN_CAPABILITIES = ":".join(["upload_app", "mr_api", "ec2_api", "neptune_api"])


  def __init__(self, host, secret):
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:%s' % (host, self.PORT))
    self.secret = secret


  def create_user(self, username, password, type='xmpp_user'):
    AppScaleLogger.log("Creating new user account {0}".format(username)) 
    result = self.server.commit_new_user(username, password, type, self.secret)
    if result != 'true':
      raise Exception(result)


  def reserve_application_name(self, username, application, language):
    AppScaleLogger.log("Registering application name {0} (lang={1}) for " + \
      "user {2}".format(application, language, username))

    result = self.server.commit_new_app(application, username,
      language, self.secret)
    if result != 'true':
      raise Exception(result)


  def commit_application_archive(self, application, file_path):
    result = self.server.commit_tar(application, file_path, self.secret)
    if result != 'true':
      raise Exception(result)


  def set_admin_role(self, username):
    AppScaleLogger.log('Granting admin privileges to %s' % username)
    self.server.set_cloud_admin_status(username, 'true', self.secret)
    self.server.set_capabilities(username, self.ADMIN_CAPABILITIES, self.secret)
