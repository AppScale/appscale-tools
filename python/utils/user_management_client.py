import SOAPpy
from utils import commons

__author__ = 'hiranya'

ADMIN_CAPABILITIES = ":".join(["upload_app", "mr_api", "ec2_api", "neptune_api"])

class UserManagementClient:

  USER_APP_SERVER_PORT = 4343

  def __init__(self, host, secret):
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:4343' % host)
    self.secret = secret
    self.logger = commons.get_logger()

  def is_port_open(self):
    if self.logger.is_verbose:
      msg = 'Checking if the port %s is open on %s' % (
        self.USER_APP_SERVER_PORT, self.host)
      self.logger.verbose(msg)
    return commons.is_port_open(self.host, self.USER_APP_SERVER_PORT)

  def create_user(self, username, password, type='xmpp_user'):
    if self.logger.is_verbose:
      msg = 'Creating new user account %s with password %s' % (
        username, password)
      self.logger.verbose(msg)

    encrypted_pass = commons.sha1_encrypt(username + password)
    try:
      result = self.server.commit_new_user(username, encrypted_pass,
        type, self.secret)
      if result != 'true':
        raise Exception(result)
    except Exception as exception:
      commons.error('Error while creating user account: %s' % username,
        exception=exception)

  def reserve_application_name(self, username, application, language):
    if self.logger.is_verbose:
      msg = 'Registering application name %s (lang=%s) for user %s' % (
        application, language, username)
      self.logger.verbose(msg)

    try:
      result = self.server.commit_new_app(application, username,
        language, self.secret)
      if result != 'true':
        raise Exception(result)
    except Exception as exception:
      commons.error('Error while reserving application name: %s' % application,
        exception=exception)

  def commit_application_archive(self, application, file_path):
    try:
      result = self.server.commit_tar(application, file_path, self.secret)
      if result != 'true':
        raise Exception(result)
    except Exception as exception:
      commons.error('Error while committing app archive: %s' % file_path,
        exception=exception)

  def set_admin_role(self, username):
    if self.logger.is_verbose:
      self.logger.verbose('Granting admin privileges to %s' % username)

    try:
      self.server.set_cloud_admin_status(username, 'true', self.secret)
      self.server.set_capabilities(username, ADMIN_CAPABILITIES, self.secret)
    except Exception as exception:
      commons.error('Error while granting admin rights to: %s' % username,
        exception=exception)
