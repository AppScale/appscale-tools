#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)
# Adapted from Hiranya's version


# Third-party imports
import SOAPpy


# AppScale-specific imports
from appscale_logger import AppScaleLogger


class UserAppClient():
  """UserAppClient provides callers with an interface to AppScale's
  UserAppServer daemon.

  The UserAppServer is a SOAP-exposed service that is responsible for handling
  user and application-level data. It uses the database-agnostic AppDB interface
  to enable callers to read and write database information, without needing to
  be concerned with the particulars of the database that AppScale is running on.
  """


  # The port that the UserAppServer runs on by default.
  PORT = 4343


  # A str that contains all of the authorizations that an AppScale cloud
  # administrator should be granted.
  ADMIN_CAPABILITIES = ":".join(["upload_app", "mr_api", "ec2_api", "neptune_api"])


  def __init__(self, host, secret):
    """Creates a new UserAppClient.

    Args:
      host: The location where an UserAppClient can be found.
      secret: A str containing the secret key, used to authenticate this client
        when talking to remote UserAppServers.
    """
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:%s' % (host, self.PORT))
    self.secret = secret


  def create_user(self, username, password, account_type='xmpp_user'):
    """Creates a new user account, with the given username and hashed password.

    Args:
      username: An e-mail address that should be set as the new username.
      password: A sha1-hashed password that is bound to the given username.
      account_type: A str that indicates if this account can be logged into by
        XMPP users.
    """
    AppScaleLogger.log("Creating new user account {0}".format(username)) 
    result = self.server.commit_new_user(username, password, account_type,
      self.secret)
    if result != 'true':
      raise Exception(result)


  def reserve_application_name(self, username, application, language):
    """Tells the UserAppServer to reserve the given application ID and
    register the given user as that application's administrator.

    Args:
      username: The e-mail address that should be set as the administrator for
        the given application.
      application: The application ID that should be reserved.
      language: A str that indicates if the application is a Python 2.5 app,
        a Java app, a Python 2.7 app, or a Go app.
    Raises:
      If the UserAppServer rejects the request to reserve the given
        application ID.
    """
    AppScaleLogger.log("Registering application name {0} (lang={1}) for " + \
      "user {2}".format(application, language, username))

    result = self.server.commit_new_app(application, username,
      language, self.secret)
    if result != 'true':
      raise Exception(result)


  def commit_application_archive(self, application, file_path):
    """Tells the UserAppServer where it can find the given application, on its
    own filesystem.

    Args:
      application: A str that indicates what the name of the application is.
      file_path: A str that points to a location on the remote filesystem where
        the application can be found.
    Raises:
      Exception: If the UserAppServer rejects the request to look for the
      application on its filesystem.
    """
    result = self.server.commit_tar(application, file_path, self.secret)
    if result != 'true':
      raise Exception(result)


  def set_admin_role(self, username):
    """Grants the given user the ability to perform any administrative action.

    Args:
      username: The e-mail address that should be given administrative
        authorizations.
    """
    AppScaleLogger.log('Granting admin privileges to %s' % username)
    self.server.set_cloud_admin_status(username, 'true', self.secret)
    self.server.set_capabilities(username, self.ADMIN_CAPABILITIES, self.secret)


  def does_user_exist(self, username):
    """Queries the UserAppServer to see if the given user exists.

    Returns:
      True if the given user exists, False otherwise.
    """
    if self.server.does_user_exist(username, self.secret) == "true":
      return True
    else:
      return False
