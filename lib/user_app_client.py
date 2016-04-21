#!/usr/bin/env python
""" Handlers interface to the user/apps soap server in AppScale. """


# General-purpose Python libraries
import json
import re
import time
import ssl


# Third-party imports
import SOAPpy


# AppScale-specific imports
from appscale_logger import AppScaleLogger
from custom_exceptions import AppScaleException
from local_state import LocalState


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
  ADMIN_CAPABILITIES = ":".join(["upload_app"])


  # The initial amount of time we should sleep when waiting for UserAppServer
  # metadata to change state.
  STARTING_SLEEP_TIME = 1


  # The maximum amount of time we should sleep when waiting for UserAppServer
  # metadata to change state.
  MAX_SLEEP_TIME = 30


  # Max time to wait to see if an application is uploaded.
  MAX_WAIT_TIME = 60 * 60 # 1 hour.


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

    # Disable certificate verification for Python 2.7.9.
    if hasattr(ssl, '_create_unverified_context'):
      ssl._create_default_https_context = ssl._create_unverified_context


  def create_user(self, username, password, account_type='xmpp_user'):
    """Creates a new user account, with the given username and hashed password.

    Args:
      username: An e-mail address that should be set as the new username.
      password: A sha1-hashed password that is bound to the given username.
      account_type: A str that indicates if this account can be logged into by
        XMPP users.
    """
    AppScaleLogger.log("Creating new user account {0}".format(username)) 
    while 1:
      try:
        result = self.server.commit_new_user(username, password, account_type,
          self.secret)
        break
      except Exception, exception:
        AppScaleLogger.log("Exception when creating user: {0}".format(exception))
        AppScaleLogger.log("Backing off and trying again")
        time.sleep(10)

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


  def does_user_exist(self, username, silent=False):
    """Queries the UserAppServer to see if the given user exists.

    Returns:
      True if the given user exists, False otherwise.
    """
  
    while 1: 
      try:
        if self.server.does_user_exist(username, self.secret) == "true":
          return True
        else:
          return False
      except Exception, exception:
        if not silent:
          AppScaleLogger.log("Exception when checking if a user exists: {0}".\
            format(exception))
          AppScaleLogger.log("Backing off and trying again")
        time.sleep(10)
 

  def does_app_exist(self, appname):
    """Queries the UserAppServer to see if the named application exists,
    and it is listening to any port.

    Args:
      appname: The name of the app that we should check for existence.
    Returns:
      True if the app does exist, False otherwise.
    """
    app_data = self.server.get_app_data(appname, self.secret)
    if "Error:" in app_data:
      return False

    result = json.loads(app_data)
    if len(result['hosts']) > 0:
      return True

    return False


  def change_password(self, username, password):
    """Sets the given user's password to the specified (hashed) value.

    Args:
      username: The e-mail address for the user whose password will be
        changed.
      password: The SHA1-hashed password that will be set as the user's
        password.
    """
    result = self.server.change_password(username, password, self.secret)
    if result != 'true':
      raise Exception(result)


  def reserve_app_id(self, username, app_id, app_language):
    """Tells the UserAppServer to reserve the given app_id for a particular
    user.

    Args:
      username: A str representing the app administrator's e-mail address.
      app_id: A str representing the application ID to reserve.
      app_language: The runtime (Python 2.5/2.7, Java, or Go) that the app runs
        over.
    """
    result = self.server.commit_new_app(app_id, username, app_language,
      self.secret)
    if result == "true":
      AppScaleLogger.log("We have reserved {0} for your app".format(app_id))
    elif result == "Error: appname already exist":
      AppScaleLogger.log("We are uploading a new version of your app.")
    elif result == "Error: User not found":
      raise AppScaleException("No information found about user {0}" \
        .format(username))
    else:
      raise AppScaleException(result)


  def get_serving_info(self, app_id, keyname):
    """Finds out what host and port are used to host the named application.

    Args:
      app_id: The application that we should find a serving URL for.
    Returns:
      A tuple containing the host and port where the application is serving
        traffic from.
    """
    total_wait_time = 0
    # first, wait for the app to start serving
    sleep_time = self.STARTING_SLEEP_TIME
    while True:
      if self.does_app_exist(app_id):
        break
      else:
        AppScaleLogger.log("Waiting {0} second(s) to check on application...".\
          format(sleep_time))
        time.sleep(sleep_time)
        sleep_time = min(sleep_time * 2, self.MAX_SLEEP_TIME)
        total_wait_time += sleep_time
      if total_wait_time > self.MAX_WAIT_TIME:
        raise AppScaleException("App took too long to upload")

    # next, get the serving host and port
    app_data = self.server.get_app_data(app_id, self.secret)
    if "Error:" in app_data:
      raise AppScaleException("Cannot find application data")

    result = json.loads(app_data)
    host = LocalState.get_login_host(keyname)
    port = 0
    if len(result['hosts']) > 0:
      port = int(result['hosts'].values()[0]['http'])

    return host, port
