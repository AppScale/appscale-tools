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
from custom_exceptions import AppControllerException


class AppControllerClient():
  """AppControllerClient provides callers with an interface to AppScale's
  AppController daemon.

  The AppController is a dispatching service that is responsible for starting
  API services on each node in an AppScale deployment. Callers may talk to
  the AppController to get information about the number of nodes in the
  deployment as well as what services each node runs.
  """


  # The port that the AppController runs on by default.
  PORT = 17443


  # The number of seconds we should wait for when waiting for the UserAppServer
  # to start up.
  WAIT_TIME = 10


  # The message that an AppController can return if callers do not authenticate
  # themselves correctly.
  BAD_SECRET_MESSAGE = 'false: bad secret'


  def __init__(self, host, secret):
    """Creates a new AppControllerClient.

    Args:
      host: The location where an AppController can be found.
      secret: A str containing the secret key, used to authenticate this client
        when talking to remote AppControllers.
    """
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:%s' % (host,
      self.PORT))
    self.secret = secret


  def set_parameters(self, locations, credentials, app=None):
    """Passes the given parameters to an AppController, allowing it to start
    configuring API services in this AppScale deployment.

    Args:
      locations: A list that contains the first node's IP address.
      credentials: A list that contains API service-level configuration info,
        as well as a mapping of IPs to the API services they should host
        (excluding the first node).
      app: A list of the App Engine apps that should be started.
    Raises:
      AppControllerException: If the remote AppController indicates that there
        was a problem with the parameters passed to it.
    """
    if app is None:
      app = 'none'

    result = self.server.set_parameters(locations, credentials,
      [ app ], self.secret)
    if result.startswith('Error'):
      raise AppControllerException(result)


  def get_all_public_ips(self):
    """Queries the AppController for a list of all the machines running in this
    AppScale deployment, and returns their public IP addresses.

    Returns:
      A list of the public IP addresses of each machine in this AppScale
      deployment.
    """
    return json.loads(self.server.get_all_public_ips(self.secret))


  def get_role_info(self):
    """Queries the AppController to determine what each node in the deployment
    is doing and how it can be externally or internally reached.

    Returns:
      A dict that contains the public IP address, private IP address, and a list
      of the API services that each node runs in this AppScale deployment.
    """
    return json.loads(self.server.get_role_info(self.secret))


  def get_uaserver_host(self, is_verbose):
    """Queries the AppController to see which machine is hosting the
    UserAppServer, and at what IP it can be reached.

    Args:
      is_verbose: A bool that indicates if we should print out the first
        AppController's status when we query it.
    Returns:
      The IP address where a UserAppServer can be located (although it is not
      guaranteed to be running).
    """
    last_known_state = None
    while True:
      try:
        status = self.get_status()
        AppScaleLogger.verbose('Received status from head node: ' + status,
          is_verbose)

        if status == self.BAD_SECRET_MESSAGE:
          raise AppControllerException("Could not authenticate successfully" + \
            " to the AppController. You may need to change the keyname in use.")

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
      except AppControllerException as exception:
        raise exception
      except Exception as exception:
        AppScaleLogger.warn('Saw {0}, waiting a few moments to try again' \
          .format(str(exception)))
      time.sleep(self.WAIT_TIME)


  def get_status(self):
    """Queries the AppController to see what its internal state is.

    Returns:
      A str that indicates what the AppController reports its status as.
    """
    return self.server.status(self.secret)


  def is_initialized(self):
    """Queries the AppController to see if it has started up all of the API
    services it is responsible for on its machine.

    Returns:
      A bool that indicates if all API services have finished starting up on
      this machine.
    """
    try:
      return self.server.is_done_initializing(self.secret)
    except Exception:
      return False


  def stop_app(self, app_name):
    """Tells the AppController to no longer host the named application.

    Args:
      app_name: A str that indicates which application should be stopped.
    Returns:
      The result of telling the AppController to no longer host the app.
    """
    return self.server.stop_app(app_name, self.secret)


  def is_app_running(self, app_name):
    """Queries the AppController to see if the named application is running.

    Args:
      app_name: A str that indicates which application we should be checking
        for.
    Returns:
      True if the application is running, False otherwise.
    """
    return self.server.is_app_running(app_name, self.secret)
