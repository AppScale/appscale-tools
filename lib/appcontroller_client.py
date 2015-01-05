#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)
# Adapted from Hiranya's version


# General-purpose Python library imports
import json
import re
import socket
import signal
import ssl
import time


# Third-party imports
import SOAPpy


# AppScale-specific imports
from appscale_logger import AppScaleLogger
from custom_exceptions import AppControllerException
from custom_exceptions import TimeoutException


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


  # The max number of seconds we should wait for when waiting for the
  # UserAppServer to start up. We'll give up after this.
  MAX_RETRIES = 100


  # The message that an AppController can return if callers do not authenticate
  # themselves correctly.
  BAD_SECRET_MESSAGE = 'false: bad secret'


  # The number of times we should retry SOAP calls in case of failures.
  DEFAULT_NUM_RETRIES = 5


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

    # Disable certificate verification for Python 2.7.9.
    if hasattr(ssl, '_create_unverified_context'):
      ssl._create_default_https_context = ssl._create_unverified_context


  def run_with_timeout(self, timeout_time, default, num_retries, function,
    *args):
    """Runs the given function, aborting it if it runs too long.

    Args:
      timeout_time: The number of seconds that we should allow function to
        execute for.
      default: The value that should be returned if the timeout is exceeded.
      num_retries: The number of times we should retry the SOAP call if we see
        an unexpected exception.
      function: The function that should be executed.
      *args: The arguments that will be passed to function.
    Returns:
      Whatever function(*args) returns if it runs within the timeout window, and
        default otherwise.
    Raises:
      AppControllerException: If the AppController we're trying to connect to is
        not running at the given IP address, or if it rejects the SOAP request.
    """
    def timeout_handler(_, __):
      """Raises a TimeoutException if the function we want to execute takes
      too long to run.

      Raises:
        TimeoutException: If a SIGALRM is raised.
      """
      raise TimeoutException()

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_time)  # trigger alarm in timeout_time seconds
    try:
      retval = function(*args)
    except TimeoutException:
      return default
    except socket.error as exception:
      signal.alarm(0)  # turn off the alarm before we retry
      if num_retries > 0:
        time.sleep(1)
        return self.run_with_timeout(timeout_time, default, num_retries - 1,
          function, *args)
      else:
        raise exception
    except ssl.SSLError:
      # these are intermittent, so don't decrement our retry count for this
      signal.alarm(0)  # turn off the alarm before we retry
      return self.run_with_timeout(timeout_time, default, num_retries, function,
        *args)
    finally:
      signal.alarm(0)  # turn off the alarm

    if retval == self.BAD_SECRET_MESSAGE:
      raise AppControllerException("Could not authenticate successfully" + \
        " to the AppController. You may need to change the keyname in use.")

    return retval


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

    result = self.run_with_timeout(10, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.set_parameters, json.dumps(locations), credentials, [app],
      self.secret)
    if result.startswith('Error'):
      raise AppControllerException(result)


  def get_all_public_ips(self):
    """Queries the AppController for a list of all the machines running in this
    AppScale deployment, and returns their public IP addresses.

    Returns:
      A list of the public IP addresses of each machine in this AppScale
      deployment.
    """
    all_ips = self.run_with_timeout(10, "", self.DEFAULT_NUM_RETRIES,
      self.server.get_all_public_ips, self.secret)
    if all_ips == "":
      return []
    else:
      return json.loads(all_ips)


  def get_role_info(self):
    """Queries the AppController to determine what each node in the deployment
    is doing and how it can be externally or internally reached.

    Returns:
      A dict that contains the public IP address, private IP address, and a list
      of the API services that each node runs in this AppScale deployment.
    """
    role_info = self.run_with_timeout(10, "", self.DEFAULT_NUM_RETRIES,
      self.server.get_role_info, self.secret)
    if role_info == "":
      return {}
    else:
      return json.loads(role_info)


  def get_uaserver_host(self, is_verbose):
    """Queries the AppController to see which machine is hosting the
    UserAppServer, and at what IP it can be reached.

    Args:
      is_verbose: A bool that indicates if we should print out the first
        AppController's status when we query it.
    Returns:
      The IP address where a UserAppServer can be located (although it is not
      guaranteed to be running).
    Raises:
      TimeoutException if MAX_RETRIES is attempted with no answer from
      controller.
    """
    last_known_state = None
    retries = 0
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
      except (AppControllerException, socket.error) as exception:
        raise exception
      except Exception as exception:
        AppScaleLogger.warn('Saw {0}, waiting a few moments to try again' \
          .format(str(exception)))
      time.sleep(self.WAIT_TIME)
      retries += 1
      if retries >= self.MAX_RETRIES:
        AppScaleLogger.warn("Too many retries to connect to UAServer.")
        raise TimeoutException()

  def get_status(self):
    """Queries the AppController to see what its internal state is.

    Returns:
      A str that indicates what the AppController reports its status as.
    """
    return self.run_with_timeout(10, "", self.DEFAULT_NUM_RETRIES,
      self.server.status, self.secret)


  def is_initialized(self):
    """Queries the AppController to see if it has started up all of the API
    services it is responsible for on its machine.

    Returns:
      A bool that indicates if all API services have finished starting up on
      this machine.
    """
    return self.run_with_timeout(10, False, self.DEFAULT_NUM_RETRIES,
      self.server.is_done_initializing, self.secret)


  def start_roles_on_nodes(self, roles_to_nodes):
    """Dynamically adds the given machines to an AppScale deployment, with the
    specified roles.

    Args:
      A JSON-dumped dict that maps roles to IP addresses.
    Returns:
      The result of executing the SOAP call on the remote AppController.
    """
    return self.run_with_timeout(10, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.start_roles_on_nodes, roles_to_nodes, self.secret)


  def stop_app(self, app_id):
    """Tells the AppController to no longer host the named application.

    Args:
      app_id: A str that indicates which application should be stopped.
    Returns:
      The result of telling the AppController to no longer host the app.
    """
    return self.run_with_timeout(10, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.stop_app, app_id, self.secret)


  def is_app_running(self, app_id):
    """Queries the AppController to see if the named application is running.

    Args:
      app_id: A str that indicates which application we should be checking
        for.
    Returns:
      True if the application is running, False otherwise.
    """
    return self.run_with_timeout(10, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.is_app_running, app_id, self.secret)


  def done_uploading(self, app_id, remote_app_location):
    """Tells the AppController that an application has been uploaded to its
    machine, and where to find it.

    Args:
      app_id: A str that indicates which application we have copied over.
      remote_app_location: The location on the remote machine where the App
        Engine application can be found.
    """
    return self.run_with_timeout(10, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.done_uploading, app_id, remote_app_location, self.secret)


  def update(self, apps_to_run):
    """Tells the AppController which applications to run, which we assume have
    already been uploaded to that machine.

    Args:
      apps_to_run: A list of apps to start running on nodes running the App
        Engine service.
    """
    return self.run_with_timeout(10, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.update, apps_to_run, self.secret)


  def get_app_info_map(self):
    """Asks the AppController for a list of all the applications it is proxying
    via nginx, haproxy, or running itself.

    Returns:
      A dict that maps application IDs (strs) to a dict indicating what nginx,
      haproxy, or dev_appserver ports host that app, with an additional field
      indicating what language the app is written in.
    """
    return json.loads(self.run_with_timeout(10, '{}', self.DEFAULT_NUM_RETRIES,
      self.server.get_app_info_map, self.secret))


  def relocate_app(self, appid, http_port, https_port):
    """Asks the AppController to start serving traffic for the named application
    on the given ports, instead of the ports that it was previously serving at.

    Args:
      appid: A str that names the already deployed application that we want to
        move to a different port.
      http_port: An int between 80 and 90, or between 1024 and 65535, that names
        the port that unencrypted traffic should be served from for this app.
      https_port: An int between 443 and 453, or between 1024 and 65535, that
        names the port that encrypted traffic should be served from for this
        app.
    Returns:
      A str that indicates if the operation was successful, and in unsuccessful
      cases, the reason why the operation failed.
    """
    return self.run_with_timeout(20, "Relocate request timed out.",
      self.DEFAULT_NUM_RETRIES, self.server.relocate_app, appid, http_port,
        https_port, self.secret)


  def get_property(self, property_regex):
    """Queries the AppController for a dictionary of its instance variables
    whose names match the given regular expression, along with their associated
    values.

    Args:
      property_regex: A str that names a regex of instance variables whose
        values should be retrieved from the AppController.
    Returns:
      A dict mapping each instance variable matched by the given regex to its
      value. This dict is empty when (1) no matches are found, or (2) if the
      SOAP call times out.
    """
    return json.loads(self.run_with_timeout(10, '{}', self.DEFAULT_NUM_RETRIES,
      self.server.get_property, property_regex, self.secret))


  def set_property(self, property_name, property_value):
    """Instructs the AppController to update one of its instance variables with
    a new value, provided by the caller.

    Args:
      property_name: A str naming the instance variable to overwrite.
      property_value: The new value that should be set for the given property.
    Returns:
      A str indicating that the request either succeeded (the string literal
      'OK'), or the reason why the request failed (e.g., the property name
      referred to a non-existent instance variable).
    """
    return self.run_with_timeout(10, 'Set property request timed out.',
      self.DEFAULT_NUM_RETRIES, self.server.set_property, property_name,
      property_value, self.secret)
