#!/usr/bin/env python


# General-purpose Python library imports
import json
import socket
import signal
import ssl
import time


# Third-party imports
import SOAPpy


# AppScale-specific imports
from appscale_logger import AppScaleLogger
from custom_exceptions import AppControllerException
from custom_exceptions import AppScaleException
from custom_exceptions import BadSecretException
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


  # The maximum amount of time we should wait before timing out the request.
  DEFAULT_TIMEOUT = 10


  # The maximum amount of time we should wait before timing out requests that take longer.
  LONGER_TIMEOUT = 20


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
        raise AppControllerException("Got exception from socket: {}".format(
          exception))

    except ssl.SSLError:
      # these are intermittent, so don't decrement our retry count for this
      signal.alarm(0)  # turn off the alarm before we retry
      return self.run_with_timeout(timeout_time, default, num_retries, function,
        *args)
    finally:
      signal.alarm(0)  # turn off the alarm

    if retval == self.BAD_SECRET_MESSAGE:
      raise BadSecretException("Could not authenticate successfully" + \
        " to the AppController. You may need to change the keyname in use.")

    return retval


  def set_parameters(self, locations, params):
    """Passes the given parameters to an AppController, allowing it to start
    configuring API services in this AppScale deployment.

    Args:
      locations: A list that contains the first node's IP address.
      params: A list that contains API service-level configuration info,
        as well as a mapping of IPs to the API services they should host
        (excluding the first node).
    Raises:
      AppControllerException: If the remote AppController indicates that there
        was a problem with the parameters passed to it.
    """

    result = self.run_with_timeout(
      self.DEFAULT_TIMEOUT, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.set_parameters, json.dumps(locations), json.dumps(params),
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
    all_ips = self.run_with_timeout(self.DEFAULT_TIMEOUT, "", self.DEFAULT_NUM_RETRIES,
      self.server.get_all_public_ips, self.secret)
    if all_ips == "":
      return []
    else:
      return json.loads(all_ips)


  def get_all_private_ips(self):
    """Queries the AppController for a list of all the machines running in this
    AppScale deployment, and returns their private IP addresses.

    Returns:
      A list of the private IP addresses of each machine in this AppScale
      deployment.
    """
    all_ips = self.run_with_timeout(self.DEFAULT_TIMEOUT, "", self.DEFAULT_NUM_RETRIES,
      self.server.get_all_private_ips, self.secret)
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
    role_info = self.run_with_timeout(self.DEFAULT_TIMEOUT, "", self.DEFAULT_NUM_RETRIES,
      self.server.get_role_info, self.secret)
    if role_info == "":
      return {}
    else:
      return json.loads(role_info)


  def get_cluster_stats(self):
    """Queries the AppController to see what its internal state is.

    Returns:
      A str that indicates what the AppController reports its status as.
    """
    stats = self.run_with_timeout(self.DEFAULT_TIMEOUT, "{}", self.DEFAULT_NUM_RETRIES,
      self.server.get_cluster_stats_json, self.secret)
    return json.loads(stats)


  def is_initialized(self):
    """Queries the AppController to see if it has started up all of the API
    services it is responsible for on its machine.

    Returns:
      A bool that indicates if all API services have finished starting up on
      this machine.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, False, self.DEFAULT_NUM_RETRIES,
      self.server.is_done_initializing, self.secret)


  def start_roles_on_nodes(self, roles_to_nodes):
    """Dynamically adds the given machines to an AppScale deployment, with the
    specified roles.

    Args:
      A JSON-dumped dict that maps roles to IP addresses.
    Returns:
      The result of executing the SOAP call on the remote AppController.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.start_roles_on_nodes, roles_to_nodes, self.secret)

  def is_appscale_terminated(self):
    """Queries the AppController to see if the system has been terminated.

    Returns:
      A boolean indicating whether appscale has finished running terminate
        on all nodes.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, "Error",
                                 self.DEFAULT_NUM_RETRIES,
                                 self.server.is_appscale_terminated,
                                 self.secret)

  def run_terminate(self, clean):
    """Tells the AppController to terminate AppScale on the deployment.

    Args:
      clean: A boolean indicating whether the clean parameter should be
        passed to terminate.rb.
    Returns:
      The request id assigned from executing the SOAP call on the remote
        AppController.
    """
    request_id = self.run_with_timeout(self.DEFAULT_TIMEOUT, "Error",
                                       self.DEFAULT_NUM_RETRIES,
                                       self.server.run_terminate, clean,
                                       self.secret)
    if request_id == "Error":
      raise AppControllerException("Unable to send request to stop AppScale "
                                   "deployment to AppController.")
    else:
      return request_id

  def receive_server_message(self):
    """Queries the AppController for a message that the server wants to send
    to the tools.

    Returns:
      The message from the AppController in JSON with format :
      {'ip':ip, 'status': status, 'output':output}
    """
    server_message = self.run_with_timeout(self.DEFAULT_TIMEOUT * 5,
                                           "Error: Client Timed Out",
                                           self.DEFAULT_NUM_RETRIES,
                                           self.server.receive_server_message,
                                           self.DEFAULT_TIMEOUT * 4,
                                           self.secret)
    if server_message.startswith("Error"):
      raise AppControllerException(server_message)
    else:
      return server_message

  def stop_app(self, app_id):
    """Tells the AppController to no longer host the named application.

    Args:
      app_id: A str that indicates which application should be stopped.
    Returns:
      The result of telling the AppController to no longer host the app.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.stop_app, app_id, self.secret)


  def done_uploading(self, app_id, remote_app_location):
    """Tells the AppController that an application has been uploaded to its
    machine, and where to find it.

    Args:
      app_id: A str that indicates which application we have copied over.
      remote_app_location: The location on the remote machine where the App
        Engine application can be found.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.done_uploading, app_id, remote_app_location, self.secret)


  def update(self, apps_to_run):
    """Tells the AppController which applications to run, which we assume have
    already been uploaded to that machine.

    Args:
      apps_to_run: A list of apps to start running on nodes running the App
        Engine service.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, "Error", self.DEFAULT_NUM_RETRIES,
      self.server.update, apps_to_run, self.secret)


  def get_app_info_map(self):
    """Asks the AppController for a list of all the applications it is proxying
    via nginx, haproxy, or running itself.

    Returns:
      A dict that maps application IDs (strs) to a dict indicating what nginx,
      haproxy, or dev_appserver ports host that app, with an additional field
      indicating what language the app is written in.
    """
    return json.loads(self.run_with_timeout(self.DEFAULT_TIMEOUT, '{}', self.DEFAULT_NUM_RETRIES,
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
    return self.run_with_timeout(self.LONGER_TIMEOUT, "Relocate request timed out.",
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
    return json.loads(self.run_with_timeout(self.DEFAULT_TIMEOUT, '{}', self.DEFAULT_NUM_RETRIES,
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
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, 'Set property request timed out.',
      self.DEFAULT_NUM_RETRIES, self.server.set_property, property_name,
      property_value, self.secret)


  def deployment_id_exists(self):
    """ Asks the AppController if the deployment ID is stored in ZooKeeper.

    Returns:
      A boolean indicating whether the deployment ID is stored or not.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT,
      'Check for deployment ID request timed out.',
      self.DEFAULT_NUM_RETRIES, self.server.deployment_id_exists, self.secret)


  def get_deployment_id(self):
    """ Retrieves the deployment ID from ZooKeeper.

    Returns:
      A string containing the deployment ID.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, 'Get deployment ID request timed out.',
      self.DEFAULT_NUM_RETRIES, self.server.get_deployment_id, self.secret)


  def set_deployment_id(self, deployment_id):
    """ Tells the AppController to set the deployment ID in ZooKeeper.

    Returns:
      A boolean indicating whether the deployment ID is stored or not.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT, 'Set deployment ID request timed out.',
      self.DEFAULT_NUM_RETRIES, self.server.set_deployment_id, self.secret, deployment_id)


  def get_all_stats(self):
    """ Queries the AppController for all the stats.

    Returns:
      A JSON string containing system and platform stats for this node.
    """
    return self.run_with_timeout(self.LONGER_TIMEOUT,
      'Get all JSON stats request timed out.', self.DEFAULT_NUM_RETRIES,
      self.server.get_all_stats, self.secret)


  def does_app_exist(self, appname):
    """ Queries the AppController to see if the named application exists,
    and if it is listening to any port.

    Args:
      appname: The name of the app that we should check for existence.
    """
    return self.run_with_timeout(self.DEFAULT_TIMEOUT,
      'Request to check if user application exists timed out.',
      self.DEFAULT_NUM_RETRIES, self.server.does_app_exist, appname, self.secret)


  def reset_password(self, username, encrypted_password):
    """ Resets a user's password in the currently running AppScale deployment.

    Args:
       username: The e-mail address for the user whose password will be
        changed.
      password: The SHA1-hashed password that will be set as the user's
        password.
    """
    result = self.run_with_timeout(self.DEFAULT_TIMEOUT,
      'Reset password request timed out.', self.DEFAULT_NUM_RETRIES,
      self.server.reset_password, username, encrypted_password, self.secret)
    if result != 'true':
      raise Exception(result)


  def does_user_exist(self, username, silent=False):
    """ Queries the AppController to see if the given user exists.

    Args:
      username: The email address registered as username for the user's application.
    """
    while True:
      try:
        user_exists = self.run_with_timeout(
          self.DEFAULT_TIMEOUT, 'Request to check if user exists timed out.',
          self.DEFAULT_NUM_RETRIES, self.server.does_user_exist, username,
          self.secret)
        if user_exists == 'true':
          return True
        elif user_exists == 'false':
          return False
        else:
          raise Exception(user_exists)
      except BadSecretException as exception:
        raise AppControllerException(
          "Exception when checking if a user exists: {0}".format(exception))
      except Exception as acc_error:
        if not silent:
          AppScaleLogger.log("Exception when checking if a user exists: {0}".
                             format(acc_error))
          AppScaleLogger.log("Backing off and trying again.")
        time.sleep(10)


  def create_user(self, username, password, account_type='xmpp_user'):
    """ Creates a new user account, with the given username and hashed password.

    Args:
      username: An e-mail address that should be set as the new username.
      password: A sha1-hashed password that is bound to the given username.
      account_type: A str that indicates if this account can be logged into by
        XMPP users.
    """
    AppScaleLogger.log("Creating new user account {0}".format(username))
    while 1:
      try:
        result = self.run_with_timeout(self.LONGER_TIMEOUT,
          'Request to create user timed out.', self.DEFAULT_NUM_RETRIES,
          self.server.create_user, username, password, account_type, self.secret)
        break
      except Exception, exception:
        AppScaleLogger.log("Exception when creating user: {0}".format(exception))
        AppScaleLogger.log("Backing off and trying again")
        time.sleep(10)

    if result != 'true':
      raise Exception(result)


  def set_admin_role(self, username, is_cloud_admin, capabilities):
    """ Grants the given user the ability to perform any administrative action.

    Args:
      username: The e-mail address that should be given administrative
        authorizations.
    """
    AppScaleLogger.log('Granting admin privileges to %s' % username)
    return self.run_with_timeout(self.DEFAULT_TIMEOUT,
      'Set admin role request timed out.', self.DEFAULT_NUM_RETRIES,
      self.server.set_admin_role, username, is_cloud_admin,
      capabilities, self.secret)

  def get_app_admin(self, app_id):
    """ Queries the AppController to see which user owns the given application.

    Args:
      app_id: The name of the app that we should see the administrator on.
    Returns:
      A str containing the name of the application's administrator, or None
        if there is none.
    Raises:
      AppScaleException if the AppController returns an error.
    """
    app_data_json = self.run_with_timeout(self.DEFAULT_TIMEOUT,
      'Get app admin request timed out.', self.DEFAULT_NUM_RETRIES,
      self.server.get_app_data, app_id, self.secret)
    if not app_data_json:
      return None

    try:
      app_data = json.loads(app_data_json)
    except ValueError as decode_error:
      if 'Error:' in app_data_json:
        raise AppScaleException(app_data_json)
      raise decode_error

    if 'owner' not in app_data:
      return None

    return app_data['owner']
