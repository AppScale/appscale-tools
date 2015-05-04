#!/usr/bin/env python

from cookielib import CookieJar
import getpass
import urllib
import urllib2

from appcontroller_client import AppControllerClient

class RegistrationHelper(object):
  """ RegistrationHelper provides convenience methods used during the
  registration process. """

  # The location of the AppScale Portal.
  PORTAL_URL = 'https://portal.appscale.com'

  # The URL used to login to the AppScale Portal.
  LOGIN_URL = PORTAL_URL + '/login'

  # The endpoint used to post new deployment info.
  ADD_DEPLOYMENT_URL = PORTAL_URL + '/appscale/add_deployment'

  # The endpoint used to retrieve a list of existing deployments.
  DEPLOYMENTS_URL = PORTAL_URL + '/appscale/get_deployments'

  # The endpoint used to retrieve an example deployment name.
  EXAMPLE_NAME_URL = PORTAL_URL + '/appscale/example_name'

  # The URL used to view existing deployments.
  PORTAL_APPSCALE_URL = PORTAL_URL + '/dashboard/appscale'

  # The URL used to sign up for the AppScale Portal.
  SIGNUP_URL = PORTAL_URL + '/trial'

  # HTTP Codes.
  HTTP_UNAUTHORIZED = 401
  HTTP_NOTFOUND = 404

  @classmethod
  def select_deployment_name(cls, deployments, opener):
    """ Prompt the user for a deployment name. """
    default_name = opener.open(cls.EXAMPLE_NAME_URL).read()
    name = raw_input('Deployment Name [{0}]: '.format(default_name)).strip()
    if name == '':
      name = default_name

    if any(deployment['name'] == name for deployment in deployments):
      print('The name {0} has already been taken. Please choose another.'
        .format(name))
      return cls.select_deployment_name(deployments, opener)

    return name

  @classmethod
  def get_deployment_url(cls, safe_name):
    """ Generate a url that opens the deployment directly. """
    return '{0}#{1}'.format(cls.PORTAL_APPSCALE_URL, safe_name)


  @classmethod
  def login(cls):
    """ Prompt the user for an email address and password and try to log in to
    the AppScale Portal. If the username is not found, ask them to create an
    account. If the password is incorrect, ask them to try again. """
    username = raw_input('AppScale Portal Login Email: ')
    password = getpass.getpass()

    login_data = {'username': username, 'password': password, 'tools': True}
    cookies = CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookies))
    opener.addheaders = [('Referer', RegistrationHelper.LOGIN_URL)]

    try:
      opener.open(RegistrationHelper.LOGIN_URL, urllib.urlencode(login_data))
      return opener
    except urllib2.HTTPError as error:
      if error.code == cls.HTTP_UNAUTHORIZED:
        print('Login failed. Please check your credentials and try again.')
        return cls.login()
      if error.code == cls.HTTP_NOTFOUND:
        print('Email not found. Please create an account at {0}'
          .format(cls.SIGNUP_URL))
        exit()

  @classmethod
  def appscale_has_deployment_id(cls, head_node, keyname):
    """ Try to retrieve a deployment ID from ZooKeeper to see if this
    deployment has already been registered.

    Args:
      head_node: A string containing the IP address of the head node.
      keyname: A string representing the SSH keypair name used for this
        AppScale deployment.
    Returns: A boolean indicating whether the deployment ID exists or not.
    """
    # Check if head node has a deployment id stored.
    secret = LocalState.get_secret_key(keyname)
    acc = AppControllerClient(head_node, secret)
    return acc.deployment_id_exists()

  @classmethod
  def set_deployment_id(cls, head_node, keyname, deployment_id):
    """ Set a deployment ID to use for communicating with the AppScale
    Portal.

    Args:
      head_node: A string containing the IP address of the head node.
      keyname: A string representing the SSH keypair name used for this
        AppScale deployment.
    """
    secret = LocalState.get_secret_key(keyname)
    acc = AppControllerClient(head_node, secret)
    acc.set_deployment_id(deployment_id)
    return
