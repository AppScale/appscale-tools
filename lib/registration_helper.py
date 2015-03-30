#!/usr/bin/env python

from cookielib import CookieJar
import getpass
import urllib
import urllib2


class RegistrationHelper(object):
  """RegistrationHelper provides convenience methods used during the
  registration process."""

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

  @classmethod
  def select_deployment_name(cls, deployments, opener):
    """Prompt the user for a deployment name."""
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
    """Generate a url that opens the deployment directly."""
    return '{0}#{1}'.format(cls.PORTAL_APPSCALE_URL, safe_name)

  @classmethod
  def ensure_new_deployment(cls, deployments, secret):
    """Make sure the deployment has not already been registered."""
    for deployment in deployments:
      if deployment['secret'] == secret:
        deployment_url = cls.get_deployment_url(deployment['safe_name'])
        print('This deployment has already been registered as {0}.\n'
          'You can view it here: {1}'
          .format(deployment['name'], deployment_url))
        exit()

  @classmethod
  def login(cls):
    """Prompt the user for an email address and password and try to log in to
    the AppScale Portal. If the username is not found, ask them to create an
    account. If the password is incorrect, ask them to try again.
    """
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
      if error.code == 401:
        print('Login failed. Please check your credentials and try again.')
        return cls.login()
      if error.code == 404:
        print('Email not found. Please create an account at {0}'
          .format(cls.SIGNUP_URL))
        exit()
