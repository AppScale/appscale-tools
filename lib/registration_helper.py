#!/usr/bin/env python

from cookielib import CookieJar
import getpass
import json
import urllib
import urllib2

from appcontroller_client import AppControllerClient
from local_state import LocalState


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

  # The endpoint used to add and retrieve projects.
  PROJECTS_URL = PORTAL_URL + '/projects'

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
  def select_deployment_name(cls, opener, project):
    """ Prompt the user for a deployment name.

    Args:
      opener: A URL opener with valid cookies set for AppScale Portal access.
    Returns:
      A string that's used as an identifiable nickname for the deployment.
    """
    query_params = urllib.urlencode({'project_id': project['project_id']})
    default_name = opener.open(cls.EXAMPLE_NAME_URL + '?' + query_params)\
      .read()
    name = raw_input('Deployment Name [{0}]: '.format(default_name)).strip()
    if name == '':
      name = default_name

    return name

  @classmethod
  def get_deployment_url(cls, safe_name):
    """ Generate a url that opens the deployment directly.

    Args:
      safe_name: A string containing a version of the deployment nickname
        that's safe for use as an HTML ID attribute.
    Returns: A string containing a link to the deployment on the portal.
    """
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
  def prompt_for_project_name(cls):
    """ Prompt the user for a project name.

    Returns: A string containing a name for the project.
    """
    name = raw_input('Project Name: ').strip()
    if name == '':
      print('You must enter a name for the project.')
      return cls.prompt_for_project_name()
    return name

  @classmethod
  def register_project(cls, opener, name):
    project_data = urllib.urlencode({'name': name})
    project = opener.open(cls.PROJECTS_URL, project_data).read()

    # TODO: Handle rejected requests.

    return json.loads(project)

  @classmethod
  def select_project(cls, opener):
    """ Asks the user to select a project to register the deployment under.

    Args:
      opener: A URL opener with valid cookies set for AppScale Portal access.
      deployment_type: A string designating the type of deployment.
      nodes: A list of containing the nodes layout.
    """
    projects = json.loads(opener.open(cls.PROJECTS_URL).read())

    if len(projects) == 0:
      print('You do not have any projects to add this deployment to.'
        ' Please create one now.')
      name = cls.prompt_for_project_name()
      return cls.register_project(opener, name)

    for idx, project in enumerate(projects):
      project_num = idx + 1
      print('  {0}) {1}'.format(project_num, project['name']))

    total_selections = str(len(projects) + 1)
    print('  {0}) Create New Project'.format(total_selections))
    prompt = 'Please select which project to use for this deployment '\
      '[1-{0}]: '.format(total_selections)
    selection = raw_input(prompt)

    if selection == total_selections:
      name = cls.prompt_for_project_name()
      return cls.register_project(opener, name)
    else:
      # TODO: Check if input is valid.
      return projects[int(selection) - 1]

  @classmethod
  def register_deployment(cls, opener, deployment_type, nodes, project, name):
    """ Asks the AppScale Portal for a new deployment ID.

    Args:
      opener: A URL opener with valid cookies set for AppScale Portal access.
      deployment_type: A string designating the type of deployment.
      nodes: A list of containing the nodes layout.
    """
    # Remove unneeded info from node layout.
    for node in nodes:
      if 'ssh_key' in node:
        del node['ssh_key']

    # TODO: Also send version of AppScale and tools.

    deployment_data = urllib.urlencode({
      'project_id': project['project_id'],
      'deployment_type': deployment_type,
      'node_layout': json.dumps(nodes),
      'name': name
    })
    deployment = opener.open(cls.ADD_DEPLOYMENT_URL, deployment_data).read()

    # TODO: Handle rejected requests (e.g. the name already exists)

    return json.loads(deployment)

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
