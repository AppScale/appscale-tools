""" A client that makes requests to the AdminServer. """

import requests

# The default service.
DEFAULT_SERVICE = 'default'

# The default version.
DEFAULT_VERSION = 'default'


class AdminError(Exception):
  """ Indicates an error while performing an administrative operation. """
  pass


class AdminClient(object):
  """ A client that makes requests to the AdminServer. """

  # The Nginx port for the AdminServer.
  PORT = 17441

  def __init__(self, host, secret):
    """ Creates a new AdminClient.

    Args:
      host: A string specifying the location of the AdminServer.
      secret: A string specifying the deployment secret.
    """
    self.host = host
    self.secret = secret
    self.prefix = 'https://{}:{}/v1/apps'.format(host, self.PORT)
    requests.packages.urllib3.disable_warnings(
      requests.packages.urllib3.exceptions.InsecureRequestWarning)

  def extract_response(self, response):
    """ Processes AdminServer responses.

    Args:
      response: A response object from the requests library.
    Returns:
      The response body as a dictionary.
    Raises:
      AdminError if the response indicates an unsuccessful request.
    """
    try:
      content = response.json()
    except ValueError:
      raise AdminError('Invalid response: {}'.format(response.content))

    try:
      response.raise_for_status()
    except requests.exceptions.HTTPError:
      try:
        message = content['error']['message']
      except KeyError:
        message = 'AdminServer returned: {}'.format(response.status_code)
      raise AdminError(message)

    return content

  def create_version(self, project_id, user, source_path, runtime,
                     threadsafe=None):
    """ Creates or updates a version.

    Args:
      project_id: A string specifying the project ID.
      user: A string specifying a user's email address.
      source_path: A string specifying the location of the source code.
      runtime: A string specifying the version's language.
      threadsafe: Indicates that the version is threadsafe.
    Returns:
      A dictionary containing the deployment operation details.
    Raises:
      AdminError if the response is formatted incorrectly.
    """
    versions_url = '{prefix}/{project}/services/{service}/versions'.format(
      prefix=self.prefix, project=project_id, service=DEFAULT_SERVICE)
    headers = {'AppScale-Secret': self.secret, 'AppScale-User': user}
    body = {
      'deployment': {'zip': {'sourceUrl': source_path}},
      'id': DEFAULT_VERSION,
      'runtime': runtime
    }
    if threadsafe is not None:
      body['threadsafe'] = threadsafe

    response = requests.post(versions_url, headers=headers, json=body,
                             verify=False)
    operation = self.extract_response(response)
    try:
      operation_id = operation['name'].split('/')[-1]
    except (KeyError, IndexError):
      raise AdminError('Invalid operation: {}'.format(operation))

    return operation_id

  def delete_version(self, project_id):
    """ Deletes a version.

    Args:
      project_id: A string specifying the project ID.
    Returns:
      A dictionary containing the delete operation details.
    Raises:
      AdminError if the response is formatted incorrectly.
    """
    version_url = '{prefix}/{project}/services/{service}/versions/{version}'.\
      format(prefix=self.prefix, project=project_id, service=DEFAULT_SERVICE,
             version=DEFAULT_VERSION)
    headers = {'AppScale-Secret': self.secret}
    response = requests.delete(version_url, headers=headers, verify=False)
    operation = self.extract_response(response)
    try:
      # Operation names should match the following template:
      # "apps/{project_id}/operations/{operation_id}"
      operation_id = operation['name'].split('/')[-1]
    except (KeyError, IndexError):
      raise AdminError('Invalid operation: {}'.format(operation))

    return operation_id

  def get_operation(self, project, operation_id):
    """ Retrieves the status of an operation.

    Args:
      project: A string specifying the project ID.
      operation_id: A string specifying
    Returns:
      A dictionary containing operation details.
    """
    headers = {'AppScale-Secret': self.secret}
    operation_url = '{prefix}/{project}/operations/{operation_id}'.format(
      prefix=self.prefix, project=project, operation_id=operation_id)
    response = requests.get(operation_url, headers=headers, verify=False)
    return self.extract_response(response)
