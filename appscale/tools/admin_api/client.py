""" A client that makes requests to the AdminServer. """

import requests
import yaml
from retrying import retry


# The default service.
DEFAULT_SERVICE = 'default'

# The version that AppScale uses. This is temporary until we support multiple
# versions per service.
DEFAULT_VERSION = 'v1'


class AdminError(Exception):
  """ Indicates an error while performing an administrative operation. """
  pass


class AdminClient(object):
  """ A client that makes requests to the AdminServer. """

  # The Nginx port for the AdminServer.
  PORT = 17441

  # Do 4 attempts with delays: 1s, 2s, 4s if AdminError is raised.
  RETRY_POLICY = {
    'stop_max_attempt_number': 4,
    'wait_exponential_multiplier': 1000,
    'retry_on_exception': lambda e: isinstance(e, AdminError)
  }

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

  @retry(**RETRY_POLICY)
  def create_version(self, version, source_path):
    """ Creates or updates a version.

    Args:
      version: A Version object.
      source_path: A string specifying the location of the source code.
    Returns:
      A dictionary containing the deployment operation details.
    Raises:
      AdminError if the Admin API call was not successful.
    """
    versions_url = '{prefix}/{project}/services/{service}/versions'.format(
      prefix=self.prefix, project=version.project_id, service=version.service_id)
    headers = {'AppScale-Secret': self.secret}
    body = {
      'deployment': {'zip': {'sourceUrl': source_path}},
      'id': DEFAULT_VERSION,
      'runtime': version.runtime
    }
    if version.env_variables:
      body['envVariables'] = version.env_variables

    if version.threadsafe is not None:
      body['threadsafe'] = version.threadsafe

    if version.inbound_services:
      body['inboundServices'] = ['INBOUND_SERVICE_{}'.format(service).upper()
                                 for service in version.inbound_services]

    if version.handlers is not None:
      body['handlers'] = [handler.to_api_dict()
                          for handler in version.handlers]

    if version.manual_scaling:
      body['manualScaling'] = version.manual_scaling
    elif version.automatic_scaling:
      body['automaticScaling'] = version.automatic_scaling

    response = requests.post(versions_url, headers=headers, json=body,
                             verify=False)
    operation = self.extract_response(response)
    try:
      operation_id = operation['name'].split('/')[-1]
    except (KeyError, IndexError):
      raise AdminError('Invalid operation: {}'.format(operation))

    return operation_id

  @retry(**RETRY_POLICY)
  def delete_version(self, project_id, service_id, version_id):
    """ Deletes a version.

    Args:
      project_id: A string specifying the project ID.
      service_id: A string specifying the service ID.
      version_id: A string specifying the version ID.
    Returns:
      A dictionary containing the delete version operation details.
    Raises:
      AdminError if the response is formatted incorrectly.
    """
    version_url = '{prefix}/{project}/services/{service}/versions/{version}'.\
      format(prefix=self.prefix, project=project_id, service=service_id,
             version=version_id)
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

  @retry(**RETRY_POLICY)
  def patch_version(self, version, fields):
    """ Patches (updates) a version.

    Args:
      version: A Version object.
      fields: The set of fields to patch.
    Returns:
      A dictionary containing the deployment operation details.
    Raises:
      AdminError if the Admin API call was not successful.
    """
    versions_url = ('{prefix}/{project}/services/{service}/versions/{version}'
                    .format(prefix=self.prefix, project=version.project_id,
                            service=version.service_id, version=version.id))
    headers = {
      'AppScale-Secret': self.secret,
      'Content-Type': 'application/json'
    }
    params = {
      'updateMask': ','.join(fields)
    }
    body = {}
    if version.serving_status:
      body['servingStatus'] = version.serving_status

    response = requests.patch(versions_url, headers=headers, params=params,
                              json=body, verify=False)
    operation = self.extract_response(response)
    try:
      operation_id = operation['name'].split('/')[-1]
    except (KeyError, IndexError):
      raise AdminError('Invalid operation: {}'.format(operation))

    return operation_id

  @retry(**RETRY_POLICY)
  def delete_service(self, project_id, service_id):
    """ Deletes a service.

    Args:
      project_id: A string specifying the project ID.
      service_id: A string specifying the service ID.
    Returns:
      A dictionary containing the delete service operation details.
    Raises:
      AdminError if the response is formatted incorrectly.
    """
    service_url = '{prefix}/{project}/services/{service}'. \
      format(prefix=self.prefix, project=project_id, service=service_id)
    headers = {'AppScale-Secret': self.secret}
    response = requests.delete(service_url, headers=headers, verify=False)
    operation = self.extract_response(response)
    try:
      # Operation names should match the following template:
      # "apps/{project_id}/operations/{operation_id}"
      operation_id = operation['name'].split('/')[-1]
    except (KeyError, IndexError):
      raise AdminError('Invalid operation: {}'.format(operation))

    return operation_id

  @retry(**RETRY_POLICY)
  def list_services(self, project_id):
    """ Lists a project's services.

    Returns:
      A list containing the project's service IDs.
    Raises:
      AdminError if the response is formatted incorrectly.
    """
    url = 'https://{}:{}/v1/apps/{}/services'.format(
      self.host, self.PORT, project_id)
    headers = {'AppScale-Secret': self.secret}
    response = requests.get(url, headers=headers, verify=False)
    return [service['id']
            for service in self.extract_response(response)['services']]

  @retry(**RETRY_POLICY)
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

  @retry(**RETRY_POLICY)
  def update_cron(self, project_id, cron_config):
    """ Updates the the project's cron configuration.

    Args:
      project_id: A string specifying the project ID.
      cron_config: A dictionary containing cron configuration details.
    Raises:
      AdminError if unable to update cron configuration.
    """
    cron_yaml = yaml.safe_dump(cron_config, default_flow_style=False)
    headers = {'AppScale-Secret': self.secret}
    cron_url = 'https://{}:{}/api/cron/update?app_id={}'.format(
      self.host, self.PORT, project_id)
    response = requests.post(cron_url, headers=headers, data=cron_yaml,
                             verify=False)

    if response.status_code == 200:
      return

    try:
      message = response.json()['error']['message']
    except (ValueError, KeyError):
      message = 'AdminServer returned: {}'.format(response.status_code)

    raise AdminError(message)

  @retry(**RETRY_POLICY)
  def update_indexes(self, project_id, indexes):
    """ Updates the the project's index configuration.

    Args:
      project_id: A string specifying the project ID.
      indexes: A dictionary containing index configuration details.
    Raises:
      AdminError if unable to update index configuration.
    """
    index_yaml = yaml.safe_dump(indexes, default_flow_style=False)
    headers = {'AppScale-Secret': self.secret}
    indexes_url = 'https://{}:{}/api/datastore/index/add?app_id={}'.format(
      self.host, self.PORT, project_id)
    response = requests.post(indexes_url, headers=headers, data=index_yaml,
                             verify=False)

    if response.status_code == 200:
      return

    try:
      message = response.json()['error']['message']
    except (ValueError, KeyError):
      message = 'AdminServer returned: {}'.format(response.status_code)

    raise AdminError(message)

  @retry(**RETRY_POLICY)
  def update_queues(self, project_id, queues):
    """ Updates the the project's queue configuration.

    Args:
      project_id: A string specifying the project ID.
      queues: A dictionary containing queue configuration details.
    Raises:
      AdminError if unable to update queue configuration.
    """
    queue_yaml = yaml.safe_dump(queues, default_flow_style=False)
    headers = {'AppScale-Secret': self.secret}
    queues_url = 'https://{}:{}/api/queue/update?app_id={}'.format(
      self.host, self.PORT, project_id)
    response = requests.post(queues_url, headers=headers, data=queue_yaml,
                             verify=False)

    if response.status_code == 200:
      return

    try:
      message = response.json()['error']['message']
    except (ValueError, KeyError):
      message = 'AdminServer returned: {}'.format(response.status_code)

    raise AdminError(message)
