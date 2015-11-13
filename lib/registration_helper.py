#!/usr/bin/env python

import json
import urllib
import urllib2

from appcontroller_client import AppControllerClient
from custom_exceptions import AppScaleException
from local_state import LocalState
from local_state import APPSCALE_VERSION

class RegistrationHelper(object):
  """ RegistrationHelper provides convenience methods used during the
  registration process. """

  # The location of the AppScale Portal.
  PORTAL_URL = 'https://portal.appscale.com'

  # The endpoint used to update a deployment by ID.
  DEPLOYMENTS_URL = PORTAL_URL + '/deployments/{0}'

  # The endpoint used to post new deployment info.
  ADD_DEPLOYMENT_URL = PORTAL_URL + '/dashboard/appscale'

  # HTTP Codes.
  HTTP_BADREQUEST = 400
  HTTP_UNAUTHORIZED = 401
  HTTP_NOTFOUND = 404
  HTTP_METHODNOTALLOWED = 405

  @classmethod
  def update_deployment(cls, deployment_type, nodes, deployment_id):
    """ Updates the deployment on the AppScale Portal.

    Args:
      deployment_type: A string designating the type of deployment.
      nodes: A list containing the nodes layout.
      deployment_id: A string containing the deployment ID.
    Returns:
      A dictionary containing the updated deployment info.
    Raises:
      AppScaleException if the deployment ID is invalid or already registered.
    """
    # Remove unneeded info from node layout.
    for node in nodes:
      if 'ssh_key' in node:
        del node['ssh_key']

    deployment_data = urllib.urlencode({
      'deployment_type': deployment_type,
      'node_layout': json.dumps(nodes),
      'appscale_version': APPSCALE_VERSION
    })
    try:
      response = urllib2.urlopen(
        cls.DEPLOYMENTS_URL.format(deployment_id), data=deployment_data)
      deployment = response.read()
      return json.loads(deployment)
    except urllib2.HTTPError as error:
      if error.code == cls.HTTP_NOTFOUND:
        raise AppScaleException('This deployment ID does not exist.')
      if error.code == cls.HTTP_METHODNOTALLOWED:
        raise AppScaleException('This feature is currently unavailable.')
      if error.code == cls.HTTP_BADREQUEST:
        raise AppScaleException(error.read())

  @classmethod
  def appscale_has_deployment_id(cls, head_node, keyname):
    """ Try to retrieve a deployment ID from ZooKeeper to see if this
    deployment has already been registered.

    Args:
      head_node: A string containing the IP address of the head node.
      keyname: A string representing the SSH keypair name used for this
        AppScale deployment.
    Returns:
      A boolean indicating whether the deployment ID exists or not.
    """
    # Check if head node has a deployment ID stored.
    secret = LocalState.get_secret_key(keyname)
    acc = AppControllerClient(head_node, secret)
    return acc.deployment_id_exists()

  @classmethod
  def get_deployment_id(cls, head_node, keyname):
    """ Retrieve this AppScale deployment's ID.

    Args:
      head_node: A string containing the IP address of the head node.
      keyname: A string representing the SSH keypair name used for this
        AppScale deployment.
    """
    secret = LocalState.get_secret_key(keyname)
    acc = AppControllerClient(head_node, secret)
    return acc.get_deployment_id()

  @classmethod
  def set_deployment_id(cls, head_node, keyname, deployment_id):
    """ Set a deployment ID to use for communicating with the AppScale
    Portal.

    Args:
      head_node: A string containing the IP address of the head node.
      keyname: A string representing the SSH keypair name used for this
        AppScale deployment.
      deployment_id: A string containing the deployment ID.
    """
    secret = LocalState.get_secret_key(keyname)
    acc = AppControllerClient(head_node, secret)
    acc.set_deployment_id(deployment_id)
