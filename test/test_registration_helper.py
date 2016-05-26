#!/usr/bin/env python

import json
import unittest
import urllib2

from flexmock import flexmock

from appscale.tools.appcontroller_client import AppControllerClient
from appscale.tools.custom_exceptions import AppScaleException
from appscale.tools.local_state import LocalState
from appscale.tools.registration_helper import RegistrationHelper

class TestRegistrationHelper(unittest.TestCase):

  def test_update_deployment(self):
    deployment = {
      'deployment_id': 'boo',
      'deployment_type': 'cluster',
      'nodes': [{'public_ip': 'public1', 'jobs': ['appengine']}]
    }

    # When the portal returns a HTTP_NOTFOUND, the tools should raise
    # an AppScaleException.
    http_error = urllib2.HTTPError('boo', RegistrationHelper.HTTP_NOTFOUND,
      'bar', 'baz', flexmock(read=lambda: 'blarg', readline=lambda: 'blarg'))
    flexmock(urllib2).should_receive('urlopen').and_raise(http_error)
    with self.assertRaises(AppScaleException):
      RegistrationHelper.update_deployment(deployment['deployment_type'],
        deployment['nodes'], deployment['deployment_id'])

    # When the portal returns a HTTP_BADREQUEST, the tools should raise an
    # AppScaleException.
    http_error = urllib2.HTTPError('boo', RegistrationHelper.HTTP_BADREQUEST,
      'bar', 'baz', flexmock(read=lambda: 'blarg', readline=lambda: 'blarg'))
    flexmock(urllib2).should_receive('urlopen').and_raise(http_error)
    with self.assertRaises(AppScaleException):
      RegistrationHelper.update_deployment(deployment['deployment_type'],
        deployment['nodes'], deployment['deployment_id'])

    # When the POST to the server completes, the function should return a
    # dictionary with the deployment info.
    flexmock(urllib2).should_receive('urlopen')\
      .and_return(flexmock(read=lambda: json.dumps(deployment)))
    self.assertEqual(
      deployment,
      RegistrationHelper.update_deployment(
        deployment['deployment_type'],
        deployment['nodes'],
        deployment['deployment_id']
      )
    )

  def test_appscale_has_deployment_id(self):
    head_node = 'boo'
    keyname = 'bar'
    flexmock(LocalState).should_receive('get_secret_key').and_return('baz')

    # When the AppControllerClient returns True, the function should
    # return True.
    flexmock(AppControllerClient).should_receive('deployment_id_exists')\
      .and_return(True)
    self.assertEqual(
      RegistrationHelper.appscale_has_deployment_id(head_node, keyname), True)

    # When the AppControllerClient returns False, the function should
    # return False.
    flexmock(AppControllerClient).should_receive('deployment_id_exists')\
      .and_return(False)
    self.assertEqual(
      RegistrationHelper.appscale_has_deployment_id(head_node, keyname),
      False)

  def test_get_deployment_id(self):
    head_node = 'boo'
    keyname = 'bar'
    flexmock(LocalState).should_receive('get_secret_key').and_return('baz')
    deployment_id = 'blarg'

    # The function should return what the AppControllerClient returns.
    flexmock(AppControllerClient).should_receive('get_deployment_id')\
      .and_return(deployment_id)
    self.assertEqual(
      RegistrationHelper.get_deployment_id(head_node, keyname), deployment_id)

  def test_set_deployment_id(self):
    head_node = 'boo'
    keyname = 'bar'
    flexmock(LocalState).should_receive('get_secret_key').and_return()
    deployment_id = 'blarg'

    # Given the deployment ID, the function should return successfully.
    flexmock(AppControllerClient).should_receive('set_deployment_id')\
      .with_args(deployment_id).and_return()
    RegistrationHelper.set_deployment_id(head_node, keyname, deployment_id)
