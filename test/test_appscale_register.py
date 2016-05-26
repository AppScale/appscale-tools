#!/usr/bin/env python

import unittest
import yaml

from flexmock import flexmock

from appscale.tools.appscale import AppScale
from appscale.tools.custom_exceptions import AppScaleException
from appscale.tools.registration_helper import RegistrationHelper

class TestAppScaleRegister(unittest.TestCase):

  def test_register(self):
    appscale_yaml = {'keyname': 'boo'}
    deployment = {
      'name': 'bar',
      'deployment_id': 'baz',
      'nodes': [{'public_ip': 'public1', 'jobs': ['shadow']}]
    }

    flexmock(AppScale).should_receive('read_appscalefile')\
      .and_return(yaml.dump(appscale_yaml))
    flexmock(yaml).should_receive('safe_load').and_return({'keyname': 'boo'})

    flexmock(AppScale).should_receive('get_nodes')\
      .and_return(deployment['nodes'])
    flexmock(AppScale).should_receive('get_head_node')\
      .and_return(deployment['nodes'][0])

    flexmock(RegistrationHelper).should_receive('update_deployment') \
      .and_return(deployment)
    flexmock(RegistrationHelper).should_receive('set_deployment_id') \
      .and_return()

    appscale = AppScale()

    # If the deployment already has an ID and it differs from the one given,
    # the tools should raise an AppScaleException.
    existing_deployment_id = 'blarg'
    flexmock(RegistrationHelper).should_receive('appscale_has_deployment_id')\
      .and_return(True)
    flexmock(RegistrationHelper).should_receive('get_deployment_id')\
      .and_return(existing_deployment_id)
    with self.assertRaises(AppScaleException):
      appscale.register(deployment['deployment_id'])

    # If the existing deployment ID is the same as the given deployment ID,
    # the tools should try to complete the registration with the portal.
    existing_deployment_id = 'baz'
    flexmock(RegistrationHelper).should_receive('get_deployment_id') \
      .and_return(existing_deployment_id)
    appscale.register(deployment['deployment_id'])

    # If the deployment does not have an ID set, the tools should try to
    # complete the registration.
    flexmock(RegistrationHelper).should_receive('appscale_has_deployment_id')\
      .and_return(False)
    appscale.register(deployment['deployment_id'])
