#!/usr/bin/env python

import unittest

from appscale.tools.appcontroller_client import AppControllerClient
from flexmock import flexmock


class TestAppControllerClient(unittest.TestCase):

  def test_deployment_id_exists(self):
    # The function should return whatever run_with_timeout returns.
    host = 'boo'
    secret = 'baz'
    deployment_id_exists = True
    flexmock(AppControllerClient).should_receive('run_with_timeout')\
      .and_return(deployment_id_exists)
    acc = AppControllerClient(host, secret)
    self.assertEqual(deployment_id_exists, acc.deployment_id_exists())

  def test_get_deployment_id(self):
    # The function should return whatever run_with_timeout_returns.
    host = 'boo'
    secret = 'baz'
    deployment_id = 'foo'
    flexmock(AppControllerClient).should_receive('run_with_timeout')\
      .and_return(deployment_id)
    acc = AppControllerClient(host, secret)
    self.assertEqual(deployment_id, acc.get_deployment_id())

  def test_set_deployment_id(self):
    host = 'boo'
    secret = 'baz'
    # The function should return whatever run_with_timeout_returns.
    flexmock(AppControllerClient).should_receive('run_with_timeout')\
      .and_return()
    acc = AppControllerClient(host, secret)
    acc.get_deployment_id()
