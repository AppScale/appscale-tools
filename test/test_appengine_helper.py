import unittest

from appscale.tools.appengine_helper import AppEngineHelper


class TestAppEngineHelper(unittest.TestCase):
  def test_is_valid_ipv4_address(self):
    to_test = {'192.168.33.10': True,
               '10.10.1.0': True,
               'node-1': False,
               '2001:0DB8:AC10:FE01::': False}
    for test_ip, should_be_valid in to_test.iteritems():
      self.assertEqual(AppEngineHelper.is_valid_ipv4_address(test_ip),
                       should_be_valid,
                       '{} should be {}'.format(test_ip, should_be_valid))
