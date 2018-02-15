import unittest
from xml.etree import ElementTree

from flexmock import flexmock

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

  def test_get_app_id_from_app_config(self):
    flexmock(AppEngineHelper).should_receive('get_config_file_from_dir').\
      and_return('appengine-web.xml')

    config_contents = """
    <?xml version="1.0" encoding="utf-8"?>
    <appengine-web-app xmlns="http://appengine.google.com/ns/1.0">
        <!-- <application>guestbook1</application> -->
        <application>guestbook2</application>
    </appengine-web-app>
    """.strip()
    root = ElementTree.fromstring(config_contents)
    tree = flexmock(getroot=lambda: root)
    flexmock(ElementTree).should_receive('parse').and_return(tree)
    self.assertEqual(AppEngineHelper.get_app_id_from_app_config('test_dir'),
                     'guestbook2')

  def test_get_inbound_services(self):
    flexmock(AppEngineHelper).should_receive('get_config_file_from_dir').\
      and_return('appengine-web.xml')

    config_contents = """
    <?xml version="1.0" encoding="utf-8"?>
    <appengine-web-app xmlns="http://appengine.google.com/ns/1.0">
      <inbound-services>
        <service>xmpp_message</service>
        <service>xmpp_presence</service>
      </inbound-services>
    </appengine-web-app>
    """.strip()
    root = ElementTree.fromstring(config_contents)
    tree = flexmock(getroot=lambda: root)
    flexmock(ElementTree).should_receive('parse').and_return(tree)

    expected_services = ['INBOUND_SERVICE_XMPP_MESSAGE',
                         'INBOUND_SERVICE_XMPP_PRESENCE']
    self.assertListEqual(AppEngineHelper.get_inbound_services('test_dir'),
                         expected_services)
