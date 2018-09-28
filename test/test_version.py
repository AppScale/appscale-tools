import unittest
from xml.etree import ElementTree

import yaml
from mock import MagicMock, mock_open, patch

from appscale.tools.admin_api.version import Version
from appscale.tools.custom_exceptions import AppEngineConfigException

SIMPLE_APP_YAML = """
runtime: python27
threadsafe: true
handlers:
- url: .*
  script: main.app
""".lstrip()

AE_WEB_XML_TEMPLATE = """
<?xml version="1.0" encoding="utf-8"?>
<appengine-web-app xmlns="http://appengine.google.com/ns/1.0">
  <threadsafe>true</threadsafe>
  {}
</appengine-web-app>
""".lstrip()

SIMPLE_AE_WEB_XML = AE_WEB_XML_TEMPLATE.format('')


class TestVersion(unittest.TestCase):
  def test_from_yaml(self):
    # Ensure an exception is raised if runtime is missing.
    with self.assertRaises(AppEngineConfigException):
      Version.from_yaml({})

    # Ensure runtime string is parsed successfully.
    app_yaml = yaml.safe_load(SIMPLE_APP_YAML)
    version = Version.from_yaml(app_yaml)
    self.assertEqual(version.runtime, 'python27')

    # Ensure project is parsed successfully.
    yaml_with_project = SIMPLE_APP_YAML + 'application: guestbook\n'
    app_yaml = yaml.safe_load(yaml_with_project)
    version = Version.from_yaml(app_yaml)
    self.assertEqual(version.runtime, 'python27')
    self.assertEqual(version.project_id, 'guestbook')

    # Ensure a default service ID is set.
    app_yaml = yaml.safe_load(SIMPLE_APP_YAML)
    version = Version.from_yaml(app_yaml)
    self.assertEqual(version.service_id, 'default')

    # Ensure service ID is parsed correctly.
    yaml_with_module = SIMPLE_APP_YAML + 'module: service1\n'
    app_yaml = yaml.safe_load(yaml_with_module)
    version = Version.from_yaml(app_yaml)
    self.assertEqual(version.service_id, 'service1')

    # Ensure omitted environment variables are handled correctly.
    app_yaml = yaml.safe_load(SIMPLE_APP_YAML)
    version = Version.from_yaml(app_yaml)
    self.assertDictEqual(version.env_variables, {})

    # Ensure environment variables are parsed correctly.
    env_vars = """
    env_variables:
      VAR1: 'foo'
    """.lstrip()
    app_yaml = yaml.safe_load(SIMPLE_APP_YAML + env_vars)
    version = Version.from_yaml(app_yaml)
    self.assertDictEqual(version.env_variables, {'VAR1': 'foo'})

    # Ensure omitted inbound services are handled correctly.
    app_yaml = yaml.safe_load(SIMPLE_APP_YAML)
    version = Version.from_yaml(app_yaml)
    self.assertListEqual(version.inbound_services, [])

    # Ensure inbound services are parsed correctly.
    inbound_services = """
    inbound_services:
      - mail
      - warmup
    """.lstrip()
    app_yaml = yaml.safe_load(SIMPLE_APP_YAML + inbound_services)
    version = Version.from_yaml(app_yaml)
    self.assertListEqual(version.inbound_services, ['mail', 'warmup'])

    # Check empty threadsafe value for non-applicable runtime.
    app_yaml = yaml.safe_load(
      'runtime: go\nhandlers:\n- url: .*\n  script: _go_app\n')
    version = Version.from_yaml(app_yaml)
    self.assertIsNone(version.threadsafe)

    # Check empty threadsafe value for applicable runtime.
    app_yaml = yaml.safe_load('runtime: python27\n')
    with self.assertRaises(AppEngineConfigException):
      Version.from_yaml(app_yaml)

    # Ensure threadsafe value is parsed correctly.
    app_yaml = yaml.safe_load(SIMPLE_APP_YAML)
    version = Version.from_yaml(app_yaml)
    self.assertEqual(version.threadsafe, True)

  def test_from_xml(self):
    # Check the default runtime string for Java apps.
    # TODO: This should be updated when the Admin API accepts 'java7'.
    appengine_web_xml = ElementTree.fromstring(SIMPLE_AE_WEB_XML)
    version = Version.from_xml(appengine_web_xml)
    self.assertEqual(version.runtime, 'java')

    xml_with_project = AE_WEB_XML_TEMPLATE.format(
      '<application>guestbook</application>')
    appengine_web_xml = ElementTree.fromstring(xml_with_project)
    version = Version.from_xml(appengine_web_xml)
    self.assertEqual(version.runtime, 'java')
    self.assertEqual(version.project_id, 'guestbook')

    # Ensure a default service ID is set.
    appengine_web_xml = ElementTree.fromstring(SIMPLE_AE_WEB_XML)
    version = Version.from_xml(appengine_web_xml)
    self.assertEqual(version.service_id, 'default')

    # Ensure service ID is parsed correctly.
    xml_with_module = AE_WEB_XML_TEMPLATE.format('<module>service1</module>')
    appengine_web_xml = ElementTree.fromstring(xml_with_module)
    version = Version.from_xml(appengine_web_xml)
    self.assertEqual(version.service_id, 'service1')

    # Ensure omitted environment variables are handled correctly.
    appengine_web_xml = ElementTree.fromstring(SIMPLE_AE_WEB_XML)
    version = Version.from_xml(appengine_web_xml)
    self.assertDictEqual(version.env_variables, {})

    # Ensure environment variables are parsed correctly.
    env_vars = """
    <env-variables>
      <env-var name="VAR1" value="foo" />
    </env-variables>
    """.lstrip()
    appengine_web_xml = ElementTree.fromstring(
      AE_WEB_XML_TEMPLATE.format(env_vars))
    version = Version.from_xml(appengine_web_xml)
    self.assertDictEqual(version.env_variables, {'VAR1': 'foo'})

    # Ensure omitted inbound services are handled correctly.
    appengine_web_xml = ElementTree.fromstring(SIMPLE_AE_WEB_XML)
    version = Version.from_xml(appengine_web_xml)
    self.assertListEqual(version.inbound_services, [])

    # Ensure inbound services are parsed correctly.
    env_vars = """
    <inbound-services>
      <service>mail</service>
    </inbound-services>
    """.lstrip()
    appengine_web_xml = ElementTree.fromstring(
        AE_WEB_XML_TEMPLATE.format(env_vars))
    version = Version.from_xml(appengine_web_xml)
    self.assertListEqual(version.inbound_services, ['mail'])

    # Check empty threadsafe value.
    appengine_web_xml = ElementTree.fromstring(
      '<?xml version="1.0" encoding="utf-8"?>'
      '<appengine-web-app xmlns="http://appengine.google.com/ns/1.0">'
      '</appengine-web-app>')
    with self.assertRaises(AppEngineConfigException):
      Version.from_xml(appengine_web_xml)

    # Ensure threadsafe value is parsed correctly.
    appengine_web_xml = ElementTree.fromstring(SIMPLE_AE_WEB_XML)
    version = Version.from_xml(appengine_web_xml)
    self.assertEqual(version.threadsafe, True)

  def test_from_yaml_file(self):
    open_path = 'appscale.tools.admin_api.version.open'
    with patch(open_path, mock_open(read_data=SIMPLE_APP_YAML)):
      version = Version.from_yaml_file('/example/app.yaml')

    self.assertEqual(version.runtime, 'python27')

  def test_from_xml_file(self):
    tree = MagicMock()
    tree.getroot.return_value = ElementTree.fromstring(SIMPLE_AE_WEB_XML)
    with patch.object(ElementTree, 'parse', return_value=tree):
      version = Version.from_xml_file('/example/appengine-web.xml')

    self.assertEqual(version.runtime, 'java')

  def test_from_directory(self):
    # Ensure an exception is raised if there are no configuration candidates.
    shortest_path_func = 'appscale.tools.admin_api.version.shortest_directory_path'
    with patch(shortest_path_func, side_effect=lambda fn, path: None):
      with self.assertRaises(AppEngineConfigException):
        Version.from_directory('/example/guestbook')

    with patch(shortest_path_func,
               side_effect=lambda fn, path: '/example/guestbook/app.yaml'):
      open_path = 'appscale.tools.admin_api.version.open'
      with patch(open_path, mock_open(read_data=SIMPLE_APP_YAML)):
        version = Version.from_yaml_file('/example/app.yaml')

      self.assertEqual(version.runtime, 'python27')

  def test_from_contents(self):
    version = Version.from_contents(SIMPLE_APP_YAML, 'app.yaml')
    self.assertEqual(version.runtime, 'python27')

    version = Version.from_contents(SIMPLE_AE_WEB_XML, 'appengine-web.xml')
    self.assertEqual(version.runtime, 'java')
