import unittest

from appscale.tools.custom_exceptions import BadConfigurationException
from appscale.tools.utils import cron_from_xml, indexes_from_xml


class TestUtils(unittest.TestCase):
  def test_cron_from_xml(self):
    contents = """
    <?xml version="1.0" encoding="UTF-8"?>
    <cronentries>
      <cron>
        <url>/recache</url>
        <description>Repopulate the cache every 2 minutes</description>
        <schedule>every 2 minutes</schedule>
      </cron>
      <cron>
        <url>/weeklyreport</url>
        <description>Mail out a weekly report</description>
        <schedule>every monday 08:30</schedule>
        <timezone>America/New_York</timezone>
      </cron>
      <cron>
        <url>/weeklyreport</url>
        <description>Mail out a weekly report</description>
        <schedule>every monday 08:30</schedule>
        <timezone>America/New_York</timezone>
        <target>version-2</target>
      </cron>
    </cronentries>
    """.strip()

    expected_config = {
      'cron': [
        {'url': '/recache',
         'description': 'Repopulate the cache every 2 minutes',
         'schedule': 'every 2 minutes'},
        {'url': '/weeklyreport', 'description': 'Mail out a weekly report',
         'schedule': 'every monday 08:30', 'timezone': 'America/New_York'},
        {'url': '/weeklyreport', 'description': 'Mail out a weekly report',
         'schedule': 'every monday 08:30', 'timezone': 'America/New_York',
         'target': 'version-2'}
      ]
    }
    self.assertDictEqual(cron_from_xml(contents), expected_config)

    contents = """
    <?xml version="1.0" encoding="UTF-8"?>
    <cronentries>
      <invalid-element></invalid-element>
    </cronentries>
    """.strip()
    with self.assertRaises(BadConfigurationException):
      cron_from_xml(contents)

  def test_indexes_from_xml(self):
    contents = """
    <?xml version="1.0" encoding="utf-8"?>
    <datastore-indexes autoGenerate="true">
        <datastore-index kind="Employee" ancestor="false">
            <property name="lastName" direction="asc" />
            <property name="hireDate" direction="desc" />
        </datastore-index>
        <datastore-index kind="Project" ancestor="false">
            <property name="dueDate" direction="asc" />
            <property name="cost" direction="desc" />
        </datastore-index>
    </datastore-indexes>
    """.strip()

    expected_config = {
      'indexes': [
        {'kind': 'Employee',
         'ancestor': 'false',
         'properties': [{'name': 'lastName', 'direction': 'asc'},
                        {'name': 'hireDate', 'direction': 'desc'}]},
        {'kind': 'Project',
         'ancestor': 'false',
         'properties': [{'name': 'dueDate', 'direction': 'asc'},
                        {'name': 'cost', 'direction': 'desc'}]}
      ]
    }
    self.assertDictEqual(indexes_from_xml(contents), expected_config)

    contents = """
    <?xml version="1.0" encoding="UTF-8"?>
    <datastore-indexes>
      <invalid-element></invalid-element>
    </datastore-indexes>
    """.strip()
    with self.assertRaises(BadConfigurationException):
      indexes_from_xml(contents)
