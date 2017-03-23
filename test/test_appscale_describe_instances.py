#!/usr/bin/env python

# General-purpose Python library imports
import unittest

from SOAPpy import faultType
from flexmock import flexmock

from appscale.tools import appscale_tools
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.custom_exceptions import AppControllerException
from appscale.tools.custom_exceptions import BadConfigurationException
from appscale.tools.local_state import LocalState


class LogsCollector(object):
  def __init__(self):
    self.info_buf = ""
    self.warn_buf = ""
    self.success_buf = ""

  def log(self, msg):
    self.info_buf += msg + "\n"

  def warn(self, msg):
    self.warn_buf += msg + "\n"

  def success(self, msg):
    self.success_buf += msg + "\n"


class TestPrintAppscaleStatus(unittest.TestCase):
  def test_started_two_nodes(self):
    # Mock functions which provides inputs for print_cluster_status
    flexmock(LocalState).should_receive("get_login_host").and_return("1.1.1.1")
    flexmock(LocalState).should_receive("get_secret_key").and_return("xxxxxxx")
    fake_ac_client = flexmock()
    (flexmock(appscale_tools)
       .should_receive("AppControllerClient")
       .and_return(fake_ac_client))
    (fake_ac_client.should_receive("get_all_private_ips")
       .and_return(["10.10.4.220", "10.10.7.12"]))
    # This huge list is the most valuable input for the function
    cluster_stats = [
      # HEAD node
      {
        'private_ip': '10.10.4.220',
        'public_ip': '1.1.1.1',
        'roles': ['load_balancer', 'taskqueue_master', 'zookeeper',
                  'db_master','taskqueue', 'shadow', 'login'],
        'is_initialized': True,
        'is_loaded': True,
        'apps': {
          'appscaledashboard': {
            'http': 1080, 'language': 'python', 'total_reqs': 24, 'appservers': 3,
            'pending_appservers': 0, 'https': 1443, 'reqs_enqueued': 0}},
        'memory': {'available': 1117507584, 'total': 3839168512, 'used': 3400077312},
        'disk': [{'/': {'total': 9687113728, 'free': 4895760384, 'used': 4364763136}}],
        'cpu': {'count': 2, 'idle': 66.7, 'system': 9.5, 'user': 19.0},
        'loadavg': {'last_1_min': 0.64, 'last_5_min': 1.04, 'last_15_min': 0.95,
                    'scheduling_entities': 381, 'runnable_entities': 3},
        # Irrelevant for status bellow
        'state': 'Done starting up AppScale, now in heartbeat mode',
        'swap': {'used': 0, 'free': 0},
        'services': {},
      },

      # AppEngine node
      {
        'private_ip': '10.10.7.12',
        'public_ip': '2.2.2.2',
        'roles': ['memcache', 'appengine'],
        'is_initialized': True,
        'is_loaded': True,
        'apps': {},
        'loadavg': {'last_1_min': 1.05, 'last_5_min': 0.92, 'last_15_min': 0.95,
                    'scheduling_entities': 312, 'runnable_entities': 2},
        'memory': {'available': 2891546624, 'total': 3839168512, 'used': 1951600640},
        'disk': [{'/': {'total': 9687113728, 'free': 5160316928, 'used': 4100206592}}],
        'cpu': {'count': 2, 'idle': 100.0, 'system': 0.0, 'user': 0.0},

        # Irrelevant for status bellow
        'state': 'Done starting up AppScale, now in heartbeat mode',
        'swap': {'used': 0, 'free': 0},
        'services': {},
      }
    ]
    (fake_ac_client.should_receive("get_cluster_stats")
       .and_return(cluster_stats))

    # Configure catching of all logged messages
    fake_logger = LogsCollector()
    flexmock(appscale_tools.AppScaleLogger,
             log=fake_logger.log, warn=fake_logger.warn,
             success=fake_logger.success)

    # Do actual call to tested function
    options = flexmock(keyname="bla-bla", verbose=False)
    AppScaleTools.print_cluster_status(options)

    # Verify if output matches expectation
    self.assertRegexpMatches(
      fake_logger.info_buf,
      r"-+\n\n"
      r"APP NAME +HTTP/HTTPS +APPSERVERS/PENDING +REQS\. ENQUEUED/TOTAL +STATE *\n"
      r"appscaledashboard +1080/1443 +3/0 +0/24 +Ready *\n"
    )
    self.assertEqual(fake_logger.warn_buf, "")
    self.assertEqual(fake_logger.success_buf,
                     "\nAppScale is up. All 2 nodes are loaded\n"
                     "\nView more about your AppScale deployment at "
                     "http://1.1.1.1:1080/status\n")

  def test_deployment_looks_down(self):
    for err in (faultType, AppControllerException, BadConfigurationException):
      flexmock(LocalState).should_receive("get_login_host").and_raise(err)

      # Catch warning and check if it matches expectation
      (flexmock(appscale_tools.AppScaleLogger)
         .should_receive("warn")
         .with_args("AppScale deployment is probably down")
         .once())

      options = flexmock(keyname="bla-bla", verbose=False)
      self.assertRaises(err, AppScaleTools.print_cluster_status, options)
