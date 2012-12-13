#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import unittest


# Third party testing libraries
from flexmock import flexmock


# AppScale import, the library that we're testing here
from appscale import AppScale
from custom_exceptions import AppScalefileException
from custom_exceptions import BadConfigurationException
from custom_exceptions import UsageException


class TestAppScale(unittest.TestCase):


  def setUp(self):
    pass

  
  def tearDown(self):
    pass


  def testGetDirective(self):
    # calling get_directive with a supported directive should be fine
    AppScale(["help"])

    # calling it with an unsupported directive should not be fine
    self.assertRaises(BadConfigurationException, AppScale, ["boo"])

    # calling it with no directive should not be fine
    self.assertRaises(BadConfigurationException, AppScale, [])


  def testReportHelp(self):
    # calling 'appscale help' should report usage information
    appscale = AppScale(["help"])
    self.assertRaises(UsageException, appscale.help)


  def testInitWithNoAppScalefile(self):
    # calling 'appscale init' if there's no AppScalefile in the local
    # directory should write a new config file there
    pass


  def testInitWithAppScalefile(self):
    # calling 'appscale init' if there is an AppScalefile in the local
    # directory should throw up and die
    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/AppScalefile').and_return(True).once()

    appscale = AppScale(["init"])
    self.assertRaises(AppScalefileException, appscale.init)
