#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import shutil
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


  def testReportHelp(self):
    # calling 'appscale help' should report usage information
    appscale = AppScale()
    self.assertRaises(UsageException, appscale.help)


  def testInitWithNoAppScalefile(self):
    # calling 'appscale init' if there's no AppScalefile in the local
    # directory should write a new config file there
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/' + appscale.APPSCALEFILE).and_return(False).once()

    # mock out the actual writing of the template file
    flexmock(shutil)
    shutil.should_receive('copy').with_args(appscale.TEMPLATE_APPSCALEFILE,
    '/boo/' + appscale.APPSCALEFILE).and_return().once()

    appscale.init()


  def testInitWithAppScalefile(self):
    # calling 'appscale init' if there is an AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/' + appscale.APPSCALEFILE).and_return(True).once()

    self.assertRaises(AppScalefileException, appscale.init)


  def testUpWithNoAppScalefile(self):
    # calling 'appscale up' if there is no AppScalefile present
    # should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/' +
    appscale.APPSCALEFILE).and_return(False).once()

    self.assertRaises(AppScalefileException, appscale.up)


  def testUpWithInvalidEC2AppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should validate the file. here, we assume the file is
    # intended for use on EC2 and is invalid, so we should throw
    # up and die
    pass


  def testUpWithValidEC2AppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should validate the file. here, we assume the file is
    # intended for use on EC2 and is valid, so we should call
    # appscale-run-instances with the given config params
    pass


  def testUpWithInvalidXenAppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should validate the file. here, we assume the file is
    # intended for use on Xen and is invalid, so we should throw
    # up and die
    pass


  def testUpWithValidXenAppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should validate the file. here, we assume the file is
    # intended for use on Xen and is valid, so we should call
    # appscale-run-instances with those params
    pass
