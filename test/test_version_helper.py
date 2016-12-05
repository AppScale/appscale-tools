#!/usr/bin/env python


# General-purpose Python library imports
import unittest


# Third-party libraries
from flexmock import flexmock
import termcolor


# AppScale import, the library that we're testing here
from appscale.tools import version_helper


class TestVersionHelper(unittest.TestCase):

  
  def setUp(self):
    # mock out any red error message printing
    flexmock(termcolor)
    termcolor.should_receive('cprint').with_args(str, 'red')


  def test_running_on_very_old_python(self):
    # If we're running on any Python version too old to have a 'version_info'
    # field, it definitely won't run the AppScale Tools, so throw up and die.
    fake_sys = flexmock(name='fake_sys')
    self.assertRaises(SystemExit, version_helper.ensure_valid_python_is_used,
      fake_sys)


  def test_running_on_python_25(self):
    # Python 2.5 is the newest version we don't support in the AppScale Tools,
    # so we should fail in this case.
    fake_sys = flexmock(name='fake_sys', version_info=[2, 5])
    self.assertRaises(SystemExit, version_helper.ensure_valid_python_is_used,
      fake_sys)


  def test_running_on_python_26(self):
    # Python 2.6 is the oldest version we support in the AppScale Tools, so
    # don't fail in this case.
    fake_sys = flexmock(name='fake_sys', version_info=[2, 6])
    version_helper.ensure_valid_python_is_used(fake_sys)
