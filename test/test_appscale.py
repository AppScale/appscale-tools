#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import os
import shutil
import subprocess
import sys
import unittest
import yaml


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
    # calling 'appscale init cloud' if there's no AppScalefile in the local
    # directory should write a new cloud config file there
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/' + appscale.APPSCALEFILE).and_return(False).once()

    # mock out the actual writing of the template file
    flexmock(shutil)
    shutil.should_receive('copy').with_args(appscale.TEMPLATE_CLOUD_APPSCALEFILE, '/boo/' + appscale.APPSCALEFILE).and_return().once()

    appscale.init('cloud')


  def testInitWithAppScalefile(self):
    # calling 'appscale init cloud' if there is an AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/' + appscale.APPSCALEFILE).and_return(True).once()

    self.assertRaises(AppScalefileException, appscale.init, 'cloud')


  def testUpWithNoAppScalefile(self):
    # calling 'appscale up' if there is no AppScalefile present
    # should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_raise(IOError))

    self.assertRaises(AppScalefileException, appscale.up)


  def testUpWithCloudAppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should call appscale-run-instances with the given config
    # params. here, we assume that the file is intended for use
    # on EC2
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1
    }
    yaml_dumped_contents = yaml.dump(contents)

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # finally, mock out the actual appscale-run-instances call
    # TODO(cgb): find a better way to do this
    flexmock(subprocess)
    subprocess.should_receive('call').and_return().once()
    appscale.up()


  def testStatusWithNoAppScalefile(self):
    # calling 'appscale status' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_raise(IOError))

    self.assertRaises(AppScalefileException, appscale.status)


  def testStatusWithCloudAppScalefile(self):
    # calling 'appscale status' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-describe-instances' command and then exec it
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1
    }
    yaml_dumped_contents = yaml.dump(contents)

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # finally, mock out the actual appscale-run-instances call
    # TODO(cgb): find a better way to do this
    flexmock(subprocess)
    subprocess.should_receive('call').and_return().once()
    appscale.status()


  def testDeployWithNoAppScalefile(self):
    # calling 'appscale deploy' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_raise(IOError))

    app = "/bar/app"
    self.assertRaises(AppScalefileException, appscale.deploy, app)


  def testDeployWithCloudAppScalefile(self):
    # calling 'appscale deploy app' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-upload-app' command and then exec it
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1
    }
    yaml_dumped_contents = yaml.dump(contents)

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # finally, mock out the actual appscale-run-instances call
    # TODO(cgb): find a better way to do this
    flexmock(subprocess)
    subprocess.should_receive('call').with_args(["appscale-upload-app", "--keyname", "bookey", "--file", "/bar/app"]).and_return().once()
    app = '/bar/app'
    appscale.deploy(app)
