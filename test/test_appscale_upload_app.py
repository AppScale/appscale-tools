#!/usr/bin/env python


# General-purpose Python library imports
import os
import shutil
import sys
import tempfile
import time
import unittest
import uuid
import yaml


# Third party libraries
from flexmock import flexmock


# AppScale import, the library that we're testing here
from appscale.tools.admin_client import AdminClient
from appscale.tools.admin_client import AdminError
from appscale.tools.appengine_helper import AppEngineHelper
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.custom_exceptions import AppEngineConfigException
from appscale.tools.local_state import LocalState
from appscale.tools.parse_args import ParseArgs
from appscale.tools.remote_helper import RemoteHelper


class TestAppScaleUploadApp(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-upload-app"
    self.app_dir = "/tmp/baz/gbaz"

    # mock out the check to make sure our app is a directory
    flexmock(os.path)
    os.path.should_call('isdir')
    os.path.should_receive('isdir').with_args(self.app_dir).and_return(True)

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()
    AppScaleLogger.should_receive('success').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    local_state = flexmock(LocalState)
    local_state.should_receive('shell').and_return()

    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    self.fake_temp_file = flexmock(name='fake_temp_file')
    self.fake_temp_file.should_receive('read').and_return('boo out')
    self.fake_temp_file.should_receive('close').and_return()
    self.fake_temp_file.should_receive('seek').with_args(0).and_return()

    flexmock(tempfile)
    tempfile.should_receive('NamedTemporaryFile').and_return(self.fake_temp_file)

    self.success = flexmock(name='success', returncode=0)
    self.success.should_receive('wait').and_return(0)

    self.failed = flexmock(name='success', returncode=1)
    self.failed.should_receive('wait').and_return(1)

    # mock out generating a random app dir, for later mocks
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return('1234')


  def test_upload_app_without_file_flag(self):
    # not specifying the file to upload should abort
    argv = [
      "--keyname", self.keyname
    ]
    self.assertRaises(SystemExit, ParseArgs, argv, self.function)


  def test_upload_app_with_no_app_yaml_or_appengine_web_xml(self):
    # all app engine apps must have a config file - abort if we can't find one

    # add in mocks so that the config files aren't found
    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(
      AppEngineHelper.get_app_yaml_location(self.app_dir)).and_return(False)
    os.path.should_receive('exists').with_args(
      AppEngineHelper.get_appengine_web_xml_location(self.app_dir)) \
      .and_return(False)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppEngineConfigException, AppScaleTools.upload_app, options)


  def test_upload_python25_app_with_no_appid(self):
    # add in mocks so that there is an app.yaml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    app_yaml_location = AppEngineHelper.get_app_yaml_location(self.app_dir)
    os.path.should_receive('exists').with_args(app_yaml_location) \
      .and_return(True)
    flexmock(AppEngineHelper).should_receive('get_app_id_from_app_config').and_return('app_id')

    # mock out reading the app.yaml file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    fake_app_yaml = flexmock(name="fake_app_yaml")
    fake_app_yaml.should_receive('read').and_return(yaml.dump({
      'appid' : ''
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppEngineConfigException, AppScaleTools.upload_app, options)


  def test_upload_java_app_with_no_appid(self):
    # add in mocks so that there is an appengine-web.xml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(
      AppEngineHelper.get_app_yaml_location(self.app_dir)).and_return(False)
    appengine_web_xml_location = AppEngineHelper.get_appengine_web_xml_location(
      self.app_dir)
    os.path.should_receive('exists').with_args(
      AppEngineHelper.get_appengine_web_xml_location(self.app_dir)).and_return(True)
    flexmock(AppEngineHelper).should_receive('get_app_id_from_app_config').and_return('app_id')
    flexmock(AppEngineHelper).should_receive('get_app_runtime_from_app_config').and_return('runtime')
    flexmock(LocalState).should_receive('get_secret_key').and_return()

    # mock out reading the app.yaml file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    fake_appengine_web_xml = flexmock(name="fake_appengine_web_xml")
    fake_appengine_web_xml.should_receive('read').and_return("<baz></baz>\n" +
      "<application></application>")
    builtins.should_receive('open').with_args(appengine_web_xml_location, 'r') \
      .and_return(fake_appengine_web_xml)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppEngineConfigException, AppScaleTools.upload_app, options)


  def test_upload_app_with_no_runtime(self):
    # as runtime is a required flag, abort if it is not set

    # add in mocks so that there is an app.yaml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    app_yaml_location = AppEngineHelper.get_app_yaml_location(self.app_dir)
    os.path.should_receive('exists').with_args(app_yaml_location) \
      .and_return(True)

    # mock out reading the app.yaml file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    fake_app_yaml = flexmock(name="fake_app_yaml")
    fake_app_yaml.should_receive('read').and_return(yaml.dump({
      'application' : 'bazid',
      'runtime' : ''
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppEngineConfigException, AppScaleTools.upload_app, options)


  def test_upload_app_with_bad_runtime(self):
    # we only support four runtimes - abort if the user gives us an unsupported
    # one

    # add in mocks so that there is an app.yaml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    app_yaml_location = AppEngineHelper.get_app_yaml_location(self.app_dir)
    os.path.should_receive('exists').with_args(app_yaml_location) \
      .and_return(True)

    # mock out reading the app.yaml file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    fake_app_yaml = flexmock(name="fake_app_yaml")
    fake_app_yaml.should_receive('read').and_return(yaml.dump({
      'application' : 'bazid',
      'runtime' : 'badruntime'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppEngineConfigException, AppScaleTools.upload_app, options)


  def test_upload_app_with_reserved_app_id(self):
    # users can't choose reserved appids for their own applications

    # add in mocks so that there is an app.yaml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    app_yaml_location = AppEngineHelper.get_app_yaml_location(self.app_dir)
    os.path.should_receive('exists').with_args(app_yaml_location) \
      .and_return(True)

    # mock out reading the app.yaml file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    fake_app_yaml = flexmock(name="fake_app_yaml")
    fake_app_yaml.should_receive('read').and_return(yaml.dump({
      'application' : 'none',  # a reserved appid
      'runtime' : 'python'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppEngineConfigException, AppScaleTools.upload_app, options)


  def test_upload_app_with_non_alpha_appid(self):
    # add in mocks so that there is an app.yaml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    app_yaml_location = AppEngineHelper.get_app_yaml_location(self.app_dir)
    os.path.should_receive('exists').with_args(app_yaml_location) \
      .and_return(True)

    # mock out reading the app.yaml file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    fake_app_yaml = flexmock(name="fake_app_yaml")
    fake_app_yaml.should_receive('read').and_return(yaml.dump({
      'application' : 'baz*',
      'runtime' : 'python'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppEngineConfigException, AppScaleTools.upload_app, options)


  def test_upload_app(self):
    app_id = 'guestbook'
    source_path = '{}.tar.gz'.format(app_id)
    extracted_dir = '/tmp/{}'.format(app_id)
    login_host = '192.168.33.10'
    secret = 'secret-key'
    operation_id = 'operation-1'
    port = 8080
    version_url = 'http://{}:{}'.format(login_host, port)

    argv = ['--keyname', self.keyname, '--file', source_path, '--test']
    options = ParseArgs(argv, self.function).args

    flexmock(LocalState).should_receive('extract_tgz_app_to_dir').\
      and_return('/tmp/{}'.format(app_id))
    flexmock(AppEngineHelper).should_receive('get_app_id_from_app_config').\
      and_return(app_id)
    flexmock(AppEngineHelper).\
      should_receive('get_app_runtime_from_app_config').and_return('python27')
    flexmock(AppEngineHelper).should_receive('is_threadsafe').and_return(True)
    flexmock(AppEngineHelper).should_receive('validate_app_id')
    flexmock(LocalState).should_receive('get_login_host').\
      and_return(login_host)
    flexmock(LocalState).should_receive('get_secret_key').and_return(secret)
    flexmock(RemoteHelper).should_receive('copy_app_to_host').\
      with_args(extracted_dir, self.keyname, False, {}).\
      and_return(source_path)
    flexmock(AdminClient).should_receive('create_version').\
      and_return(operation_id)
    flexmock(AdminClient).should_receive('get_operation').\
      and_return({'done': True, 'response': {'versionUrl': version_url}})
    flexmock(shutil).should_receive('rmtree').with_args(extracted_dir)

    given_host, given_port = AppScaleTools.upload_app(options)
    self.assertEquals(given_host, login_host)
    self.assertEquals(given_port, port)

    # If provided user is not app admin, deployment should fail.
    flexmock(AdminClient).should_receive('create_version').\
      and_raise(AdminError)
    self.assertRaises(AdminError, AppScaleTools.upload_app, options)

    # An application with the PHP runtime should be deployed successfully.
    flexmock(AppEngineHelper).\
      should_receive('get_app_runtime_from_app_config').and_return('php')
    flexmock(AdminClient).should_receive('create_version').\
      and_return(operation_id)
    given_host, given_port = AppScaleTools.upload_app(options)
    self.assertEquals(given_host, login_host)
    self.assertEquals(given_port, port)
 
 
  def test_java_bad_sdk_version(self):
    bad_jars = ['test.jar', 'appengine-api-1.0-sdk-1.7.3.jar']
    flexmock(os)
    os.should_receive('listdir').and_return(bad_jars)
    self.assertEquals(True, AppEngineHelper.is_sdk_mismatch(''))

    
  def test_java_good_sdk_version(self):
    target_jar = AppEngineHelper.JAVA_SDK_JAR_PREFIX + '-' \
      + AppEngineHelper.SUPPORTED_SDK_VERSION + '.jar'
    good_jars = ['test.jar', target_jar]

    aeh = flexmock(AppEngineHelper)
    aeh.should_receive('get_appengine_lib_locations').and_return(['blah'])
    flexmock(os)
    os.should_receive('listdir').and_return(good_jars)
    self.assertEquals(False, AppEngineHelper.is_sdk_mismatch(''))
