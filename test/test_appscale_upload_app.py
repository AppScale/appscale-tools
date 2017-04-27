#!/usr/bin/env python


# General-purpose Python library imports
import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import yaml


# Third party libraries
from flexmock import flexmock
import SOAPpy


# AppScale import, the library that we're testing here
from appscale.tools.appengine_helper import AppEngineHelper
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.custom_exceptions import AppEngineConfigException
from appscale.tools.custom_exceptions import AppScaleException
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


  def test_upload_app_when_app_exists_on_virt_cluster(self):
    # we do let you upload an app if it's already running

    # add in mocks so that there is an app.yaml with an appid set
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
      'application' : 'baz',
      'runtime' : 'python27'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    # Mock out service host and port
    app_data = {'owner' : 'a@a.com',
      'hosts' : {'192.168.1.1' : {'http' : 8080, 'https' : 4380 }}}
    app_stats_data = {'baz': {'nginx': 8080}}

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('done_uploading').with_args(
      'baz', '/opt/appscale/apps/baz.tar.gz', 'the secret').and_return('OK')
    fake_appcontroller.should_receive('update').with_args(
      ['baz'], 'the secret').and_return('OK')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@a.com', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@public1', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_app_exist').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_data').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_info_map').with_args(
      'the secret').and_return(json.dumps(app_stats_data))
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out reading the secret key from ~/.appscale
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out asking the user for the admin on the new app, and slip in an
    # answer for them
    builtins.should_receive('raw_input').and_return("a@a.com")
    flexmock(getpass)
    getpass.should_receive('getpass').and_return('aaaaaa')

    # mock out making the remote app directory
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('mkdir -p'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # and mock out tarring and copying the app
    subprocess.should_receive('Popen').with_args(re.compile('tar -czhf'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    subprocess.should_receive('Popen').with_args(re.compile(
      '/tmp/appscale-app-baz.tar.gz'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # as well as removing the tar'ed app once we're done copying it
    flexmock(os)
    os.should_receive('remove').with_args('/tmp/appscale-app-baz-1234.tar.gz') \
      .and_return()

    # and slap in a mock that says the app comes up after waiting for it
    # three times
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      8080)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)
    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    (host, port) = AppScaleTools.upload_app(options)
    self.assertEquals('public1', host)
    self.assertEquals(8080, port)


  def test_upload_app_when_app_admin_not_this_user(self):
    # we don't let you upload an app if the appid is registered to someone else,
    # so abort

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
      'application' : 'baz',
      'runtime' : 'python27'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    # Mock out service host and port
    app_data = {'owner' : 'a@a.com','hosts' : { }}
    app_data_not_admin = {'owner': 'notappadmin@a.com'}

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@a.com', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@public1', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_app_exist').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_data').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data_not_admin))
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out reading the secret key from ~/.appscale
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out asking the user for the admin on the new app, and slip in an
    # answer for them
    builtins.should_receive('raw_input').and_return("a@a.com")
    flexmock(getpass)
    getpass.should_receive('getpass').and_return('aaaaaa')

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppScaleException, AppScaleTools.upload_app, options)


  def test_upload_app_when_app_exists_on_cloud(self):
    # we don't let you upload an app if it's already running, so abort

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
      'application' : 'baz',
      'runtime' : 'python27'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    # Mock out service host and port
    app_data = {'owner' : 'a@a.com',
      'hosts' : {'192.168.1.1' : { 'http' : 8080, 'https' : 4380 }}}
    app_stats_data = {'baz': {'nginx': 8080}}

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('done_uploading').with_args(
      'baz', '/opt/appscale/apps/baz.tar.gz', 'the secret').and_return('OK')
    fake_appcontroller.should_receive('update').with_args(
      ['baz'], 'the secret').and_return('OK')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@a.com', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@public1', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_app_exist').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_data').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_info_map').with_args(
      'the secret').and_return(json.dumps(app_stats_data))
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out reading the secret key from ~/.appscale
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out asking the user for the admin on the new app, and slip in an
    # answer for them
    builtins.should_receive('raw_input').and_return("a@a.com")
    flexmock(getpass)
    getpass.should_receive('getpass').and_return('aaaaaa')

    # mock out making the remote app directory
    local_state = flexmock(LocalState)
    local_state.should_receive('shell') \
      .with_args(re.compile('^ssh'), False, 5, stdin=re.compile('^mkdir -p')) \
      .and_return()

    # and mock out tarring and copying the app
    local_state.should_receive('shell') \
      .with_args(re.compile('tar -czhf'), False) \
      .and_return()

    local_state.should_receive('shell') \
      .with_args(re.compile('/tmp/appscale-app-baz.tar.gz'), False, 5) \
      .and_return()

    # as well as removing the tar'ed app once we're done copying it
    flexmock(os)
    os.should_receive('remove').with_args('/tmp/appscale-app-baz-1234.tar.gz') \
      .and_return()

    # and slap in a mock that says the app comes up after waiting for it
    # three times
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      8080)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)
    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    (host, port) = AppScaleTools.upload_app(options)
    self.assertEquals('public1', host)
    self.assertEquals(8080, port) 


  def test_upload_app_successfully(self):
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
      'application' : 'baz',
      'runtime' : 'python27'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    # Mock out service host and port
    app_data = {'owner' : 'a@a.com',
      'hosts' : {'192.168.1.1' : { 'http' : 8080, 'https' : 4380 }}}
    app_stats_data = {'baz': {'nginx': 8080}}

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('done_uploading').with_args('baz',
      '/opt/appscale/apps/baz.tar.gz', 'the secret').and_return()
    fake_appcontroller.should_receive('update').with_args(['baz'],
      'the secret').and_return()
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@a.com', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@public1', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_app_exist').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_data').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_info_map').with_args(
      'the secret').and_return(json.dumps(app_stats_data))
    fake_appcontroller.should_receive('reserve_app_id').with_args(
      'a@a.com','baz','python27','the secret').and_return("true")
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out reading the secret key from ~/.appscale
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out asking the user for the admin on the new app, and slip in an
    # answer for them
    builtins.should_receive('raw_input').and_return("a@a.com")
    flexmock(getpass)
    getpass.should_receive('getpass').and_return('aaaaaa')

    # mock out making the remote app directory
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('mkdir -p'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # and mock out tarring and copying the app
    subprocess.should_receive('Popen').with_args(re.compile('tar -czhf'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    subprocess.should_receive('Popen').with_args(re.compile(
      '/tmp/appscale-app-baz.tar.gz'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # as well as removing the tar'ed app once we're done copying it
    flexmock(os)
    os.should_receive('remove').with_args('/tmp/appscale-app-baz-1234.tar.gz') \
      .and_return()

    # and slap in a mock that says the app comes up after waiting for it
    # three times
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      8080)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)
    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    (host, port) = AppScaleTools.upload_app(options)
    self.assertEquals('public1', host)
    self.assertEquals(8080, port) 


  def test_upload_tar_gz_app_successfully(self):
    app_dir = '/tmp/appscale-app-1234'

    # add in mocks so that the gzip'ed file gets extracted to /tmp
    # as well as for removing it later
    flexmock(os)
    os.should_receive('mkdir').with_args(app_dir) \
      .and_return(True)
    flexmock(shutil)
    shutil.should_receive('rmtree').with_args(app_dir).and_return()

    local_state = flexmock(LocalState)
    local_state.should_receive('shell')\
      .with_args(re.compile('tar zxvf'),False)\
      .and_return()

    # add in mocks so that there is an app.yaml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    app_yaml_location = AppEngineHelper.get_app_yaml_location(app_dir)
    os.path.should_receive('exists').with_args(app_yaml_location) \
      .and_return(True)

    # mock out reading the app.yaml file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    fake_app_yaml = flexmock(name="fake_app_yaml")
    fake_app_yaml.should_receive('read').and_return(yaml.dump({
      'application' : 'baz',
      'runtime' : 'python27'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    # Mock out service host and port
    app_data = {'owner' : 'a@a.com',
      'hosts' : {'192.168.1.1' : { 'http' : 8080, 'https' : 4380 }}}
    app_stats_data = {'baz': {'nginx': 8080}}

    remote_tarball = '/opt/appscale/apps/baz.tar.gz'

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('done_uploading').with_args('baz',
      remote_tarball, 'the secret').and_return()
    fake_appcontroller.should_receive('update').with_args(['baz'],
      'the secret').and_return()
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@a.com', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@public1', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_app_exist').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_data').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_info_map').with_args(
      'the secret').and_return(json.dumps(app_stats_data))
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out reading the secret key from ~/.appscale
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out asking the user for the admin on the new app, and slip in an
    # answer for them
    builtins.should_receive('raw_input').and_return("a@a.com")
    flexmock(getpass)
    getpass.should_receive('getpass').and_return('aaaaaa')

    # mock out making the remote app directory
    local_state.should_receive('shell') \
      .with_args(re.compile('^ssh'), False, 5, stdin=re.compile('^mkdir -p')) \
      .and_return()

    # and mock out tarring and copying the app
    local_state.should_receive('shell') \
      .with_args(re.compile('tar -czhf'), False) \
      .and_return()

    local_state.should_receive('shell') \
      .with_args(re.compile('/tmp/appscale-app-baz.tar.gz'), False, 5) \
      .and_return()

    # as well as removing the tar'ed app once we're done copying it
    flexmock(os)
    os.should_receive('remove').with_args('/tmp/appscale-app-baz-1234.tar.gz') \
      .and_return()

    os.should_receive('listdir').and_return(['app.yaml','index.py'])

    # and slap in a mock that says the app comes up after waiting for it
    # three times
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      8080)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)
    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    flexmock(RemoteHelper).should_receive('copy_app_to_host').\
      and_return(remote_tarball)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir + ".tar.gz"
    ]
    options = ParseArgs(argv, self.function).args
    (host, port) = AppScaleTools.upload_app(options)
    self.assertEquals('public1', host)
    self.assertEquals(8080, port)


  def test_upload_php_app_successfully(self):
    app_dir = '/tmp/appscale-app-1234'

    # add in mocks so that the gzip'ed file gets extracted to /tmp
    # as well as for removing it later
    flexmock(os)
    os.should_receive('mkdir').with_args(app_dir) \
      .and_return(True)
    flexmock(shutil)
    shutil.should_receive('rmtree').with_args(app_dir).and_return()

    local_state = flexmock(LocalState)
    local_state.should_receive('shell')\
      .with_args(re.compile('tar zxvf'),False)\
      .and_return()

    # add in mocks so that there is an app.yaml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    app_yaml_location = AppEngineHelper.get_app_yaml_location(app_dir)
    os.path.should_receive('exists').with_args(app_yaml_location) \
      .and_return(True)

    # mock out reading the app.yaml file
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    fake_app_yaml = flexmock(name="fake_app_yaml")
    fake_app_yaml.should_receive('read').and_return(yaml.dump({
      'application' : 'baz',
      'runtime' : 'php'
    }))
    builtins.should_receive('open').with_args(app_yaml_location, 'r') \
      .and_return(fake_app_yaml)

    # Mock out service host and port
    app_data = {'owner' : 'a@a.com',
      'hosts' : {'192.168.1.1' : { 'http' : 8080, 'https' : 4380 }}}
    app_stats_data = {'baz': {'nginx': 8080}}

    remote_tarball = '/opt/appscale/apps/baz.tar.gz'

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('Database is at public1')
    fake_appcontroller.should_receive('done_uploading').with_args('baz',
      remote_tarball, 'the secret').and_return()
    fake_appcontroller.should_receive('update').with_args(['baz'],
      'the secret').and_return()
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@a.com', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_user_exist').with_args(
      'a@public1', 'the secret').and_return('true')
    fake_appcontroller.should_receive('does_app_exist').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_data').with_args(
      'baz', 'the secret').and_return(json.dumps(app_data))
    fake_appcontroller.should_receive('get_app_info_map').with_args(
      'the secret').and_return(json.dumps(app_stats_data))
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_json_location(self.keyname)).and_return(True)

    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(
      json.dumps({"node_info": [{
        "public_ip": "public1",
        "private_ip": "private1",
        "jobs": ["shadow", "login"]
      }]}))
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)

    # mock out reading the secret key from ~/.appscale
    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)

    # mock out asking the user for the admin on the new app, and slip in an
    # answer for them
    builtins.should_receive('raw_input').and_return("a@a.com")
    flexmock(getpass)
    getpass.should_receive('getpass').and_return('aaaaaa')

    # mock out making the remote app directory
    local_state.should_receive('shell') \
      .with_args(re.compile('^ssh'), False, 5, stdin=re.compile('^mkdir -p')) \
      .and_return()

    # and mock out tarring and copying the app
    local_state.should_receive('shell') \
      .with_args(re.compile('tar -czf'), False) \
      .and_return()

    local_state.should_receive('shell') \
      .with_args(re.compile('/tmp/appscale-app-baz.tar.gz'), False, 5) \
      .and_return()

    # as well as removing the tar'ed app once we're done copying it
    flexmock(os)
    os.should_receive('remove').with_args('/tmp/appscale-app-baz-1234.tar.gz') \
      .and_return()

    os.should_receive('listdir').and_return(['app.yaml','index.py'])

    # and slap in a mock that says the app comes up after waiting for it
    # three times
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('public1',
      8080)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)
    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    flexmock(RemoteHelper).should_receive('copy_app_to_host').\
      and_return(remote_tarball)

    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir + ".tar.gz"
    ]
    options = ParseArgs(argv, self.function).args
    (host, port) = AppScaleTools.upload_app(options)
    self.assertEquals('public1', host)
    self.assertEquals(8080, port) 
 
 
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
