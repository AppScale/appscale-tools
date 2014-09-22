#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import json
import locale
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import yaml


# Third party testing libraries
import SOAPpy
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appscale_logger import AppScaleLogger
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException
from local_state import LocalState
from node_layout import NodeLayout
from parse_args import ParseArgs


class TestLocalState(unittest.TestCase):


  def setUp(self):
    # set up a mock here to avoid making every test do it
    flexmock(os)
    flexmock(os.path)
    os.path.should_call('exists')

    self.keyname = "booscale"
    self.locations_yaml = LocalState.LOCAL_APPSCALE_PATH + "locations-" + \
      self.keyname + ".yaml"


  def test_make_appscale_directory_creation(self):
    # let's say that our ~/.appscale directory
    # does not exist
    os.path.should_receive('exists') \
      .with_args(LocalState.LOCAL_APPSCALE_PATH) \
      .and_return(False) \
      .once()

    # thus, mock out making the appscale dir
    os.should_receive('mkdir') \
      .with_args(LocalState.LOCAL_APPSCALE_PATH) \
      .and_return()

    LocalState.make_appscale_directory()


  def test_ensure_appscale_isnt_running_but_it_is(self):
    # if there is a locations.yaml file and force isn't set,
    # we should abort
    os.path.should_receive('exists').with_args(
      LocalState.get_secret_key_location(self.keyname)).and_return(True)

    self.assertRaises(BadConfigurationException,
      LocalState.ensure_appscale_isnt_running, self.keyname,
      False)


  def test_ensure_appscale_isnt_running_but_it_is_w_force(self):
    # if there is a locations.yaml file and force is set,
    # we shouldn't abort
    os.path.should_receive('exists').with_args(self.locations_yaml) \
      .and_return(True)

    LocalState.ensure_appscale_isnt_running(self.keyname, True)


  def test_ensure_appscale_isnt_running_and_it_isnt(self):
    # if there isn't a locations.yaml file, we're good to go
    os.path.should_receive('exists').with_args(self.locations_yaml) \
      .and_return(False)

    LocalState.ensure_appscale_isnt_running(self.keyname, False)


  def test_generate_deployment_params(self):
    # this method is fairly light, so just make sure that it constructs the dict
    # to send to the AppController correctly
    options = flexmock(name='options', table='cassandra', keyname='boo',
      appengine='1', autoscale=False, group='bazgroup',
      infrastructure='ec2', machine='ami-ABCDEFG', instance_type='m1.large',
      use_spot_instances=True, max_spot_price=1.23, alter_etc_resolv=True,
      clear_datastore=False, disks={'node-1' : 'vol-ABCDEFG'},
      zone='my-zone-1b', verbose=True, user_commands=[], flower_password="abc",
      max_memory=ParseArgs.DEFAULT_MAX_MEMORY)
    node_layout = NodeLayout({
      'table' : 'cassandra',
      'infrastructure' : "ec2",
      'min' : 1,
      'max' : 1
    })

    expected = {
      'alter_etc_resolv' : 'True',
      'clear_datastore' : 'False',
      'table' : 'cassandra',
      'hostname' : 'public1',
      'ips' : json.dumps([]),
      'keyname' : 'boo',
      'replication' : '1',
      'appengine' : '1',
      'autoscale' : 'False',
      'group' : 'bazgroup',
      'machine' : 'ami-ABCDEFG',
      'infrastructure' : 'ec2',
      'instance_type' : 'm1.large',
      'min_images' : 1,
      'max_images' : 1,
      'use_spot_instances' : True,
      'user_commands' : json.dumps([]),
      'max_spot_price' : '1.23',
      'zone' : json.dumps('my-zone-1b'),
      'verbose' : 'True',
      'flower_password' : 'abc',
      'max_memory' : ParseArgs.DEFAULT_MAX_MEMORY
    }
    actual = LocalState.generate_deployment_params(options, node_layout,
      'public1', {'max_spot_price':'1.23'})
    self.assertEquals(expected, actual)


  def test_obscure_dict(self):
    # make sure that EC2 credentials get filtered correctly
    creds = {
      'ec2_access_key' : 'ABCDEFG',
      'ec2_secret_key' : 'HIJKLMN',
      'CLOUD_EC2_ACCESS_KEY' : 'OPQRSTU',
      'CLOUD_EC2_SECRET_KEY' : 'VWXYZAB'
    }

    expected = {
      'ec2_access_key' : '***DEFG',
      'ec2_secret_key' : '***KLMN',
      'CLOUD_EC2_ACCESS_KEY' : '***RSTU',
      'CLOUD_EC2_SECRET_KEY' : '***YZAB'
    }

    actual = LocalState.obscure_dict(creds)
    self.assertEquals(expected['ec2_access_key'], actual['ec2_access_key'])
    self.assertEquals(expected['ec2_secret_key'], actual['ec2_secret_key'])
    self.assertEquals(expected['CLOUD_EC2_ACCESS_KEY'],
      actual['CLOUD_EC2_ACCESS_KEY'])
    self.assertEquals(expected['CLOUD_EC2_SECRET_KEY'],
      actual['CLOUD_EC2_SECRET_KEY'])


  def test_update_local_metadata(self):
    # mock out getting all the ips in the deployment from the head node
    fake_soap = flexmock(name='fake_soap')
    fake_soap.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return(json.dumps(['public1']))
    role_info = [{
        'public_ip' : 'public1',
        'private_ip' : 'private1',
        'jobs' : ['shadow', 'db_master']
    }]
    fake_soap.should_receive('get_role_info').with_args('the secret') \
      .and_return(json.dumps(role_info))
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://public1:17443') \
      .and_return(fake_soap)

    # mock out reading the secret key
    fake_secret = flexmock(name='fake_secret')
    fake_secret.should_receive('read').and_return('the secret')
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')
    builtins.should_receive('open').with_args(
      LocalState.get_secret_key_location('booscale'), 'r') \
      .and_return(fake_secret)

    # mock out writing the yaml file
    fake_locations_yaml = flexmock(name='fake_locations_yaml')
    fake_locations_yaml.should_receive('write').with_args(yaml.dump({
      'load_balancer': 'public1', 'instance_id': 'i-ABCDEFG',
      'secret': 'the secret', 'infrastructure': 'ec2',
      'group': 'boogroup', 'ips': 'public1', 'table': 'cassandra',
      'db_master': 'node-0', 'zone' : 'my-zone-1b'
    })).and_return()
    builtins.should_receive('open').with_args(
      LocalState.get_locations_yaml_location('booscale'), 'w') \
      .and_return(fake_locations_yaml)

    # and mock out writing the json file
    fake_locations_json = flexmock(name='fake_locations_json')
    fake_locations_json.should_receive('write').with_args(json.dumps(
      role_info)).and_return()
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location('booscale'), 'w') \
      .and_return(fake_locations_json)

    options = flexmock(name='options', table='cassandra', infrastructure='ec2',
      keyname='booscale', group='boogroup', zone='my-zone-1b')
    node_layout = NodeLayout(options={
      'min' : 1,
      'max' : 1,
      'infrastructure' : 'ec2',
      'table' : 'cassandra'
    })
    host = 'public1'
    instance_id = 'i-ABCDEFG'
    LocalState.update_local_metadata(options, node_layout, host, instance_id)


  def test_extract_tgz_app_to_dir(self):
    flexmock(os)
    os.should_receive('mkdir').and_return()
    flexmock(os.path)
    os.path.should_receive('abspath').with_args('relative/app.tar.gz') \
      .and_return('/tmp/relative/app.tar.gz')

    flexmock(LocalState)
    LocalState.should_receive('shell') \
      .with_args(re.compile("tar zxvf '/tmp/relative/app.tar.gz'"), False) \
      .and_return()

    os.should_receive('listdir').and_return(['one_folder'])
    os.path.should_receive('isdir').with_args(re.compile('one_folder')) \
      .and_return(True)

    location = LocalState.extract_tgz_app_to_dir('relative/app.tar.gz', False)
    self.assertEquals(True, 'one_folder' in location)


  def test_extract_tgz_app_to_dir_with_dotfiles(self):
    flexmock(os)
    os.should_receive('mkdir').and_return()
    flexmock(os.path)
    os.path.should_receive('abspath').with_args('relative/app.tar.gz') \
      .and_return('/tmp/relative/app.tar.gz')

    flexmock(LocalState)
    LocalState.should_receive('shell') \
      .with_args(re.compile("tar zxvf '/tmp/relative/app.tar.gz'"), False) \
      .and_return()

    os.should_receive('listdir').and_return(['one_folder', '.dot_file',
      '.dot_folder'])
    os.path.should_receive('isdir').with_args(re.compile('one_folder')) \
      .and_return(True)
    os.path.should_receive('isdir').with_args(re.compile('.dot_file')) \
      .and_return(False)
    os.path.should_receive('isdir').with_args(re.compile('.dot_folder')) \
      .and_return(True)

    location = LocalState.extract_tgz_app_to_dir('relative/app.tar.gz', False)
    self.assertTrue('one_folder' in location)


  def test_shell_exceptions(self):
    fake_tmp_file = flexmock(name='tempfile')
    fake_tmp_file.should_receive('write').and_return()
    fake_tmp_file.should_receive('read').and_return('')
    fake_tmp_file.should_receive('seek').and_return()
    fake_tmp_file.should_receive('close').and_return()
    flexmock(tempfile).should_receive('NamedTemporaryFile')\
      .and_return(fake_tmp_file)
    flexmock(tempfile).should_receive('TemporaryFile')\
      .and_return(fake_tmp_file)

    fake_result = flexmock(name='result')
    fake_result.returncode = 1
    fake_result.should_receive('wait').and_return()
    fake_subprocess = flexmock(subprocess)
    fake_subprocess.should_receive('Popen').and_return(fake_result)
    fake_subprocess.STDOUT = ''
    flexmock(time).should_receive('sleep').and_return()

    self.assertRaises(ShellException, LocalState.shell, 'fake_cmd', False)
    self.assertRaises(ShellException, LocalState.shell, 'fake_cmd', False, 
        stdin='fake_stdin')
      
    fake_subprocess.should_receive('Popen').and_raise(OSError)

    self.assertRaises(ShellException, LocalState.shell, 'fake_cmd', False)
    self.assertRaises(ShellException, LocalState.shell, 'fake_cmd', False, 
        stdin='fake_stdin')


  def test_generate_crash_log(self):
    crashlog_suffix = '123456'
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return(crashlog_suffix)

    exception_class = 'Exception'
    exception_message = 'baz message'
    exception = Exception(exception_message)
    stacktrace = "\n".join(['Traceback (most recent call last):',
      '  File "<stdin>", line 2, in <module>',
      '{0}: {1}'.format(exception_class, exception_message)])

    # Mock out grabbing our system's information
    flexmock(platform)
    platform.should_receive('platform').and_return("MyOS")
    platform.should_receive('python_implementation').and_return("MyPython")

    flexmock(locale)
    locale.should_receive('getlocale').and_return(("'Murica", None))

    # Mock out writing it to the crash log file
    expected = '{0}log-{1}'.format(LocalState.LOCAL_APPSCALE_PATH,
      crashlog_suffix)

    fake_file = flexmock(name='fake_file')
    fake_file.should_receive('write').with_args(str)

    fake_builtins = flexmock(sys.modules['__builtin__'])
    fake_builtins.should_call('open')  # set the fall-through
    fake_builtins.should_receive('open').with_args(expected, 'w').and_return(
      fake_file)

    # mock out printing the crash log message
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('warn')

    actual = LocalState.generate_crash_log(exception, stacktrace)
    self.assertEquals(expected, actual)


  def test_generate_crash_log_on_unsupported_locale(self):
    crashlog_suffix = '123456'
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return(crashlog_suffix)

    exception_class = 'Exception'
    exception_message = 'baz message'
    exception = Exception(exception_message)
    stacktrace = "\n".join(['Traceback (most recent call last):',
      '  File "<stdin>", line 2, in <module>',
      '{0}: {1}'.format(exception_class, exception_message)])

    # Mock out grabbing our system's information
    flexmock(platform)
    platform.should_receive('platform').and_return("MyOS")
    platform.should_receive('python_implementation').and_return("MyPython")

    flexmock(locale)
    locale.should_receive('setlocale').and_raise(locale.Error)

    # Mock out writing it to the crash log file
    expected = '{0}log-{1}'.format(LocalState.LOCAL_APPSCALE_PATH,
      crashlog_suffix)

    fake_file = flexmock(name='fake_file')
    fake_file.should_receive('write').with_args(str)

    fake_builtins = flexmock(sys.modules['__builtin__'])
    fake_builtins.should_call('open')  # set the fall-through
    fake_builtins.should_receive('open').with_args(expected, 'w').and_return(
      fake_file)

    # mock out printing the crash log message
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('warn')

    actual = LocalState.generate_crash_log(exception, stacktrace)
    self.assertEquals(expected, actual)
