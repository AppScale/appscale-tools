#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import base64
import httplib
import json
import os
import re
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
import M2Crypto
import SOAPpy


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appcontroller_client import AppControllerClient
from appengine_helper import AppEngineHelper
from appscale_logger import AppScaleLogger
from appscale_tools import AppScaleTools
from custom_exceptions import AppEngineConfigException
from custom_exceptions import BadConfigurationException
from local_state import APPSCALE_VERSION
from local_state import LocalState
from node_layout import NodeLayout
from parse_args import ParseArgs
from remote_helper import RemoteHelper
from user_app_client import UserAppClient


class TestAppScaleUploadApp(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-upload-app"
    self.app_dir = "/tmp/baz/gbaz"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    """
    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    self.fake_temp_file = flexmock(name='fake_temp_file')
    self.fake_temp_file.should_receive('read').and_return('boo out')
    self.fake_temp_file.should_receive('close').and_return()

    flexmock(tempfile)
    tempfile.should_receive('TemporaryFile').and_return(self.fake_temp_file)

    self.success = flexmock(name='success', returncode=0)
    self.success.should_receive('wait').and_return(0)

    self.failed = flexmock(name='success', returncode=1)
    self.failed.should_receive('wait').and_return(1)
    """


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
    # if the user gives us an app with a reserved appid, we should abort

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
    # if the user gives us an app with a reserved appid, we should abort

    # add in mocks so that there is an appengine-web.xml, but with no appid set
    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(
      AppEngineHelper.get_app_yaml_location(self.app_dir)).and_return(False)
    appengine_web_xml_location = AppEngineHelper.get_appengine_web_xml_location(
      self.app_dir)
    os.path.should_receive('exists').with_args(
      AppEngineHelper.get_appengine_web_xml_location(self.app_dir)).and_return(True)

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
    argv = [
      "--keyname", self.keyname,
      "--file", self.app_dir
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(AppEngineConfigException, AppScaleTools.upload_app, options)
    """
    # let's say that appscale isn't already running
    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(
      LocalState.get_locations_yaml_location(self.keyname)).and_return(False)

    # mock out talking to logs.appscale.com
    fake_connection = flexmock(name='fake_connection')
    fake_connection.should_receive('request').with_args('POST', '/upload', str,
      AppScaleLogger.HEADERS).and_return()

    flexmock(httplib)
    httplib.should_receive('HTTPSConnection').with_args('logs.appscale.com') \
      .and_return(fake_connection)

    # mock out generating the secret key
    flexmock(uuid)
    uuid.should_receive('uuid4').and_return('the secret')

    # mock out writing the secret key to ~/.appscale, as well as reading it
    # later
    builtins = flexmock(sys.modules['__builtin__'])
    builtins.should_call('open')  # set the fall-through

    secret_key_location = LocalState.get_secret_key_location(self.keyname)
    fake_secret = flexmock(name="fake_secret")
    fake_secret.should_receive('read').and_return('the secret')
    fake_secret.should_receive('write').and_return()
    builtins.should_receive('open').with_args(secret_key_location, 'r') \
      .and_return(fake_secret)
    builtins.should_receive('open').with_args(secret_key_location, 'w') \
      .and_return(fake_secret)

    # mock out seeing if the image is appscale-compatible, and assume it is
    # mock out our attempts to find /etc/appscale and presume it does exist
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('/etc/appscale'),
      shell=True, stdout=self.fake_temp_file, stderr=sys.stdout) \
      .and_return(self.success)

    # mock out our attempts to find /etc/appscale/version and presume it does
    # exist
    subprocess.should_receive('Popen').with_args(re.compile(
      '/etc/appscale/{0}'.format(APPSCALE_VERSION)),
      shell=True, stdout=self.fake_temp_file, stderr=sys.stdout) \
      .and_return(self.success)

    # put in a mock indicating that the database the user wants is supported
    subprocess.should_receive('Popen').with_args(re.compile(
      '/etc/appscale/{0}/{1}'.format(APPSCALE_VERSION, 'cassandra')),
      shell=True, stdout=self.fake_temp_file, stderr=sys.stdout) \
      .and_return(self.success)

    # mock out generating the private key
    flexmock(M2Crypto.RSA)
    fake_rsa_key = flexmock(name='fake_rsa_key')
    fake_rsa_key.should_receive('save_key').with_args(
      LocalState.get_private_key_location(self.keyname), None)
    M2Crypto.RSA.should_receive('gen_key').and_return(fake_rsa_key)

    flexmock(M2Crypto.EVP)
    fake_pkey = flexmock(name='fake_pkey')
    fake_pkey.should_receive('assign_rsa').with_args(fake_rsa_key).and_return()
    M2Crypto.EVP.should_receive('PKey').and_return(fake_pkey)

    # and mock out generating the certificate
    flexmock(M2Crypto.X509)
    fake_cert = flexmock(name='fake_x509')
    fake_cert.should_receive('set_pubkey').with_args(fake_pkey).and_return()
    fake_cert.should_receive('set_subject')
    fake_cert.should_receive('set_issuer_name')
    fake_cert.should_receive('set_not_before')
    fake_cert.should_receive('set_not_after')
    fake_cert.should_receive('sign').with_args(fake_pkey, md="sha256")
    fake_cert.should_receive('save_pem').with_args(
      LocalState.get_certificate_location(self.keyname))
    M2Crypto.X509.should_receive('X509').and_return(fake_cert)

    # assume that we started god fine
    subprocess.should_receive('Popen').with_args(re.compile('god &'),
      shell=True, stdout=self.fake_temp_file, stderr=sys.stdout) \
      .and_return(self.success)

    # and that we copied over the AppController's god file
    subprocess.should_receive('Popen').with_args(re.compile(
      'appcontroller.god'),
      shell=True, stdout=self.fake_temp_file, stderr=sys.stdout) \
      .and_return(self.success)

    # also, that we started the AppController itself
    subprocess.should_receive('Popen').with_args(re.compile('god load'),
      shell=True, stdout=self.fake_temp_file, stderr=sys.stdout) \
      .and_return(self.success)

    # assume that the AppController comes up on the third attempt
    fake_socket = flexmock(name='fake_socket')
    fake_socket.should_receive('connect').with_args(('1.2.3.4',
      AppControllerClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    # same for the UserAppServer
    fake_socket.should_receive('connect').with_args(('1.2.3.4',
      UserAppClient.PORT)).and_raise(Exception).and_raise(Exception) \
      .and_return(None)

    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    # mock out the SOAP call to the AppController and assume it succeeded
    fake_appcontroller = flexmock(name='fake_appcontroller')
    fake_appcontroller.should_receive('set_parameters').with_args(list, list,
      ['none'], 'the secret').and_return('OK')
    fake_appcontroller.should_receive('get_all_public_ips').with_args('the secret') \
      .and_return(json.dumps(['1.2.3.4']))
    role_info = [{
      'public_ip' : '1.2.3.4',
      'private_ip' : '1.2.3.4',
      'jobs' : ['shadow', 'login']
    }]
    fake_appcontroller.should_receive('get_role_info').with_args('the secret') \
      .and_return(json.dumps(role_info))
    fake_appcontroller.should_receive('status').with_args('the secret') \
      .and_return('nothing interesting here') \
      .and_return('Database is at not-up-yet') \
      .and_return('Database is at 1.2.3.4')
    fake_appcontroller.should_receive('is_done_initializing') \
      .and_raise(Exception) \
      .and_return(False) \
      .and_return(True)
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').with_args('https://1.2.3.4:17443') \
      .and_return(fake_appcontroller)

    # mock out reading the locations.json file, and slip in our own json
    fake_nodes_json = flexmock(name="fake_nodes_json")
    fake_nodes_json.should_receive('read').and_return(json.dumps([{
      "public_ip" : "1.2.3.4",
      "private_ip" : "1.2.3.4",
      "jobs" : ["shadow", "login"]
    }]))
    fake_nodes_json.should_receive('write').and_return()
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'r') \
      .and_return(fake_nodes_json)
    builtins.should_receive('open').with_args(
      LocalState.get_locations_json_location(self.keyname), 'w') \
      .and_return(fake_nodes_json)

    # copying over the locations yaml and json files should be fine
    subprocess.should_receive('Popen').with_args(re.compile(
      'locations-{0}.[yaml|json]'.format(self.keyname)),
      shell=True, stdout=self.fake_temp_file, stderr=sys.stdout) \
      .and_return(self.success)

    # mock out calls to the UserAppServer and presume that calls to create new
    # users succeed
    fake_userappserver = flexmock(name='fake_appcontroller')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@a.a', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('commit_new_user').with_args(
      'a@1.2.3.4', str, 'xmpp_user', 'the secret') \
      .and_return('true')
    fake_userappserver.should_receive('set_cloud_admin_status').with_args(
      'a@a.a', 'true', 'the secret').and_return()
    fake_userappserver.should_receive('set_capabilities').with_args(
      'a@a.a', UserAppClient.ADMIN_CAPABILITIES, 'the secret').and_return()
    SOAPpy.should_receive('SOAPProxy').with_args('https://1.2.3.4:4343') \
      .and_return(fake_userappserver)

    argv = [
      "--ips_layout", base64.b64encode(yaml.dump(ips_layout)),
      "--keyname", self.keyname,
      "--test"
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.run_instances(options)
    """
