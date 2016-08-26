#!/usr/bin/env python


# General-purpose Python library imports
import base64
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import yaml


# Third party libraries
from flexmock import flexmock


# AppScale import, the library that we're testing here
from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.custom_exceptions import BadConfigurationException
from appscale.tools.local_state import LocalState
from appscale.tools.parse_args import ParseArgs


class TestAppScaleAddKeypair(unittest.TestCase):


  def setUp(self):
    self.keyname = "boobazblargfoo"
    self.function = "appscale-add-keypair"

    # mock out any writing to stdout
    flexmock(AppScaleLogger)
    AppScaleLogger.should_receive('log').and_return()

    # mock out all sleeping
    flexmock(time)
    time.should_receive('sleep').and_return()

    # throw some default mocks together for when invoking via shell succeeds
    # and when it fails
    self.fake_temp_file = flexmock(name='fake_temp_file')
    self.fake_temp_file.should_receive('seek').with_args(0).and_return()
    self.fake_temp_file.should_receive('read').and_return('boo out')
    self.fake_temp_file.should_receive('close').and_return()

    flexmock(tempfile)
    tempfile.should_receive('NamedTemporaryFile').and_return(self.fake_temp_file)

    self.success = flexmock(name='success', returncode=0)
    self.success.should_receive('wait').and_return(0)

    self.failed = flexmock(name='success', returncode=1)
    self.failed.should_receive('wait').and_return(1)


  def test_appscale_with_ips_layout_flag_but_no_copy_id(self):
    # assume that we have ssh-keygen but not ssh-copy-id
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('hash ssh-keygen'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('hash ssh-copy-id'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.failed)

    # don't use a 192.168.X.Y IP here, since sometimes we set our virtual
    # machines to boot with those addresses (and that can mess up our tests).
    ips_layout = yaml.safe_load("""
master : public1
database: public1
zookeeper: public2
appengine:  public3
    """)

    argv = [
      "--ips_layout", base64.b64encode(yaml.dump(ips_layout)),
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    self.assertRaises(BadConfigurationException, AppScaleTools.add_keypair,
      options)


  def test_appscale_with_ips_layout_flag_and_success(self):
    # assume that ssh is running on each machine
    fake_socket = flexmock(name='socket')
    fake_socket.should_receive('connect').with_args(('1.2.3.4', 22)) \
      .and_return(None)
    fake_socket.should_receive('connect').with_args(('1.2.3.5', 22)) \
      .and_return(None)
    fake_socket.should_receive('connect').with_args(('1.2.3.6', 22)) \
      .and_return(None)

    flexmock(socket)
    socket.should_receive('socket').and_return(fake_socket)

    # assume that we have ssh-keygen and ssh-copy-id
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('which ssh-keygen'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('which ssh-copy-id'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # assume that we have a ~/.appscale
    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(LocalState.LOCAL_APPSCALE_PATH) \
      .and_return(True)

    # and assume that we don't have public and private keys already made
    path = LocalState.LOCAL_APPSCALE_PATH + self.keyname
    public_key = LocalState.LOCAL_APPSCALE_PATH + self.keyname + '.pub'
    private_key = LocalState.LOCAL_APPSCALE_PATH + self.keyname + '.key'

    os.path.should_receive('exists').with_args(public_key).and_return(False)
    os.path.should_receive('exists').with_args(private_key).and_return(False)

    # next, assume that ssh-keygen ran fine
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('ssh-keygen'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # assume that we can rename the private key
    flexmock(shutil)
    shutil.should_receive('copy').with_args(path, private_key).and_return()

    # finally, assume that we can chmod 0600 those files fine
    flexmock(os)
    os.should_receive('chmod').with_args(public_key, 0600).and_return()
    os.should_receive('chmod').with_args(path, 0600).and_return()

    # and assume that we can ssh-copy-id to each of the three IPs below
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('ssh-copy-id'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # also, we should be able to copy over our new public and private keys fine
    flexmock(subprocess)
    subprocess.should_receive('Popen').with_args(re.compile('id_rsa[.pub]?'),
      shell=True, stdout=self.fake_temp_file, stderr=subprocess.STDOUT) \
      .and_return(self.success)

    # don't use a 192.168.X.Y IP here, since sometimes we set our virtual
    # machines to boot with those addresses (and that can mess up our tests).
    ips_layout = yaml.safe_load("""
master : 1.2.3.4
database: 1.2.3.4
zookeeper: 1.2.3.5
appengine: 1.2.3.6
    """)

    argv = [
      "--ips_layout", base64.b64encode(yaml.dump(ips_layout)),
      "--keyname", self.keyname
    ]
    options = ParseArgs(argv, self.function).args
    AppScaleTools.add_keypair(options)
