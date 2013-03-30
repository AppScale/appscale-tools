#!/usr/bin/env python


# General-purpose Python library imports
import json
import os
import signal
import sys
import time
import unittest
import yaml

# Third party testing libraries
import SOAPpy
from flexmock import flexmock

# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appcontroller_client import AppControllerClient

class TestAppControllerClientSuccess(Exception):
  pass

class TestAppControllerClient(unittest.TestCase):

  def setUp(self):
    flexmock(signal)
    signal.should_receive('signal').and_return()
    signal.should_receive('alarm').and_return()
    flexmock(time)
    time.should_receive('sleep').and_return()
    
  def test_get_api_status(self):
    fake_soap = flexmock(name='fake_soap')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').and_return(fake_soap)
    fake_soap.should_receive('get_api_status')\
      .and_return(
        json.dumps({'api1':'running', 'api2':'failed'})
      )

    #run commands
    acc = AppControllerClient('fake_host', 'fake_secret')
    ret = acc.get_api_status() 
    if ret['api1'] != 'running' or\
       ret['api2'] != 'failed':
      raise Exception('get_api_status failed')


