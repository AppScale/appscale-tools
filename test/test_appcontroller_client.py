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

  def test_get_database_information(self):
    fake_soap = flexmock(name='fake_soap')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').and_return(fake_soap)
    fake_soap.should_receive('get_database_information')\
      .and_return(
        json.dumps({'table':'test_db', 'replication':1 })
      )
    #run commands
    acc = AppControllerClient('fake_host', 'fake_secret')
    ret = acc.get_database_information()
    if ret['table'] != 'test_db' or\
       ret['replication'] != 1:
      raise Exception('get_database_information failed')

  def test_upload_tgz(self):
    fake_soap = flexmock(name='fake_soap')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').and_return(fake_soap)
    fake_soap.should_receive('upload_tgz_file')\
      .and_return("fake success message")
    #run commands
    acc = AppControllerClient('fake_host', 'fake_secret')
    ret = acc.upload_tgz('/fake/file.tar.gz','fake@email.com')
    if ret != "fake success message":
      raise Exception('upload_tgz failed')

  def test_get_stats(self):
    fake_soap = flexmock(name='fake_soap')
    flexmock(SOAPpy)
    SOAPpy.should_receive('SOAPProxy').and_return(fake_soap)
    fake_soap.should_receive('get_stats_json')\
      .and_return(json.dumps([
      {'apps' : {'app1':True, 'app2':False} }
      ]))
    #run commands
    acc = AppControllerClient('fake_host', 'fake_secret')
    ret = acc.get_stats()
    if ret[0]['apps']['app1'] is not True or\
       ret[0]['apps']['app2'] is not False:
      raise Exception('get_stats failed')


