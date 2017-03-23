#!/usr/bin/env python


# General-purpose Python library imports
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
import yaml


# Third party testing libraries
import boto.ec2
from flexmock import flexmock


# AppScale import, the library that we're testing here
from appscale.tools.agents.ec2_agent import EC2Agent
from appscale.tools.appscale import AppScale
from appscale.tools.appscale_tools import AppScaleTools
from appscale.tools.custom_exceptions import AppScaleException
from appscale.tools.custom_exceptions import AppScalefileException
from appscale.tools.custom_exceptions import BadConfigurationException
from appscale.tools.local_state import LocalState
from appscale.tools.remote_helper import RemoteHelper


class TestAppScale(unittest.TestCase):


  def setUp(self):
    os.environ['EC2_ACCESS_KEY'] = ''
    os.environ['EC2_SECRET_KEY'] = ''

  
  def tearDown(self):
    os.environ['EC2_ACCESS_KEY'] = ''
    os.environ['EC2_SECRET_KEY'] = ''


  def addMockForNoAppScalefile(self, appscale):
    flexmock(os)
    os.should_receive('getcwd').and_return('/boo')

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_raise(IOError))


  def addMockForAppScalefile(self, appscale, contents):
    flexmock(os)
    os.should_receive('getcwd').and_return('/boo')

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
     .with_args('/boo/' + appscale.APPSCALEFILE)
     .and_return(flexmock(read=lambda: contents)))

    return mock


  def test_get_nodes(self):
    appscale = flexmock(AppScale())
    builtin = flexmock(sys.modules['__builtin__'])
    builtin.should_call('open')
    nodes = {'node_info':[{'public_ip': 'blarg'}]}
    appscale_yaml = {'keyname': 'boo'}
    appscale.should_receive('get_locations_json_file').\
      and_return('locations.json')

    # If the locations JSON file exists, it should return the locations as a
    # dictionary.
    builtin.should_receive('open').with_args('locations.json').\
      and_return(flexmock(read=lambda: json.dumps(nodes)))
    self.assertEqual(nodes.get('node_info'),
                     appscale.get_nodes(appscale_yaml['keyname']))

    # If the locations JSON file does not exist, it should throw an
    # AppScaleException.
    builtin.should_receive('open').with_args('locations.json').\
      and_raise(IOError)
    with self.assertRaises(AppScaleException):
      appscale.get_nodes(appscale_yaml['keyname'])


  def test_get_head_node(self):
    shadow_node_1 = {'public_ip': 'public2', 'jobs': ['shadow']}
    appengine_node = {'public_ip': 'public1', 'jobs': ['appengine']}
    shadow_node_2 = {'public_ip': 'public3', 'jobs': ['shadow']}
    appscale = AppScale()

    # If the list of nodes does not have a node with the shadow role, the
    # tools should raise an AppScaleException.
    with self.assertRaises(AppScaleException):
      appscale.get_head_node([appengine_node])

    # If the list of nodes contains any nodes with the shadow role, the tools
    # should return the public IP address of the first node which has that
    # role.
    self.assertEqual(shadow_node_1['public_ip'],
      appscale.get_head_node([shadow_node_1, appengine_node, shadow_node_2]))


  def testInitWithNoAppScalefile(self):
    # calling 'appscale init cloud' if there's no AppScalefile in the local
    # directory should write a new cloud config file there
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo')

    flexmock(os.path)
    os.path.should_receive('exists').with_args(
      '/boo/' + appscale.APPSCALEFILE).and_return(False)

    # mock out the actual writing of the template file
    flexmock(shutil)
    shutil.should_receive('copy').with_args(
      appscale.TEMPLATE_CLOUD_APPSCALEFILE, '/boo/' + appscale.APPSCALEFILE) \
      .and_return()

    appscale.init('cloud')


  def testInitWithAppScalefile(self):
    # calling 'appscale init cloud' if there is an AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo')

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/' + appscale.APPSCALEFILE).and_return(True)

    self.assertRaises(AppScalefileException, appscale.init, 'cloud')


  def testUpWithNoAppScalefile(self):
    # calling 'appscale up' if there is no AppScalefile present
    # should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.up)


  def testUpWithClusterAppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should call appscale-run-instances with the given config
    # params. here, we assume that the file is intended for use
    # on a virtualized cluster
    appscale = AppScale()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'ips_layout': {'master': 'ip1', 'appengine': 'ip1',
                     'database': 'ip2', 'zookeeper': 'ip2'},
      'keyname': 'boobazblarg',
      'group': 'boobazblarg'
    }
    yaml_dumped_contents = yaml.dump(contents)
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(
      '/boo/' + appscale.APPSCALEFILE).and_return(True)

    # for this test, let's say that we don't have an SSH key already
    # set up for ip1 and ip2
    # TODO(cgb): Add in tests where we have a key for ip1 but not ip2,
    # and the case where we have a key but it doesn't work
    key_path = os.path.expanduser('~/.appscale/boobazblarg.key')
    os.path.should_receive('exists').with_args(key_path).and_return(False)

    # finally, mock out the actual appscale tools calls. since we're running
    # via a cluster, this means we call add-keypair to set up SSH keys, then
    # run-instances to start appscale
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('add_keypair')
    AppScaleTools.should_receive('run_instances')

    appscale.up()


  def testUpWithMalformedClusterAppScalefile(self):
    # if we try to use an IPs layout that isn't a dictionary, we should throw up
    # and die
    appscale = AppScale()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file, with an IPs layout that is a str
    contents = {
      'ips_layout': "'master' 'ip1' 'appengine' 'ip1'",
      'keyname': 'boobazblarg', 'group' : 'boobazblarg'
    }
    yaml_dumped_contents = yaml.dump(contents)
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(
      '/boo/' + appscale.APPSCALEFILE).and_return(True)

    # finally, mock out the actual appscale tools calls. since we're running
    # via a cluster, this means we call add-keypair to set up SSH keys, then
    # run-instances to start appscale
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('add_keypair')

    self.assertRaises(BadConfigurationException, appscale.up)


  def testUpWithCloudAppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should call appscale-run-instances with the given config
    # params. here, we assume that the file is intended for use
    # on EC2
    appscale = AppScale()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'instance_type' : 'm3.medium',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'min' : 1,
      'max' : 1,
      'zone' : 'my-zone-1b'
    }
    yaml_dumped_contents = yaml.dump(contents)
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(
      '/boo/' + appscale.APPSCALEFILE).and_return(True)

    # throw in some mocks for the argument parsing
    for credential in EC2Agent.REQUIRED_CREDENTIALS:
      os.environ[credential] = "baz"

    # finally, pretend that our ec2 zone and image exists
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_all_instances')

    fake_ec2.should_receive('get_all_zones').with_args('my-zone-1b') \
      .and_return('anything')

    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()
    flexmock(boto.ec2)
    boto.ec2.should_receive('connect_to_region').with_args('my-zone-1',
      aws_access_key_id='baz', aws_secret_access_key='baz').and_return(fake_ec2)

    # finally, mock out the actual appscale-run-instances call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('run_instances')
    appscale.up()


  def testUpWithEC2EnvironmentVariables(self):
    # if the user wants us to use their EC2 credentials when running AppScale,
    # we should make sure they get set
    appscale = AppScale()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'instance_type' : 'm3.medium',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'min' : 1,
      'max' : 1,
      'EC2_ACCESS_KEY' : 'access key',
      'EC2_SECRET_KEY' : 'secret key',
      'zone' : 'my-zone-1b'
    }
    yaml_dumped_contents = yaml.dump(contents)
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    flexmock(os.path)
    os.path.should_call('exists')
    os.path.should_receive('exists').with_args(
      '/boo/' + appscale.APPSCALEFILE).and_return(True)

    # finally, pretend that our ec2 zone/image to use exist
    fake_ec2 = flexmock(name="fake_ec2")
    fake_ec2.should_receive('get_all_instances')

    fake_ec2.should_receive('get_all_zones').with_args('my-zone-1b') \
      .and_return('anything')

    fake_ec2.should_receive('get_image').with_args('ami-ABCDEFG') \
      .and_return()
    flexmock(boto.ec2)
    boto.ec2.should_receive('connect_to_region').with_args('my-zone-1',
      aws_access_key_id='access key',
      aws_secret_access_key='secret key').and_return(fake_ec2)

    # finally, mock out the actual appscale-run-instances call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('run_instances')
    appscale.up()

    self.assertEquals('access key', os.environ['EC2_ACCESS_KEY'])
    self.assertEquals('secret key', os.environ['EC2_SECRET_KEY'])


  def testSshWithNoAppScalefile(self):
    # calling 'appscale ssh' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.ssh, 1)


  def testSshWithNotIntArg(self):
    # calling 'appscale ssh not-int' should throw up and die
    appscale = AppScale()
    self.addMockForAppScalefile(appscale, "")
    self.assertRaises(TypeError, appscale.ssh, "boo")


  def testSshWithNoNodesJson(self):
    # calling 'appscale ssh' when there isn't a locations.json
    # file should throw up and die
    appscale = AppScale()

    contents = { 'keyname' : 'boo' }
    yaml_dumped_contents = yaml.dump(contents)

    mock = self.addMockForAppScalefile(appscale, yaml_dumped_contents)
    (mock.should_receive('open')
      .with_args(appscale.get_locations_json_file('boo'))
      .and_raise(IOError))

    self.assertRaises(AppScaleException, appscale.ssh, 0)


  def testSshWithIndexOutOfBounds(self):
    # calling 'appscale ssh 1' should ssh to the second node
    # (nodes[1]). If there's only one node in this deployment,
    # we should throw up and die
    appscale = AppScale()

    contents = { 'keyname' : 'boo' }
    yaml_dumped_contents = yaml.dump(contents)

    one = {
      'public_ip' : 'blarg'
    }
    nodes = {'node_info': [one]}
    nodes_contents = json.dumps(nodes)

    mock = self.addMockForAppScalefile(appscale, yaml_dumped_contents)
    (mock.should_receive('open')
      .with_args(appscale.get_locations_json_file('boo'))
      .and_return(flexmock(read=lambda: nodes_contents)))

    self.assertRaises(AppScaleException, appscale.ssh, 1)


  def testSshWithIndexInBounds(self):
    # calling 'appscale ssh 1' should ssh to the second node
    # (nodes[1]). If there are two nodes in this deployment,
    # we should ssh into it successfully
    appscale = AppScale()

    contents = { 'keyname' : 'boo' }
    yaml_dumped_contents = yaml.dump(contents)

    one = {
      'public_ip' : 'blarg'
    }
    two = {
      'public_ip' : 'blarg2'
    }
    nodes = {'node_info': [one, two]}
    nodes_contents = json.dumps(nodes)

    mock = self.addMockForAppScalefile(appscale, yaml_dumped_contents)
    (mock.should_receive('open')
      .with_args(appscale.get_locations_json_file('boo'))
      .and_return(flexmock(read=lambda: nodes_contents)))

    flexmock(subprocess)
    subprocess.should_receive('call').with_args(["ssh", "-o", "StrictHostkeyChecking=no", "-i", appscale.get_key_location('boo'), "root@blarg2"]).and_return().once()
    appscale.ssh(1)


  def testStatusWithNoAppScalefile(self):
    # calling 'appscale status' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.status)


  def testStatusWithCloudAppScalefile(self):
    # calling 'appscale status' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-describe-instances' command and then exec it
    appscale = AppScale()

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
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-describe-instances call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('print_cluster_status')
    appscale.status()


  def testDeployWithNoAppScalefile(self):
    # calling 'appscale deploy' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    app = "/bar/app"
    self.assertRaises(AppScalefileException, appscale.deploy, app)


  def testDeployWithCloudAppScalefile(self):
    # calling 'appscale deploy app' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-upload-app' command and then exec it
    appscale = AppScale()

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
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-run-instances call
    fake_port = 8080
    fake_host = 'fake_host'
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('upload_app').and_return(
      (fake_host, fake_port))
    app = '/bar/app'
    (host, port) = appscale.deploy(app)
    self.assertEquals(fake_host, host)
    self.assertEquals(fake_port, port)


  def testUndeployWithNoAppScalefile(self):
    # calling 'appscale undeploy' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    appid = "barapp"
    self.assertRaises(AppScalefileException, appscale.undeploy, appid)


  def testUndeployWithCloudAppScalefile(self):
    # calling 'appscale undeploy app' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-remove-app' command and then exec it
    appscale = AppScale()

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
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-run-instances call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('remove_app')
    app = 'barapp'
    appscale.undeploy(app)


  def testDeployWithCloudAppScalefileAndTestFlag(self):
    # same as before, but with the 'test' flag in our AppScalefile
    appscale = AppScale()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1,
      'test' : True
    }
    yaml_dumped_contents = yaml.dump(contents)
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-run-instances call
    fake_port = 8080
    fake_host = 'fake_host'
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('upload_app').and_return(
      (fake_host, fake_port))
    app = '/bar/app'
    (host, port) = appscale.deploy(app)
    self.assertEquals(fake_host, host)
    self.assertEquals(fake_port, port)


  def testTailWithNoAppScalefile(self):
    # calling 'appscale tail' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.tail, 0, '')


  def testTailWithNotIntArg(self):
    # calling 'appscale tail not-int *' should throw up and die
    appscale = AppScale()
    self.addMockForAppScalefile(appscale, "")
    self.assertRaises(TypeError, appscale.tail, "boo", "")


  def testTailWithNoNodesJson(self):
    # calling 'appscale tail' when there isn't a locations.json
    # file should throw up and die
    appscale = AppScale()

    contents = { 'keyname' : 'boo' }
    yaml_dumped_contents = yaml.dump(contents)

    mock = self.addMockForAppScalefile(appscale, yaml_dumped_contents)
    (mock.should_receive('open')
      .with_args(appscale.get_locations_json_file('boo'))
      .and_raise(IOError))

    self.assertRaises(AppScaleException, appscale.tail, 0, "")

  def testTailWithIndexOutOfBounds(self):
    # calling 'appscale tail 1 *' should tail from the second node
    # (nodes[1]). If there's only one node in this deployment,
    # we should throw up and die
    appscale = AppScale()

    contents = { 'keyname' : 'boo' }
    yaml_dumped_contents = yaml.dump(contents)

    one = {
      'public_ip' : 'blarg'
    }
    nodes = {'node_info': [one]}
    nodes_contents = json.dumps(nodes)

    mock = self.addMockForAppScalefile(appscale, yaml_dumped_contents)
    (mock.should_receive('open')
      .with_args(appscale.get_locations_json_file('boo'))
      .and_return(flexmock(read=lambda: nodes_contents)))

    self.assertRaises(AppScaleException, appscale.tail, 1, '')

  def testTailWithIndexInBounds(self):
    # calling 'appscale tail 1 *' should tail from the second node
    # (nodes[1]). If there are two nodes in this deployment,
    # we should tail from it successfully
    appscale = AppScale()

    contents = { 'keyname' : 'boo' }
    yaml_dumped_contents = yaml.dump(contents)

    one = {
      'public_ip' : 'blarg'
    }
    two = {
      'public_ip' : 'blarg2'
    }
    nodes = {'node_info': [one, two]}
    nodes_contents = json.dumps(nodes)

    mock = self.addMockForAppScalefile(appscale, yaml_dumped_contents)
    (mock.should_receive('open')
      .with_args(appscale.get_locations_json_file('boo'))
      .and_return(flexmock(read=lambda: nodes_contents)))

    flexmock(subprocess)
    subprocess.should_receive('call').with_args(["ssh", "-o",
      "StrictHostkeyChecking=no", "-i", appscale.get_key_location('boo'),
      "root@blarg2", "tail -F /var/log/appscale/c*"]).and_return().once()
    appscale.tail(1, "c*")


  def testGetLogsWithNoAppScalefile(self):
    # calling 'appscale logs' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.logs, '')


  def testGetLogsWithKeyname(self):
    # calling 'appscale logs dir' with a keyname should produce
    # a command to exec with the --keyname flag
    appscale = AppScale()
    contents = {
      "keyname" : "boo"
    }
    yaml_dumped_contents = yaml.dump(contents)
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # mock out the actual call to appscale-gather-logs
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('run_instances')
    self.assertRaises(BadConfigurationException, appscale.logs, '/baz')

  
  def testRelocateWithNoAppScalefile(self):
    # calling 'appscale relocate' with no AppScalefile in the local directory
    # should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.relocate, 'myapp', 80, 443)


  def testRelocateWithAppScalefile(self):
    # calling 'appscale relocate' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-relocate-app' command and then exec it
    appscale = AppScale()

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
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-relocate-app call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('relocate_app')
    appscale.relocate('myapp', 80, 443)


  def testGetPropertyWithNoAppScalefile(self):
    # calling 'appscale get' with no AppScalefile in the local directory
    # should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.get, '.*')


  def testGetPropertyWithAppScalefile(self):
    # calling 'appscale get' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-get-property' command and then exec it
    appscale = AppScale()

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
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-get-property call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('get_property')
    appscale.get('.*')


  def testSetPropertyWithNoAppScalefile(self):
    # calling 'appscale set' with no AppScalefile in the local directory
    # should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.set, 'key', 'value')


  def testSetPropertyWithAppScalefile(self):
    # calling 'appscale set' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-get-property' command and then exec it
    appscale = AppScale()

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
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-set-property call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('set_property')
    appscale.set('key', 'value')


  def testDownWithNoAppScalefile(self):
    # calling 'appscale down' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()
    self.addMockForNoAppScalefile(appscale)
    self.assertRaises(AppScalefileException, appscale.down)


  def testDownWithCloudAppScalefile(self):
    # calling 'appscale down' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-terminate-instances' command and then exec it
    appscale = AppScale()

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
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-terminate-instances call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('terminate_instances')
    appscale.down()


  def testDownWithEC2EnvironmentVariables(self):
    # if the user wants us to use their EC2 credentials when running AppScale,
    # we should make sure they get set
    appscale = AppScale()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'min' : 1,
      'max' : 1,
      'EC2_ACCESS_KEY' : 'access key',
      'EC2_SECRET_KEY' : 'secret key'
    }
    yaml_dumped_contents = yaml.dump(contents)
    self.addMockForAppScalefile(appscale, yaml_dumped_contents)

    # finally, mock out the actual appscale-terminate-instances call
    flexmock(AppScaleTools)
    AppScaleTools.should_receive('terminate_instances')
    appscale.down()

    self.assertEquals('access key', os.environ['EC2_ACCESS_KEY'])
    self.assertEquals('secret key', os.environ['EC2_SECRET_KEY'])

