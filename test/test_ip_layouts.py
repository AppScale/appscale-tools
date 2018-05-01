#!/usr/bin/env python

IP_1 = '1.1.1.1'
IP_2 = '2.2.2.2'
IP_3 = '3.3.3.3'
IP_4 = '4.4.4.4'
IP_5 = '5.5.5.5'
IP_6 = '6.6.6.6'
IP_7 = '7.7.7.7'
IP_8 = '8.8.8.8'

DISK_ONE = 'disk_number_1'
DISK_TWO = 'disk_number_2'

INSTANCE_TYPE_1 = "instance_type_1"
INSTANCE_TYPE_2 = "instance_type_2"

ONE_NODE_CLOUD = [
  {
    'roles': ['master', 'database', 'appengine'],
    'nodes': 1
  }
]

ONE_NODE_CLUSTER = [
  {
    'roles': ['master', 'database', 'appengine'],
    'nodes': IP_1,
    'instance_type': INSTANCE_TYPE_1
  }
]

OPEN_NODE_CLOUD = [{'roles': ['master', 'database', 'appengine'], 'nodes': 1, 'instance_type': INSTANCE_TYPE_1},
                  {'roles': 'open', 'nodes': 1, 'instance_type': INSTANCE_TYPE_1}]

LOGIN_NODE_CLOUD = [{'roles': ['master', 'database', 'appengine'], 'nodes': 1, 'instance_type': INSTANCE_TYPE_1},
                  {'roles': 'login', 'nodes': 1, 'instance_type': INSTANCE_TYPE_2}]

FOUR_NODE_CLOUD = [{'roles': 'master', 'nodes': 1, 'instance_type': INSTANCE_TYPE_1},
                   {'roles': 'appengine', 'nodes': 1, 'instance_type': INSTANCE_TYPE_1},
                   {'roles': 'database', 'nodes': 1, 'instance_type': INSTANCE_TYPE_1},
                   {'roles': 'zookeeper', 'nodes': 1, 'instance_type': INSTANCE_TYPE_1}]

FOUR_NODE_CLUSTER = [{'roles': 'master', 'nodes': IP_1, 'instance_type': INSTANCE_TYPE_1},
                     {'roles': 'appengine', 'nodes': IP_2, 'instance_type': INSTANCE_TYPE_2},
                     {'roles': 'database', 'nodes': IP_3, 'instance_type': INSTANCE_TYPE_1},
                     {'roles': 'zookeeper', 'nodes': IP_4, 'instance_type': INSTANCE_TYPE_2}]

THREE_NODE_CLOUD = [{'roles': 'master', 'nodes': 1},
                     {'roles': 'zookeeper', 'nodes': 1},
                     {'roles': ['database', 'appengine'], 'nodes': 1}]

TWO_NODES_TWO_DISKS_CLOUD = [{'roles': ['master', 'database'], 'nodes': 1,
                              'instance_type': INSTANCE_TYPE_1, 'disks': DISK_ONE},
                             {'roles': ['appengine'], 'nodes': 1,
                              'instance_type': INSTANCE_TYPE_2, 'disks': DISK_TWO}]

TWO_NODES_ONE_NOT_UNIQUE_DISK_CLOUD = [
  {'roles': ['master', 'database'], 'nodes': 1, 'disks': DISK_ONE},
   {'roles': ['appengine'], 'nodes': 1, 'disks': DISK_ONE}]

THREE_NODES_TWO_DISKS_CLOUD =  [
  {'roles': ['master', 'database'], 'nodes': 1, 'disks': DISK_ONE},
  {'roles': ['appengine'], 'nodes': 2, 'disks': DISK_TWO}]

THREE_NODES_TWO_DISKS_FOR_NODESET_CLOUD =  [
  {'roles': ['master', 'database'], 'nodes': 1, 'instance_type': INSTANCE_TYPE_1},
  {'roles': ['appengine'], 'nodes': 2,
   'instance_type': INSTANCE_TYPE_2, 'disks': [DISK_ONE, DISK_TWO]}]

