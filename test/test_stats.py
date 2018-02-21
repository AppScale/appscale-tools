import unittest
import StringIO
import argparse

from mock import patch, Mock

from appscale.tools.appscale_stats import (
  get_node_stats, get_process_stats, get_summary_process_stats, get_proxy_stats,
  sort_process_stats, sort_proxy_stats, show_stats,
  INCLUDE_NODE_LIST, _get_stats)


class TestStats(unittest.TestCase):

  test_raw_node_stats = {
    u'192.168.33.10': {
      u'memory': {u'available': 1334953984,
                  u'total': 4145442816, u'used': 2592751616},
      u'loadavg': {u'last_1min': 0.14, u'last_5min': 0.36, u'last_15min': 0.21},
      u'partitions_dict': {
        u'/': {u'total': 9687113728, u'used': 4356263936},
        u'/user': {u'total': 9387513728, u'used': 2356263936},
        u'/test': {u'total': 9617113728, u'used': 8856263936},
        u'/main': {u'total': 9817113728, u'used': 8256263936}
      },
      u'cpu': {u'count': 1}
    },
    u'192.168.33.11': {
      u'memory': {u'available': 2154953984,
                  u'total': 4194742816, u'used': 15551616},
      u'loadavg': {u'last_1min': 2.01,
                   u'last_5min': 1.36, u'last_15min': 0.80},
      u'partitions_dict': {
        u'/': {u'total': 9625113728, u'used': 7456263936}
      },
      u'cpu': {u'count': 2}
    }
  }

  test_all_roles = {
    u'192.168.33.10': [
      u'load_balancer', u'shadow', u'login', u'appengine'
    ],
    u'192.168.33.11': [
      u'taskqueue_master', u'zookeeper', u'db_master', u'taskqueue', u'memcache'
    ]
  }

  test_raw_process_stats = {
    u'192.168.33.10': {
      u'processes_stats': [
        {
          u'unified_service_name': u'zookeeper', u'application_id': None,
          u'monit_name': u'zookeeper', u'memory': {u'unique': 76214272},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'uaserver', u'application_id': None,
          u'monit_name': u'uaserver', u'memory': {u'unique': 40448000},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'taskqueue', u'application_id': None,
          u'monit_name': u'taskqueue-17448', u'memory': {u'unique': 44400640},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'taskqueue', u'application_id': None,
          u'monit_name': u'taskqueue-17447', u'memory': {u'unique': 44453888},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'rabbitmq', u'application_id': None,
          u'monit_name': u'rabbitmq', u'memory': {u'unique': 54009856},
          u'children_num': 1, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0.0}, u'memory': {u'unique': 65536}
          }
        },
        {
          u'unified_service_name': u'nginx', u'application_id': None,
          u'monit_name': u'nginx', u'memory': {u'unique': 704512},
          u'children_num': 1, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0.1}, u'memory': {u'unique': 12554240}
          }
        },
        {
          u'unified_service_name': u'memcached', u'application_id': None,
          u'monit_name': u'memcached', u'memory': {u'unique': 5242880},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'log_service', u'application_id': None,
          u'monit_name': u'log_service', u'memory': {u'unique': 20582400},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'hermes', u'application_id': None,
          u'monit_name': u'hermes', u'memory': {u'unique': 28336128},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'haproxy', u'application_id': None,
          u'monit_name': u'haproxy', u'memory': {u'unique': 7872512},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'datastore', u'application_id': None,
          u'monit_name': u'datastore_server-4001',
          u'memory': {u'unique': 47923200}, u'children_num': 0,
          u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'datastore', u'application_id': None,
          u'monit_name': u'datastore_server-4000',
          u'memory': {u'unique': 46436352}, u'children_num': 0,
          u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'controller', u'application_id': None,
          u'monit_name': u'controller', u'memory': {u'unique': 60841984},
          u'children_num': 1, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0.0}, u'memory': {u'unique': 102400}
          }
        },
        {
          u'unified_service_name': u'cassandra', u'application_id': None,
          u'monit_name': u'cassandra', u'memory': {u'unique': 1374511104},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'backup_recovery_service',
          u'application_id': None, u'monit_name': u'backup_recovery_service',
          u'memory': {u'unique': 45424640}, u'children_num': 0,
          u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        },
        {
          u'unified_service_name': u'appmanager', u'application_id': None,
          u'monit_name': u'appmanagerserver', u'memory': {u'unique': 15781888},
          u'children_num': 0, u'cpu': {u'percent': 0.0},
          u'children_stats_sum': {
            u'cpu': {u'percent': 0}, u'memory': {u'unique': 0}
          }
        }
      ]
    }
  }

  test_raw_proxy_stats = {
    u'192.168.33.10': {
      u'proxies_stats': [
        {
          u'unified_service_name': u'taskqueue', u'servers_count': 2,
          u'application_id': None, u'backend': {u'qcur': 0},
          u'frontend': {
            u'bin': 0, u'scur': 0, u'hrsp_5xx': 0, u'hrsp_4xx': 0,
            u'req_rate': 0, u'req_tot': 0, u'bout': 0
          }
        },
        {
          u'unified_service_name': u'blobstore', u'servers_count': 1,
          u'application_id': None, u'backend': {u'qcur': 0},
          u'frontend': {
            u'bin': 0, u'scur': 0, u'hrsp_5xx': 0, u'hrsp_4xx': 0,
            u'req_rate': 0, u'req_tot': 0, u'bout': 0
          }
        },
        {
          u'unified_service_name': u'datastore', u'servers_count': 2,
          u'application_id': None, u'backend': {u'qcur': 0},
          u'frontend': {
            u'bin': 54355, u'scur': 0, u'hrsp_5xx': 0, u'hrsp_4xx': 0,
            u'req_rate': 0, u'req_tot': 181, u'bout': 38676
          }
        },
        {
          u'unified_service_name': u'application', u'servers_count': 3,
          u'application_id': u'appscaledashboard', u'backend': {u'qcur': 0},
          u'frontend': {
            u'bin': 40757, u'scur': 0, u'hrsp_5xx': 0, u'hrsp_4xx': 0,
            u'req_rate': 0, u'req_tot': 130, u'bout': 24381
          }
        },
        {
          u'unified_service_name': u'uaserver', u'servers_count': 1,
          u'application_id': None, u'backend': {u'qcur': 0},
          u'frontend': {
            u'bin': 662451, u'scur': 0, u'hrsp_5xx': 0, u'hrsp_4xx': 0,
            u'req_rate': 0, u'req_tot': 831, u'bout': 667143
          }
        },
        {
          u'unified_service_name': u'application', u'servers_count': 3,
          u'application_id': u'app_test', u'backend': {u'qcur': 0},
          u'frontend': {
            u'bin': 26157, u'scur': 0, u'hrsp_5xx': 1, u'hrsp_4xx': 0,
            u'req_rate': 0, u'req_tot': 235, u'bout': 24511
          }
        }

      ]
    }
  }

  def test_get_node_stats_headers_and_specified_roles(self):
    specified_roles = [u'login', u'shadow']

    node_headers, node_stats = get_node_stats(
      raw_node_stats=self.test_raw_node_stats,
      all_roles=self.test_all_roles,
      specified_roles=specified_roles,
      verbose=False
    )

    expected_node_headers = [
      "PRIVATE IP", "AVAILABLE MEMORY", "LOADAVG", "PARTITIONS USAGE", "ROLES"
    ]

    expected_node_stats = [
      [
        "\x1b[1m192.168.33.10\x1b[0m",
        "\x1b[1m32% (1273 MB)\x1b[0m",
        "\x1b[1m0.14 / 0.36 / 0.21\x1b[0m",
        "\x1b[1m\x1b[91m'/test': 92%\x1b[0m, "
        "'/main': 84%, '/': 44%, ...\x1b[0m",
        "\x1b[1mload_balancer, shadow, login, appengine\x1b[0m"
      ]
    ]

    self.assertEqual(node_headers, expected_node_headers)
    self.assertEqual(node_stats, expected_node_stats)

  def test_get_node_stats_verbose(self):
    verbose = True

    node_stats = get_node_stats(
      raw_node_stats=self.test_raw_node_stats,
      all_roles=self.test_all_roles,
      specified_roles=None,
      verbose=verbose
    )[1]

    expected_node_stats = [
      [
        "\x1b[1m192.168.33.10\x1b[0m",
        "\x1b[1m32% (1273 MB)\x1b[0m",
        "\x1b[1m0.14 / 0.36 / 0.21\x1b[0m",
        "\x1b[1m\x1b[91m'/test': 92%\x1b[0m, "
          "'/main': 84%, '/': 44%, '/user': 25%\x1b[0m",
        "\x1b[1mload_balancer, shadow, login, appengine\x1b[0m"
      ],
      [
        "192.168.33.11",
        "51% (2055 MB)",
        "\x1b[91m2.01\x1b[0m / 1.36 / 0.8",
        "'/': 77%",
        "taskqueue_master, zookeeper, db_master, taskqueue, memcache"
      ]
    ]

    self.assertEqual(node_stats, expected_node_stats)

  def test_get_process_stats_headers_and_verbose(self):
    process_headers, process_stats = get_process_stats(
      raw_process_stats=self.test_raw_process_stats
    )

    expected_process_headers = [
      "PRIVATE IP", "MONIT NAME", "UNIQUE MEMORY (MB)", "CPU (%)"
    ]

    expected_process_stats = [
      [u'192.168.33.10', u'zookeeper', 72, 0.0],
      [u'192.168.33.10', u'uaserver', 38, 0.0],
      [u'192.168.33.10', u'taskqueue-17448', 42, 0.0],
      [u'192.168.33.10', u'taskqueue-17447', 42, 0.0],
      [u'192.168.33.10', u'rabbitmq', 51, 0.0],
      [u'192.168.33.10', u'nginx', 12, 0.1],
      [u'192.168.33.10', u'memcached', 5, 0.0],
      [u'192.168.33.10', u'log_service', 19, 0.0],
      [u'192.168.33.10', u'hermes', 27, 0.0],
      [u'192.168.33.10', u'haproxy', 7, 0.0],
      [u'192.168.33.10', u'datastore_server-4001', 45, 0.0],
      [u'192.168.33.10', u'datastore_server-4000', 44, 0.0],
      [u'192.168.33.10', u'controller', 58, 0.0],
      [u'192.168.33.10', u'cassandra', 1310, 0.0],
      [u'192.168.33.10', u'backup_recovery_service', 43, 0.0],
      [u'192.168.33.10', u'appmanagerserver', 15, 0.0]
    ]

    self.assertEqual(expected_process_headers, process_headers)
    self.assertEqual(expected_process_stats, process_stats)

  def test_get_process_stats_headers_and_order_and_top(self):
    process_headers, process_stats = get_summary_process_stats(
      raw_process_stats=self.test_raw_process_stats,
      raw_node_stats=self.test_raw_node_stats
    )

    process_stats = sort_process_stats(
      process_stats=process_stats,
      column=0,   # order by "SERVICE (ID)"
      top=5,
      reverse=False
    )

    expected_process_headers = [
      "SERVICE (ID)", "INSTANCES", "UNIQUE MEMORY SUM (MB)",
      "CPU SUM (%)", "CPU PER 1 PROCESS (%)", "CPU PER 1 CORE (%)"
    ]

    expected_process_stats = [
      [u'appmanager', 1, 15, 0.0, 0.0, 0.0],
      [u'backup_recovery_service', 1, 43, 0.0, 0.0, 0.0],
      [u'cassandra', 1, 1310, 0.0, 0.0, 0.0],
      [u'controller', 1, 58, 0.0, 0.0, 0.0],
      [u'datastore', 2, 89, 0.0, 0.0, 0.0]
    ]

    self.assertEqual(expected_process_headers, process_headers)
    self.assertEqual(expected_process_stats, process_stats)

  def test_get_proxy_stats_headers_and_order(self):
    proxy_headers, proxy_stats = get_proxy_stats(
      raw_proxy_stats=self.test_raw_proxy_stats,
      verbose=False,
      apps_filter=False
    )

    proxy_stats = sort_proxy_stats(
      proxy_stats=proxy_stats,
      column=0  # order by "SERVICE | ID"
    )

    expected_proxy_headers = [
      "SERVICE | ID", "SERVERS", "REQ RATE / REQ TOTAL", "5xx / 4xx", "QUEUE CUR"
    ]

    expected_proxy_stats = [
      [u'app | app_test', 3, '0 / 235', '\x1b[91m1\x1b[0m / 0', '0'],
      [u'app | appscaledashboard', 3, '0 / 130', '0 / 0', '0'],
      [u'blobstore', 1, '0 / 0', '0 / 0', '0'],
      [u'datastore', 2, '0 / 181', '0 / 0', '0'],
      [u'taskqueue', 2, '0 / 0', '0 / 0', '0'],
      [u'uaserver', 1, '0 / 831', '0 / 0', '0']
    ]

    self.assertEqual(expected_proxy_headers, proxy_headers)
    self.assertEqual(expected_proxy_stats, proxy_stats)

  def test_get_proxy_stats_order_and_verbose_and_apps_only(self):
    proxy_stats = get_proxy_stats(
      raw_proxy_stats=self.test_raw_proxy_stats,
      verbose=True,
      apps_filter=True
    )[1]

    proxy_stats = sort_proxy_stats(
      proxy_stats=proxy_stats,
      column=0    # order by "SERVICE | ID"
    )

    expected_proxy_stats = [
      [
        u'app | app_test', 3, '0 / 235',
        '\x1b[91m1\x1b[0m / 0', '26157 / 24511', '0 / 0'
      ],
      [
        u'app | appscaledashboard', 3, '0 / 130',
        '0 / 0', '40757 / 24381', '0 / 0'
      ]
    ]

    self.assertEqual(expected_proxy_stats, proxy_stats)

  @patch("appscale.tools.appscale_stats.LocalState.get_login_host")
  @patch("appscale.tools.appscale_stats.LocalState.get_secret_key")
  @patch("requests.get")
  def test_get_stats(self, mock_get, mock_get_secret_key, mock_get_login_host):
    mock_get_login_host.return_value = "192.168.33.10"
    mock_get_secret_key.return_value = "secret_key"

    attr = {
      "json.return_value": {
        "stats": {
          u'192.168.33.10': {
            u'memory': {u'available': 1292578816,
                        u'total': 4145442816, u'used': 2634752000},
            u'loadavg': {u'last_1min': 0.15,
                         u'last_5min': 0.2, u'last_15min': 0.19},
            u'cpu': {u'count': 1},
            u'partitions_dict': {
              u'/': {u'total': 9687113728, u'used': 4363988992}
            }
          }
        },
        "failures": {}
      }
    }
    mock_get.return_value = Mock(**attr)

    stats, failures = _get_stats(
      keyname="keyname",
      stats_kind="nodes",
      include_lists=INCLUDE_NODE_LIST
    )

    expected_stats = {
      u'192.168.33.10': {
        u'memory': {u'available': 1292578816,
                    u'total': 4145442816, u'used': 2634752000},
        u'loadavg': {u'last_1min': 0.15,
                     u'last_5min': 0.2, u'last_15min': 0.19},
        u'cpu': {u'count': 1},
        u'partitions_dict': {u'/': {u'total': 9687113728, u'used': 4363988992}}
      }
    }

    expected_failures = {}

    self.assertEqual(stats, expected_stats)
    self.assertEqual(failures, expected_failures)

    mock_get.assert_called_with(
      url="https://192.168.33.10:17441/stats/cluster/nodes",
      headers={'Appscale-Secret': "secret_key"},
      json={
        'include_lists': {
          'node': ['memory', 'loadavg', 'partitions_dict', 'cpu'],
          'node.loadavg': ['last_1min', 'last_5min', 'last_15min'],
          'node.partition': ['used', 'total'],
          'node.cpu': ['count']
        }
      },
      verify=False
    )

  @patch("appscale.tools.appscale_stats._get_stats")
  def test_show_stats(self, mock_get_stats):
    raw_proxy_stats = {
      u'192.168.33.10': {
        u'proxies_stats': [
          {
            u'unified_service_name': u'taskqueue', u'servers_count': 2,
            u'application_id': None, u'backend': {u'qcur': 0},
            u'frontend': {
              u'bin': 0, u'scur': 0, u'hrsp_5xx': 0, u'hrsp_4xx': 0,
              u'req_rate': 0, u'req_tot': 0, u'bout': 0
            }
          },
          {
            u'unified_service_name': u'blobstore', u'servers_count': 1,
            u'application_id': None, u'backend': {u'qcur': 0},
            u'frontend': {
              u'bin': 0, u'scur': 0, u'hrsp_5xx': 0, u'hrsp_4xx': 0,
              u'req_rate': 0, u'req_tot': 0, u'bout': 0
            }
          }
        ]
      }
    }

    mock_get_stats.return_value = (raw_proxy_stats, {})

    options = argparse.Namespace()
    options.keyname = "keyname"
    options.show = ["proxies"]
    options.verbose = False
    options.apps_only = False

    buf = StringIO.StringIO()

    def mock_log(s):
      buf.write(s + "\n")

    logger_fullname = "appscale.tools.appscale_stats.AppScaleLogger.log"

    with patch(logger_fullname, side_effect=mock_log):
      show_stats(options=options)

    expected_table_name = "PROXY STATISTICS"
    unexpected_table_names = [
      "NODE STATISTICS", "SUMMARY PROCESS STATISTICS", "PROCESS STATISTICS"
    ]

    for table_name in unexpected_table_names:
      self.assertNotIn(table_name, buf.getvalue())

    self.assertIn(expected_table_name, buf.getvalue())
