import unittest
import StringIO
import argparse

from mock import patch, Mock

from appscale.tools.appscale_stats import (
  get_node_stats_rows, get_process_stats_rows, get_summary_process_stats_rows, get_proxy_stats_rows,
  sort_process_stats_rows, sort_proxy_stats_rows, show_stats,
  INCLUDE_NODE_LIST, _get_stats
)


class TestStats(unittest.TestCase):

  test_raw_node_stats = {
    '192.168.33.10': {
      'memory': {'available': 1334953984,
                  'total': 4145442816, 'used': 2592751616},
      'loadavg': {'last_1min': 0.14, 'last_5min': 0.36, 'last_15min': 0.21},
      'partitions_dict': {
        '/': {'total': 9687113728, 'used': 4356263936},
        '/user': {'total': 9387513728, 'used': 2356263936},
        '/test': {'total': 9617113728, 'used': 8856263936},
        '/main': {'total': 9817113728, 'used': 8256263936}
      },
      'cpu': {'count': 1}
    },
    '192.168.33.11': {
      'memory': {'available': 2154953984,
                  'total': 4194742816, 'used': 15551616},
      'loadavg': {'last_1min': 2.01,
                   'last_5min': 1.36, 'last_15min': 0.80},
      'partitions_dict': {
        '/': {'total': 9625113728, 'used': 7456263936}
      },
      'cpu': {'count': 2}
    }
  }

  test_all_roles = {
    '192.168.33.10': [
      'load_balancer', 'shadow', 'login', 'appengine'
    ],
    '192.168.33.11': [
      'taskqueue_master', 'zookeeper', 'db_master', 'taskqueue', 'memcache'
    ]
  }

  test_raw_process_stats = {
    '192.168.33.10': {
      'processes_stats': [
        {
          'unified_service_name': 'zookeeper', 'application_id': None,
          'monit_name': 'zookeeper', 'memory': {'unique': 76214272},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'uaserver', 'application_id': None,
          'monit_name': 'uaserver', 'memory': {'unique': 40448000},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'taskqueue', 'application_id': None,
          'monit_name': 'taskqueue-17448', 'memory': {'unique': 44400640},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'taskqueue', 'application_id': None,
          'monit_name': 'taskqueue-17447', 'memory': {'unique': 44453888},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'rabbitmq', 'application_id': None,
          'monit_name': 'rabbitmq', 'memory': {'unique': 54009856},
          'children_num': 1, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0.0}, 'memory': {'unique': 65536}
          }
        },
        {
          'unified_service_name': 'nginx', 'application_id': None,
          'monit_name': 'nginx', 'memory': {'unique': 704512},
          'children_num': 1, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0.1}, 'memory': {'unique': 12554240}
          }
        },
        {
          'unified_service_name': 'memcached', 'application_id': None,
          'monit_name': 'memcached', 'memory': {'unique': 5242880},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'log_service', 'application_id': None,
          'monit_name': 'log_service', 'memory': {'unique': 20582400},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'hermes', 'application_id': None,
          'monit_name': 'hermes', 'memory': {'unique': 28336128},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'haproxy', 'application_id': None,
          'monit_name': 'haproxy', 'memory': {'unique': 7872512},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'datastore', 'application_id': None,
          'monit_name': 'datastore_server-4001',
          'memory': {'unique': 47923200}, 'children_num': 0,
          'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'datastore', 'application_id': None,
          'monit_name': 'datastore_server-4000',
          'memory': {'unique': 46436352}, 'children_num': 0,
          'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'controller', 'application_id': None,
          'monit_name': 'controller', 'memory': {'unique': 60841984},
          'children_num': 1, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0.0}, 'memory': {'unique': 102400}
          }
        },
        {
          'unified_service_name': 'cassandra', 'application_id': None,
          'monit_name': 'cassandra', 'memory': {'unique': 1374511104},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'backup_recovery_service',
          'application_id': None, 'monit_name': 'backup_recovery_service',
          'memory': {'unique': 45424640}, 'children_num': 0,
          'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        },
        {
          'unified_service_name': 'appmanager', 'application_id': None,
          'monit_name': 'appmanagerserver', 'memory': {'unique': 15781888},
          'children_num': 0, 'cpu': {'percent': 0.0},
          'children_stats_sum': {
            'cpu': {'percent': 0}, 'memory': {'unique': 0}
          }
        }
      ]
    }
  }

  test_raw_proxy_stats = {
    '192.168.33.10': {
      'proxies_stats': [
        {
          'unified_service_name': 'taskqueue', 'servers_count': 2,
          'application_id': None, 'backend': {'qcur': 0},
          'frontend': {
            'bin': 0, 'scur': 0, 'hrsp_5xx': 0, 'hrsp_4xx': 0,
            'req_rate': 0, 'req_tot': 0, 'bout': 0
          },
          'servers': [{'status': 'UP'}, {'status': 'UP'}]
        },
        {
          'unified_service_name': 'blobstore', 'servers_count': 1,
          'application_id': None, 'backend': {'qcur': 0},
          'frontend': {
            'bin': 0, 'scur': 0, 'hrsp_5xx': 0, 'hrsp_4xx': 0,
            'req_rate': 0, 'req_tot': 0, 'bout': 0
          },
          'servers': [{'status': 'UP'}]
        },
        {
          'unified_service_name': 'datastore', 'servers_count': 2,
          'application_id': None, 'backend': {'qcur': 0},
          'frontend': {
            'bin': 54355, 'scur': 0, 'hrsp_5xx': 0, 'hrsp_4xx': 0,
            'req_rate': 0, 'req_tot': 181, 'bout': 38676
          },
          'servers': [{'status': 'UP'}, {'status': 'UP'}]
        },
        {
          'unified_service_name': 'application', 'servers_count': 3,
          'application_id': 'appscaledashboard', 'backend': {'qcur': 0},
          'frontend': {
            'bin': 40757, 'scur': 0, 'hrsp_5xx': 0, 'hrsp_4xx': 0,
            'req_rate': 0, 'req_tot': 130, 'bout': 24381
          },
          'servers': [{'status': 'UP'}, {'status': 'UP'}, {'status': 'UP'}]
        },
        {
          'unified_service_name': 'uaserver', 'servers_count': 1,
          'application_id': None, 'backend': {'qcur': 0},
          'frontend': {
            'bin': 662451, 'scur': 0, 'hrsp_5xx': 0, 'hrsp_4xx': 0,
            'req_rate': 0, 'req_tot': 831, 'bout': 667143
          },
          'servers': [{'status': 'UP'}]
        },
        {
          'unified_service_name': 'application', 'servers_count': 3,
          'application_id': 'app_test', 'backend': {'qcur': 0},
          'frontend': {
            'bin': 26157, 'scur': 0, 'hrsp_5xx': 1, 'hrsp_4xx': 0,
            'req_rate': 0, 'req_tot': 235, 'bout': 24511
          },
          'servers': [{'status': 'UP'}, {'status': 'DOWN'}, {'status': 'UP'}]
        }
      ]
    }
  }

  def test_get_node_stats_headers_and_specified_roles(self):
    specified_roles = ['login', 'shadow']

    node_headers, node_stats = get_node_stats_rows(
      raw_node_stats=self.test_raw_node_stats,
      all_roles=self.test_all_roles,
      specified_roles=specified_roles,
      verbose=False
    )

    expected_node_headers = [
      "PRIVATE IP", "AVAILABLE MEM", "LOADAVG", "DISK USAGE%", "ROLES"
    ]

    expected_node_stats = [
      [
        u"\x1b[1m192.168.33.10\x1b[0m",
        u"\x1b[1m32% (1273 MB)\x1b[0m",
        u"\x1b[1m0.1 0.4 0.2\x1b[0m",
        u"\x1b[1m\x1b[31m\x1b[1m/test: 92\x1b[0m\x1b[1m, /main: 84, /: 44, ...\x1b[0m",
        u"\x1b[1mload_balancer shadow login appengine\x1b[0m"
      ]
    ]

    self.assertEqual(node_headers, expected_node_headers)
    self.assertEqual(node_stats, expected_node_stats)

  def test_get_node_stats_verbose(self):
    verbose = True

    node_stats = get_node_stats_rows(
      raw_node_stats=self.test_raw_node_stats,
      all_roles=self.test_all_roles,
      specified_roles=None,
      verbose=verbose
    )[1]

    expected_node_stats = [
      [
        "\x1b[1m192.168.33.10\x1b[0m",
        "\x1b[1m32% (1273 MB)\x1b[0m",
        "\x1b[1m0.1 0.4 0.2\x1b[0m",
        ("\x1b[1m\x1b[31m\x1b[1m/test: 92\x1b[0m\x1b[1m, /main: 84, "
         "/: 44, /user: 25\x1b[0m"),
        "\x1b[1mload_balancer shadow login appengine\x1b[0m"
      ],
      [
        "192.168.33.11",
        "51% (2055 MB)",
        "\x1b[31m\x1b[1m2.0\x1b[0m 1.4 0.8",
        "/: 77",
        "taskqueue_master zookeeper db_master taskqueue memcache"
      ]
    ]

    self.assertEqual(node_stats, expected_node_stats)

  def test_get_process_stats_headers_and_verbose(self):
    process_headers, process_stats = get_process_stats_rows(
      raw_process_stats=self.test_raw_process_stats
    )

    expected_process_headers = [
      "PRIVATE IP", "MONIT NAME", "MEM MB", "CPU%"
    ]

    expected_process_stats = [
      ['192.168.33.10', 'zookeeper', 72, 0.0],
      ['192.168.33.10', 'uaserver', 38, 0.0],
      ['192.168.33.10', 'taskqueue-17448', 42, 0.0],
      ['192.168.33.10', 'taskqueue-17447', 42, 0.0],
      ['192.168.33.10', 'rabbitmq', 51, 0.0],
      ['192.168.33.10', 'nginx', 12, 0.1],
      ['192.168.33.10', 'memcached', 5, 0.0],
      ['192.168.33.10', 'log_service', 19, 0.0],
      ['192.168.33.10', 'hermes', 27, 0.0],
      ['192.168.33.10', 'haproxy', 7, 0.0],
      ['192.168.33.10', 'datastore_server-4001', 45, 0.0],
      ['192.168.33.10', 'datastore_server-4000', 44, 0.0],
      ['192.168.33.10', 'controller', 58, 0.0],
      ['192.168.33.10', 'cassandra', 1310, 0.0],
      ['192.168.33.10', 'backup_recovery_service', 43, 0.0],
      ['192.168.33.10', 'appmanagerserver', 15, 0.0]
    ]

    self.assertEqual(expected_process_headers, process_headers)
    self.assertEqual(expected_process_stats, process_stats)

  def test_get_process_stats_headers_and_order_and_top(self):
    process_headers, process_stats = get_summary_process_stats_rows(
      raw_process_stats=self.test_raw_process_stats,
      raw_node_stats=self.test_raw_node_stats
    )

    process_stats = sort_process_stats_rows(
      process_stats=process_stats,
      column=0,   # order by "SERVICE (ID)"
      top=5,
      reverse=False
    )

    expected_process_headers = [
      "SERVICE (ID)", "INSTANCES", u"\u2211 MEM MB",
      u"\u2211 CPU%", "CPU% PER PROCESS", "CPU% PER CORE"
    ]

    expected_process_stats = [
      ['appmanager', 1, 15, 0.0, 0.0, 0.0],
      ['backup_recovery_service', 1, 43, 0.0, 0.0, 0.0],
      ['cassandra', 1, 1310, 0.0, 0.0, 0.0],
      ['controller', 1, 58, 0.0, 0.0, 0.0],
      ['datastore', 2, 89, 0.0, 0.0, 0.0]
    ]

    self.assertEqual(expected_process_headers, process_headers)
    self.assertEqual(expected_process_stats, process_stats)

  def test_get_proxy_stats_headers_and_order(self):
    proxy_headers, proxy_stats = get_proxy_stats_rows(
      raw_proxy_stats=self.test_raw_proxy_stats,
      verbose=False,
      apps_filter=False
    )

    proxy_stats = sort_proxy_stats_rows(
      proxy_stats=proxy_stats,
      column=0  # order by "SERVICE | ID"
    )

    expected_proxy_headers = [
      "SERVICE (ID)", "SERVERS | DOWN", "RATE | REQ TOTAL", "5xx | 4xx", "QCUR"
    ]

    expected_proxy_stats = [
      ['app (app_test)', '3 | \x1b[31m\x1b[1m1\x1b[0m',
       '0 | 235', '\x1b[31m\x1b[1m1\x1b[0m | 0', 0],
      ['app (appscaledashboard)', '3 | 0', '0 | 130', '0 | 0', 0],
      ['blobstore', '1 | 0', '0 | 0', '0 | 0', 0],
      ['datastore', '2 | 0', '0 | 181', '0 | 0', 0],
      ['taskqueue', '2 | 0', '0 | 0', '0 | 0', 0],
      ['uaserver', '1 | 0', '0 | 831', '0 | 0', 0]
    ]

    self.assertEqual(expected_proxy_headers, proxy_headers)
    self.assertEqual(expected_proxy_stats, proxy_stats)

  def test_get_proxy_stats_order_and_verbose_and_apps_only(self):
    proxy_stats = get_proxy_stats_rows(
      raw_proxy_stats=self.test_raw_proxy_stats,
      verbose=True,
      apps_filter=True
    )[1]

    proxy_stats = sort_proxy_stats_rows(
      proxy_stats=proxy_stats,
      column=0    # order by "SERVICE | ID"
    )

    expected_proxy_stats = [
      [
        'app (app_test)', '3 | \x1b[31m\x1b[1m1\x1b[0m', '0 | 235',
        '\x1b[31m\x1b[1m1\x1b[0m | 0', '26157 | 24511', '0 | 0'
      ],
      [
        'app (appscaledashboard)', '3 | 0', '0 | 130',
        '0 | 0', '40757 | 24381', '0 | 0'
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
          '192.168.33.10': {
            'memory': {'available': 1292578816,
                        'total': 4145442816, 'used': 2634752000},
            'loadavg': {'last_1min': 0.15,
                         'last_5min': 0.2, 'last_15min': 0.19},
            'cpu': {'count': 1},
            'partitions_dict': {
              '/': {'total': 9687113728, 'used': 4363988992}
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
      '192.168.33.10': {
        'memory': {'available': 1292578816,
                    'total': 4145442816, 'used': 2634752000},
        'loadavg': {'last_1min': 0.15,
                     'last_5min': 0.2, 'last_15min': 0.19},
        'cpu': {'count': 1},
        'partitions_dict': {'/': {'total': 9687113728, 'used': 4363988992}}
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
      '192.168.33.10': {
        'proxies_stats': [
          {
            'unified_service_name': 'taskqueue', 'servers_count': 2,
            'application_id': None, 'backend': {'qcur': 0},
            'frontend': {
              'bin': 0, 'scur': 0, 'hrsp_5xx': 0, 'hrsp_4xx': 0,
              'req_rate': 0, 'req_tot': 0, 'bout': 0
            },
            'servers': [{'status': 'UP'}, {'status': 'DOWN'}]
          },
          {
            'unified_service_name': 'blobstore', 'servers_count': 1,
            'application_id': None, 'backend': {'qcur': 0},
            'frontend': {
              'bin': 0, 'scur': 0, 'hrsp_5xx': 0, 'hrsp_4xx': 0,
              'req_rate': 0, 'req_tot': 0, 'bout': 0
            },
            'servers': [{'status': 'UP'}]
          }
        ]
      }
    }

    mock_get_stats.return_value = (raw_proxy_stats, {})

    options = argparse.Namespace()
    options.keyname = "keyname"
    options.types = ["proxies"]
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
