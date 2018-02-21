import requests

from appcontroller_client import AppControllerClient
from local_state import LocalState

from tabulate import tabulate
from appscale_logger import AppScaleLogger
from termcolor import colored
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# Fields needed for node statistics
INCLUDE_NODE_LIST = {
  'node': ['memory', 'loadavg', 'partitions_dict', 'cpu'],
  'node.loadavg': ['last_1min', 'last_5min', 'last_15min'],
  'node.partition': ['used', 'total'],
  'node.cpu': ['count']
}

# Fields needed for process statistics
INCLUDE_PROCESS_LIST = {
  'process': ['unified_service_name', 'application_id', 'monit_name', 'memory',
              'cpu', 'children_num', 'children_stats_sum'],
  'process.memory': ['unique'],
  'process.cpu': ['percent'],
  'process.children_stats_sum': ['memory', 'cpu']
}

# Fields needed for proxy statistics
INCLUDE_PROXY_LIST = {
  'proxy': ['unified_service_name', 'application_id', 'servers_count',
            'frontend', 'backend'],
  'proxy.frontend': ['req_rate', 'req_tot', 'hrsp_5xx', 'hrsp_4xx',
                     'bin', 'bout', 'scur'],
  'proxy.backend': ['qtime', 'rtime', 'qcur']
}

PROCESSES_NAME_COLUMN_NUMBER = 0
PROCESSES_NAME_COLUMN_VERBOSE_NUMBER = 1
PROCESSES_MEMORY_COLUMN_NUMBER = 2
PROCESSES_CPU_COLUMN_NUMBER = 3


def _get_stats(keyname, stats_kind, include_lists):
  """
  Returns statistics from Hermes.

  Args:
    keyname: A string representing an identifier from AppScaleFile.
    stats_kind: A string representing a kind of statistics.
    include_lists: A dict representing desired fields.

  Returns:
    A dict of statistics.
    A dict of failures.
  """
  login_host = LocalState.get_login_host(keyname=keyname)
  secret = LocalState.get_secret_key(keyname=keyname)
  administration_port = "17441"
  stats_path = "/stats/cluster/{stats_kind}".format(stats_kind=stats_kind)

  headers = {
    'Appscale-Secret': secret
  }

  data = {
    'include_lists': include_lists
  }

  url = "https://{ip}:{port}{path}".format(
    ip=login_host,
    port=administration_port,
    path=stats_path
  )

  try:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    resp = requests.get(
      url=url,
      headers=headers,
      json=data,
      verify=False
    )
    resp.raise_for_status()
  except requests.HTTPError as e:
    AppScaleLogger.warn(
      "Failed to get {stats_kind} stats."
      .format(stats_kind=stats_kind)
    )
    return {}, {}

  resp = resp.json()

  return resp["stats"], resp["failures"]


def show_stats(options):
  """
  Prints node, process and/or proxy statistics nicely.

  Args:
    options: A Namespace that has fields for each parameter that can be
      passed in via the command-line interface.
  """
  failures = {}

  if "nodes" in options.types:
    raw_node_stats, node_failures = _get_stats(
      keyname=options.keyname,
      stats_kind="nodes",
      include_lists=INCLUDE_NODE_LIST
    )
    all_roles = get_roles(keyname=options.keyname)
    node_headers, node_stats = get_node_stats(
      raw_node_stats=raw_node_stats,
      all_roles=all_roles,
      specified_roles=options.roles,
      verbose=options.verbose
    )
    print_table(
      table_name="NODE STATISTICS",
      headers=node_headers,
      data=node_stats
    )
    if node_failures:
      failures["nodes"] = node_failures

  if "processes" in options.types:
    if "name" == options.order_processes:
      order = (PROCESSES_NAME_COLUMN_NUMBER
               if not options.verbose
               else PROCESSES_NAME_COLUMN_VERBOSE_NUMBER)
    elif "mem" == options.order_processes:
      order = PROCESSES_MEMORY_COLUMN_NUMBER
    elif "cpu" == options.order_processes:
      order = PROCESSES_CPU_COLUMN_NUMBER

    raw_process_stats, process_failures = _get_stats(
      keyname=options.keyname,
      stats_kind="processes",
      include_lists=INCLUDE_PROCESS_LIST
    )
    if "nodes" not in options.types:
      raw_node_stats, node_failures = _get_stats(
        keyname=options.keyname,
        stats_kind="nodes",
        include_lists=INCLUDE_NODE_LIST
      )
      if node_failures:
        failures["nodes"] = node_failures

    process_headers, process_stats = (
      get_process_stats(raw_process_stats=raw_process_stats)
      if options.verbose
      else get_summary_process_stats(
        raw_process_stats=raw_process_stats,
        raw_node_stats=raw_node_stats
      )
    )
    process_stats = sort_process_stats(
      process_stats=process_stats,
      column=order,
      top=options.top if options.top else None,
      reverse="name" not in options.order_processes
    )
    print_table(
      table_name="SUMMARY APPSCALE PROCESS STATISTICS"
      if not options.verbose else "APPSCALE PROCESS STATISTICS",
      headers=process_headers,
      data=process_stats
    )
    if process_failures:
      failures["processes"] = process_failures

  if "proxies" in options.types:
    raw_proxy_stats, proxy_failures = _get_stats(
      keyname=options.keyname,
      stats_kind="proxies",
      include_lists=INCLUDE_PROXY_LIST
    )
    proxy_headers, proxy_stats = get_proxy_stats(
      raw_proxy_stats=raw_proxy_stats,
      verbose=options.verbose,
      apps_filter=options.apps_only
    )
    proxy_stats = sort_proxy_stats(
      proxy_stats=proxy_stats,
      column=0
    )
    print_table(
      table_name="PROXY STATISTICS",
      headers=proxy_headers,
      data=proxy_stats
    )
    if proxy_failures:
      failures["proxies"] = proxy_failures

  if failures:
    print_failures(failures=failures)


def get_marked(data, mark):
  """
  Marks data in a specified mark.

  Args:
    data: An object to be marked in.
    mark: A string representing one of the existing marks
      ('red', 'green' or 'bold').

  Returns:
    A string marked in.
  """
  colors = ["red", "green"]
  attrs = ["bold"]
  if mark in colors:
    return colored(text=str(data), color=mark)
  elif mark in attrs:
    return colored(text=str(data), attrs=[mark])
  else:
    return str(data)


def render_loadavg(loadavg):
  """
  Renders loadavg information.

  Args:
    loadavg: A dict representing loadavg values.

  Returns:
    A string with information about node loadavg
    last 1, 5 and 15 minuts in format: "last 1min / last 5min / last 15min"
    and marked in red if loadavg is more than 2.0.
  """
  limit_value = 2.0
  last_1 = loadavg["last_1min"]
  last_5 = loadavg["last_5min"]
  last_15 = loadavg["last_15min"]

  return "{} | {} | {}".format(
    last_1 if last_1 < limit_value else get_marked(last_1, "red"),
    last_5 if last_5 < limit_value else get_marked(last_5, "red"),
    last_15 if last_15 < limit_value else get_marked(last_15, "red")
  )


def render_partitions(partitions, verbose):
  """
  Renders partitions information.

  Args:
    partitions: A dict representing partition values.
    verbose: A boolean - render all partitions if True,
      add only three the most used partitions if False.

  Returns:
    A string with information about partition values
      marked partition and value in red if value > 90%.
  """
  part_list = [[part, 100 * value["used"] / value["total"]]
               for part, value in
               partitions.iteritems()]  # calculate percents

  # sort from more used to less used
  part_list.sort(key=lambda p: p[1], reverse=True)

  partitions_info = [
    "'{part}': {usage}%".format(part=part[0], usage=part[1])
    if part[1] < 90
    else get_marked(
      "'{part}': {usage}%".format(part=part[0], usage=part[1]), "red"
    )
    for part in part_list
  ]

  if not verbose and len(partitions_info) > 3:
    partitions_info = partitions_info[:3] + ["..."]

  return ", ".join(partitions_info)


def render_memory(memory):
  """
  Renders memory information.

  Args:
    memory: A dict representing memory values.

  Returns:
    A string with information about node memory
    in format: "available % / available MB".
  """
  return "{}% ({} MB)".format(
    (100 * memory["available"] / memory["total"]),
    (memory["available"] / 1024 / 1024)
  )


def sort_process_stats(process_stats, column, top, reverse=True):
  """
  Sorts process statistics by specified column.

  Args:
    process_stats: A list of process statistics.
    column: An int representing a column number the list should be sorted by.
    top: An int representing a process count to be printed.
    reverse: A boolean to reverse or not reverse sorted list.

  Returns:
    A list of top processes sorted by specified column.
  """
  if top == None:
    top = len(process_stats)

  return sorted(process_stats, key=lambda p: p[column], reverse=reverse)[:top]


def sort_proxy_stats(proxy_stats, column):
  """
  Sorts proxy statistics by specified column.

  Args:
    proxy_stats: A list of proxy statistics.
    column: An int representing a column number the list should be sorted by.

  Returns:
    A list sorted by specified column.
  """
  return sorted(proxy_stats, key=lambda p: p[column], reverse=False)


def get_roles(keyname):
  """
  Obtains roles for each ip from AppControllerClient.

  Args:
    keyname: A string representing an identifier from AppScaleFile.

  Returns:
    A dict in which each key is an ip and value is a role list.
  """
  login_host = LocalState.get_login_host(keyname=keyname)
  login_acc = AppControllerClient(
    host=login_host,
    secret=LocalState.get_secret_key(keyname)
  )
  cluster_stats = login_acc.get_cluster_stats()

  roles_data = {
    node["private_ip"]: (node["roles"] if len(node["roles"]) > 0 else ["?"])
    for node in cluster_stats
  }

  return roles_data


def get_node_stats(raw_node_stats, all_roles, specified_roles, verbose):
  """
  Obtains useful information from node statistics and returns:
  PRIVATE IP, AVAILABLE MEMORY, LOADAVG, PARTITIONS USAGE, ROLES values.

  Args:
    raw_node_stats: A dict in which each key is an ip and value is a dict
      of useful information.
    all_roles: A dict in which each key is an ip and value is a role list.
    specified_roles: A list representing specified roles
      that nodes should contain.
    verbose: A boolean - add all partitions if True,
      add only three the most used partitions if False.

  Returns:
    A list of node statistics headers.
    A list of node statistics.
  """
  node_stats_headers = [
    "PRIVATE IP", "AVAILABLE MEMORY", "LOADAVG", "PARTITIONS USAGE", "ROLES"
  ]

  node_stats = []
  for ip, node in raw_node_stats.iteritems():
    ip_roles = all_roles[ip]

    if specified_roles:
      matches = [role for role in specified_roles if role in ip_roles]
      if not matches:
        continue

    if "shadow" in ip_roles:
      node_info = [
        get_marked(ip, "bold"),
        get_marked(render_memory(memory=node["memory"]), "bold"),
        get_marked(render_loadavg(loadavg=node["loadavg"]), "bold"),
        get_marked(
          render_partitions(partitions=node["partitions_dict"],
                            verbose=verbose), "bold"
        ),
        get_marked(u", ".join(ip_roles), "bold")
      ]
    else:
      node_info = [
        ip,
        render_memory(memory=node["memory"]),
        render_loadavg(loadavg=node["loadavg"]),
        render_partitions(partitions=node["partitions_dict"], verbose=verbose),
        u", ".join(ip_roles)
      ]
    node_stats.append(node_info)

  node_stats.sort(key=lambda n: n[0], reverse=False)

  return node_stats_headers, node_stats


def get_process_stats(raw_process_stats):
  """
  Obtains useful information from process statistics and returns:
  PRIVATE IP, MONIT NAME, UNIQUE MEMORY (MB), CPU (%) values.

  Args:
    raw_process_stats: A dict in which each key is an ip and value is a dict
      of useful information.

  Returns:
    A list of process statistics headers.
    A list of process statistics.
  """
  process_stats_headers = [
    "PRIVATE IP", "MONIT NAME", "UNIQUE MEMORY (MB)", "CPU (%)"
  ]

  process_stats = []
  for ip, node in raw_process_stats.iteritems():
    stat = node["processes_stats"]
    for proc in stat:
      memory_unique = int(proc["memory"]["unique"])
      cpu_percent = float(proc["cpu"]["percent"])
      if proc["children_num"] > 0:
        child = proc["children_stats_sum"]
        memory_unique += int(child["memory"]["unique"])
        cpu_percent += float(child["cpu"]["percent"])
      process_stats.append([
        ip,
        proc["monit_name"],
        memory_unique / 1024 / 1024,  # row[2] from B to MB
        cpu_percent
      ])

  return process_stats_headers, process_stats


def get_summary_process_stats(raw_process_stats, raw_node_stats):
  """
  Obtains useful information from summary process statistics and returns:
  SERVICE (ID), INSTANCES, UNIQUE MEMORY SUM (MB),
  CPU SUM (%), CPU PER 1 PROCESS (%), CPU PER 1 CORE (%) values.

  Args:
    raw_process_stats: A dict in which each key is an ip and value is a dict
      of useful information.

  Returns:
    A list of summary process statistics headers.
    A list of summary process statistics.
  """
  cpu_count = sum(
    int(node["cpu"]["count"])
    for node in raw_node_stats.itervalues()
  )

  process_stats = []
  process_list = []
  unique_processes = set()

  process_stats_headers = [
    "SERVICE (ID)", "INSTANCES", "UNIQUE MEMORY SUM (MB)",
    "CPU SUM (%)", "CPU PER PROCESS (%)", "CPU PER CORE (%)"
  ]

  for proc in raw_process_stats.itervalues():
    process_list += proc["processes_stats"]

  for proc in process_list:
    name = proc["unified_service_name"]
    app_id = proc["application_id"]
    name_id = name + (" ({})".format(app_id) if app_id else "")
    if name_id in unique_processes:  # if calculating with process has been made
      continue

    process_group = [
      p for p in process_list
      if p["unified_service_name"] == name
      and p["application_id"] == app_id
    ]

    unique_processes.add(name_id)
    unique_memory = 0
    cpu_percent = 0

    for p in process_group:
      unique_memory += int(p["memory"]["unique"])
      cpu_percent += float(p["cpu"]["percent"])
      if p["children_num"] > 0:
        child = p["children_stats_sum"]
        unique_memory += int(child["memory"]["unique"])
        cpu_percent += float(child["cpu"]["percent"])

    avg_cpu_per_process = cpu_percent / len(process_group)
    cpu_percent_cpu_count = cpu_percent / cpu_count

    process_stats.append([
      name_id,
      len(process_group),
      unique_memory / 1024 / 1024,  # row[2] from B to MB
      cpu_percent,
      avg_cpu_per_process,
      cpu_percent_cpu_count
    ])

  return process_stats_headers, process_stats


def get_proxy_stats(raw_proxy_stats, verbose, apps_filter):
  """
  Obtains useful information from proxy statistics and returns:
  SERVICE (ID), UNIQUE MEMORY SUM (MB), CPU PER 1 PROCESS (%),
  CPU PER 1 CORE (%), CPU SUM (%) values.

  Args:
    raw_proxy_stats: A dict in which each key is an ip and value is a dict
      of useful information.
    verbose: A boolean - verbose or not verbose mode.
    apps_filter: A boolean - show all services or applications only.

  Returns:
    A list of proxy statistics headers.
    A list of proxy statistics.
  """
  proxy_stats_headers = [
    "SERVICE (ID)", "SERVERS", "REQ RATE | REQ TOTAL", "5xx | 4xx", "QUEUE CUR"
  ]

  proxy_stats_headers_verbose = [
    "SERVICE (ID)", "SERVERS", "REQ RATE | REQ TOTAL", "5xx | 4xx",
    "BYTES IN | BYTES OUT", "SESSION CUR | QUEUE CUR", "QTIME | RTIME"
  ]

  proxy_stats = []
  proxy_groups = []
  unique_proxies = {}

  for node in raw_proxy_stats.itervalues():
    proxy_groups += node["proxies_stats"]

  for node in proxy_groups:
    if apps_filter and "application" != node["unified_service_name"]:
      continue

    service_name_id = (
      node["unified_service_name"]
      + ((" (" + node["application_id"] + ")")
         if node["application_id"] else "")
    )

    summary_proxy = unique_proxies.get(service_name_id)
    if not service_name_id in unique_proxies:
      summary_proxy = {}
      summary_proxy["req_rate"] = 0
      summary_proxy["req_tot"] = 0
      summary_proxy["hrsp_5xx"] = 0
      summary_proxy["hrsp_4xx"] = 0

      if verbose:
        summary_proxy["bin"] = 0
        summary_proxy["bout"] = 0
        summary_proxy["scur"] = 0

      summary_proxy["qcur"] = 0

      if verbose and "qtime" and "rtime" in node["backend"]:
        summary_proxy["qtime"] = 0
        summary_proxy["rtime"] = 0

    summary_proxy["servers_count"] = node["servers_count"]

    summary_proxy["req_rate"] += node["frontend"]["req_rate"]
    summary_proxy["req_tot"] += node["frontend"]["req_tot"]
    summary_proxy["hrsp_5xx"] += node["frontend"]["hrsp_5xx"]
    summary_proxy["hrsp_4xx"] += node["frontend"]["hrsp_4xx"]

    if verbose:
      summary_proxy["bin"] += node["frontend"]["bin"]
      summary_proxy["bout"] += node["frontend"]["bout"]
      summary_proxy["scur"] += node["frontend"]["scur"]

    summary_proxy["qcur"] += node["backend"]["qcur"]

    if verbose and "qtime" and "rtime" in node["backend"]:
      summary_proxy["qtime"] += node["backend"]["qtime"]
      summary_proxy["rtime"] += node["backend"]["rtime"]

    unique_proxies[service_name_id] = summary_proxy

  for key, value in unique_proxies.iteritems():
    proxy = []
    proxy.append(key if not key.startswith("application")
                else key.replace("application", "app", 1))
    proxy.append(value["servers_count"])
    proxy.append(
      "{r_rate} | {r_tot}"
        .format(r_rate=value["req_rate"], r_tot=value["req_tot"])
    )
    proxy.append("{hrsp_5xx} | {hrsp_4xx}".format(
      hrsp_5xx=(value["hrsp_5xx"] if not value["hrsp_5xx"]
      else get_marked(value["hrsp_5xx"], "red")),
      hrsp_4xx=(value["hrsp_4xx"] if not value["hrsp_4xx"]
      else get_marked(value["hrsp_4xx"], "red"))
    ))

    if verbose:
      proxy.append(
        "{bin} | {bout}"
          .format(bin=value["bin"], bout=value["bout"])
      )

    proxy.append(
      "{scur}{qcur}"
        .format(scur=((str(value["scur"]) + " | ") if verbose else ""),
                qcur=value["qcur"])
    )

    if verbose and "qtime" and "rtime" in value:
      proxy.append(
        "{qtime} | {rtime}".format(qtime=value["qtime"], rtime=value["rtime"])
      )

    proxy_stats.append(proxy)

  headers = proxy_stats_headers_verbose if verbose else proxy_stats_headers

  return headers, proxy_stats


def print_table(table_name, headers, data):
  """
  Prints a list of statistics with specified headers.

  Args:
    table_name: A string representing a name of table.
    headers: A list of statistic headers.
    data: A list of statistics.
  """
  table = tabulate(tabular_data=data, headers=headers, tablefmt='simple',
                   floatfmt=".1f", numalign="right", stralign="left")

  table_width = len(table.split("\n", 2)[1])
  left_signs = "=" * ((table_width - len(table_name) - 2) / 2)
  right_signs = left_signs + (
    "=" if (table_width - len(table_name)) % 2 == 1 else ""
  )
  result_table_name = (
    "{l_signs} {name} {r_signs}"
      .format(l_signs=left_signs, name=table_name, r_signs=right_signs)
  )

  AppScaleLogger.log(get_marked(data=result_table_name, mark="green"))
  AppScaleLogger.log(table + "\n")


def print_failures(failures):
  """
  Prints a failure list.

  Args:
    failures: A dict in which each key is a kind of statistics and
      value if a failure list.
  """
  stats_kinds = {
    "nodes": "Node",
    "processes": "Process",
    "proxies": "Proxy"
  }

  AppScaleLogger.warn("There are some failures while getting stats:")
  for kind, fails in failures.iteritems():
    for ip, failure in fails.iteritems():
      AppScaleLogger.warn(
        "  {stats_kind} stats from {ip}: {failure}".format(
          stats_kind=stats_kinds[kind],
          ip=ip,
          failure=failure
        )
      )
