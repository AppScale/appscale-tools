class AppInfo(object):
  def __init__(self, app_name, app_info_dict):
    self.name = app_name
    self.language = app_info_dict["language"]
    self.appservers = app_info_dict["appservers"]
    self.pending_appservers = app_info_dict["pending_appservers"]
    self.http = app_info_dict["http"]
    self.https = app_info_dict["https"]
    self.reqs_enqueued = app_info_dict["reqs_enqueued"]
    self.total_reqs = app_info_dict["total_reqs"]


class NodeStats(object):
  class CPU(object):
    def __init__(self, cpu_dict):
      self.idle = cpu_dict["idle"]
      self.system = cpu_dict["system"]
      self.user = cpu_dict["user"]
      self.load = 100.0 - self.idle
      self.count = cpu_dict["count"]

  class Memory(object):
    def __init__(self, memory_dict):
      self.total = memory_dict["total"]
      self.available = memory_dict["available"]
      self.used = memory_dict["used"]
      self.available_percent = 100.0 * self.available / self.total
      self.used_percent = 100.0 * self.used / self.total

  class Swap(object):
    def __init__(self, swap_dict):
      self.free = swap_dict["free"]
      self.used = swap_dict["used"]
      self.total = self.free + self.used
      self.free_percent = 100.0 * self.free / self.total if self.total else None
      self.used_percent = 100.0 - self.free_percent if self.total else None

  class Partition(object):
    def __init__(self, mountpoint, partition_dict):
      self.mountpoint = mountpoint
      self.total = partition_dict["total"]
      self.free = partition_dict["free"]
      self.used = partition_dict["used"]
      self.free_percent = 100.0 * self.free / self.total
      self.used_percent = 100.0 - self.free_percent

  class LoadAvg(object):
    def __init__(self, loadavg_dict):
      self.last_1_min = loadavg_dict["last_1_min"]
      self.last_5_min = loadavg_dict["last_5_min"]
      self.last_15_min = loadavg_dict["last_15_min"]
      self.runnable_entities = loadavg_dict["runnable_entities"]
      self.scheduling_entities = loadavg_dict["scheduling_entities"]

  class Disk(object):
    def __init__(self, partitions):
      self.partitions = partitions
      self.most_loaded = max(partitions, key=lambda partition: partition.used)

  def __init__(self, private_ip, node_stats_dict):
    self.private_ip = private_ip
    self.public_ip = node_stats_dict["public_ip"]
    self.state = node_stats_dict["state"]
    self.is_initialized = node_stats_dict["is_initialized"]
    self.is_loaded = node_stats_dict["is_loaded"]
    self.roles = node_stats_dict["roles"]
    self.cpu = NodeStats.CPU(node_stats_dict["cpu"])
    self.memory = NodeStats.Memory(node_stats_dict["memory"])
    self.swap = NodeStats.Swap(node_stats_dict["swap"])
    partitions = [
      NodeStats.Partition(mountpoint, details)
      for partition_dict in node_stats_dict["disk"]
      for mountpoint, details in partition_dict.iteritems()
    ]
    self.disk = NodeStats.Disk(partitions)
    self.loadavg = NodeStats.LoadAvg(node_stats_dict["loadavg"])
