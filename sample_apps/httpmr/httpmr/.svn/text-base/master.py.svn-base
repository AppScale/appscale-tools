import logging
import os
import string
import time
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from httpmr import base
from httpmr import driver
from httpmr import sinks
from wsgiref import handlers


class Error(Exception): pass
class UnknownTaskError(Error): pass
class MissingRequiredParameterError(Error): pass


# Some constants for URL handling.  These values must correspond to the base
# name of the template that should be rendered at task completion.  For
# instance, when a mapper task is completed, the name of the template that will
# be rendered is MAPPER_TASK_NAME + ".html"
#
# The *_MASTER_TASK_NAME constants are defined in the driver module because the
# driver should be a standalone file (to facilitate ease of use, one can simply
# copy that file around by itself).
MAP_MASTER_TASK_NAME = driver.MAP_MASTER_TASK_NAME
MAPPER_TASK_NAME = "mapper"
REDUCE_MASTER_TASK_NAME = driver.REDUCE_MASTER_TASK_NAME
REDUCER_TASK_NAME = "reducer"
INTERMEDIATE_DATA_CLEANUP_MASTER_TASK_NAME = \
    driver.INTERMEDIATE_DATA_CLEANUP_MASTER_TASK_NAME
INTERMEDIATE_DATA_CLEANUP_TASK_NAME = "cleanup"
VALID_TASK_NAMES = [MAP_MASTER_TASK_NAME,
                    MAPPER_TASK_NAME,
                    REDUCE_MASTER_TASK_NAME,
                    REDUCER_TASK_NAME,
                    INTERMEDIATE_DATA_CLEANUP_MASTER_TASK_NAME,
                    INTERMEDIATE_DATA_CLEANUP_TASK_NAME]

SOURCE_START_POINT = "source_start_point"
SOURCE_END_POINT = "source_end_point"
SOURCE_MAX_ENTRIES = "source_max_entries"
OPERATION_TIMEOUT_SEC = driver.OPERATION_TIMEOUT_SEC
DEFAULT_OPERATION_TIMEOUT_SEC = 10
GREATEST_UNICODE_CHARACTER = "\xEF\xBF\xBD"


def tobase(base, number):
  """Ugly.
  
  I really wish I didn't have to copy this over, why doesn't Python have a
  built-in function for representing an int as a string in an arbitrary base?
  
  Copied from:
    http://www.megasolutions.net/python/How-to-convert-a-number-to-binary_-78436.aspx
  """
  number = int(number) 
  base = int(base)         
  if base < 2 or base > 36: 
    raise ValueError, "Base must be between 2 and 36"     
  if not number: 
    return 0
  symbols = string.digits + string.lowercase[:26] 
  answer = [] 
  while number: 
    number, remainder = divmod(number, base) 
    answer.append(symbols[remainder])       
  return ''.join(reversed(answer)) 

def tob36(number):
  return tobase(36, number)


class TaskSetTimer(object):
  
  def __init__(self, timeout_sec=10.0):
    self.timeout_sec = timeout_sec
    self.task_completion_times = []
  
  def Start(self):
    self.start_time = time.time()
  
  def TaskCompleted(self):
    self.task_completion_times.append(time.time())
  
  def ShouldStop(self):
    if len(self.task_completion_times) == 0:
      return False
    max_execution_time = 0
    for i in xrange(len(self.task_completion_times)):
      if i == 0: continue
      start_time = self.task_completion_times[i-1]
      end_time = self.task_completion_times[i]
      max_execution_time = max(max_execution_time,
                               end_time - start_time)
    worst_case_completion_time = time.time() + max_execution_time
    worst_case_completion_time_since_start_time = \
        worst_case_completion_time - self.start_time
    return (worst_case_completion_time_since_start_time >
            self.timeout_sec * 0.8)


class OperationStatistics(object):
  
  READ = "read"
  WRITE = "write"
  MAP = "map"
  REDUCE = "reduce"
  CLEAN = "clean"
  _valid_operation_names = [READ,
                            WRITE,
                            MAP,
                            REDUCE,
                            CLEAN]
  
  def __init__(self):
    self._operation_statistics = {}
    for name in self._valid_operation_names:
      self._operation_statistics[name] = 0
      self._operation_statistics[self._GetCounterName(name)] = 0
    self._started = False
  
  def _GetCounterName(self, operation_name):
    return operation_name + "-count"
  
  def Start(self, operation):
    assert not self._started
    assert operation in self._valid_operation_names
    self._started = True
    self._operation = operation
    self._last_operation_time = time.time()
  
  def _Increment(self, name):
    self._operation_statistics[name] += time.time() - self._last_operation_time
  
  def Count(self, name):
    self._operation_statistics[self._GetCounterName(name)] += 1
  
  def Stop(self):
    assert self._started
    self._started = False
    self._Increment(self._operation)
  
  def GetStatistics(self):
    lines = []
    for key in self._operation_statistics:
      lines.append("%s %s" % (key, self._operation_statistics[key]))
    return "\n".join(lines)


class Master(webapp.RequestHandler):
  """The MapReduce master coordinates mappers, reducers, and data."""
  
  def QuickInit(self,
                jobname,
                mapper=None,
                reducer=None,
                source=None,
                mapper_sink=None,
                reducer_source=None,
                sink=None):
    logging.debug("Beginning QuickInit.")
    assert jobname is not None
    self._jobname = jobname
    self.SetMapper(mapper)
    self.SetReducer(reducer)
    self.SetSource(source)
    self.SetMapperSink(mapper_sink)
    self.SetReducerSource(reducer_source)
    self.SetSink(sink)
    logging.debug("Done QuickInit.")
    return self
  
  def SetMapper(self, mapper):
    """Set the Mapper that should be used for mapping operations."""
    assert isinstance(mapper, base.Mapper)
    self._mapper = mapper
    return self
  
  def SetReducer(self, reducer):
    """Set the Reducer that should be used for reduce operations."""
    assert isinstance(reducer, base.Reducer)
    self._reducer = reducer
    return self
  
  def SetCleanupMapper(self, cleanup_mapper):
    """Set the Mapper that should be used to clean up the intermediate data.
    
    Sets a Mapper that will clean up the intermediate data created by the
    primary Mapper class.  This Mapper's source will be the same as the
    Reducer's source.
    """
    assert isinstance(cleanup_mapper, base.Mapper)
    self._cleanup_mapper = cleanup_mapper
    return self
    
  def SetSource(self, source):
    """Set the data source from which mapper input should be read."""
    self._source = source
    return self
  
  def SetMapperSink(self, sink):
    """Set the data sink to which mapper output should be written."""
    self._mapper_sink = sink
    return self
  
  def SetReducerSource(self, source):
    """Set the data source from which reducer input should be read."""
    self._reducer_source = source
    return self
  
  def SetSink(self, sink):
    """Set the data sink to which reducer output should be written."""
    self._sink = sink
    return self
  
  def get(self):
    """Handle task dispatch."""
    logging.debug("MapReduce Master Dispatching Request.")

    task = None
    try:
      task = self.request.params["task"]
    except KeyError, e:
      pass
    if task is None:
      task = MAP_MASTER_TASK_NAME
    
    template_data = {}
    if task == MAP_MASTER_TASK_NAME:
      template_data = self.GetMapMaster()
    elif task == MAPPER_TASK_NAME:
      template_data = self.GetMapper()
    elif task == REDUCE_MASTER_TASK_NAME:
      template_data = self.GetReduceMaster()
    elif task == REDUCER_TASK_NAME:
      template_data = self.GetReducer()
    elif task == INTERMEDIATE_DATA_CLEANUP_MASTER_TASK_NAME:
      template_data = self.GetCleanupMaster()
    elif task == INTERMEDIATE_DATA_CLEANUP_TASK_NAME:
      template_data = self.GetCleanupMapper()
    else:
      raise UnknownTaskError("Task name '%s' is not recognized.  Valid task "
                             "values are %s" % (task, VALID_TASK_NAMES))
    self.RenderResponse("%s.html" % task, template_data)
  
  def _TaskUrl(self, path_data):
    logging.debug("Rendering next url with path data %s" % path_data)
    params = []
    for key in path_data:
      params.append("%s=%s" % (key, path_data[key]))
    return ("%s?%s" % (self.request.path_url, "&".join(params)))
  
  def _GetShardBoundaries(self):
    # TODO(peterdolan): Expand this to allow an arbitrary number of shards
    # instead of a fixed set of 36 shards.
    boundaries = [""]
    for i in xrange(35):
      j = (i + 1)
      boundaries.append(tob36(j))
    boundaries.append(GREATEST_UNICODE_CHARACTER)
    return boundaries
  
  def _GetShardBoundaryTuples(self):
    boundaries = self._GetShardBoundaries()
    boundary_tuples = []
    for i in xrange(len(boundaries)):
      if i == 0:
        continue
      boundary_tuples.append((boundaries[i-1], boundaries[i]))
    return boundary_tuples
  
  def _GetUrlsForShards(self, task):
    urls = []
    for boundary_tuple in self._GetShardBoundaryTuples():
      start_point = boundary_tuple[0]
      end_point = boundary_tuple[1]
      
      timeout = DEFAULT_OPERATION_TIMEOUT_SEC
      if OPERATION_TIMEOUT_SEC in self.request.params:
        timeout = float(self.request.params[OPERATION_TIMEOUT_SEC])
      
      urls.append(self._TaskUrl({"task": task,
                                 SOURCE_START_POINT: start_point,
                                 SOURCE_END_POINT: end_point,
                                 SOURCE_MAX_ENTRIES: 1000,
                                 OPERATION_TIMEOUT_SEC: timeout}))
    return urls
  
  def GetMapMaster(self):
    """Handle Map controlling page."""
    return {'urls': self._GetUrlsForShards(MAPPER_TASK_NAME)}

  def GetMapper(self):
    """Handle mapper tasks."""
    return self._GetGeneralMapper(self._mapper,
                                  self._source,
                                  self._mapper_sink,
                                  OperationStatistics.MAP)
  
  def _GetGeneralMapper(self, mapper, source, sink, operation_statistics_name):
    """Handle general Mapper tasks.
    
    specifically base mapping and intermediate data cleanup.
    """
    assert isinstance(mapper, base.Mapper)
    assert isinstance(source, base.Source)
    assert isinstance(sink, base.Sink)
    
    # Initialize the statistics object, to time the operations for reporting
    statistics = OperationStatistics()

    # Grab the parameters for this map task from the URL
    task = self.request.params["task"]
    start_point = self.request.params[SOURCE_START_POINT]
    end_point = self.request.params[SOURCE_END_POINT]
    max_entries = int(self.request.params[SOURCE_MAX_ENTRIES])
    timeout = float(self.request.params[OPERATION_TIMEOUT_SEC])
    
    statistics.Start(OperationStatistics.READ)
    mapper_data = source.Get(start_point, end_point, max_entries)
    statistics.Stop()
    
    # Initialize the timer, and begin timing our operations
    timer = TaskSetTimer(timeout)
    timer.Start()
    
    last_key_mapped = None
    values_mapped = 0

    # TODO: Much of this mess with statistics recording can be cleaned up by
    # setting the statistics object in the class that's performing the relevant
    # operation.  i.e. source.SetStatisticsObject(statistics), mapper.SetStat...
    # The relevant time-consuming operation would then record the time it
    # spends.  This can all be handled in base classes.
    statistics.Start(OperationStatistics.READ)
    for key_value_pair in mapper_data:
      statistics.Stop()
      statistics.Count(OperationStatistics.READ)
      if timer.ShouldStop():
        break
      key = key_value_pair[0]
      value = key_value_pair[1]
      statistics.Start(operation_statistics_name)
      for (output_key, output_value) in mapper.Map(key, value):
        statistics.Stop()
        
        statistics.Start(OperationStatistics.WRITE)
        sink.Put(output_key, output_value)
        statistics.Stop()
        statistics.Count(OperationStatistics.WRITE)
        
        statistics.Start(operation_statistics_name)
      statistics.Stop()
      statistics.Count(operation_statistics_name)
      last_key_mapped = key
      values_mapped += 1
      timer.TaskCompleted()
      statistics.Start(OperationStatistics.READ)
    
    next_url = None
    if values_mapped > 0:
      logging.debug("Completed %d map operations" % values_mapped)
      next_url = self._TaskUrl({"task": task,
                                SOURCE_START_POINT: last_key_mapped,
                                SOURCE_END_POINT: end_point,
                                SOURCE_MAX_ENTRIES: max_entries,
                                OPERATION_TIMEOUT_SEC: timeout})
    else:
      next_url = None
    return { "next_url": next_url,
             "statistics": statistics.GetStatistics() }
      
  def GetReduceMaster(self):
    """Handle Reduce controlling page."""
    return {'urls': self._GetUrlsForShards(REDUCER_TASK_NAME)}

  def GetReducer(self):
    """Handle reducer tasks."""
    statistics = OperationStatistics()
    
    # Grab the parameters for this map task from the URL
    #
    # TODO: This logic is replicated exactly in _GetGeneralMapper, refactor.
    start_point = self.request.params[SOURCE_START_POINT]
    end_point = self.request.params[SOURCE_END_POINT]
    max_entries = int(self.request.params[SOURCE_MAX_ENTRIES])
    timeout = float(self.request.params[OPERATION_TIMEOUT_SEC])
    
    reducer_keys_values = self._GetReducerKeyValues(start_point,
                                                    end_point,
                                                    max_entries,
                                                    statistics)
    
    last_key_reduced = None
    keys_reduced = 0
    # Initialize the timer, and begin timing our operations
    timer = TaskSetTimer(timeout)
    timer.Start()
    for key in reducer_keys_values:
      if timer.ShouldStop():
        break
      values = reducer_keys_values[key]
      statistics.Start(OperationStatistics.REDUCE)
      for (output_key, output_value) in self._reducer.Reduce(key, values):
        statistics.Stop()
        
        statistics.Start(OperationStatistics.WRITE)
        self._sink.Put(output_key, output_value)
        statistics.Stop()
        statistics.Count(OperationStatistics.WRITE)
        
        statistics.Start(OperationStatistics.REDUCE)
      statistics.Stop()
      statistics.Count(OperationStatistics.REDUCE)
      last_key_reduced = key
      keys_reduced += 1
      timer.TaskCompleted()
    
    next_url = None
    if keys_reduced > 0:
      logging.debug("Completed %d reduce operations" % keys_reduced)
      next_url = self._TaskUrl({"task": REDUCER_TASK_NAME,
                                SOURCE_START_POINT: last_key_reduced,
                                SOURCE_END_POINT: end_point,
                                SOURCE_MAX_ENTRIES: max_entries,
                                OPERATION_TIMEOUT_SEC: timeout})
    else:
      next_url = None
    return { "next_url": next_url,
             "statistics": statistics.GetStatistics() }
  
  def _GetReducerKeyValues(self,
                           start_point,
                           end_point,
                           max_entries,
                           statistics):
    statistics.Start(OperationStatistics.READ)
    reducer_data = self._reducer_source.Get(start_point, end_point, max_entries)
    statistics.Stop()
    
    # Retrieve the mapped data from the datastore and sort it by key.
    #
    # The Source interface specification guarantees that we will retrieve every
    # intermediate value for a given key.
    reducer_keys_values = {}
    statistics.Start(OperationStatistics.READ)
    for key_value_pair in reducer_data:
      statistics.Count(OperationStatistics.READ)
      key = key_value_pair[0]
      value = key_value_pair[1].intermediate_value
      if key in reducer_keys_values:
        reducer_keys_values[key].append(value)
      else:
        reducer_keys_values[key] = [value]
    statistics.Stop()
    return reducer_keys_values
  
    
  def GetCleanupMaster(self):
    """Handle Cleanup controlling page."""
    return {'urls': self._GetUrlsForShards(INTERMEDIATE_DATA_CLEANUP_TASK_NAME)}
  
  def GetCleanupMapper(self):
    """Handle Cleanup Mapper tasks."""
    return self._GetGeneralMapper(self._cleanup_mapper,
                                  self._reducer_source,
                                  sinks.NoOpSink(),
                                  OperationStatistics.CLEAN)
  
  def RenderResponse(self, template_name, template_data):
    path = os.path.join(os.path.dirname(__file__),
                        'templates',
                        template_name)
    logging.debug("Rendering template at path %s" % path)
    self.response.out.write(template.render(path, template_data))