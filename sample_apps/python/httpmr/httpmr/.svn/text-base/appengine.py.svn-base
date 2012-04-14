import logging
import random
import sys
from google.appengine.ext import db
from httpmr import base
from httpmr import master


class IntermediateValueHolder(db.Model):
  job_name = db.StringProperty(required=False)
  nonsense = db.IntegerProperty(required=False)
  intermediate_key = db.StringProperty(required=True)
  intermediate_value = db.TextProperty(required=True)


class AppEngineSink(base.Sink):
  
  def Put(self, key, value):
    """Puts the provided value into the AppEngine datastore.  Key discarded.
    
    Args:
      key: Ignored
      value: An instance of a db.Model descendent
    
    Returns: None
    
    Raises: httpmr.base.SinkError on any datastore errors
    """
    assert isinstance(value, db.Model)
    try:
      value.put()
    except db.Error, e:
      raise base.SinkError(e)


class AppEngineIntermediateSink(AppEngineSink):
  
  def __init__(self, job_name):
    self.SetJobName(job_name)
    self.SetAddJobName(True)
    self.SetAddNonsenseValue(True)
  
  def SetJobName(self, job_name):
    self._job_name = job_name
  
  def SetAddJobName(self, add_job_name):
    self._add_job_name = add_job_name
    return self
    
  def SetAddNonsenseValue(self, add_nonsense_value):
    self._add_nonsense_value = add_nonsense_value
    return self
  
  def Put(self, key, value):
    intermediate_value = \
        IntermediateValueHolder(intermediate_key=key,
                                intermediate_value=value)
    if self._add_nonsense_value:
      max = sys.maxint
      # For the intermediate value sink to function properly, we have to guarantee
      # that no values are written with the _actual_ minimum integer value.
      min = 2 - max
      nonsense = random.randint(min, max)
      logging.debug("Setting intermediate value's nonsense value to %d" %
                    nonsense)
      intermediate_value.nonsense = nonsense
    
    if self._add_job_name:
      logging.debug("Setting intermediate value's job name to %s" %
                    self._job_name)
      intermediate_value.job_name = self._job_name
    
    logging.debug("Writing intermediate value: %s" % intermediate_value)
    intermediate_value.put()
                            

class AppEngineSource(base.Source):

  def __init__(self, base_query, key_parameter):
    """Initialize the AppEngineSource with a base GQL object and key parameter.
    
    The supplied base_query
    
    for example:
      class Story(db.Model):
        title = db.StringProperty()
        active = db.BooleanProperty()
      
      query = Story.all().filter('active = True')
      source = AppEngineSource(query, 'title')
    
    The source constructed in the example will be used as:
    
      query.filter("%s >= " % key_parameter, start_point)
      query.filter("%s <= " % key_parameter, end_point)
      for entry in query.fetch():
        mapper.Map(getattr(entry, key_parameter), entry)

    Args:
      base_query: A db.Query instance that defines the base filters for
        all mapper operations
      key_parameter: The parameter of the model that will be retrieved by the
        base_query that should be used as the mapper key, and which will be
        used to shard map operations.
    """
    assert isinstance(base_query, db.Query)
    self.base_query = base_query
    self.key_parameter = key_parameter

  def Get(self,
        start_point,
        end_point,
        max_entries):
    assert isinstance(max_entries, int)
    self.base_query.filter("%s > " % self.key_parameter, start_point)
    self.base_query.filter("%s <= " % self.key_parameter, end_point)
    self.base_query.order(self.key_parameter)
    for model in self.base_query.fetch(limit=max_entries):
      key = getattr(model, self.key_parameter)
      yield key, model


class IntermediateAppEngineSource(base.Source):
  """A Source for the intermediate values output by the MapReduce Mappers
  
  """

  def __init__(self, job_name):
    self.job_name = job_name
  
  def SetUseJobName(self, use_job_name):
    self._use_job_name = use_job_name
    return self

  def SetUseNonsenseValues(self, use_nonsense_values):
    self._use_nonsense_values = use_nonsense_values
    return self

  def Get(self,
          start_point,
          end_point,
          max_entries):
    assert isinstance(max_entries, int)
    num_values_returned = 0
    num_keys_returned = 0
    while True:
      if num_values_returned > max_entries:
        return
      
      # TODO: This is a pretty inefficient way to loop through the keys, but
      # is done to simplify fetching full sets of intermediate values for
      # intermediate value keys.  A more effective method would loop through
      # a full set of 1000 results, and depending on the keys that were seen in
      # that set either issue queries for the subsequent set of results or
      # stop iteration.
      current_key = self._GetNextKey(start_point, end_point)
      if current_key is None:
        return
      else:
        # The next time we loop, the next key we fetch should be > the key we're
        # currently serving
        start_point = current_key
      
      for intermediate_value in \
          self._GetIntermediateValuesForKey(current_key,
                                            max_entries - num_values_returned):
        yield current_key, intermediate_value
        num_values_returned += 1
      
  def _GetIntermediateValuesForKey(self, intermediate_key, limit):
    """For the given intermediate value key, get all intermediate values.
    
    Get all intermediate values from the Datastore.
    
    If we're using nonsense values on the intermediate values, then we can
    issue multiple queries to retrieve every intermediate value for a given key,
    allowing us to get past the 1000-result limit built into the AppEngine
    datastore.  If not, then we can only retrieve the first 1000 entries, and
    log a warning if we retrieve exactly 1000 entries for a given key.
    """
    # We're guaranteed by the intermediate value sink that no intermediate
    # values are written with the _actual_ minimum value.  Always 1 greater.
    current_nonsense = 1 - sys.maxint
    while True:
      # Loop through all possible intermediate values
      query = IntermediateValueHolder.all()
      query.filter("intermediate_key = ", intermediate_key)
      
      if self._use_job_name:
        logging.debug("Using job name '%s' in intermediate value query." %
                      self.job_name)
        query.filter("job_name = ", self.job_name)

      if self._use_nonsense_values:
        logging.debug("Using nonsense value '%d' in intermediate value query." %
                      current_nonsense)
        query.filter("nonsense > ", current_nonsense)
        query.order("nonsense")
      
      intermediate_values_fetched = 0
      for intermediate_value in query.fetch(limit=limit):
        intermediate_values_fetched += 1

        if self._use_nonsense_values:
          current_nonsense = intermediate_value.nonsense
        elif intermediate_values_fetched == min(limit, 1000):
          logging.warning("Retrieved %d intermediate values for intermediate "
                          "value key '%s', which is the maximum number of "
                          "query results we could have returned.  There may be "
                          "more values available, but because nonsense values "
                          "are not in use, it is impossible to access them.  "
                          "You can resolve this by setting "
                          "intermediate_values_set_nonsense_value = True in "
                          "the AppEngineMaster initializer." %
                          (min(limit, 1000),
                           intermediate_value.intermediate_key))
        
        yield intermediate_value
      
      # Test for whether or not we've returned > the maximum number of results
      # desired outside of the yielding loop so that we can guarantee to return
      # all intermediate values for each given key (don't return the first half
      # of the intermediate values for intermediate key X just because the
      # result limit cutoff happened to fall there).
      if intermediate_values_fetched < limit:
        return
  
  def _GetNextKey(self, greater_than_key, less_than_eq_key):
    """Determine the value of the next key that should be reduced.
    
    Args:
      greater_than_key: The value that the next key should be greater than.
      less_than_eq_key: The value that the next key should be less than or
        equal to.
    """
    get_next_key_query = IntermediateValueHolder.all()
    if self._use_job_name:
      get_next_key_query.filter("job_name = ", self.job_name)
    
    get_next_key_query.filter("intermediate_key > ", greater_than_key)
    get_next_key_query.filter("intermediate_key <= ", less_than_eq_key)
    value = get_next_key_query.get()
    if value is None:
      return None
    else:
      return value.intermediate_key


class AppEngineValueDeletingMapper(base.Mapper):
  """A Mapper that deletes every value given to it.
  
  Useful for cleaning up intermediate data.
  """ 
  
  def Map(self, key, value):
    """Delete the supplied value."""
    value.delete()
    yield key, value


class AppEngineMaster(master.Master):
  
  def QuickInit(self,
                jobname,
                mapper=None,
                reducer=None,
                source=None,
                sink=None,
                intermediate_values_set_job_name=True,
                intermediate_values_set_nonsense_value=True):
    logging.debug("Beginning QuickInit.")
    assert jobname is not None
    self._jobname = jobname
    self.SetMapper(mapper)
    self.SetReducer(reducer)
    self.SetCleanupMapper(AppEngineValueDeletingMapper())
    self.SetSource(source)

    self.SetMapperSink(
        AppEngineIntermediateSink(jobname)
            .SetAddJobName(intermediate_values_set_job_name)
            .SetAddNonsenseValue(intermediate_values_set_nonsense_value))
    self.SetReducerSource(
        IntermediateAppEngineSource(jobname)
            .SetUseJobName(intermediate_values_set_job_name)
            .SetUseNonsenseValues(intermediate_values_set_nonsense_value))
    
    self.SetSink(sink)
    logging.debug("Done QuickInit.")
    return self