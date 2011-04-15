class Error(Exception): pass

class NotImplementedError(Error):
  """This method has not been implemented, override it in a subclass."""

class SinkError(Error): pass


class Mapper(object):

  def Map(self, key, value):
    """Map the provided key and value to a set of intermediate keys and values.
    
    Mapper#Map must be implemented as a generator, outputting its key-value
    pairs via the 'yield' keyword.

    For example, a simple Map method that would be used to count the number of
    times a given value is seen by outputting 1 for every value:
      def Map(self, key, value):
        yield value, 1
    
    All yielded output must be a (object, object) tuple.
    
    For more information on generators, see
    the official Python documentation at
    http://www.python.org/doc/2.5/tut/node11.html#SECTION00111000000000000000000
    or consider the stock Mappers for more examples.
    """
    raise NotImplementedError()


class Reducer(object):
  
  def Reduce(self, key, values):
    """Operate on all values output for the given key simultaneously.
    
    Reduce must be implemented as a generator, outputting its reduced key-value
    pairs via the 'yield' operator.
    
    For example, a simple Reduce method that counts the number of times a given
    key was seen:
      def Reduce(self, key, values):
        yield key, len(values)
    
    All yielded output must be a (str, str) tuple.
    
    For more information on generators, see
    the official Python documentation at
    http://www.python.org/doc/2.5/tut/node11.html#SECTION00111000000000000000000
    or consider the stock Reducers for more examples.
    
    Args:
      key: The key (arbitrary object) to which all of the values correspond
      values: A list of values (arbitrary objects) corresponding to the key.
    
    Returns:
      A generator
    """
    raise NotImplementedError()


class Source(object):
  
  def Get(self,
          start_point,
          end_point,
          max_entries):
    """Get a set of data for Mapping
    
    The data returned by this method must be in ascending order by key.
    
    Args:
      start_point: The starting point for data segmentation.  Values for this
        key are excluded (restrictions are 'key > start_point')
      end_point: The ending point for data segmentation.  Values for this key
        must be included (restrictions are 'key <= end_point')
      max_entries: The maximum number of data points that should be retrieved
    """
    raise NotImplementedError()
  

class Sink(object):
  
  def Put(self, key, value):
    """Output the provided key and value to persistent storage.
    
    """
    raise NotImplementedError()