"""General Sink implementations that require no data storage system-specifics.
"""

from httpmr import base

class NoOpSink(base.Sink):
  
  def Put(self, key, value):
    """No-op.  Equivalent to ... > /dev/null."""
    pass