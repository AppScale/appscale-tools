from httmr import base

class IdentityMapper(base.Mapper):
  
  def Map(self, key, value):
    yield key, value


class CountMapper(base.Mapper):
  
  def Map(self, key, value):
    yield key, "1"