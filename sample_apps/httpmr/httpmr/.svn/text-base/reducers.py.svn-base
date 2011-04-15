from httpmr import base

class IdentityReducer(base.Reducer):
  
  def Reduce(self, key, values):
    for value in values:
      yield key, value


class SumReducer(base.Reducer):
  
  def Reduce(self, key, values):
    sum = 0
    for value in values:
      try:
        sum += int(value)
      except ValueError, e:
        # TODO: Log the error
        pass
    yield key, sum


class CountReducer(base.Reducer):
  
  def Reduce(self, key, values):
    yield key, str(len(values))