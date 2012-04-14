from time import sleep
import random
import string
import logging
import cgi
import datetime
import wsgiref.handlers

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp

V = "VALID"
I = "INVALID"

def RandomInt():
  return int(1000000 * random.random())

def RandomString():     
  alphabet = 'abcdefghijklmnopqrstuvwxyz'
  min = 5
  max = 15
  total = 2 
  string=''
  for count in xrange(1,total):
    for x in random.sample(alphabet,random.randint(min,max)):
        string+=x
  return string


class Accumulator(db.Model):
  counter = db.IntegerProperty()

class GP(db.Model):
  name = db.StringProperty(required = True)
  val = db.StringProperty(required = True)
  birthdate = db.DateProperty()

class P(db.Model):
  name = db.StringProperty(required = True)
  val = db.StringProperty(required = True)
  birthdate = db.DateProperty()

class C(db.Model):
  name = db.StringProperty(required = True)
  val = db.StringProperty(required = True)
  birthdate = db.DateProperty()

def increment_counter(key, amount, raiseException):
  obj = db.get(key)
  if not obj:
    raise db.Rollback()
  obj.counter += amount
  obj.put()
  if raiseException:
    raise db.Rollback()

def del_object(key, raiseException):
  if type(key) != type([]):
    key = [key]

  for ii in key:
    obj = db.get(ii)
    if not obj:
      raise db.Rollback()
    obj.delete()
  if raiseException:
    raise db.Rollback()

def put_object(key, value, raiseException):
  if type(key) != type([]):
    key = [key]
  
  for ii in key:
    obj = db.get(ii)
    if not obj:
      raise db.Rollback()
    obj.val = value
    obj.put()
  if raiseException:
      raise db.Rollback()
  
def get_value(key, raiseException):
  logging.info(str(key))
  obj = db.get(key)
  if not obj: 
    raise db.Rollback()
  logging.info(str(obj))
  return obj.val

def get_object(key, raiseException):
  if type(key) != type([]):
    key = [key]
  ret = []
  for ii in key:
    obj = db.get(ii)
    if not obj: 
      raise db.Rollback()
    ret.append(obj)
  return ret

def query_type(type, raiseException):
  q = db.GqlQuery("SELECT * FROM " + type)
  if raiseException:
    raise db.Rollback()
  values = []
  for ii in q:
    values.append(ii.val)
  return values

def query_type_verify(type, value, raiseException):
  q = db.GqlQuery("SELECT * FROM " + type)
  if raiseException:
    raise db.Rollback()
  for ii in q:
    if ii.val != value:
      raise db.Rollback()
  return True

def query_type_with_value(type, value, raiseException):
  q = db.GqlQuery("SELECT * FROM " + type + " WHERE val = '" + value + "'")
  if raiseException:
    raise db.Rollback()
  count = 0
  for ii in q:
    count += 1
  return count

def get_put_verify_delete(key, value, raiseException):
  obj = get_object(key, raiseException)
  if not obj:
    raise db.Rollback()
  put_object(key, value, raiseException)
  if type(key) != type([]):
    key = [key]
  for ii in key:
    v = get_value(ii, raiseException)
    if v != value:
      raise db.Rollback()
  del_object(key, raiseException)

def delete_database(types, raiseException):
  for ii in types:
    q = db.GqlQuery("SELECT * FROM " + ii)
    for kk in q:
      db.delete(kk.key())

class Greeting(db.Model):
  author = db.UserProperty()
  content = db.StringProperty(multiline=True)
  date = db.DateTimeProperty(auto_now_add=True)

class DoNothing(webapp.RequestHandler):
  def get(self):
    self.response.out.write("hey guy")

class DoStuff(webapp.RequestHandler):
  def get(self):
    #################
    # COUNTER TESTING
    #################
    print "Content-Type: text/plain"

    types = ["Accumulator","GP","P","C"]
    delete_database(types, False)

    count = Accumulator()
    count.counter = 0
    count.put()
    acc = db.get(count.key())
    if not acc:
      raise Exception("Test 0 failed")

    test_counter = RandomInt()

    if acc.counter != 0:
      raise Exception("Test 1 failed")
    try:
      db.run_in_transaction(increment_counter, acc.key(), test_counter, False)
    except:
      raise Exception("Test 2 failed") 
    acc = db.get(acc.key())
    if acc.counter != test_counter:
      raise Exception("Test 2 failed")

    try:
      db.run_in_transaction(increment_counter, acc.key(), 1, True)
    except:
      pass

    if acc.counter != test_counter:
      raise Exception("Test 3 failed %d vs %d"%(acc.counter, test_counter))

    db.delete(acc.key())
    acc = db.get(acc.key())
    if acc:
      raise Exception("Test 4 failed")

    updated = []

    gp1key = RandomString()
    gp1 = GP(key_name = gp1key, name = gp1key, val = V)
    updated.append(gp1)

    gp2key = RandomString()
    gp2 = GP(key_name = gp2key, name = gp2key, val = V)
    updated.append(gp2)

    p1key = RandomString()
    p1 = P(key_name = p1key, parent = gp1, name = p1key, val = V)
    updated.append(p1)

    p2key = RandomString()
    p2 = P(key_name = p2key, parent = gp2, name = p2key, val = V)
    updated.append(p2)

    c1key = RandomString()
    c1 = C(key_name = c1key, parent = p1, name = c1key, val = V)
    updated.append(c1)

    c2key = RandomString()
    c2 = C(key_name = c2key, parent = p2, name = c2key, val = V)
    updated.append(c2)

    db.put(updated)

    if not query_type_verify("GP", V, False) or not query_type_verify("P", V, False) or not query_type_verify("C", V, False):
       raise Exception("Test 5 failed")

    # These are all apart of the same entity group
    updated1 = [gp1.key(),p1.key(),c1.key()]
    updated2 = [gp2.key(),p2.key(),c2.key()]

    # Get a batch of keys in a transaction
    try:
      db.run_in_transaction(get_object, updated1, False)
    except:
      raise Exception("Test 6 Failed")
    try:
      db.run_in_transaction(get_object, updated2, False)
    except:
      raise Exception("Test 6 Failed")
    logging.info(str(query_type_with_value("GP", V, False)))
    if query_type_with_value("GP", V, False) < 2:
      raise Exception("Test 6 failed")
    if query_type_with_value("P", V, False) < 2:
      raise Exception("Test 7 failed")
    if query_type_with_value("C", V, False) < 2:
      raise Exception("Test 8 failed")

    try:
      db.run_in_transaction(put_object, updated1, V, False)
    except:
      raise Exception("Test 9 Failed")
    try:
      db.run_in_transaction(put_object, updated2, V, False)
    except:
      raise Exception("Test 9 Failed")

    # Try to put some invalid keys
    try:
      db.run_in_transaction(put_object, updated1, I, True)
    except:
      pass
    try:
      db.run_in_transaction(put_object, updated2, I, True)
    except:
      pass

    if query_type_with_value("GP", V, False) < 2:
      raise Exception("Test 9 failed")
    if query_type_with_value("P", V, False) < 2:
      raise Exception("Test 10 failed")
    if query_type_with_value("C", V, False) < 2:
      raise Exception("Test 11 failed")

    db.run_in_transaction(put_object, updated1, V, False)
    db.run_in_transaction(put_object, updated2, V, False)

    if query_type_with_value("GP", V, False) < 2:
      raise Exception("Test 12 failed")
    if query_type_with_value("P", V, False) < 2:
      raise Exception("Test 13 failed")
    if query_type_with_value("C", V, False) < 2:
      raise Exception("Test 14 failed")

    db.run_in_transaction(del_object, updated1, True)
    db.run_in_transaction(del_object, updated2, True)
    # Verify that none of the values have changed
    if query_type_with_value("GP", V, False) < 2:
      raise Exception("Test 15 failed")
    if query_type_with_value("P", V, False) < 2:
      raise Exception("Test 16 failed")
    if query_type_with_value("C", V, False) < 2:
      raise Exception("Test 17 failed")

    db.run_in_transaction(get_put_verify_delete, updated1, V, False)
    db.run_in_transaction(get_put_verify_delete, updated2, V, False)

    if query_type_with_value("GP", V, False) > 0:
      raise Exception("Test 18 failed")
    if query_type_with_value("P", V, False) > 0:
      raise Exception("Test 19 failed")
    if query_type_with_value("C", V, False) > 0:
      raise Exception("Test 20 failed")

    should_not_exist1 = db.get(updated1)
    should_not_exist2 = db.get(updated2)
    for ii in should_not_exist1:
      if ii:
        raise Exception("Test 21 failed")
    for ii in should_not_exist2:
      if ii:
        raise Exception("Test 22 failed")
    print "SUCCESS"

application = webapp.WSGIApplication([
  ('/', DoNothing),
  ('/transtest', DoStuff)
], debug=True)


def main():
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()


