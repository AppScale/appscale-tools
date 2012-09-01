
from google.appengine.ext import db
from google.appengine.api import users

import sys
import random
import string
import logging 
import traceback 
import time

class Timer:    
  def __init__(self):
    self.init = time.time()
    self.start = time.time()

  def done(self, description):
    self.end = time.time()
    self.interval = self.end - self.start
    print "<p>" + description + ": " + str(self.interval) + "</p>"
    self.start = time.time()

  def total(self):
    self.end = time.time()
    self.interval = self.end - self.init
    print "<p> Total: " + str(self.interval) + "</p>"
    
def GenString():
  newstr = "_"
  for i in range(1):
    newstr = newstr + str(random.random())
  return newstr

class GP(db.Model):
  name = db.StringProperty(required = True)
  rank = db.StringProperty(required = True)
  birthdate = db.DateProperty()
class P(db.Model):
  name = db.StringProperty(required = True)
  birthdate = db.DateProperty()
  rank = db.StringProperty(required = False)
class C(db.Model):
  name = db.StringProperty(required = True)
  birthdate = db.DateProperty()
  rank = db.StringProperty(required = False)

class KindTestCase():
  def __init__(self):
    self.entities = []
    self.names = []
    self.ent_group1 = []
    self.ent_group2 = []

    key = GenString()
    self.gp1 = GP(key_name = key, name = key, rank = "A")
    self.entities.append(self.gp1)
    self.names.append(key)
    self.ent_group1.append(key)

    key = GenString()
    self.gp2 = GP(key_name = key, name = key, rank = "B")
    self.entities.append(self.gp2)
    self.ent_group2.append(key)
    self.names.append(key)

    key = GenString()
    self.p1 = P(key_name = key, parent = self.gp1, name = key, rank = "C")
    self.entities.append(self.p1)
    self.ent_group1.append(key)
    self.names.append(key)

    key = GenString()
    p2 = P(key_name = key, parent = self.gp2, name = key, rank = "D")
    self.ent_group2.append(key)
    self.entities.append(p2)
    self.names.append(key)

    key = GenString()
    self.c1 = C(key_name = key, parent = self.p1, name = key, rank = "E")
    self.entities.append(self.c1)
    self.ent_group1.append(key)
    self.names.append(key)

    key = GenString()
    c2 = C(key_name = key, parent = p2, name = key, rank = "F")
    self.ent_group2.append(key)
    self.entities.append(c2)
    self.names.append(key)

    db.put(self.entities)


  def kindTest(self): 
    # Check if kind queries work
    q = db.GqlQuery("SELECT * FROM GP")
    count = 0
 
    for ent in q:
      count += 1
      assert ent.name in self.names
    assert count == 2

    q = db.GqlQuery("SELECT * FROM C")
    count = 0
    for ent in q:
      count += 1
      assert ent.name in self.names
    assert count == 2

    q = db.GqlQuery("SELECT * FROM P")
    count = 0
    for ent in q:
      count += 1
      assert ent.name in self.names
    assert count == 2

  def ancestorTest(self): 
    # check if ancestor queries work
    q = db.Query()
    q.ancestor(self.gp1.key())
    count = 0
    for ent in q:
      count += 1
      assert ent.name in self.ent_group1
    assert count == len(self.ent_group1)
 
    q = db.Query()
    q.ancestor(self.gp2.key())
    count = 0
    for ent in q:
      count += 1
      assert ent.name in self.ent_group2
    assert count == len(self.ent_group2)

  def kindlessTest(self): 
    # kindless query
    q = db.Query()
    q.filter('__key__ >', self.gp1) 
    # we may get 3 or 6 entities depending on order of gp1.name 
    # compared to gp2.name
    count = 0
    for ent in q:
      count += 1
    assert count == 3 or count == 6

  def getTest(self):
    gp = GP.get_by_key_name(self.gp1.name, parent=None)
    assert gp.name == self.gp1.name
    p = P.get_by_key_name(self.p1.name, parent=self.gp1)
    assert p.name == self.p1.name
    c = C.get_by_key_name(self.c1.name, parent=self.p1)
    assert c.name == self.c1.name

  def kindlessAncestorTest(self):
    # kindless query
    q = db.Query()
    q.ancestor(self.gp1)
    q.filter('__key__ >', self.p1) 
    # we may get 3 or 6 entities depending on order of gp1.name 
    # compared to gp2.name
    count = 0
    for ent in q:
      count += 1
    assert count == 1 

  def singlePropertyTest(self):
    q = GP.all()
    q.filter("rank =", "A")
    results = q.fetch(5)
    for p in results:
      assert p.rank == "A"     
      assert p.name == self.gp1.name

    q = GP.all()
    q.filter("rank =", "B")
    results = q.fetch(5)
    for p in results:
      assert p.rank == "B"     
      assert p.name == self.gp2.name

    q = P.all()
    q.filter("rank =", "C")
    results = q.fetch(5)
    for p in results:
      assert p.rank == "C"     
      assert p.name == self.p1.name

    q = GP.all()
    q.filter("rank >", "A")
    results = q.fetch(5)
    for p in results:
      assert p.rank == "B"     
      assert p.name == self.gp2.name

    q = GP.all()
    q.filter("rank >=", "A")
    results = q.fetch(5)
    count = 0
    for p in results:
      assert p.rank == "A" or p.rank == "B"
      assert p.name == self.gp2.name or p.name == self.gp1.name
      count += 1
    assert count == 2

    q = GP.all()
    q.filter("rank >=", "B")
    results = q.fetch(5)
    count = 0
    for p in results:
      count += 1
    assert count == 1

    q = GP.all()
    q.filter("rank >", "B")
    results = q.fetch(5)
    count = 0
    for p in results:
      count += 1
    assert count == 0

    q = GP.all()
    q.filter("rank <=", "B")
    results = q.fetch(5)
    count = 0
    for p in results:
      count += 1
    assert count == 2

    q = GP.all()
    q.filter("rank <", "B")
    results = q.fetch(5)
    count = 0
    for p in results:
      count += 1
    assert count == 1

    q = GP.all()
    q.filter("rank !=", "B")
    results = q.fetch(5)
    count = 0
    for p in results:
      assert p.rank == "A"
      count += 1
    assert count == 1


  def singlePropertyDescTest(self):
    q = GP.all()
    q.filter("rank =", "A")
    q.order("-rank")
    results = q.fetch(5)
    for p in results:
      assert p.rank == "A"     
      assert p.name == self.gp1.name

    q = GP.all()
    q.filter("rank =", "B")
    q.order("-rank")
    results = q.fetch(5)
    for p in results:
      assert p.rank == "B"     
      assert p.name == self.gp2.name

    q = P.all()
    q.filter("rank =", "C")
    q.order("-rank")
    results = q.fetch(5)
    for p in results:
      assert p.rank == "C"     
      assert p.name == self.p1.name

    q = GP.all()
    q.filter("rank >", "A")
    q.order("-rank")
    results = q.fetch(5)
    for p in results:
      assert p.rank == "B"     
      assert p.name == self.gp2.name

    q = GP.all()
    q.filter("rank >=", "A")
    q.order("-rank")
    results = q.fetch(5)
    count = 0
    for p in results:
      assert p.rank == "A" or p.rank == "B"
      assert p.name == self.gp2.name or p.name == self.gp1.name
      count += 1
    assert count == 2

    q = GP.all()
    q.filter("rank >=", "B")
    q.order("-rank")
    results = q.fetch(5)
    count = 0
    for p in results:
      count += 1
    assert count == 1

    q = GP.all()
    q.filter("rank >", "B")
    q.order("-rank")
    results = q.fetch(5)
    count = 0
    for p in results:
      count += 1
    assert count == 0

    q = GP.all()
    q.filter("rank <=", "B")
    q.order("-rank")
    results = q.fetch(5)
    count = 0
    for p in results:
      count += 1
    assert count == 2

    q = GP.all()
    q.filter("rank <", "B")
    q.order("-rank")
    results = q.fetch(5)
    count = 0
    for p in results:
      count += 1
    assert count == 1

    q = GP.all()
    q.filter("rank !=", "B")
    q.order("-rank")
    results = q.fetch(5)
    count = 0
    for p in results:
      assert p.rank == "A"
      count += 1
    assert count == 1

  def tearDown(self):
    db.delete(self.entities)
  
    q = db.GqlQuery("SELECT * FROM GP")
    for ent in q:
      assert False

    q = db.GqlQuery("SELECT * FROM C")
    for ent in q:
      assert False

    q = db.GqlQuery("SELECT * FROM P")
    for ent in q:
      assert False

  def purgePrevious(self):
    q = db.GqlQuery("SELECT * FROM GP")
    for ent in q:
      db.delete(ent)
    q = db.GqlQuery("SELECT * FROM C")
    for ent in q:
      db.delete(ent)

    q = db.GqlQuery("SELECT * FROM P")
    for ent in q:
      db.delete(ent)

    
#TODO test out special characters in the values like ! and chr(255)
# TODO test with multiple entities having the same value for a prop
# TODO Test None cases
# Reset:
print "<html><body>"
kt = KindTestCase()
kt.purgePrevious()

t = Timer()
kt = KindTestCase()
t.done("Creation")
kt.kindTest()
t.done("KindTest")
kt.ancestorTest()
t.done("AncestorTest")
kt.kindlessTest()
t.done("KindlessTest")
kt.kindlessAncestorTest()
t.done("KindlessAncestorTest")
kt.getTest()
t.done("GetTest")
kt.singlePropertyTest()
t.done("SinglePropertyTest")
kt.singlePropertyDescTest()
t.done("SinglePropertyDescTest")
logging.info("SUCCESS")
kt.tearDown()
t.done("TearDown")
t.total()
#t.exit()
print "</body></html>"
