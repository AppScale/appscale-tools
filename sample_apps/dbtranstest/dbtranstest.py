#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import cgi
import datetime
import wsgiref.handlers
import logging
from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp
import time 
class Parent(db.Model):
  name = db.StringProperty(required = True)
  cash = db.IntegerProperty(required = True, default=1000000)

class Child(db.Model):
  name = db.StringProperty(required = True)
  cash = db.IntegerProperty(required = True, default=0)

class Accumulator(db.Model):
  counter = db.IntegerProperty()

def increment_counter(key, amount, raiseException):
  obj = Accumulator.get_by_key_name(key) 
  if not obj:
    raise db.Rollback()
  obj.counter += amount
  obj.put()
  if raiseException:
    raise db.Rollback()

def pay_allowance(parent_key, child_key, amount):
  p = Parent(key_name = parent_key, name = parent_key)
  c = Child(parent=p,key_name=child_key, name=child_key)
  p = Parent.get(p.key())
  if not p:
    raise db.Rollback()
  if not c:
    raise db.Rollback()
  c = Child.get(c.key())  
  p.cash -= amount
  p.put()
  c.cash += amount
  c.put()

def create_parent_child(parent_key, child_key):
  p = Parent(key_name = parent_key, name = parent_key)
  c = Child(parent=p,key_name=child_key, name=child_key)
  p.put()
  c.put()  

class BatchGetCount(webapp.RequestHandler):
  def post(self):
    reqstart = time.time()
    keys = self.request.get('keys')
    keys = keys.split(':')
    values = [] 
    timings = []
    total = 0
    error = False
    for key in keys:
      start = time.time()
      acc = Accumulator.get_by_key_name(key)
      end = time.time()
      if not acc:
        error = True
        break
      timings.append((end - start)) 
      total += (end - start)
      values.append(acc.counter)
    reqend = time.time()
    if not error:
      self.response.out.write("Success:True\n")
      self.response.out.write("Start time:" + str(reqstart) + '\n')
      self.response.out.write("End time:" + str(reqstart) + '\n')
      self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
      self.response.out.write("Cumulative DB Time Taken:" + str(total) + "\n")
      self.response.out.write("Number of Keys:" + str(len(timings)) + "\n")
      self.response.out.write("Timings:")
      for index,ii in enumerate(timings): timings[index] = str(ii)
      self.response.out.write(','.join(timings))
      self.response.out.write('\n') 

      self.response.out.write("Value:\n")
      for index,ii in enumerate(values): values[index] = str(ii)
      self.response.out.write(','.join(values))
      self.response.out.write('\n') 
    else:
      self.response.out.write("Success: False\n")


class GetCount(webapp.RequestHandler):
  def post(self):
    reqstart = time.time()
    logging.info("Running GetCount")
    start = time.time()
    acc = Accumulator.get_by_key_name(self.request.get('key'))
    end = time.time()
    reqend = time.time()
    if acc:
      self.response.out.write("Success:True\n")
      self.response.out.write("Start time:" + str(reqstart) + '\n')
      self.response.out.write("End time:" + str(reqend) + '\n')
      self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
      self.response.out.write("Cumulative DB Time Taken:" + str(end-start) + "\n")
      self.response.out.write("Value:" + str(acc.counter) + "\n")
    else:
      self.response.out.write("Success:False\n")

class PutCount(webapp.RequestHandler):
  def post(self):
    acc = Accumulator(key_name = self.request.get('key'))
    acc.counter = int(self.request.get('value'))
    start = time.time()
    key = acc.put()
    end = time.time()
    total = end - start 
    self.response.out.write("Time Taken:" + str(total) + "\n")

class BatchPutCount(webapp.RequestHandler):
  def post(self):
    reqstart = time.time()
    keys = self.request.get('keys')
    keys = keys.split(':')
    logging.info("keys:" + str(keys))
    value = int(self.request.get('value'))
    logging.info("value:" + str(value))
    total = 0
    timings = []
    try:
      for key in keys:
        key = str(key)
        acc = Accumulator(key_name = key)
        acc.counter = int(value)
        start = time.time()
        key = acc.put()
        end = time.time()
        timings.append(end - start)
        total += (end - start)
      reqend = time.time()
      self.response.out.write("Success:True\n")
      self.response.out.write("Start time:" + str(reqstart) + '\n')
      self.response.out.write("End time:" + str(reqend) + '\n')
      self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
      self.response.out.write("Cumulative DB Time Taken:" + str(total) + "\n")
      self.response.out.write("Number of Keys:" + str(len(keys)) + "\n")
      self.response.out.write("Timings:")
      for index,ii in enumerate(timings): timings[index] = str(ii)
      self.response.out.write(','.join(timings))
      self.response.out.write('\n') 
    except:
      self.response.out.write("Success:False")

class BatchDeleteCount(webapp.RequestHandler):
  def post(self):
    reqstart = time.time()
    keys = self.request.get('keys')
    keys = keys.split(':')
    total = 0
    timings = []
    #try:
    for key in keys:
      acc = Accumulator(key_name = key)
      start = time.time()
      key = acc.delete()
      end = time.time()
      timings.append(end - start)
      total += (end - start)
    reqend = time.time()
    self.response.out.write("Success:True\n")
    self.response.out.write("Start time:" + str(reqstart) + '\n')
    self.response.out.write("End time:" + str(reqend) + '\n')
    self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
    self.response.out.write("Cumulative DB Time Taken:" + str(total) + "\n")
    self.response.out.write("Number of Keys:" + str(len(keys)) + "\n")
    self.response.out.write("Timings:")
    for index,ii in enumerate(timings): timings[index] = str(ii)
    self.response.out.write(','.join(timings))

    self.response.out.write('\n') 
    #except:
    #  self.response.out.write("Error")

class BatchDeleteParent(webapp.RequestHandler):
  def post(self):
    reqstart = time.time()
    keys = self.request.get('keys')
    keys = keys.split(':')
    total = 0
    timings = []
    try:
      for key in keys:
        p = Parent(key_name = self.request.get(key))
        start = time.time()
        key = p.delete()
        end = time.time()
        timings.append(end - start)
        total += (end - start) 
      reqend = time.time()
      self.response.out.write("Success:True\n")
      self.response.out.write("Start time:" + str(reqstart) + '\n')
      self.response.out.write("End time:" + str(reqend) + '\n')
      self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
      self.response.out.write("Cumulative DB Time Taken:" + str(total) + "\n")
      self.response.out.write("Number of Keys:" + str(len(keys)) + "\n")
      self.response.out.write("Timings:")
      for index,ii in enumerate(timings): timings[index] = str(ii)
      self.response.out.write(','.join(timings))

      self.response.out.write('\n') 
    except:
      self.response.out.write("Success:False")

class BatchDeleteChild(webapp.RequestHandler):
  def post(self):
    keys = self.request.get('keys')
    keys = keys.split(':')
    total = 0
    timings = []
    try:
      for key in keys:
        c = Child(key_name = self.request.get(key))
        start = time.time()
        key = c.delete()
        end = time.time()
        timings.append(end - start)
        total += (end - start)
      self.response.out.write("Success:True\n")
      self.response.out.write("Start time:" + str(reqstart) + '\n')
      self.response.out.write("End time:" + str(reqend) + '\n')
      self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
      self.response.out.write("Cumulative DB Time Taken:" + str(total) + "\n")
      self.response.out.write("Number of Keys:" + str(len(keys)) + "\n")
      self.response.out.write("Timings:")
      for index,ii in enumerate(timings): timings[index] = str(ii)
      self.response.out.write(','.join(timings))

      self.response.out.write('\n') 
    except:
      self.response.out.write("Sucess:False\n")

class DeleteCount(webapp.RequestHandler):
  def post(self):
    acc = Accumulator(key_name = self.request.get('key'))
    start = time.time() 
    acc.delete()
    end = time.time()
    total = end - start 
    self.response.out.write("Time Taken:" + str(total) + "\n")

class DeleteParent(webapp.RequestHandler):
  def post(self):
    p = Parent(key_name = self.request.get('key'))
    start = time.time() 
    p.delete()
    end = time.time()
    total = end - start 
    self.response.out.write("Time Taken:" + str(total) + "\n")

class DeleteChild(webapp.RequestHandler):
  def post(self):
    c = Child(key_name = self.request.get('key'))
    start = time.time() 
    c.delete()
    end = time.time()
    total = end - start 
    self.response.out.write("Time Taken:" + str(total) + "\n")


class DeleteCount(webapp.RequestHandler):
  def post(self):
    acc = Accumulator(key_name = self.request.get('key'))
    start = time.time() 
    acc.delete()
    end = time.time()
    total = end - start 
    self.response.out.write("Time Taken:" + str(total) + "\n")

class Increment(webapp.RequestHandler):
  def post(self):
    key_name = self.request.get('key')
    amount = int(self.request.get('value'))
    error = False
    start = time.time()
    try:
      db.run_in_transaction_custom_retries(1, increment_counter,key_name, amount, False)
    except:
      error = True
    end = time.time()
    if error:
      self.response.out.write("Sucess:False" + "\n") 
    else:
      self.response.out.write("Start Time:" + str(start) + "\n")
      self.response.out.write("End Time:" + str(end) + "\n")
      self.response.out.write("Time Taken:" + str(end - start) + "\n")

 
class BatchIncrement(webapp.RequestHandler):
  def post(self):
    reqstart = time.time()
    keys = self.request.get('keys')
    amount = int(self.request.get('value'))
    keys = keys.split(':')
    error = False
    total = 0
    timings = []
    for key in keys:
      try:
        start = time.time()
        db.run_in_transaction_custom_retries(1, 
                                          increment_counter, 
                                          key, amount, False)        
        end = time.time()
        timings.append(end - start)
        total += end - start
      except:
        error = True 
    reqend = time.time()
    if error:
      self.response.out.write("Success:False") 
    else:
      self.response.out.write("Success:True\n")
      self.response.out.write("Start time:" + str(reqstart) + '\n')
      self.response.out.write("End time:" + str(reqend) + '\n')
      self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
      self.response.out.write("Cumulative DB Time Taken:" + str(total) + "\n")
      self.response.out.write("Number of Keys:" + str(len(timings)) + "\n")
      self.response.out.write("Timings:")
      for index,ii in enumerate(timings): timings[index] = str(ii)
      self.response.out.write(','.join(timings))
      self.response.out.write('\n') 
class Query(webapp.RequestHandler):
  def post(self):
    reqstart = time.time()
    type = self.request.get('type')
    start = time.time()
    items = db.GqlQuery("SELECT * "
                            "FROM " + type)
    end = time.time()
    reqend = time.time()
    self.response.out.write("Success:True\n")
    self.response.out.write("Start time:" + str(reqstart) + '\n')
    self.response.out.write("End time:" + str(reqend) + '\n')
    self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
    self.response.out.write("Cumulative DB Time Taken:" + str(end - start) + "\n")
    self.response.out.write("Number of Keys:" + str(items.count()) + "\n")
    self.response.out.write("Timings:")
    self.response.out.write(str(end - start) + '\n')
    self.response.out.write("Type: %s\n"%type) 
    #for index,ii in enumerate(items): items[index] = str(ii)
    #self.response.out.write(','.join(items))
    #self.response.out.write('\n') 

class GiveAllowance(webapp.RequestHandler):
  def post(self):
    parent_key = self.request.get('parent')
    child_key = self.request.get('child')
    amount = int(self.request.get('amount'))
    success = True
    start = time.time()
    try:
      db.run_in_transaction_custom_retries(1,  
                                         pay_allowance,
                                         parent_key,
                                         child_key,
                                         amount)
    except:
      success = False
    end = time.time()
    self.response.out.write("Success: %s\n"%str(success))
    self.response.out.write("Time Taken: " + str(end - start) + "\n") 
 
class BatchGiveAllowance(webapp.RequestHandler):
  def post(self):   
    reqstart = time.time()
    parent_key = self.request.get('parent')
    child_key = self.request.get('child')
    tries = int(self.request.get('tries'))
    amount = int(self.request.get('amount'))
    timings = []
    total = 0
    #try:
    success = True
    for ii in range(0, tries):
      start = time.time()
      try:
        db.run_in_transaction_custom_retries(1,  
                                            pay_allowance,
                                            parent_key,
                                            child_key,
                                            amount)
      except:
        success = False
      end = time.time()
      total += (end - start)
      timings.append(end-start)
      if not success:
        break
    reqend = time.time()
    #except:
    #  self.response.out.write("error")     
    self.response.out.write("Success:%s\n"%str(success))
    self.response.out.write("Start time:" + str(reqstart) + '\n')
    self.response.out.write("End time:" + str(reqend) + '\n')
    self.response.out.write("Total Time Taken:" + str(reqend - reqstart) + '\n')
    self.response.out.write("Cumulative DB Time Taken:" + str(total) + "\n")
    self.response.out.write("Number of Keys:" + str(len(timings)) + "\n")
    self.response.out.write("Timings:")
    for index,ii in enumerate(timings): timings[index] = str(ii)
    self.response.out.write(','.join(timings))
    self.response.out.write('\n') 
     
class CreateParentChild(webapp.RequestHandler):
  def post(self):
    parent_key = self.request.get('parent')
    child_key = self.request.get('child')
    success = True
    start = time.time()
    try:
      db.run_in_transaction_custom_retries(1, create_parent_child, parent_key, child_key)
    except:
      success = False
    end = time.time()
    self.response.out.write("Success: %s\n"%str(success))
    self.response.out.write("Time Taken: "+str(end - start) + "\n")

class MainIndex(webapp.RequestHandler):
  def get(self):
    self.response.out.write("Hello From DB Trans Tester")
  def post(self):
    self.response.out.write("Hello From DB Trans Tester")

class Root(webapp.RequestHandler):
  def get(self):
    self.response.out.write("Hello From DB Trans Tester")
    # prime database:
    p = Parent(key_name = "prime_key", name = "prime_key")
    c = Child(key_name = "prime_key", name = "prime_key")
    a = Accumulator(key_name = "prime_key", name = "prime_key") 
    p.put()
    c.put()
    a.put()
    p.delete()
    c.delete()
    a.delete()
  def post(self):
    self.response.out.write("Hello From DB Trans Tester")
    p = Parent(key_name = "prime_key", name = "prime_key")
    c = Child(key_name = "prime_key", name = "prime_key")
    a = Accumulator(key_name = "prime_key", name = "prime_key") 
    p.put()
    c.put()
    a.put()
    p.delete()
    c.delete()
    a.delete()

application = webapp.WSGIApplication([
  ('/',MainIndex),
  ('/root', Root),
  ('/increment', Increment),
  ('/batchincrement', BatchIncrement),
  ('/getcount', GetCount),
  ('/batchgetcount', BatchGetCount),
  ('/batchputcount', BatchPutCount),
  ('/putcount', PutCount),
  ('/batchdeletecount', BatchDeleteCount),
  ('/deletecount', DeleteCount),
  ('/query', Query),
  ('/giveallowance', GiveAllowance),
  ('/batchgiveallowance', BatchGiveAllowance),
  ('/createparentchild', CreateParentChild),
  ('/deleteparent', DeleteParent),
  ('/deletechild', DeleteChild), 
  ('/batchdeleteparent', BatchDeleteParent),
  ('/batchdeletechild', BatchDeleteChild) 
], debug=True)


def main():
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
