import time 
import math
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

def getAverage(points):
  total = 0
  for ii in points:
    total += float(ii)
  return total/len(points)

def getStDev(points, average=None):
  total = 0;
  if average == None:
    average = getAverage(points)
  for ii in points:
    total += (float(ii) - average) * (float(ii) - average)
  return math.sqrt(total/len(points))


class GP(db.Model):
  name = db.StringProperty(required = True)
  val = db.StringProperty(required = True)
  birthdate = db.DateProperty()

class DoNothing(webapp.RequestHandler):
  def get(self):
    self.response.out.write("hey guy")

class DoStuff(webapp.RequestHandler):
  def get(self):
       
    #self.response.out.write("Content-Type: text/plain\r\n\r\n")
    self.response.headers['Content-Type'] = 'text/plain'
    MAX_ITEMS = 100
    total_put_time = 0
    max_put_time = 0
    min_put_time = 99999
    put_stdev = 0
    put_average = 0
    updated = []
    all_values = []
    for ii in range(0,MAX_ITEMS):
      gp1key = RandomString()
      gp1 = GP(key_name = gp1key, name = gp1key, val = V)
      start_time = time.time()
      gp1.put()
      end_time = time.time()
      timetaken = end_time - start_time
      all_values.append(timetaken)
      updated.append(gp1)
      total_put_time += timetaken
      if timetaken > max_put_time:
        max_put_time = timetaken
      if timetaken < min_put_time:
        min_put_time = timetaken  
    put_average = getAverage(all_values)
    put_stdev = getStDev(all_values, put_average)
    self.response.out.write("PUTTING " + str(MAX_ITEMS) + " Items:\n")
    self.response.out.write("Total Time:" + str(total_put_time) + "\n")
    self.response.out.write("Avg Time:" + str(put_average)+ "\n")
    self.response.out.write("Stdev :" + str(put_stdev)+ "\n")
    self.response.out.write("Max Time:" + str(max_put_time)+ "\n")
    self.response.out.write("Min Time:" + str(min_put_time)+ "\n")
    hr = "." * 100
    self.response.out.write(hr+ "\n")
     
    all_values = []
    total_get_time = 0
    min_get_time = 9999
    max_get_time = 0
    get_average = 0
    get_stdev = 0
    for ii in updated:
      start_time = time.time()
      obj = db.get(ii.key()) 
      end_time = time.time()  
      timetaken = end_time - start_time
      all_values.append(timetaken)
      total_get_time += timetaken
      if timetaken > max_get_time:
        max_get_time = timetaken
      if timetaken < min_get_time:
        min_get_time = timetaken  
    get_average = getAverage(all_values)
    get_stdev = getStDev(all_values, get_average)
    self.response.out.write("GETTING " + str(MAX_ITEMS) + " Items:\n")
    self.response.out.write("Total Time:" + str(total_get_time)+ "\n")
    self.response.out.write("Avg Time:" + str(get_average)+ "\n")
    self.response.out.write("Stdev :" + str(get_stdev)+ "\n")
    self.response.out.write("Max Time:" + str(max_get_time)+ "\n")
    self.response.out.write("Min Time:" + str(min_get_time)+ "\n")
    self.response.out.write(hr+ "\n")

    total_query_time = 0
    start_time = time.time()
    q = db.GqlQuery("SELECT * FROM GP")
    end_time = time.time()  
    timetaken = end_time - start_time
    total_query_time += timetaken
    self.response.out.write("QUERY " + str(MAX_ITEMS) + " Items:\n")
    self.response.out.write("Total Time:" + str(total_query_time)+ "\n")
    self.response.out.write(hr + "\n")

    
    all_values = []
    total_delete_time = 0
    min_delete_time = 9999
    max_delete_time = 0
    delete_average = 0
    delete_stdev = 0
    for ii in updated:
      start_time = time.time()
      db.delete(ii.key()) 
      end_time = time.time()  
      timetaken = end_time - start_time
      all_values.append(timetaken)
      total_delete_time += timetaken
      if timetaken > max_delete_time:
        max_delete_time = timetaken
      if timetaken < min_delete_time:
        min_delete_time = timetaken  
    delete_average = getAverage(all_values)
    delete_stdev = getStDev(all_values, delete_average)
    self.response.out.write("DELETING " + str(MAX_ITEMS) + " Items:\n")
    self.response.out.write("Total Time:" + str(total_delete_time)+ "\n")
    self.response.out.write("Avg Time:" + str(delete_average)+ "\n")
    self.response.out.write("Stdev :" + str(delete_stdev)+ "\n")
    self.response.out.write("Max Time:" + str(max_delete_time)+ "\n")
    self.response.out.write("Min Time:" + str(min_delete_time)+ "\n")
    self.response.out.write(hr + "\n")

application = webapp.WSGIApplication([
  ('/', DoNothing),
  ('/transtest', DoStuff)
], debug=True)


def main():
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()


