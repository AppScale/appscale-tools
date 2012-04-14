# Programmer: Chris Bunch
# mapreduce app: A sample app to test out the following in AppScale:
# - MapReduce functionality ala Hadoop
# - Memcache Support

import wsgiref.handlers

from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.api.appscale.mapreduce import mapreduce
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

class MapReduceHandler(webapp.RequestHandler):
  def get(self):
    if users.is_current_user_capable("mr_api"):
      currentVal = memcache.get("currentVal")
      currentTask = memcache.get("currentTask")
      if currentVal is None:
        currentVal = ""
        currentTask = ""
      power = memcache.get("power-" + currentVal)

      result = None
      if currentTask == "runMRJob":
        result = memcache.get("result-" + currentVal)
      elif currentTask == "timing":
        result = memcache.get("timing-" + currentVal)

      if power is None:
        power = "(Not run yet)"
      if result is None:
        result = "No result data yet."
    else:
      power = ""
      result = """You are not authorized to run MapReduce jobs. Please get
authorization on your user account for MapReduce jobs and try again.
"""

    self.response.out.write(template.render('mapreduce.html',
                                            {'power': power,
					     'result': result}))

  def post(self):
    buttonClicked = self.request.get('button')
    power = self.request.get('power')
    try:
      power = int(power)
    except:
      power = 3
    powerStr = str(power)

    memcache.set("currentVal", powerStr)

    if buttonClicked == "Run MapReduce Job":
      memcache.set("currentTask", "runMRJob")
      self.runMRJob(powerStr)
    elif buttonClicked == "Get Timing Info":
      memcache.set("currentTask", "timing")
      self.getLogs(powerStr)
      
    self.redirect('/')      
    
  def getLogs(self, powerStr):
    resultStr = memcache.get("timing-" + powerStr)

    if resultStr is None:
      outputFile = "output-" + powerStr
      resultStr = mapreduce.getMRLogs(outputFile)

      if resultStr == "this user cannot call the mapreduce api":
        resultStr = """You are not authorized to view the log files.
          Please log in as a user that it authorized to do so and try again.
"""
      else:
        resultStr = resultStr.replace("\n", "<br />")
        resultStr = resultStr.replace("<value>", " = ")
        memcache.set("power-" + powerStr, powerStr)
        memcache.set("timing-" + powerStr, resultStr)

  def runMRJob(self,powerStr):
    mapFile = "map.rb"
    redFile = "reduce.rb"
    power = int(powerStr)
        
    outputFile = "output-" + powerStr
     
    resultStr = memcache.get("result-" + powerStr)
    if resultStr is None:
      inputFile = "input-" + powerStr
      authorized = self.genInput(power,inputFile)
      
      if authorized == "success":
        jobStarted = mapreduce.runMRJob(mapFile, redFile, inputFile, outputFile)

        if jobStarted == "this user cannot call the mapreduce api":
          return

        resultStr = mapreduce.getMROutput(outputFile)
        if resultStr == "this user cannot call the mapreduce api":
          return

        resultStr = resultStr.replace("\n", "<br />")
        resultStr = resultStr.replace("sum", "&#931;")
        memcache.set("currentVal", powerStr)
        memcache.set("currentTask", "runMRJob")
        memcache.set("power-" + powerStr, powerStr)
        memcache.set("result-" + powerStr, resultStr)

  def genInput(self, power, inputLoc):
    n = 2 ** power
    numOfNodes = mapreduce.getNumOfNodes()

    if numOfNodes == "this user cannot call the mapreduce api":
      return numOfNodes

    bucket_size = n / numOfNodes
    
    vals = range(1, n / bucket_size + 1)  
    vals = [i * bucket_size for i in vals]
    
    buckets = ""
    index = 0
    for i in vals:
      if index == 0:
        start = 0
      else:
        start = vals[index - 1]
    
      this_range = str(start+1) + "\t" + str(vals[index]) + "\n"
      buckets += this_range
      index += 1

    result = mapreduce.putMRInput(buckets, inputLoc)

    if result == "this user cannot call the mapreduce api":
      return result

    return "success"

def main():
  wsgiref.handlers.CGIHandler().run(webapp.WSGIApplication([
    ('/', MapReduceHandler),
  ]))

if __name__ == '__main__':
  main()
