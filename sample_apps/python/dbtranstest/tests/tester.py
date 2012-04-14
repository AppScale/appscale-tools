# Author Navraj Chohan
# This program is the client side tester to dbtranstest
import sys 
import time
import math
import test_functions
import getopt
import threading
tf = test_functions
DEFAULT_IP = ["128.111.55.223"]
DEFAULT_PORT = [8080]
DEFAULT_RATE = 1 # per second
DEFAULT_BATCH_SIZE = 1
DEFAULT_TRIAL_LENGTH = 1
ID_KEY_LENGTH = 15 
DEFAULT_TRIALS = 1
DEFAULT_TESTS = ["batchput"]
VALID_TESTS = ["put","get","delete","query","increment","allowance","query","batchput","batchget","batchdelete","batchincrement","batchallowance"]
SINGLE_TESTS = VALID_TESTS[0:6]
BATCH_TESTS = VALID_TESTS[7:]
DEBUG = False 
PUTCOUNTVALUE = "1"
INCREMENTVALUE = "1"
VALID_QUERY_KIND = ["Accumulator", "Parent", "Child"]
DEFAULT_QUERY_KIND = VALID_QUERY_KIND[0]
DEFAULT_OFFSET = 1

def padString(string):
  zero_padded_id = ("0" * (ID_KEY_LENGTH - len(string))) + string 
  return zero_padded_id

def generateKeys(numOfKeys, offset = 1):
  keys = []
  for ii in range(offset, offset + numOfKeys + 1):
    keys.append(padString(str(ii)))     
  return keys

def getBatchKeyString(keys):
  return ':'.join(keys)

def getIPsAndPorts(file):
  FILE = open(file, "r")
  contents = FILE.readlines()
  ips = []
  ports = []
  for line in contents:
    if line[0] == '#':
      continue 
    tokens = line.split(':')
    ip = tokens[0]
    port = tokens[1].rstrip() 
    ips.append(ip)
    ports.append(port)
  return ips,ports

""" Latency test:
  Do X puts for a counter, time it
  Do X gets for those same counters, time it
  Do Y number of repeat queries, time each
  Do X increments on those same counters, time it
  Do X gets on each counter to verify
  Do X delets on all counters, time it
"""
def usage():
  print "Usage:"
  print "-r or --request for number of request per second"
  print "-l or --lenth for number of seconds per trial"
  print "-b or --batch_size for size of a batch request"
  print "-t or --trials for the number of trials"
  print "-y or --tests for which test to run"
  print "\tFormat is test1:test2:test3:....testN"
  print "\tValid test include:",VALID_TESTS
  print "-s or --slave_file for location of slave file" 
  print "\tFormat of file should be a ip:port for each line"
  print "-o or --output to specify the output file"
  print "-k for query kind"
  print "\t valid types are Accumulator, Child, and Parent"
  print "-d for debug"
  print "-f or --offset for key offset number"
  print "\t useful for having multiple clients during testing"
  print "Examples:"
  print "TODO"
def main(argv):
  debug = DEBUG
  ips = DEFAULT_IP
  ports = DEFAULT_PORT
  req_per_sec = DEFAULT_RATE 
  batch_size = DEFAULT_BATCH_SIZE
  num_trials = DEFAULT_TRIALS
  trial_length = DEFAULT_TRIAL_LENGTH
  tests = DEFAULT_TESTS
  query_kind = DEFAULT_QUERY_KIND
  offset = DEFAULT_OFFSET
  output_file = ""
  try:
    opts, args = getopt.getopt(argv, "k:r:s:b:t:l:y:o:f:ud",
                            ["kind=",
                             "request=",
                             "slave_file=",
                             "batch_size=",
                             "trials=",
                             "length=",
                             "tests=",
                             "output=",
                             "offset=",
                             "usage",
                             "debug"])
  except getopt.GetoptError:
    usage()
    sys.exit(1)
  for opt, arg in opts:
    if opt in ("-r", "--request"):
      req_per_sec = int(arg)
      if debug: print "Number of request per second:",arg
    if opt in ("-s", "--slave_file"):
      ips, ports = getIPsAndPorts(arg)
      if debug: print "IPs:",str(ips)
      if debug: print "Ports:",str(ports)
    if opt in ("-b", "--batch_size"):
      batch_size = int(arg) 
      if debug: print "Batch size:",batch_size
    if opt in ("-t", "--trials"):
      num_trials = int(arg)
      if debug: print "Number of trials",num_trials
    if opt in ("-k", "--kind"):
      query_kind = arg
      if debug: print "Kind of query:",query_kind,"seconds"
      if query_kind not in VALID_QUERY_KIND:
        print "%s is not a valid kind of query type"%query_kind
        exit(1)
    if opt in ("-l", "--length"):
      trial_length = int(arg)
      if debug: print "Length of test:",trial_length,"seconds"
    if opt in ("-y", "--tests"):
      tests = arg
      tests = tests.split(":")
      error = False
      for ii in tests:
        if ii not in VALID_TESTS:
          error = True
          print "Test \"" + ii + "\" is not a valid test"
      if error:
          usage()
          exit(1)
      if debug: print "Running tests:",tests
    if opt in ("-o", "--output"):
      output_file = arg
      if debug: print "Output file:",output_file
    if opt in ("-u", "--usage"):
      usage()
      exit(0)
    if opt in ("-d", "--debug"):
      debug = True
      if debug: print "Debug mode is on"
    if opt in ("-f", "--offset"):
      offset = int(arg)
      if debug: print "Offset is:",offset

  error = False
  # Primes the database if needed (Hbase in particular)
  if debug:  print "Accessing web page",ips[0],":",ports[0]
  ret = tf.Root(ips[0], ports[0])
  if ret != "Hello From DB Trans Tester":
    error = True
    print "Error accessing web page",ips[ii],":",ports[ii]
  # Check to see that all slaves are running
  for ii in range(0, len(ips)): 
    if debug:  print "Accessing web page",ips[ii],":",ports[ii]
    ret = tf.MainIndex(ips[ii], ports[ii])
    if ret != "Hello From DB Trans Tester":
      error = True
      print "Error accessing web page",ips[ii],":",ports[ii]
  if error:
    print "exiting due to errors..."
    exit(1) 

  results = {}
  for ii in tests:  
    total_data = [] 
    if ii in SINGLE_TESTS or ii in BATCH_TESTS: 
      if debug: print "Running Single Test"
      for kk in range(0, num_trials):
        output = single_test(ips, 
                             ports, 
                             req_per_sec,  
                             trial_length, 
                             batch_size, 
                             ii, 
                             query_kind, 
                             offset,
                             debug)
        total_data.append(output)
      if debug: print "Method:",ii,",Output:\n",output 
    results[ii] = total_data

  logit(output_file, results)     
  stats(results)

def logit(output_file, results):
  if output_file:
    for r in results:
      ofile = open(output_file + "_" + r, "w")
      for ii in results[r]:
        ofile.write(ii)
        #file.write('\n#\n')
      ofile.close()

def getTotal(points):
  total = 0
  for ii in points:
    total += float(ii)
  return total

def getAverage(points, total = None):
  if total == None:
    total = getTotal(points)
  if len(points) == 0:
    return 0
  return total/len(points)

def getStDev(points, average=None):
  total = 0;
  if average == None:
    average = getAverage(points)
  for ii in points:
    total += (float(ii) - average) * (float(ii) - average)
  if len(points) == 0:
    return 0
  return math.sqrt(total/len(points))


def stats(results):
  for key in results:
    total = 0
    avg = 0
    min = 9999
    max = 0
    stdev = 0 
    numFailed = 0
    timings = []
    print "Key:",key
    for ii in results[key]:
      lines = ii.split('\n')
      isSuccess = False
      for line in lines:
        if line.startswith("<html>"):
          # Timeout error in appscale
          isSuccess = False
          numFailed += 1
        if line.startswith("Success:"): 
          if line.endswith("True"):
            isSuccess = True 
          else:
            isSuccess = False
            numFailed += 1
        if line.startswith("Timings:") and isSuccess:
          tokens = line.split(':')
          times = tokens[1]
          times = times.split(',')
          for index, tt in enumerate(times): 
            tt.rstrip('\n')
            times[index] = float(tt)
          timings += times
    for ii in timings:
      if ii < min:
        min = ii
      if ii > max:
        max = ii
    total = getTotal(timings)
    avg = getAverage(timings, total)
    stdev = getStDev(timings, avg)
    print "Average:",avg
    print "Total:",total
    print "Total Number:",len(timings)
    print "Stdev:",stdev
    print "Min:",min
    print "Max:",max
    print "Number of failures:",numFailed
    print "="*80

class testThread(threading.Thread):
  def setup(self, keyset1, keyset2, ip, port, command, batch_size, query_kind, debug=False):
    self.ip_ = ip
    self.port_ = port
    self.command_ = command 
    self.keyset1_ = keyset1
    self.keyset2_ = keyset2
    self.batch_size_ = batch_size
    self.query_kind_ = query_kind
    self.debug_ = debug
    self.status_ = "init"
    self.output_ = ""
    self.start_ = time.time()
    self.end_ = 0
    if self.debug_: print "ip: %s, port: %s, command: %s"\
                            %(self.ip_,self.port_,self.command_)
    
  def run(self):
    self.status_ = "running"
    if self.debug_: print "Thread %s run function: %s"\
              %(str(self),(self.command_ + "_test"))
    function = getattr(self, self.command_ + "_test")
    self.output_ = function()
    if self.debug_: print "Thread %s done"%(str(self))
    self.status_ = "terminated"
    self.end_ = time.time()

  def put_test(self):
    result = tf.PutCount(self.ip_, self.port_, self.keyset1_[0], PUTCOUNTVALUE)
    return result

  def get_test(self):
    result = tf.GetCount(self.ip_, self.port_, self.keyset1_[0])
    return result

  def delete_test(self):
    result = tf.DeleteCount(self.ip_, self.port_, self.keyset1_[0])
    return result

  def increment_test(self):
    result = tf.Increment(self.ip_, self.port_, self.keyset1_[0], INCREMENTVALUE)
    return result

  def allowance_test(self):
    tf.CreateParentChild(self.ip_, self.port_, self.keyset1_[0], self.keyset2_[0])
    result = tf.GiveAllowance(self.ip_, self.port_, self.keyset1_[0], self.keyset2_[0],  PUTCOUNTVALUE)
    return result

  def query_test(self):
    return tf.Query(self.ip_, self.port_, self.query_kind_)

  def batchput_test(self):
    result = tf.BatchPutCount(self.ip_, self.port_, self.keyset1_, PUTCOUNTVALUE)
    return result

  def batchget_test(self):
    result = tf.BatchGetCount(self.ip_, self.port_, self.keyset1_)
    return result

  def batchdelete_test(self):
    result = tf.BatchDeleteCount(self.ip_, self.port_, self.keyset1_)
    return result

  def batchincrement_test(self):
    result = tf.BatchIncrement(self.ip_, self.port_, self.keyset1_, PUTCOUNTVALUE)
    return result

  def batchallowance_test(self):
    tf.CreateParentChild(self.ip_, self.port_, self.keyset1_[0], self.keyset2_[0])
    result = tf.BatchGiveAllowance(self.ip_, self.port_, self.keyset1_[0], self.keyset2_[0], PUTCOUNTVALUE, self.batch_size_)
    return result

# returns results of a single trial 
def single_test(ips, ports, rps, trial_length, batch_size, method, query_kind, offset, debug = DEBUG):
  #log = logger()
  log = ""
  total_request = rps * trial_length * batch_size * len(ips)
  keys1 = generateKeys(total_request, offset)
  keys2 = generateKeys(total_request, 1 + len(keys1))
  if debug: print "Total keyspace 1:",keys1
  if debug: print "Total keyspace 2:",keys2
  if debug: print "ips %s, ports %s, rps %s, trial_length %s, debug %s"                           %(ips, ports, rps, trial_length, debug)
  if debug: print "Sending a total of %d request"%total_request
  key_index = 0
  threadlist = []
  for length in range(0, trial_length):
    for ii in range(0,rps):
      # send as threaded request
      for index, ip in enumerate(ips):
        if debug: print "Sending to ",ip,"on port",ports[index]
        thread = testThread()
        threadlist.append(thread)
        keysub1 = keys1[key_index:key_index + batch_size]
        keysub2 = keys2[key_index:key_index + batch_size]
        if debug: print "key space 1:",keysub1
        if debug: print "key space 2:",keysub2
        thread.setup(keysub1, keysub2, ip, ports[index], method, batch_size, query_kind, debug)
        thread.start()
        key_index += batch_size
    time.sleep(1)
  for thread in threadlist:
    thread.join()
    if debug: print "Joining thread %s"%str(thread)
    if thread.status_ == "terminated":
      log += "Method:"+thread.command_ + "\n"
      log += "RTT Start:"+ str(thread.start_) + "\n"
      log += "RTT End:"+str(thread.end_)+ "\n"
      log += "RTT Time:"+str(thread.end_ - thread.start_)+ "\n"
      log += thread.output_ 
      log += "#\n"
    else:
      print "Error with thread after join with status %s"%thread.status_
  return log   

if __name__ == '__main__':
  main(sys.argv[1:])
