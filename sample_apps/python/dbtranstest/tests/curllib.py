#Navraj Chohan
# Functions for calling Curl
import subprocess
DEBUG = True
def curl_get(ip, port, isSSL, method = None):
  command = "curl -s "
  if isSSL:
    command += "https://"
  else:
    command += "http://"
  command +=ip
  if method:
    command += (":" + str(port) + "/" + method) 
  else:
    command += (":" + str(port) + "/")
  if DEBUG: print "curllib command:",command
  output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
  output = output.communicate()[0]
  if DEBUG: print "curllib output:",output
  return output

def curl_post(ip, port, isSSL, method = None, argsdic = None):
  command = "curl -s " 
  if isSSL:
    command += "https://"
  else:
    command += "http://"
  command += ip
  if method:
    command += (":" + str(port) + "/" + method)
  else:
    command += (":" + str(port) + "/")
  if argsdic:
    command += " -d \"" 
    numargs = len(argsdic)
    for index,key in enumerate(argsdic):
      command += (key + "=" + str(argsdic[key]))
      if numargs - 1 != index:
        command += "&"
    command += "\""
  if DEBUG: print "curllib command:",command
  output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
  output = output.communicate()[0]
  if DEBUG: print "curllib output:",output
  
  return output
