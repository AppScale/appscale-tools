import curllib
"""
  ('/', MainIndex),
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
"""
def __curl(ip, port, method, args):
  return curllib.curl_post(ip, port, False, method, args)

def MainIndex(ip, port):
  return curllib.curl_post(ip, port, False, None, None)
  
def Root(ip, port):
  return curllib.curl_post(ip, port, False, "root", None)

def Query(ip, port, type):
  args = {}
  args['type'] = type
  return __curl(ip, port, "query", args)

def Increment(ip, port, key, value):
  args = {}  
  args['key'] = key
  args['value'] = int(value)
  return __curl(ip, port, "increment", args)


def BatchIncrement(ip, port, keys, value):
  if isinstance(keys,list):
    keys = ':'.join(keys)
  args = {}
  args['keys'] = keys
  args['value'] = str(value)
  return __curl(ip, port, "batchincrement", args)


def GetCount(ip, port, key):
  args = {}
  args['key'] = key
  return __curl(ip, port, "getcount", args)


def BatchGetCount(ip, port, keys):
  if isinstance(keys,list):
    keys = ':'.join(keys)
  args = {}
  args['keys'] = keys
  return __curl(ip, port, "batchgetcount", args)


def BatchPutCount(ip, port, keys, value):
  if isinstance(keys,list):
    keys = ':'.join(keys)
  args = {}
  args['keys'] = keys
  args['value'] = value
  return __curl(ip, port, "batchputcount", args)


def PutCount(ip, port, key, value):
  args = {}
  args['key'] = key
  args['value'] = value
  return __curl(ip, port, "putcount", args)


def BatchDeleteCount(ip, port, keys):
  if isinstance(keys,list):
    keys = ':'.join(keys)
  args = {}
  args['keys'] = keys
  return __curl(ip, port, "batchdeletecount", args) 


def DeleteCount(ip, port, key):
  args = {}
  args['key'] = key
  return __curl(ip, port, "deletecount", args) 


def Query(ip, port, type):
  args = {}
  args['type'] = type
  return __curl(ip, port, "query", args)


def GiveAllowance(ip, port, parent, child, amount):
  args = {}
  args['parent'] = parent
  args['child'] = child
  args['amount'] = amount
  return __curl(ip, port, "giveallowance", args)


def BatchGiveAllowance(ip, port, parent, child, amount, tries):
  args = {}
  args['parent'] = parent
  args['child'] = child
  args['amount'] = amount
  args['tries'] = tries
  return __curl(ip, port, "batchgiveallowance", args)


def CreateParentChild(ip, port, parent, child):
  args = {}
  args['parent'] = parent
  args['child'] = child
  return __curl(ip, port, "createparentchild", args)


def DeleteParent(ip, port, key):
  args = {}
  args['key'] = key
  return __curl(ip, port, "deleteparent", args) 


def DeleteChild(ip, port, key):
  args = {}
  args['key'] = key
  return __curl(ip, port, "deletechild", args) 


def BatchDeleteParent(ip, port, keys):
  if isinstance(keys,list):
    keys = ':'.join(keys)
  args = {}
  args['keys'] = keys
  return __curl(ip, port, "batchdeletechild", args) 


def BatchDeleteChild(ip, port, keys):
  if isinstance(keys,list):
    keys = ':'.join(keys)
  args = {}
  args['keys'] = keys
  return __curl(ip, port, "batchdeletechild", args) 
 
