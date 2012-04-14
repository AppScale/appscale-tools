#!/usr/bin/env python
#
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

ID_KEY_LENGTH = 15

def padString(string):
  zero_padded_id = ("0" * (ID_KEY_LENGTH - len(string))) + string
  return zero_padded_id

class Account(db.Model):
  owner = db.StringProperty(required=True)
  balance = db.IntegerProperty(required=True, default=0)
  payload = db.BlobProperty()
class Transfer(db.Model):
  amount = db.IntegerProperty(required=True)
  target = db.ReferenceProperty(Account, required=True)
  other = db.SelfReferenceProperty()
  timestamp = db.DateTimeProperty(required=True, auto_now_add=True)
  payload = db.BlobProperty()

def transfer_funds(src, dest, amount):
  def _tx():
    account = Account.get(src)
    # Allow for overdrafts
    #if account.balance < amount:
    #  return None
    transfer_payload  = 1 * "x"
    account.balance -= amount
    transfer = Transfer(
        parent=account,
        amount=-amount,
        target=dest,
        payload=transfer_payload)
    db.put([account, transfer])
    return transfer
  return db.run_in_transaction(_tx)

def roll_forward(transfer):
  def _tx():
    dest_transfer = Transfer.get_by_key_name(str(transfer.key()), parent=transfer.target.key())
    #dest_transfer = Transfer.get_by_key_name(parent=transfer.target.key(), str(transfer.key()))
    transfer_payload  = 1 * "x"
    if not dest_transfer:
      dest_transfer = Transfer(
          parent=transfer.target.key(),
          key_name=str(transfer.key()),
          amount=-transfer.amount,
          target=transfer.key().parent(),
          other=transfer,
          payload=transfer_payload)
      account = Account.get(transfer.target.key())
      account.balance -= transfer.amount
      db.put([account, dest_transfer])
      return dest_transfer
  #try:
  dest_transfer = db.run_in_transaction(_tx)
  transfer.other = dest_transfer
  transfer.put()
  #except Exception:
  #  return False

  return True

def execute_unapplied_transactions(count=20):
  cutoff = datetime.datetime.now() - datetime.timedelta(seconds=30)
  q = Transfer.all().filter("other =", None).filter("timestamp <", cutoff)
  for transfer in q.fetch(count):
    roll_forward(transfer)

class CreateAccount(webapp.RequestHandler):
  def post(self):
    success = True
    start = time.time()
    ammount = int(self.request.get('balance'))
    account_key = self.request.get('account')
    account_payload = 10000 * "x"
    a = Account(key_name = account_key, owner = account_key, balance = int(ammount), payload=account_payload)
    try:
      db.put(a)
    except Exception, e: 
      self.response.out.write("Reason: %s\n"%str(e)) 
      success = False
    end = time.time()
    self.response.out.write("Success: %s\n"%str(success))
    if success:
      self.response.out.write("Time Taken: " + str(end - start) + "\n") 

class GetAccount(webapp.RequestHandler):
  def post(self):
    success = True
    start = time.time()
    account_key = self.request.get('account')
    #a = Account(key_name = account_key, owner = account_key, balance = 0)
    try:
      a = Account.get_by_key_name(padString(account_key))
    except Exception, e: 
      self.response.out.write("Reason: %s\n"%str(e)) 
      success = False
    end = time.time()
    self.response.out.write("Success: %s\n"%str(success))
    if success:
      self.response.out.write("Time Taken: " + str(end - start) + "\n") 

class BatchCreateAccount(webapp.RequestHandler):
  def post(self):
    success = True
    ammount = int(self.request.get('balance'))
    offset = self.request.get('offset')
    num_accounts = int(self.request.get('numaccounts'))
    accounts = []
    start = time.time()
    account_payload = 10000 * "x"
    for ii in range(int(offset), int(offset) + num_accounts): 
      a = Account(key_name = padString(str(ii)), owner = padString(str(ii)), balance = (ammount) , payload=account_payload)
      accounts.append(a)
    db.put(accounts)      
    end = time.time()
    self.response.out.write("Range: %s to %s\n"%(str(offset),str(int(offset) + num_accounts)))
    self.response.out.write("Success: %s\n"%str(success))
    if success:
      self.response.out.write("Time Taken: " + str(end - start) + "\n") 

class BatchDeleteAccount(webapp.RequestHandler):
  def post(self):
    ammount = int(self.request.get('balance'))
    offset = int(self.request.get('offset'))
    num_accounts = int(self.request.get('numaccounts'))
    accounts = []
    start = time.time()
    for ii in range(int(offset), int(offset) + num_accounts): 
      a = Account(key_name = padString(str(ii)), owner = padString(str(ii)), balance = int(ammount))
      accounts.append(a)
    db.delete(accounts)      
    end = time.time()
    success = True
    self.response.out.write("Range: %s to %s\n"%(str(offset),str(int(offset) + num_accounts)))
    self.response.out.write("Success: %s\n"%str(success))
    if success:
      self.response.out.write("Time Taken: " + str(end - start) + "\n") 

class DeleteAccount(webapp.RequestHandler):
  def post(self):
    key = self.request.get('account')
    a = Account(key_name = padString(str(ii)), owner = padString(key), balance = int(ammount))
    db.delete(accounts)      
    success = True
    self.response.out.write("Success: %s\n"%str(success))

class CheckAccount(webapp.RequestHandler):
  def post(self):
    key = self.request.get('account')
    a = Account.get_by_key_name(padString(key))
    accounts = db.get(a)      
    for ii in accounts:
      self.response.out.write("Account value: %s\n"%ii.balance )

class CreateTransfer(webapp.RequestHandler):
  def post(self):
    sender_key = self.request.get('sender')
    receiver_key = self.request.get('receiver')
    amount = int(self.request.get('amount'))
    retries = int(self.request.get('retries'))
    success = True
    reason = ""
    start = time.time()
    src = Account.get_by_key_name(padString(sender_key))
    dest = Account.get_by_key_name(padString(receiver_key))
    
    if not src or not dest:
      logging.info("Src or dest account not found!")

    try:
      t1 = transfer_funds(src.key(), dest.key(), amount)
      if not t1:
        logging.info("Unable to create transfer")
        success = False
        reason = "Unable to transfer funds"
      if not roll_forward(t1):
        logging.info("Unable to roll forward")
        reason = "Unable to roll forward funds"
        success = False
    except Exception, e:
      success = False
      reason = str(e);
    end = time.time()
    if reason:
      self.response.out.write("Reason: %s\n"%str(reason))
    self.response.out.write("Success: %s\n"%str(success))
    if success == True:
      self.response.out.write("Time Taken: " + str(end - start) + "\n") 
 
class MainIndex(webapp.RequestHandler):
  def get(self):
    self.response.out.write("Hello From DB Trans Tester\n")
  def post(self):
    self.response.out.write("Hello From DB Trans Tester\n")

class Root(webapp.RequestHandler):
  def post(self):
    self.response.out.write("Hello From DB Trans Tester\n")
    start = time.time()
    # prime database:
    a1 = Account(key_name = "prime_key", owner = "prime_key", balance = 100)
    a2 = Account(key_name = "prime_key2", owner = "prime_key2", balance = 100)
    db.put([a1,a2])
    t1 = transfer_funds(a1.key(), a2.key(),10)
    roll_forward(t1)
    db.delete([a1,a2,t1])
    dest_transfer = Transfer.get_by_key_name(str(t1.key()), parent=t1.target.key())
    if dest_transfer:
      dest_transfer.delete()
      self.response.out.write("Success: True\n");
    else:
      self.response.out.write("Success: False\n");
    end = time.time()
    self.response.out.write("Time Taken: " + str(end - start) + "\n")

  def get(self):
    self.response.out.write("Hello From DB Trans Tester\n")
    start = time.time()
    # prime database:
    a1 = Account(key_name = "prime_key", owner = "prime_key", balance = 100)
    a2 = Account(key_name = "prime_key2", owner = "prime_key2", balance = 100)
    db.put([a1,a2])
    t1 = transfer_funds(a1.key(), a2.key(),10)
    roll_forward(t1)
    db.delete([a1,a2,t1])
    dest_transfer = Transfer.get_by_key_name(str(t1.key()), parent=t1.target.key())
    if dest_transfer:
      dest_transfer.delete()
      self.response.out.write("Success: True\n");
    else:
      self.response.out.write("Success: False\n");
    end = time.time()
    self.response.out.write("Time Taken: " + str(end - start) + "\n")


application = webapp.WSGIApplication([
  ('/',MainIndex),
  ('/root', Root),
  ('/createaccount', CreateAccount),
  ('/createtransfer', CreateTransfer),
  ('/deleteaccount', DeleteAccount),
  ('/batchcreateaccount', BatchCreateAccount),
  ('/batchdeleteaccount', BatchDeleteAccount),
  ('/getaccount', GetAccount)
], debug=True)


def main():
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
