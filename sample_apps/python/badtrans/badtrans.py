from google.appengine.ext import db

class Accumulator(db.Model):
    counter = db.IntegerProperty()

def increment_counter(key, amount, raiseExcept):
    obj = db.get(key)
    obj.counter += amount
    obj.put()
    if raiseExcept:
      raise db.Rollback() 

q = Accumulator()
q.counter = 0
q.put()

acc = db.get(q.key())
print "Content-Type: text/plain"
print ""
print "Count:",acc.counter
db.run_in_transaction(increment_counter, acc.key(), 5, False)
acc = db.get(acc.key())
print "New Count:",acc.counter
try:
  db.run_in_transaction(increment_counter, acc.key(), 1000, True)
except:
  pass
  print "Exception was tossed"

acc = db.get(acc.key())
print "Second New Count (should be 5):",acc.counter
db.run_in_transaction(increment_counter, acc.key(), 5, False)

print "After exception:"
acc = db.get(acc.key())
print "Second New Count (should be 10): ",acc.counter
db.delete(acc.key())

acc = db.get(acc.key())
print "After deleting the key:",str(acc)
