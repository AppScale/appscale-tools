from google.appengine.ext import db
from google.appengine.api import users
from time import sleep
import random
import string

def GenPasswd():
    newpasswd = "_"
    for i in range(8):
      newpasswd = newpasswd + str(random.random())
    return newpasswd

class GP(db.Model):
  name = db.StringProperty(required = True)
  birthdate = db.DateProperty()
class P(db.Model):
  name = db.StringProperty(required = True)
  birthdate = db.DateProperty()
class C(db.Model):
  name = db.StringProperty(required = True)
  birthdate = db.DateProperty()

key = GenPasswd()
gp1 = GP(key_name = key, name = key)
key = GenPasswd()
gp2 = GP(key_name = key, name = key)
key = GenPasswd()
p1 = P(key_name = key, parent = gp1, name = key)
key = GenPasswd()
p2 = P(key_name = key, parent = gp2, name = key)
key = GenPasswd()
c1 = C(key_name = key, parent = p1, name = key)
key = GenPasswd()
c2 = C(key_name = key, parent = p2, name = key)

print "Content-Type: text/plain"
print ""
print "Adding 2 Grandparents, 2 Parents, 2 children" 
gp1.put()
gp2.put()
p1.put()
p2.put()
c1.put()
c2.put()
print "Done"
print "Querying for grandparents"
q = db.GqlQuery("SELECT * FROM GP")
for gp in q:
  print gp.name
print "Done"

print "Querying for parents"
q = db.GqlQuery("SELECT * FROM P")
for p in q:
  print p.name
print "Done"
print "Querying for children"
q = db.GqlQuery("SELECT * FROM C")
for c in q:
  print c.name
print "Done"

print "Deleting all grandparents, parents, and children"
gp1.delete()
gp2.delete()
p1.delete()
p2.delete()
c1.delete()
c2.delete()
print "Done"

print "Querying for grandparents"
q = db.GqlQuery("SELECT * FROM GP")
for gp in q:
  print gp.name
print "Done"

print "Querying for parents"
q = db.GqlQuery("SELECT * FROM P")
for p in q:
  print p.name
print "Done"
print "Querying for children"
q = db.GqlQuery("SELECT * FROM C")
for c in q:
  print c.name
print "Done"

 
