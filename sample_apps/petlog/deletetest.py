from google.appengine.ext import db
from google.appengine.api import users
from time import sleep

class Pet(db.Model):
  name = db.StringProperty(required = True)
  type = db.StringProperty(required = True, choices=set(["cat", "dog", "bird"]))
  birthdate = db.DateProperty()
  weight_in_pounds = db.IntegerProperty()
  spayed_or_neutered = db.BooleanProperty()

pet1 = Pet(name="Fluffy", type = "cat")
pet2 = Pet(name="Spot", type = "dog")
pet3 = Pet(name="Dinner", type = "bird")

print "Content-Type: text/plain"
print ""
print "Adding 3 pets, Fluffy, Spot, and Dinner..."
pet1.put()
pet2.put()
pet3.put()
print "Done"
print "Querying for pets...:"
q = db.GqlQuery("SELECT * FROM Pet")
print "Done"
for pet in q:
  print pet.name
print "Done"
print "Dinner the bird died =( removing her from the db..."
pet3.delete()
print "Done"
print "Querying for pets still alive...:"
q = db.GqlQuery("SELECT * FROM Pet")
print "Done"
for pet in q:
  print pet.name
print "Done"
  
