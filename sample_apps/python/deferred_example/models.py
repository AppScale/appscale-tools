from google.appengine.ext import webapp, db 

class State(db.Model):
    currentTime = db.IntegerProperty(default=0)
    running = db.BooleanProperty(default=False)
    
