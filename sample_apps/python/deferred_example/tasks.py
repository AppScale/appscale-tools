from google.appengine.ext import webapp, db
import time

def update_state(state):
    state = db.get(state.key())
    if state.running:
        state.currentTime = int(time.time())
        state.put()
        from google.appengine.ext import deferred
        deferred.defer(update_state, state, _countdown=1)
