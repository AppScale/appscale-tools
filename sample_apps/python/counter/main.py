import wsgiref.handlers
from google.appengine.api.labs import taskqueue
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

class Counter(db.Model):
  count = db.IntegerProperty(indexed=False)

class CounterHandler(webapp.RequestHandler):
  def get(self):
    self.response.out.write(template.render('counters.html',
                                            {'counters': Counter.all()}))

  def post(self):
    key = self.request.get('key')

    # Add the task to the default queue.
    taskqueue.add(url='/worker', params={'key': key})

    self.redirect('/')

class CounterWorker(webapp.RequestHandler):
  def post(self): # should run at most 1/s
    key = self.request.get('key')
    def txn():
      counter = Counter.get_by_key_name(key)
      if counter is None:
        counter = Counter(key_name=key, count=1)
      else:
        counter.count += 1
      counter.put()
    db.run_in_transaction(txn)

def main():
  wsgiref.handlers.CGIHandler().run(webapp.WSGIApplication([
    ('/', CounterHandler),
    ('/worker', CounterWorker),
  ]))

if __name__ == '__main__':
  main()