import cgi
import datetime
import logging
import StringIO
import time

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import memcache
from google.appengine.api import images

logging.getLogger().setLevel(logging.DEBUG)

class Greeting(db.Model):
  author = db.UserProperty()
  content = db.StringProperty(multiline=True)
  avatar = db.BlobProperty()
  date = db.DateTimeProperty(auto_now_add=True)

class MainPage(webapp.RequestHandler):
  def get(self):
    self.response.out.write("<html><body>")

    before = time.time()
    greetings = self.get_greetings() 
    after = time.time()
    timeTaken = str(after - before)
    
    stats = memcache.get_stats()
    
    self.response.out.write("<b>Time to get Greetings:%s seconds</b><br>" % timeTaken)
    self.response.out.write("<b>Cache Hits:%s</b><br>" % stats['hits'])
    self.response.out.write("<b>Cache Misses:%s</b><br><br>" %
                            stats['misses'])
    self.response.out.write(greetings)
    self.response.out.write("""
          <form action="/sign" enctype="multipart/form-data" method="post">
            <div><label>Message:</label></div>
            <div><textarea name="content" rows="3" cols="60"></textarea></div>
            <div><label>Avatar:</label></div>
            <div><input type="file" name="img"/></div>
            <div><input type="submit" value="Sign Guestbook"></div>
          </form>
        </body>
      </html>""")

  def get_greetings(self):
    """
        get_greetings()
        Checks the cache to see if there are cached greetings.
        If not, call render_greetings and set the cache

        Returns:
           A string of HTML containing greetings.
    """
    greetings = memcache.get("greetings")
    if greetings is not None:
      return greetings
    else:
      greetings = self.render_greetings()
      if not memcache.add("greetings", greetings, 10):
        logging.error("Memcache set failed.")
      return greetings

  def render_greetings(self):
    """
        render_greetings()
        Queries the database for greetings, iterate through the
        results and create the HTML.

        Returns:
           A string of HTML containing greetings
    """
    results = db.GqlQuery("SELECT * "
                          "FROM Greeting "
                          "ORDER BY date DESC").fetch(10)
    output = StringIO.StringIO()
    for result in results:
      if result.author:
        output.write("<b>%s</b> wrote:" % result.author.nickname())
      else:
        output.write("An anonymous person wrote:")
      output.write("<div><img src='img?img_id=%s'></img>" %
                                    result.key())
      output.write(' %s</div>' % cgi.escape(result.content))

    return output.getvalue()  

class Image (webapp.RequestHandler):
    def get(self):
        greeting = db.get(self.request.get("img_id"))
        if greeting.avatar:
            self.response.headers['Content-Type'] = "image/png"
            self.response.out.write(greeting.avatar)
        else:
            self.response.out.write("No image")
     
class Guestbook(webapp.RequestHandler):
  def post(self):
    greeting = Greeting()

    if users.get_current_user():
      greeting.author = users.get_current_user()

    greeting.content = self.request.get('content')
    if self.request.get("img"):
      avatar = images.resize(self.request.get("img"), 32, 32)
      greeting.avatar = db.Blob(avatar)
    greeting.put()
    self.redirect('/')

application = webapp.WSGIApplication([
  ('/', MainPage),
  ('/img', Image),
  ('/sign', Guestbook)
], debug=True)


def main():
  run_wsgi_app(application)


if __name__ == '__main__':
  main()

