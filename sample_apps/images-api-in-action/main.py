import re
import wsgiref.handlers
from google.appengine.api import users
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.api import urlfetch
from google.appengine.api import images

class Uploaded(db.Model):
  author = db.UserProperty()
  image = db.BlobProperty()

class UploadImage(webapp.RequestHandler):
  def get(self):
    user = users.get_current_user()
    if user is not None:
      response = "You are logged in as " + user.nickname() + ".<br />"
      response += "Is that <a href='" + users.create_logout_url("/upload") + "'>not you?</a><br /><br />"
    else:
      response = "You are not logged in yet.<br />"
      response += "Would you <a href='" + users.create_login_url("/upload") + "'>like to?</a><br /><br />"

    response += "Please upload an image:<br /><br />"
    response += "<form action='upload' enctype='multipart/form-data' method='post'>"
    response += "<div><label>From your Computer:</label><input type='file' name='hdd'/></div><br />"
    response += "<div><label>From the Interwebs:</label><input type='text' name='net'/></div><br />"
    response += "<div><input type='submit' value='Upload'></div>"
    response += "</form>"
    self.response.out.write(template.render('index.html',
                                            {'tool': 'Upload an image',
                                            'result': response}))
  def post(self):
    hdd = self.request.get("hdd") 
    net = self.request.get("net")

    user = users.get_current_user()
    uploaded = Uploaded(key_name=str(user))
    response = "Uploaded an image anonymously.<br /><br />"
    if user:
      uploaded.author = user
      response = "Uploaded an image as " + user.nickname() + "<br /><br />"

    if hdd != "":
      uploaded.image = db.Blob(hdd)
      uploaded.put()
    elif net != "":
      data = urlfetch.fetch(net).content
      uploaded.image = db.Blob(data)
      uploaded.put()

    self.redirect("/")

class ManipulateImage(webapp.RequestHandler):
  def get(self):
    user = users.get_current_user()
    username = "anonymous"
    if user:
      username = user.nickname()

    uploaded = Uploaded.get_by_key_name(str(user))
    if uploaded is None:
      response = "No image uploaded yet."
    else:
      response = "Image for " + username + ":"
      response += "<div><img src='img?img_id=" + str(uploaded.key()) + "'></img></div><br /><br />"
      response += "Actions (choose one):<br /><br />"
      response += "<form action='/' method='post'>"
      response += "<div><input type='submit' name='rotater' value='Rotate Right'/></div><br />"
      response += "<div><input type='submit' name='rotatel' value='Rotate Left' /></div><br />"
      response += "<div><input type='submit' name='hflip' value='Horizontal Flip'/></div><br />"
      response += "<div><input type='submit' name='vflip' value='Vertical Flip' /></div><br />"
      response += "</form>"
    self.response.out.write(template.render('index.html',
                                            {'tool': 'Your Image',
                                             'result': response}))
  def post(self):
    user = users.get_current_user()
    uploaded = Uploaded.get_by_key_name(str(user))
    response = "baz"
    if uploaded is None:
      response = "No image uploaded yet."
    else:
      image = uploaded.image
      if self.request.get('hflip'):
        newimage = images.horizontal_flip(image)
      elif self.request.get('vflip'):
        newimage = images.vertical_flip(image)
      elif self.request.get('rotater'):
        newimage = images.rotate(image, 90)
      elif self.request.get('rotatel'):
        newimage = images.rotate(image, 270)
        
      uploaded.image = newimage
      uploaded.put()

    self.redirect("/")
  
class Image(webapp.RequestHandler):
    def get(self):
      uploaded = db.get(self.request.get("img_id"))
      if uploaded.image:
          self.response.headers['Content-Type'] = "image/png"
          self.response.out.write(uploaded.image)
      else:
          self.error(404)

def main():
  wsgiref.handlers.CGIHandler().run(webapp.WSGIApplication([
    ('/', ManipulateImage),
    ('/img', Image),
    ('/upload', UploadImage)
  ]))

if __name__ == '__main__':
  main()
