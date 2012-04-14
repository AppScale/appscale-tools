#!/usr/bin/env python
#

import cgi
import datetime
import logging
import wsgiref.handlers

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.api import xmpp
from google.appengine.ext import webapp

#class Greeting(db.Model):
#  author = db.UserProperty()
#  content = db.StringProperty(multiline=True)
#  date = db.DateTimeProperty(auto_now_add=True)


class MainPage(webapp.RequestHandler):
  def get(self):
    self.response.out.write('<html><body>')

    self.response.out.write('Send a message to:')
    self.response.out.write("""
          <form action="/send" method="post">
            <div><textarea rows="1" cols="20" value="recipient" name="recipient"></textarea></div>""")

    self.response.out.write('Your message:')
    self.response.out.write("""
            <div><textarea rows="3" cols="60" value="message" name="message"></textarea></div>
            <div><input type="submit" value="Send Message"></div>
          </form>
        </body>
      </html>""")

class SendMessage(webapp.RequestHandler):
  def post(self): 
    user_address = self.request.get('recipient')
    message = self.request.get('message')

    logging.info('User is logged in? %s' % str(xmpp.get_presence(user_address)))

    if xmpp.get_presence(user_address):
        status_code = xmpp.send_message(user_address, message)
        chat_message_sent = (status_code != xmpp.NO_ERROR)

    self.redirect('/')

class XMPPHandler(webapp.RequestHandler):
  def post(self):
    message = xmpp.Message(self.request.POST)
    if message.body[0:5].lower() == 'hello':
        message.reply("Greetings!")

    #greeting = Greeting()
    #greeting.content = message
    #greeting.put()
    self.redirect('/')

application = webapp.WSGIApplication([
  ('/', MainPage),
  ('/send', SendMessage),
  ('/_ah/xmpp/message/chat/', XMPPHandler)
], debug=True)


def main():
  logging.getLogger().setLevel(logging.INFO)
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
