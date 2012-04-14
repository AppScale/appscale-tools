#!/usr/bin/python2.4
#
# Copyright 2010 Google Inc. All Rights Reserved.

# pylint: disable-msg=C6310

"""Channel Tic Tac Toe

This module demonstrates the App Engine Channel API by implementing a
simple tic-tac-toe game.
"""

import datetime
import logging
import os
import random
import re
from django.utils import simplejson
from google.appengine.api import channel
from google.appengine.api import users
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app
import hashlib

receiverid = "receiverappid" 
senderid = "senderappid"

def randomString(length):
  s = hashlib.sha256()
  ret = "a"
  while len(ret) < length:
    s.update(str(random.random()))
    ret += s.hexdigest()
  return ret[0:length]


class MainPage(webapp.RequestHandler):
  """The main UI page, renders the 'index.html' template."""

  def get(self):
    """Renders the main page. When this page is shown, we create a new
    channel to push asynchronous updates to the client."""
    path = os.path.join(os.path.dirname(__file__), 'index.html')
    template_values = {'senderid': senderid, 'receiverid': receiverid}
    self.response.out.write(template.render(path, template_values))

class CreateChannel(webapp.RequestHandler):
  def get(self):
    randomness = randomString(5)
    token = channel.create_channel(randomness)
    self.response.out.write('Appid created: ' + randomness)
    self.response.out.write('Token created: ' + token)

class SendMessage(webapp.RequestHandler):
  def get(self):
    token = channel.create_channel("senderappid")
    template_values = {'token': token,
                      'appid': 'receiverappid',
                      'message': "helloworld"}

    path = os.path.join(os.path.dirname(__file__), 'sendMessage.html')
    self.response.out.write(template.render(path, template_values))
    #self.response.out.write('AppID used to send: ' + randomness)
    #self.response.out.write('Token used to send: ' + token)

class ReceiveMessage(webapp.RequestHandler):
  def get(self):
    token = channel.create_channel("receiverappid")
    template_values = {'token': token,
                      'appid': 'receiverappid'}

    path = os.path.join(os.path.dirname(__file__), 'receiveMessage.html')
    self.response.out.write(template.render(path, template_values))
    #self.response.out.write('AppID used to send: ' + randomness)
    #self.response.out.write('Token used to send: ' + token)


class PostMessage(webapp.RequestHandler):
  def post(self):
    message = "helloworld"
    receiverid = "receiverappid" 
    channel.send_message(receiverid, message)
    self.response.out.write("message sent")

application = webapp.WSGIApplication([
    ('/', MainPage),
    ('/createchannel', CreateChannel),
    ('/sendmessage', SendMessage),
    ('/postmessage', PostMessage),
    ('/receivemessage', ReceiveMessage)], debug=True)
  

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
