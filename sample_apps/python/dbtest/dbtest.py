#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import cgi
import datetime
import time
import wsgiref.handlers

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.api import namespace_manager 

class Greeting(db.Model):
  author = db.UserProperty()
  content = db.StringProperty(multiline=True)
  date = db.DateTimeProperty(auto_now_add=True)

class Get(webapp.RequestHandler):
  def post(self):
    ns = self.request.get('ns')
    namespace_manager.set_namespace(ns)
    greeting = Greeting.get_by_key_name(self.request.get('key'))

    try:
      self.response.out.write(greeting.content)
    except AttributeError:
      self.response.out.write("key didn't exist")
  def get(self):
    start = time.time()
    ns = self.request.get('ns')
    namespace_manager.set_namespace(ns)
    greeting = Greeting.get_by_key_name(self.request.get('key'))

    try:
      self.response.out.write(greeting.content)
    except AttributeError:
      self.response.out.write("key didn't exist")
    end = time.time()
    self.response.out.write("Time Taken: " + str(end - start))
class Put(webapp.RequestHandler):
  def post(self):
    ns = self.request.get('ns')
    namespace_manager.set_namespace(ns)
    greeting = Greeting(key_name = self.request.get('key'))
    greeting.content = self.request.get('value')
    key = greeting.put()
    self.response.out.write("success!")
  def get(self):
    start = time.time()
    ns = self.request.get('ns')
    namespace_manager.set_namespace(ns)
    greeting = Greeting(key_name = self.request.get('key'))
    greeting.content = self.request.get('value')
    key = greeting.put()
    self.response.out.write("success!")
    end = time.time()
    self.response.out.write("Time Taken: " + str(end - start))


class Delete(webapp.RequestHandler):
  def post(self):
    ns = self.request.get('ns')
    namespace_manager.set_namespace(ns)
    greeting = Greeting(key_name = self.request.get('key'))
    key = greeting.delete()
    self.response.out.write("success!")
  def get(self):
    start = time.time()
    ns = self.request.get('ns')
    namespace_manager.set_namespace(ns)
    greeting = Greeting(key_name = self.request.get('key'))
    key = greeting.delete()
    self.response.out.write("success!")
    end = time.time()
    self.response.out.write("Time Taken: " + str(end - start))


class Query(webapp.RequestHandler):
  def get(self):
    start = time.time()
    ns = self.request.get('ns')
    namespace_manager.set_namespace(ns)
    self.response.out.write('<html><body>')

    greetings = db.GqlQuery("SELECT * "
                            "FROM Greeting "
                            "ORDER BY date DESC")

    for greeting in greetings:
      self.response.out.write('An anonymous person wrote:')
      self.response.out.write('<blockquote>%s</blockquote>' %
                              cgi.escape(greeting.content))
    end = time.time()
    self.response.out.write("Time Taken: " + str(end - start))

application = webapp.WSGIApplication([
  ('/get', Get),
  ('/put', Put),
  ('/delete', Delete),
  ('/query', Query)
], debug=True)


def main():
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()

