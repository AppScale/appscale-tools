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
import wsgiref.handlers

from google.appengine.ext import webapp
from google.appengine.api import capabilities

CAPABILITIES = ["blobstore", "datastore", "datastore_write", "images", "mail", "memcache", "taskqueue", "url_fetch", "xmpp", "mapreduce", "ec2", "neptune"]

class MainPage(webapp.RequestHandler):
  def get(self):
    for c in CAPABILITIES:
      if capabilities.CapabilitySet(c).is_enabled():
        self.response.out.write("<br />capability %s is enabled!" % c)
      else:
        self.response.out.write("<br />capability %s is disabled!" % c)

application = webapp.WSGIApplication([
  ('/', MainPage)
], debug=True)

def main():
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
