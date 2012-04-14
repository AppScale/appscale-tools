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
from google.appengine.ext import webapp, db
from google.appengine.ext.webapp import util, template
import os, tasks, models, time


class MainHandler(webapp.RequestHandler):

    def get(self):
        path = os.path.join(os.path.dirname(__file__), 'index.html')
        self.response.out.write(template.render(path, {"state":models.State.get_by_key_name("instance"), "real_time":int(time.time())}))
        
    def post(self):
        def trans():
            state = models.State.get_by_key_name("instance")
            if not state:
                state = models.State(key_name="instance")
            state.running = not state.running
            state.put()
            if state.running:
                from google.appengine.ext import deferred
                deferred.defer(tasks.update_state, state) # Transactional enqueued deferred call!
        db.run_in_transaction(trans)
        self.redirect("/")

def main():
    application = webapp.WSGIApplication([('/', MainHandler)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
