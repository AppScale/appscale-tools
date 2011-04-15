#!/usr/bin/env python

import os, urllib
from google.appengine.api import users
from google.appengine.ext import blobstore, db, webapp
from google.appengine.ext.webapp import blobstore_handlers, template
from google.appengine.ext.webapp.util import run_wsgi_app, login_required
from google.appengine.runtime.apiproxy_errors import CapabilityDisabledError

class Wrapper(db.Model):
	user = db.UserProperty(auto_current_user=True)
	blob = blobstore.BlobReferenceProperty(required=True)
	date = db.DateTimeProperty(auto_now_add=True)

class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
	def post(self):
		try:
			upload_files = self.get_uploads('file')
			if len(upload_files) > 0:
				blob_info = upload_files[0]
				Wrapper(blob=blob_info.key()).put()
			self.redirect('/')
		except CapabilityDisabledError:
			self.response.out.write('Uploading disabled')

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
    def get(self, resource):
        resource = str(urllib.unquote(resource))
        blob_info = blobstore.BlobInfo.get(resource)
        self.send_blob(blob_info)

class DeleteHandler(webapp.RequestHandler):
	def post(self):
		try:
			key = self.request.get("key")
			wrapper = Wrapper.get(key)
			if wrapper:
				if wrapper.blob:
					blobstore.delete(wrapper.blob.key())
				else: self.response.out.write('No blob in wrapper')
				db.delete(wrapper)
				self.redirect('/')
			else: self.response.out.write('No wrapper for key %s' % key)
		except CapabilityDisabledError:
			self.response.out.write('Deleting disabled')

class MainHandler(webapp.RequestHandler):
	def get(self):
		if users.get_current_user():
			loginout_url = users.create_logout_url('/')
		else:
			loginout_url = users.create_login_url('/')
		values = {
			'user' : users.get_current_user(),
			'users' : users,
			'upload_url' : blobstore.create_upload_url('/upload'),
			'wrappers' : Wrapper.all(),
		}
		path = os.path.join(os.path.dirname(__file__), 'main.html')
		self.response.out.write(template.render(path, values))

class AccountHandler(webapp.RequestHandler):
	def get(self):
		if users.get_current_user():
			self.redirect(users.create_logout_url('/'))
		else:
			self.redirect(users.create_login_url('/'))

def main():
	run_wsgi_app(webapp.WSGIApplication([
		('/', MainHandler),
		('/account', AccountHandler),
		('/upload', UploadHandler),
		('/serve/([^/]+)?', ServeHandler),
		('/delete', DeleteHandler),
		], debug=True))

if __name__ == '__main__':
	main()