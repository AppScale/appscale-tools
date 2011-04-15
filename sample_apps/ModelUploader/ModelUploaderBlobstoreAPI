import cgi
import urllib
import zlib

from google.appengine.api import users
from google.appengine.api import mail

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db

from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers

'''
Version 2: Using the Blobstore API to handle larger model files
'''

class ColladaModel(db.Model):
    author = db.StringProperty(multiline=True)
    model = db.StringProperty(multiline=True)
    fiducial = db.StringProperty(multiline=False)
    
class Fiducial(db.Model):
    name = db.StringProperty(multiline=False)
    marker = db.BlobProperty()
    pic = db.BlobProperty()
    used = db.BooleanProperty()
    model = db.StringProperty(multiline=False)


class MainPage(webapp.RequestHandler):
    def get(self):
        blob_url = blobstore.create_upload_url('/upload')
        self.response.out.write("""
            <html> 
            <head><title>Model Uploader</title></head> 
            <body> 
                <form action="%s" enctype="multipart/form-data" method="POST"> 
                    Please enter your email:<br> 
                    <input name="author" type="text" size="30"> 
                    <br><br> 
                    Please select your model:<br> 
                    <input name="model" type="file"> 
                    <br><br> 
                    <input type="submit" value="Submit"> 
                </form> 
            </body> 
            </html>""" % blob_url)
        
class UploadModel(blobstore_handlers.BlobstoreUploadHandler):
    status = False
    def post(self):
        collada = ColladaModel()
        # Need to enforce email
        collada.author = self.request.get('author')
        # Only one blobstore upload, first elem in the list
        collada.model = str((self.get_uploads('model')[0].key()))

        # Get and assign fiducial marker 
        fiducials = db.GqlQuery("SELECT * FROM Fiducial WHERE used = False")
        if fiducials.count() > 0:
            self.status = True
            marker = (fiducials.fetch(1))[0]

            # Currently stores string, fix later
            collada.fiducial = marker.name
            marker.model = collada.author 

            # Send an email with an attachment
            mail.send_mail \
                (sender="jnoraky@gmail.com",
                 to = collada.author,
                 subject = "ARTag",
                 body = """
Attached is your ARTag. Print it and bring it to your destination.
Your unique ARTag identifier is %s. This will be used to load your
model on the client.

The Ops Lab
                 """ % collada.model,
                 attachments=[(marker.name, marker.pic)]
                 )

            # Disable ARTag for other models
            marker.used = True
            # Push to server
            db.put(marker)
            db.put(collada)    
        self.redirect('/')

'''
    def redirect(self, uri, permanent=False):
        if self.status:
            msg = "Model successfully written to the database. Please \
                   check your email for the ARTag!"       
        else:
            # Add debug info later
            msg = "Sorry, your model could not be uploaded. Please \
                   try again."
        self.response.out.write(
                """
                <html><head>
                <script language="javascript" type="text/javascript">
                alert("%s");
                window.location="%s";
                </script>
                </head></html>
                """ % (msg, uri))
'''

# For use only in development. In actual instantiation, all
# fiducial markers will be loaded beforehand.
class FiducialUploader(webapp.RequestHandler):
    def get(self):
        self.response.out.write("""
            <html> 
            <head><title>Fiducial Uploader</title></head> 
            <body> 
                <form action="/fiducialupload" enctype="multipart/form-data" method="POST"> 
                    Please enter the marker name:<br> 
                    <input name="marker" type="text" size="30"> 
                    <br><br> 
                    Please upload the image of the fiducial:<br> 
                    <input name="pic" type="file"> 
                    <br><br>
                    Please upload the pattern file of the fiducial:<br>
                    <input name="fiducial" type="file">
                    <br><br>
                    <input type="submit" value="Submit"> 
                </form> 
            </body>
            </html>
        """)

class UploadFiducial(webapp.RequestHandler):
    def post(self):
        fiducial = Fiducial()
        fiducial.name = self.request.get('marker')
        fiducial.pic = db.Blob(self.request.get('pic'))
        fiducial.marker = db.Blob(self.request.get('fiducial'))
        fiducial.used = False
        fiducial.put()
        self.redirect('/fiducial')

# Currently will download first entry in db query list
class Download(blobstore_handlers.BlobstoreDownloadHandler):
    def get(self, resource):
        resource = str(urllib.unquote(resource))
        models = db.GqlQuery("SELECT * FROM ColladaModel WHERE model = '%s'" % resource)
        if models.count() > 0:
            model = (models.fetch(1))[0]
            self.send_blob(model.model, save_as="model.dae")
        
application = webapp.WSGIApplication(
                                    [('/', MainPage), 
                                     ('/upload', UploadModel),
                                     ('/fiducial', FiducialUploader),
                                     ('/fiducialupload', UploadFiducial),
                                     ('/download/([^/]+)?', Download)],
                                    debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
