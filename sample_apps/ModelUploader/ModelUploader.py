import cgi
import urllib
import zlib
import re
import os

from google.appengine.api import users
from google.appengine.api import mail

from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db

'''
Version 2: Using partition to store larger model files to the online db

# Changes to be deployment:
* Add admin permissions back to /delete domain
* Design a sleeker webform layout
* Organize CSS
'''

class PartitionObj(db.Model):
    model = db.StringProperty(multiline=False)
    owner = db.StringProperty(multiline=True)
    name = db.StringProperty(multiline=True)
    content = db.BlobProperty()

class ColladaModel(db.Model):
    name = db.StringProperty(multiline=False)
    author = db.StringProperty(multiline=True)
    fiducial = db.StringProperty(multiline=True)
    model = db.BlobProperty()
    # Stores ZipFile obj
    texture = db.BlobProperty()
    album = db.StringProperty(multiline=True)
    
class Fiducial(db.Model):
    name = db.StringProperty(multiline=False)
    marker = db.BlobProperty()
    pic = db.BlobProperty()
    used = db.BooleanProperty()
    model = db.StringProperty(multiline=False)

class Album(db.Model):
    name = db.StringProperty(multiline=False)
    models = db.StringProperty(multiline=True)
    desc = db.StringProperty(multiline=True)
    broadcast = db.BooleanProperty()
    
class Partition:
    def __init__(self, obj, name, owner, psize=500):
        self.file = obj
        # Use to ID
        self.model = name
        self.owner = owner
        # Partition size
        self.psize = psize*1024
        
    # The file object is a byte array, so we can partition into 
    # chunks of 500 kb, and return a link to first obj
    def partition(self):
        partition_num = 0
        next_byte = len(self.file)
        current_byte = len(self.file)
        while (current_byte > self.psize):
            next_byte = current_byte - self.psize
            pobj = PartitionObj(model=self.model, \
                                owner=self.owner, name=str(partition_num), \
                                content=self.file[next_byte:current_byte])
            pobj.put()
            partition_num += 1
            current_byte = next_byte
            
        retObj = PartitionObj(model=self.model, \
                            owner=self.owner, name=str(partition_num + 1), \
                            content=self.file[0:next_byte])
        retObj.put()
        
def combinePartitions(name, owner):
    partitions = db.GqlQuery("SELECT * FROM PartitionObj WHERE model='%s' \
                             AND owner='%s' ORDER BY name DESC" % (name, owner))
    partitions = partitions.fetch(partitions.count())

    
    merged = ""
    for partition in partitions:
        for byte in partition.content:
            merged += byte
        
    return merged

class MainPage(webapp.RequestHandler):
    def get(self):
        path = os.path.join(os.path.dirname(__file__), 'index.html')
        context = {}

        albums = db.GqlQuery("SELECT * FROM Album")
        albums = albums.fetch(albums.count())
        context['models'] = []
        
        if len(albums) > 0:
            context['albums'] = albums 
            for album in albums:
                if album.models != None:
                    models = db.GqlQuery("SELECT * FROM ColladaModel WHERE album = '%s'" % album.name)
                    models = models.fetch(models.count())
                    retobj = ModelTable()
                    retobj.name = album.name
                    retobj.content = models
                    context['models'].append(retobj)
            
        self.response.out.write(template.render(path, context))

class ModelTable:
    name = ""
    content = []
    

class UploadModel(webapp.RequestHandler):

    # dbg message
    dbg = ""

    # flag to write to db
    process = True
    
    def post(self):
        collada = ColladaModel()
        
        # Need to enforce email
        collada.author = self.request.get('author')
        if len(collada.author) < 7 or re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", collada.author) == None:
            self.dbg += "Please enter a properly formatted email. "

        collada.name= self.request.get('name')
        # If name is blank, use email
        if collada.name == "":
            self.dbg += "Please enter a model name. "
            
        
        # Get model and compress before upload
        model = self.request.get('model')
        # Check if model not null, should add xml validation at some point
        # Need to learn more about libraries available on app engine
        if model == "":
            self.dbg += "Please select a collada model. "
        else:
            cmodel = zlib.compress(model)

        # Check if album is selected
        album = self.request.get('albums')
        if album == None:
            self.dbg += "Please create an album. "            
        else:
            album = db.GqlQuery("SELECT * FROM Album WHERE name = '%s'" % album)
            if album.count() == 0:
                self.dbg += "Album has been deleted. Please create another album."
        
        if len(self.dbg) > 0:
            self.process = False
            
        # Sanity Check: At this point, all values are stored somehow
        
        # Get and assign fiducial marker 
        fiducials = db.GqlQuery("SELECT * FROM Fiducial WHERE used = False")
        if fiducials.count() > 0 and self.process:
            self.dbg = "Model successfully written to the database. Please \
                   check your email for the ARTag!"     
            marker = (fiducials.fetch(1))[0]

            # Currently stores string, fix later
            collada.fiducial = marker.name
            marker.model = collada.name 

            # Handle model attachment
            if len(cmodel)/1024 > 500:
                partition = Partition(cmodel, collada.name, collada.author)
                partition.partition()
            else:
                collada.model = cmodel

            # Handles texture attachment, if application
            textures = self.request.get("texture")
            if textures != None:
                if len(textures)/1024 > 500:
                    partition = Partition(textures, collada.name + "_texture", collada.author)
                    partition.partition()
                    collada.texture = "PARTITION"
                elif len(textures)/1024 > 0:
                    collada.texture = textures

            # Handles album
            album = album.fetch(1)[0]
            collada.album = album.name
            try:
                album.models += " " + collada.name
            except:
                album.models = collada.name
             
            # Send an email with an attachment
            mail.send_mail \
                (sender="jnoraky@gmail.com",
                 to = collada.author,
                 subject = "ARTag",
                 body = """
Attached is your ARTag. Print it and bring it to your destination.
Your unique ARTag identifier is <b>%s</b>. This will be used to load your
model on the client.

The Ops Lab
                 """ % collada.name,
                 attachments=[(marker.name, marker.pic)]
                 )

            # Disable ARTag for other models
            marker.used = True
            
            # Push to server
            db.put(marker)
            db.put(collada)
            db.put(album)
        elif fiducials.count() <= 0 and self.process:
            self.dbg = "Sorry, your model could not be uploaded. Please \
                   try again when more ARTags become available"
        self.redirect('/?tab=step2&dbg=%s' % self.dbg)

    '''
    def redirect(self, uri, permanent=False):
        self.response.out.write(
                """
                <html><head>
                <script language="javascript" type="text/javascript">
                alert("%s");
                window.location="%s";
                </script>
                </head></html>
                """ % (self.dbg, uri))
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

class CreateAlbum(webapp.RequestHandler):
    def post(self):
        album = Album()
        name = self.request.get('name')
        dbg = ''
        album.desc = self.request.get('description')
        # Check if there is a name and eventually check if other names
        # exist
        if len(name) > 0:
            album.name = name
            dbg = 'Awesome! Album %s successfully created!' % name
            album.put()
        else:
            dbg = 'Please enter a name'
        self.redirect('/?tab=step1&dbg=%s' % dbg)
        
# Download the collada file
class DownloadModel(webapp.RequestHandler):
    def get(self, resource):
        model_name = str(urllib.unquote(resource))
        models = db.GqlQuery("SELECT * FROM ColladaModel WHERE name= '%s'" % model_name)
        if models.count() > 0:
            model = (models.fetch(1))[0]
            if model.model == None:
                mfiles = combinePartitions(model.name, model.author)
                self.response.out.write(zlib.decompress(mfiles))
            else:
                self.response.out.write(zlib.decompress(model.model))

# Download the pattern file
class DownloadPattern(webapp.RequestHandler):
    def get(self, resource):
        model_name = str(urllib.unquote(resource))
        patterns = db.GqlQuery("SELECT * FROM Fiducial WHERE model= '%s'" % model_name)
        if patterns.count() > 0:
            pattern = (patterns.fetch(1))[0]
            self.response.out.write(pattern.marker)

# Download the textures 
class DownloadTexture(webapp.RequestHandler):
    def get(self, resource):
        texture_name = str(urllib.unquote(resource))
        textures = db.GqlQuery("SELECT * FROM ColladaModel WHERE name = '%s'" % texture_name)
        if textures.count() > 0:
            texture = (textures.fetch(1))[0]
            if texture.texture == "PARTITION":
                combined_texture = combinePartitions(texture.name + "_texture", texture.author)
                self.response.out.write(combined_texture)
            elif texture.texture != None:
                self.response.headers['Content-Type'] = "application/zip"
                self.response.out.write(texture.texture)
            
# Clear db of models and reset the fiducial markers, run at midnight
class clearDb(webapp.RequestHandler):
    def get(self):
        # delete models
        models = db.GqlQuery("SELECT * FROM ColladaModel")
        models = models.fetch(models.count())
        db.delete(models)

        # delete partitions
        partitions = db.GqlQuery("SELECT * FROM PartitionObj")
        partitions = partitions.fetch(partitions.count())
        db.delete(partitions)
        
        #reset fiducials
        tags = db.GqlQuery("SELECT * FROM Fiducial")
        tags = tags.fetch(tags.count())
        for tag in tags:
            tag.used = False
            tag.put()
            
        self.response.out.write("All Models have been deleted")

class All(webapp.RequestHandler):
    def get(self):
        albums = db.GqlQuery("SELECT * FROM Album WHERE broadcast=True")
        try:
            album = albums.fetch(1)[0]
            self.response.out.write(album.models)
        except:
            self.response.out.write("")

class Broadcast(webapp.RequestHandler):
    def post(self):
        dbg = 'Album %s is now successfully being broadcasted!' % self.request.get('albums')
        albums = db.GqlQuery("SELECT * FROM Album")
        albums = albums.fetch(albums.count())
        for album in albums:
            if album.name == self.request.get('albums'):
                album.broadcast = True
            else:
                album.broadcast = False
            db.put(album)
        
        self.redirect('/?tab=step3&dbg=%s' % dbg)
        
application = webapp.WSGIApplication(
                                    [('/', MainPage), 
                                     ('/upload', UploadModel),
                                     ('/createAlbum', CreateAlbum),
                                     ('/broadcast', Broadcast),
                                     ('/fiducial', FiducialUploader),        
                                     ('/fiducialupload', UploadFiducial),
                                     ('/all', All),
                                     ('/download/([^/]+)?', DownloadModel),
                                     ('/pattern/([^/]+)?', DownloadPattern),
                                     ('/texture/([^/]+)?', DownloadTexture),
                                     ('/delete', clearDb)],
                                    debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
