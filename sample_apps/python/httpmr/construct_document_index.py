import wsgiref
from google.appengine.ext import webapp
from httpmr import appengine
from httpmr import base
from wsgiref import handlers
from google.appengine.ext import db


class Document(db.Model):
  title = db.StringProperty(required=True)
  contents = db.TextProperty(required=True)


class DocumentIndex(db.Model):
  token = db.StringProperty(required=True)
  document_titles = db.StringListProperty()


class TokenMapper(base.Mapper):
  
  def Map(self, document_title, document):
    for token in list(set(document.contents.split(" "))):
      if token:
        yield token, document_title


class TokenReducer(base.Reducer):
  
  def Reduce(self, token, document_titles):
    yield None, DocumentIndex(token=token,
                              document_titles=document_titles)


class ConstructDocumentIndexMapReduce(appengine.AppEngineMaster):
  
  def __init__(self):
    self.QuickInit("construct_token_index",
                   mapper=TokenMapper(),
                   reducer=TokenReducer(),
                   source=appengine.AppEngineSource(Document.all(),
                                                    "title"),
                   sink=appengine.AppEngineSink(),
                   intermediate_values_set_job_name=False,
                   intermediate_values_set_nonsense_value=False)


def main():
  application = webapp.WSGIApplication([('/construct_document_index',
                                         ConstructDocumentIndexMapReduce)],
                                       debug=True)
  wsgiref.handlers.CGIHandler().run(application)

if __name__ == "__main__":
  main()