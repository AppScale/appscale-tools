import construct_document_index
import random
import logging
from google.appengine.ext import db

vocabulary = ['Nunc',
  'nec',
  'lectus',
  'ut',
  'lacus',
  'accumsan',
  'malesuada.',
  'Mauris',
  'at',
  'odio.',
  'Curabitur',
  'feugiat.',
  'Aenean',
  'convallis',
  'nibh',
  'eu',
  'nisl.',
  'Donec',
  'luctus',
  'lectus',
  'sed',
  'metus.',
  'Duis',
  'convallis',
  'dictum',
  'turpis.',
  'Vivamus',
  'dignissim',
  'hendrerit',
  'lectus.',
  'Aliquam',
  'nec',
  'nulla.',
  'Nullam',
  'sit',
  'amet',
  'urna',
  'ac',
  'massa',
  'fermentum',
  'auctor.',
  'Etiam',
  'eleifend,',
  'magna',
  'at',
  'hendrerit',
  'dapibus,',
  'massa',
  'quam',
  'eleifend',
  'velit,',
  'a',
  'porttitor',
  'lacus',
  'est',
  'ac',
  'nisi.']

def main():
  documents = []
  for i in xrange(1000):
    document = []
    for i in xrange(50):
      document.append(random.choice(vocabulary))
    documents.append(" ".join(document))
  
  for document in documents:
    title = document[0:50]
    logging.info("Filling store with document title: %s, document: %s" %
                 (title, document))
    construct_document_index.Document(title=title, contents=document).put()

if __name__ == "__main__":
  main()