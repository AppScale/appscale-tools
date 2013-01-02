#!/usr/bin/env python 
import os

from distutils.core import setup 

SCRIPT_DIR = os.path.dirname(__file__)
if SCRIPT_DIR == '':
    SCRIPT_DIR = '.'

scripts = filter(lambda x: not os.path.basename(x).startswith('.'), ['bin/%s' % x for x in os.listdir('%s/bin' % (SCRIPT_DIR,))])

data_files=[
        ('share/bootstrap', ['bootstrap/appscale-bootstrap-ec2']),
]

setup(name = 'appscale-tools', 
      version = '0.1', 
      description = "AppScale Management Tools",
      author = "Roberto Aguilar", 
      author_email = "roberto@appscale.com", 
      packages = ['appscaletools'], 
      long_description=open('README').read(),
      scripts=scripts,
      data_files=data_files,
      url='http://github.com/AppScale/appscale-tools',
      license='LICENSE'
)
