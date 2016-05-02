import glob
from setuptools import setup

from lib import version_helper

version_helper.ensure_valid_python_is_used()

long_description = """AppScale Tools
--------------

A set of command-line tools for interacting with AppScale.

What is AppScale?
-----------------

AppScale is an open-source cloud computing platform that automatically deploys
and scales unmodified Google App Engine applications over public and private
cloud systems and on-premise clusters. AppScale is modeled on the App Engine
APIs and has support for Python, Go, PHP and Java applications.

AppScale is developed and maintained by AppScale Systems, Inc., based in
Santa Barbara, California, and Google.

http://www.appscale.com
"""

setup(
  name='appscale-tools',
  version='2.8.0',
  description='A set of command-line tools for interacting with AppScale',
  long_description=long_description,
  author='AppScale Systems, Inc.',
  url='https://github.com/AppScale/appscale-tools',
  license='Apache License 2.0',
  keywords='appscale google-app-engine python java go php',
  platforms='Posix; MacOS X',
  install_requires=[
    'httplib2',
    'termcolor',
    'SOAPpy',
    'PyYAML',
    'boto',
    'google-api-python-client>=1.5.0',
    'argparse',
    'oauth2client>=2.0.0',
  ],
  classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: Apache Software License',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Topic :: Utilities'
  ],
  package_dir={'appscale': 'lib'},
  packages=['appscale', 'appscale.agents'],
  scripts=glob.glob('bin/*'),
  package_data={'appscale': ['../templates/*']}
)
