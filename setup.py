from lib import version_helper
from setuptools import setup
import glob

version_helper.ensure_valid_python_is_used()


def readme():
  """Return the contents of the readme file."""
  with open('README.md') as readme_file:
    return readme_file.read()

setup(
  name='appscale-tools',
  version='2.4.0',
  description='A set of command-line tools for interacting with AppScale',
  long_description=readme(),
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
    'google-api-python-client',
    'argparse'
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
