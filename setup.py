import sys

from setuptools import setup

# Require users to uninstall versions that used the appscale namespace.
try:
  import appscale.appscale_tools
  print('Please run "pip uninstall appscale-tools" first.\n'
        "Your installed version conflicts with this version's namespace.")
  sys.exit()
except ImportError:
  pass


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
  version='3.3.1',
  description='A set of command-line tools for interacting with AppScale',
  long_description=long_description,
  author='AppScale Systems, Inc.',
  url='https://github.com/AppScale/appscale-tools',
  license='Apache License 2.0',
  keywords='appscale google-app-engine python java go php',
  platforms='Posix; MacOS X',
  install_requires=[
    'adal==0.4.5',
    'azure==2.0.0rc6',
    'azure-common[autorest]==1.1.4',
    'cryptography',
    'argparse',
    'boto',
    'google-api-python-client==1.5.4',
    'haikunator',
    'httplib2',
    'msrest',
    'msrestazure',
    'oauth2client==4.0.0',
    'PyYAML',
    'requests[security]>=2.7.0,<2.15',
    'setuptools>=11.3,<34',
    'SOAPpy',
    'termcolor',
    'wstools==0.4.3',
    'tabulate==0.7.7'
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
  namespace_packages=['appscale'],
  packages=['appscale', 'appscale.tools', 'appscale.tools.agents',
            'appscale.tools.scripts'],
  entry_points={
    'console_scripts': [
      'appscale=appscale.tools.scripts.appscale:main',
      'appscale-add-instances=appscale.tools.scripts.add_instances:main',
      'appscale-add-keypair=appscale.tools.scripts.add_keypair:main',
      'appscale-describe-instances='
        'appscale.tools.scripts.describe_instances:main',
      'appscale-gather-logs=appscale.tools.scripts.gather_logs:main',
      'appscale-get-property=appscale.tools.scripts.get_property:main',
      'appscale-relocate-app=appscale.tools.scripts.relocate_app:main',
      'appscale-remove-app=appscale.tools.scripts.remove_app:main',
      'appscale-reset-pwd=appscale.tools.scripts.reset_pwd:main',
      'appscale-run-instances=appscale.tools.scripts.run_instances:main',
      'appscale-set-property=appscale.tools.scripts.set_property:main',
      'appscale-terminate-instances='
        'appscale.tools.scripts.terminate_instances:main',
      'appscale-upgrade=appscale.tools.scripts.upgrade:main',
      'appscale-upload-app=appscale.tools.scripts.upload_app:main'
    ]
  },
  package_data={'appscale.tools': ['templates/*']}
)
