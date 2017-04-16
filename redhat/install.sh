# Install script for yum based distributions.
yum install python-setuptools 
easy_install termcolor
easy_install SOAPpy
easy_install pyyaml
easy_install boto
easy_install oauth2client
easy_install google-api-python-client
easy_install httplib2
easy_install argparse
easy_install python-gflags
test -e /root/.ssh/id_rsa || ssh-keygen -q -t rsa -f /root/.ssh/id_rsa -N ""
