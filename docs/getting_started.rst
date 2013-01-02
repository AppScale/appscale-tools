Getting Started
===============

The quickest way to get started using AppScale Tools is using VirtualBox and
Vagrant.

Note, while the process below should work on any system that VirtualBox and
Vagrant run on, this documentation was written while following the steps below
on a Mac OS X system.

Installing VirtualBox
---------------------

Please visit the `VirtualBox website`__ for more details.

Installing Vagrant
------------------

Make sure you have Ruby and Rubygems support.  Then, from the command line, run::

    gem install vagrant

Downloading the base box
~~~~~~~~~~~~~~~~~~~~~~~~

Vagrant uses a base box to create VMs.  Run the command below to download an
Ubuntu 10.04 Lucid 64-bit box::

    vagrant box add lucid64 http://files.vagrantup.com/lucid64.box

Clone the AppScale Tools repository
-----------------------------------

Vagrant is configured to automatically mount ``~/Appscale`` as
``/srv/appscale`` on the VM, and look for the ``appscale-tools`` repo at
``/srv/appscale/repo/appscale-tools``.  At the moment there are some
limitations with the Puppet manifest script that require hard-coded absolute
paths.

Clone the repository in ``~/Appscale/repo`` on your computer::

    mkdir -p ~/Appscale/repo
    cd ~/Appscale/repo
    git clone https://github.com/AppScale/appscale-tools.git
    cd appscale-tools

Currently this documentation reflects the changes in the
``auto_appscale_install`` branch, so switch to that branch::

    git checkout auto_appscale_install

Configure AWS credentials
-------------------------

Create the AppScale Tools configuration directory::

    mkdir ~/.appscale-tools

Next, create the file ``~/.appscale-tools/appscale_config.sh`` with the
following content (filling in your personal information, of course.  Do not
include curly braces)::

    export EC2_ACCESS_KEY='{{ your key here }}'
    export EC2_SECRET_KEY='{{ your key here }}'
    export EC2_USER_ID='{{ your id here }}'
    export EC2_MY_SSH_KEY=~/.appscale-tools/id_{{ your username }}

Finally, download your account's certificate and private key, or ask your
administrator for IAM credentials, and copy the AWS certificate and private
key::

    cp <path to cert-*.pem> ~/.appscale-tools/cert.pem
    cp <path to pk-*.pem> ~/.appscale-tools/pk.pem

Launch a development VM
--------------------------

Once the prerequisites are installed and credentials configured, run the
command ``vagrant up`` to setup the environment, followed by ``vagrant ssh`` to
connect to the VM.  The repository is mounted inside the VM at
``/srv/appscale/repo/appscale-tools``.

The ``repo`` command
~~~~~~~~~~~~~~~~~~~~

AppScale Tools includes a ``repo`` command which makes it easy to switch to
repositories located in ``/srv/appscale/repo``.  Type ``repo``, followed by a
space, and enter the ``tab`` key.  You will then see a list of available
repositories in the ``/srv/appscale/repo`` directory.  Please see the
`Wikipedia article on tab completion`_ for more information.

Confirm EC2 Tools are working
-----------------------------

Once you SSH into the VM (``vagrant ssh``), confirm your personal
information is displayed when using the command::

    echo $EC2_ACCESS_KEY

Confirm EC2 Tools are working by running the command::

    ec2-describe-instances

Create an EC2 SSH key
---------------------

With a working EC2 environment, create an SSH key that will be used to SSH into
EC2 instances.  Run the following commands substituting your name below::

    ec2-add-keypair <your name> >> ~/.appscale-tools/id_<your username>
    chmod 0600 ~/.appscale-tools/id_<your username>

For example::

    ec2-add-keypair berto >> ~/.appscale-tools/id_berto
    chmod 0600 ~/.appscale-tools/id_berto

Your system is now configured!  Note that even if you destroy this VM, you will
not need to re-configure the system.  These configuration files are kept in
your host machine's home directory under ``~/.appscale-tools``.  You can run
``vagrant destroy``, followed by ``vagrant up`` and you'll be ready to run
instantly.

.. _VirtualBox: http://virtualbox.org/
__ VirtualBox_
.. _Wikipedia article on tab completion: http://en.wikipedia.org/wiki/Command-line_completion
