First Run
=========

With a configured EC2 Tools environment, now it's time to create an AppScale image.

If not already there, SSH into the Vagrant box::

    vagrant ssh

Then go into the appscale-tools repository::

    cd /srv/appscale/repo/appscale-tools

From here you can bootstrap the image creation process using the command::

    ./bin/appscale-bootstrap

For more information on this command simply run it with the ``-h`` flag::

    ./bin/appscale-bootstrap -h

This command will take a while to run.  Once it's complete, you will see in the
last few lines of the log the instance id and the image id that was created.

NOTE: The bootstrap script does not currently terminate the instance that is
created in order to make an AppScale image.  Please terminate it once you are
done.

Create an AppScale Cluster
--------------------------

``appscale-run-instances`` [with flags] - fires up a cluster

