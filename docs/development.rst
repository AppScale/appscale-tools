Development
===========

There are a couple tools configured for developing AppScale Tools with Python:
``nose`` and ``pylint``.  Nose is a test runner that is invoked using the
``nosetests`` command.  Nose will automatically find and run any tests it can
find.  Initial tests have been placed in the ``tests`` directory.

Pylint is a "linter", which helps keep the code free of syntax and formatting
convention errors.  Before pushing code upstream, make sure to run pylint in
order to catch errors and keep code consistent.

Pylint has been re-configured with the following changes from the default:

    * the messages in the report include their respective IDs.  they are useful for configuring pylint

    * the max line width was changed from 80 to 120.

    * the string module is not in the deprecated list because there are useful
      functions in there not anywhere else.

    * there is a ``lint`` package in the project's root that contains a module
      that defines a helper module for defining objects in the ``sh`` module
      that are used in the code, but are dynamic so pylint, by default, counts
      them as errors.

To make it easier to run there is a ``make`` target: pylint.  Run it like so to lint the ``appscaletools`` package::

    make pylint

Or to run it on another file, like ``bin/appscale-boostrap``::

    make pylint f=bin/appscale-tools
