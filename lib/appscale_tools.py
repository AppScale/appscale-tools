#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


from custom_exceptions import BadConfigurationException


class AppScaleTools():
  """AppScaleTools provides callers with a way to start,
  stop, and interact with AppScale deployments, on virtualized
  clusters or on cloud infrastructures.

  These methods provide an interface for users who wish to
  start and control AppScale through a dict of parameters. An
  alternative to this method is to use the AppScale class,
  which stores state in an AppScalefile in the current working
  directory (as opposed to a dict), but under the hood these
  methods get called anyways.
  """


  def run_instances(self, options):
    """Starts a new AppScale deployment with the parameters given.

    Args:
      options: A Namespace that has fields for each parameter that
        can be passed in via the command-line interface.
    Raises:
      BadConfigurationException: If the user passes in options
        that are not sufficient to start an AppScale deplyoment
        (e.g., running on EC2 but not specifying the AMI to use),
        or if the user provides us contradictory options (e.g.,
        running on EC2 but not specifying EC2 credentials).
    """
    # make sure the user gave us an ami if running in cloud
    if options.infrastructure and not options.machine:
      raise BadConfigurationException("Need a machine image (ami) " +
        "when running in a cloud infrastructure.")
