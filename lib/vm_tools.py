#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# The instance type that should be used if the user does not
# specify one.
DEFAULT_INSTANCE_TYPE = "m1.large"


# A list of the instance types we allow users to run AppScale over.
ALLOWED_INSTANCE_TYPES = ["m1.large"]


# A list of the infrastructures that AppScale can deploy to.
ALLOWED_INFRASTRUCTURES = ["ec2", "euca"]


# A list of environment variables that the user must set
# when deploying AppScale over a cloud infrastructure.
EC2_ENVIRONMENT_VARIABLES = ["EC2_PRIVATE_KEY", "EC2_CERT",
  "EC2_SECRET_KEY", "EC2_ACCESS_KEY"]


class VMTools():
  pass
